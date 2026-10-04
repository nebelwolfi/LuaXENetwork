// NOMINMAX first: framework.h has no <algorithm> in front of windows.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "framework.h"

#include "Dial.h"
#include "CertHelper.h"
#include "TlsVerify.h"

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

// TB-287: the module's single dial path. See socket/Dial.h.

namespace {

int Seconds(int milliseconds)
{
    return std::max(1, (milliseconds + 999) / 1000);
}

std::string Utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string utf8(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
        utf8.data(), size, nullptr, nullptr);
    return utf8;
}

std::string Endpoint(const std::wstring& host, unsigned short port)
{
    std::string text = Utf8(host);
    text += ":";
    text += std::to_string(port);
    return text;
}

// The whole connect plus handshake budget: connect_timeout_ms on its own, or
// what is left of total_timeout_ms when the caller set one.
int Remaining(const DialOptions& options, std::chrono::steady_clock::time_point started)
{
    if (options.total_timeout_ms <= 0) return options.connect_timeout_ms;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    const auto left = static_cast<long long>(options.total_timeout_ms) - elapsed;
    if (left <= 0)
        throw DialError("timeout", "[timeout] the total timeout of "
            + std::to_string(options.total_timeout_ms) + " ms expired before connecting");
    return static_cast<int>(std::min<long long>(options.connect_timeout_ms, left));
}

} // namespace

// ---- SOCKS5 (RFC 1928 greeting, RFC 1929 authentication, CONNECT) ------------

namespace {

std::string LowerAscii(std::string text)
{
    for (char& character : text)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return text;
}

std::wstring WideFromUtf8(const std::string& text)
{
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring wide(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

int HexDigit(char character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

std::string PercentDecode(const std::string& text)
{
    std::string out;
    for (size_t index = 0; index < text.size(); ++index) {
        if (text[index] != '%') { out += text[index]; continue; }
        if (index + 2 >= text.size())
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] truncated escape in the proxy credentials");
        const int high = HexDigit(text[index + 1]);
        const int low = HexDigit(text[index + 2]);
        if (high < 0 || low < 0)
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] bad escape sequence in the proxy credentials");
        out += static_cast<char>((high << 4) | low);
        index += 2;
    }
    return out;
}

// socks5 resolves the target HERE, so a name has to become an address before it
// can go on the wire (socks5h is the other way round: the name is sent as-is).
// IPv4 is preferred because the module's own direct connect is an AF_INET socket;
// IPv6 is the fallback, so an IPv6-only target still works. The bytes come back
// ready to append: 4 for ATYP 1, 16 for ATYP 4.
bool ResolveLocally(const std::wstring& host, std::vector<unsigned char>& address)
{
    address.clear();
    ADDRINFOW hintsW{};
    hintsW.ai_family = AF_UNSPEC;
    hintsW.ai_socktype = SOCK_STREAM;
    hintsW.ai_protocol = IPPROTO_TCP;
    PADDRINFOW results = nullptr;
    // The W variant explicitly: this translation unit is an ANSI build, so the
    // unqualified name is the one that takes char*, and the host is a wstring.
    if (GetAddrInfoW(host.c_str(), nullptr, &hintsW, &results) != 0 || results == nullptr)
        return false;
    for (const int family : { AF_INET, AF_INET6 }) {
        for (const ADDRINFOW* entry = results; entry != nullptr; entry = entry->ai_next) {
            if (entry->ai_family != family || entry->ai_addr == nullptr) continue;
            const size_t wanted = family == AF_INET ? 4u : 16u;
            if (entry->ai_addrlen < wanted) continue;
            const unsigned char* first = reinterpret_cast<const unsigned char*>(entry->ai_addr) +
                (family == AF_INET
                    ? offsetof(sockaddr_in, sin_addr)
                    : offsetof(sockaddr_in6, sin6_addr));
            address.assign(first, first + wanted);
            FreeAddrInfoW(results);
            return true;
        }
    }
    FreeAddrInfoW(results);
    return false;
}

// Every step of the exchange is armed from the caller's deadline instead of from
// the one timeout that was set before the TCP connect: CBaseSock restarts its
// recv timer on every read, so without this a caller that set total_timeout_ms
// (the only overall budget there is) could still be held for a fresh
// connect_timeout per step - or, with a proxy that answers a byte at a time,
// for as long as it likes.
struct StepBudget {
    CActiveSock& socket;
    const DialOptions& options;
    const std::chrono::steady_clock::time_point started;

    // Remaining() throws [timeout] once the budget is spent, so an expired
    // deadline is a failure instead of one more read. The socket's own timers
    // count whole seconds (CBaseSock keeps a seconds count), which is why
    // Seconds() rounds up: the deadline holds to within a second.
    void Arm() const
    {
        const int milliseconds = Remaining(options, started);
        socket.SetSendTimeoutSeconds(Seconds(milliseconds));
        socket.SetRecvTimeoutSeconds(Seconds(milliseconds));
    }
};

void SendAll(const StepBudget& budget, const std::string& bytes, const char* what)
{
    budget.Arm();
    const int sent = budget.socket.Send(bytes.data(), bytes.size());
    if (sent != static_cast<int>(bytes.size()))
        throw DialError("proxy_protocol_error",
            std::string("[proxy_protocol_error] could not send the ") + what + " to the SOCKS5 proxy ("
            + std::to_string(sent) + " of " + std::to_string(bytes.size()) + " bytes, error "
            + std::to_string(budget.socket.GetLastError()) + ")");
}

// Exactly `count` bytes, or a failure that says which one it was. A short read is
// never taken as good enough: CBaseSock::Recv already loops until MinLen, so
// anything less than count means the connection ended or stopped making progress.
std::string RecvExact(const StepBudget& budget, size_t count, const char* what)
{
    if (count == 0) return {};
    budget.Arm();
    std::string buffer(count, '\0');
    const int received = budget.socket.Recv(buffer.data(), count, count);
    if (received == SOCKET_ERROR) {
        const DWORD error = budget.socket.GetLastError();
        if (error == ERROR_TIMEOUT || error == WSAETIMEDOUT)
            throw DialError("proxy_timeout", std::string("[proxy_timeout] the SOCKS5 proxy did not send the ")
                + what + " in time");
        throw DialError("proxy_closed", std::string("[proxy_closed] the SOCKS5 proxy closed the connection during the ")
            + what);
    }
    if (static_cast<size_t>(received) != count)
        throw DialError("proxy_closed", std::string("[proxy_closed] the SOCKS5 proxy closed the connection during the ")
            + what + " (" + std::to_string(received) + " of " + std::to_string(count)
            + " bytes, error " + std::to_string(budget.socket.GetLastError()) + ")");
    return buffer;
}

std::string ReplyText(unsigned char code)
{
    switch (code) {
    case 0x01: return "the SOCKS5 proxy reported a general failure";
    case 0x02: return "the SOCKS5 proxy refused this connection (not allowed by ruleset)";
    case 0x03: return "the SOCKS5 proxy reported the network as unreachable";
    case 0x04: return "the SOCKS5 proxy could not reach the host (its own DNS or route failed)";
    case 0x05: return "the target refused the connection through the SOCKS5 proxy";
    case 0x06: return "the SOCKS5 proxy reported the TTL expired";
    case 0x07: return "the SOCKS5 proxy does not support the CONNECT command";
    case 0x08: return "the SOCKS5 proxy does not support the address type asked for";
    default: return "the SOCKS5 proxy answered with an unknown reply code " + std::to_string(code);
    }
}

std::string ReplyCode(unsigned char code)
{
    switch (code) {
    case 0x01: return "proxy_general_failure";
    case 0x02: return "proxy_not_allowed";
    case 0x03: return "proxy_network_unreachable";
    case 0x04: return "proxy_host_unreachable";
    case 0x05: return "proxy_target_refused";
    case 0x06: return "proxy_ttl_expired";
    case 0x07: return "proxy_command_unsupported";
    case 0x08: return "proxy_address_type_unsupported";
    default: return "proxy_reply_unknown";
    }
}

// The target address the CONNECT carries: a name for socks5h (the proxy resolves
// it), a locally resolved address for socks5.
std::string ConnectRequest(const ProxyTarget& target, const std::wstring& host, unsigned short port)
{
    std::string request;
    request += static_cast<char>(0x05);   // version
    request += static_cast<char>(0x01);   // CONNECT
    request += static_cast<char>(0x00);   // reserved
    if (target.remote_dns) {
        const std::string name = Utf8(host);
        // RFC 1928: ATYP 3 carries the length in ONE octet, so 1-255 bytes.
        if (name.empty() || name.size() > 255)
            throw DialError("proxy_target_name_invalid",
                "[proxy_target_name_invalid] the target host name must be 1-255 bytes for socks5h, this one is "
                + std::to_string(name.size()));
        request += static_cast<char>(0x03);   // domain name
        request += static_cast<char>(name.size());
        request += name;
    } else {
        // socks5: the address goes on the wire in binary, not as text - which
        // means the name has to be resolved HERE first.
        IN_ADDR v4{};
        if (InetPtonW(AF_INET, host.c_str(), &v4)) {
            request += static_cast<char>(0x01);
            request.append(reinterpret_cast<const char*>(&v4), 4);
        } else {
            std::vector<unsigned char> resolved;
            if (!ResolveLocally(host, resolved))
                throw DialError("proxy_dns_failed",
                    "[proxy_dns_failed] could not resolve " + Endpoint(host, port)
                    + " locally for a socks5 proxy request; socks5h:// lets the proxy resolve it instead");
            request += resolved.size() == 4 ? static_cast<char>(0x01) : static_cast<char>(0x04);
            request.append(reinterpret_cast<const char*>(resolved.data()), resolved.size());
        }
    }
    request += static_cast<char>((port >> 8) & 0xFF);
    request += static_cast<char>(port & 0xFF);
    return request;
}

void Socks5Handshake(CActiveSock& socket, const ProxyTarget& target, const DialOptions& options,
    std::chrono::steady_clock::time_point started, const std::wstring& host, unsigned short port)
{
    const std::string where = "the SOCKS5 proxy at " + Utf8(target.host) + ":" + std::to_string(target.port);
    const StepBudget budget{ socket, options, started };

    // 1. method negotiation
    std::string greeting;
    greeting += static_cast<char>(0x05);
    if (target.has_credentials) {
        greeting += static_cast<char>(0x02);
        greeting += static_cast<char>(0x00);
        greeting += static_cast<char>(0x02);
    } else {
        greeting += static_cast<char>(0x01);
        greeting += static_cast<char>(0x00);
    }
    SendAll(budget, greeting, "method list");
    const std::string choice = RecvExact(budget, 2, "method reply");
    if (static_cast<unsigned char>(choice[0]) != 0x05)
        throw DialError("proxy_protocol_error", "[proxy_protocol_error] " + where + " is not SOCKS5");
    if (static_cast<unsigned char>(choice[1]) == 0xFF)
        throw DialError("proxy_no_acceptable_auth",
            "[proxy_no_acceptable_auth] " + where + " accepts no authentication method this client offers");
    if (static_cast<unsigned char>(choice[1]) != 0x00 && static_cast<unsigned char>(choice[1]) != 0x02)
        throw DialError("proxy_no_acceptable_auth",
            "[proxy_no_acceptable_auth] " + where + " chose an authentication method this client does not support");

    // 2. RFC 1929 username/password, only when the proxy picked it
    if (static_cast<unsigned char>(choice[1]) == 0x02) {
        if (!target.has_credentials)
            throw DialError("proxy_no_acceptable_auth",
                "[proxy_no_acceptable_auth] " + where + " requires a username and password, and none were given");
        // RFC 1929: ULEN and PLEN are one octet each, which ParseProxyUrl has
        // already bounded to 1-255 bytes - the cast cannot truncate.
        std::string authentication;
        authentication += static_cast<char>(0x01);
        authentication += static_cast<char>(target.user.size());
        authentication += target.user;
        authentication += static_cast<char>(target.password.size());
        authentication += target.password;
        SendAll(budget, authentication, "credentials");
        const std::string verdict = RecvExact(budget, 2, "authentication reply");
        if (static_cast<unsigned char>(verdict[0]) != 0x01)
            throw DialError("proxy_protocol_error",
                "[proxy_protocol_error] " + where + " answered the RFC 1929 authentication with a bad version");
        if (static_cast<unsigned char>(verdict[1]) != 0x00)
            // Deliberately says nothing about the values: credentials never
            // appear in an error message.
            throw DialError("proxy_auth_failed",
                "[proxy_auth_failed] " + where + " rejected the supplied username and password");
    }

    // 3. CONNECT and the whole reply, including the bound address
    SendAll(budget, ConnectRequest(target, host, port), "CONNECT request");
    const std::string header = RecvExact(budget, 4, "CONNECT reply");
    if (static_cast<unsigned char>(header[0]) != 0x05)
        throw DialError("proxy_protocol_error", "[proxy_protocol_error] " + where + " answered a CONNECT with a bad version");
    const unsigned char code = static_cast<unsigned char>(header[1]);
    if (code != 0x00)
        throw DialError(ReplyCode(code), "[" + ReplyCode(code) + "] " + where + ": " + ReplyText(code));
    size_t address_length = 0;
    switch (static_cast<unsigned char>(header[3])) {
    case 0x01: address_length = 4; break;
    case 0x04: address_length = 16; break;
    case 0x03: {
        // ATYP 3: the length itself is one more octet, and it is read before the
        // address - a fixed-size read here would swallow part of the name.
        const std::string length = RecvExact(budget, 1, "CONNECT reply");
        address_length = static_cast<unsigned char>(length[0]);
        if (address_length == 0)
            throw DialError("proxy_protocol_error",
                "[proxy_protocol_error] " + where + " answered a CONNECT with an empty bound address");
        break;
    }
    default:
        throw DialError("proxy_protocol_error", "[proxy_protocol_error] " + where + " answered with an unknown address type");
    }
    RecvExact(budget, address_length, "CONNECT reply");   // the bound address
    RecvExact(budget, 2, "CONNECT reply");                // the bound port
}

} // namespace

ProxyTarget ParseProxyUrl(const std::string& url)
{
    const std::string lowered = LowerAscii(url);
    ProxyTarget target;
    if (lowered.starts_with("socks5h://")) {
        target.remote_dns = true;
    } else if (lowered.starts_with("socks5://")) {
        target.remote_dns = false;
    } else {
        throw DialError("proxy_url_invalid",
            "[proxy_url_invalid] the proxy must be socks5:// or socks5h://");
    }
    std::string rest = url.substr(lowered.starts_with("socks5h://") ? 10 : 9);

    const size_t at = rest.find('@');
    if (at != std::string::npos) {
        if (rest.find('@', at + 1) != std::string::npos)
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy URL has more than one '@'");
        const std::string userinfo = rest.substr(0, at);
        rest = rest.substr(at + 1);
        const size_t colon = userinfo.find(':');
        target.user = PercentDecode(colon == std::string::npos ? userinfo : userinfo.substr(0, colon));
        target.password = colon == std::string::npos ? std::string() : PercentDecode(userinfo.substr(colon + 1));
        if (target.user.empty() || target.user.size() > 255 || target.password.size() > 255)
            throw DialError("proxy_url_invalid",
                "[proxy_url_invalid] the proxy user name and password must each be 1-255 bytes");
        target.has_credentials = true;
    }

    std::string authority;
    if (!rest.empty() && rest[0] == '[') {   // [::1]:1080
        const size_t closing = rest.find(']');
        if (closing == std::string::npos)
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] the bracketed proxy host is not closed");
        authority = rest.substr(1, closing - 1);
        rest = rest.substr(closing + 1);
        if (rest.empty() || rest[0] != ':')
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy URL has no port");
    } else {
        const size_t colon = rest.rfind(':');
        if (colon == std::string::npos)
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy URL has no port");
        authority = rest.substr(0, colon);
        rest = rest.substr(colon);
    }

    const std::string port_text = rest.substr(1);
    if (port_text.empty() || port_text.size() > 5)
        throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy port is missing or malformed");
    unsigned long port = 0;
    for (const char digit : port_text) {
        if (digit < '0' || digit > '9')
            throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy port is not a number");
        port = port * 10 + static_cast<unsigned long>(digit - '0');
    }
    if (authority.empty() || port == 0 || port > 65535)
        throw DialError("proxy_url_invalid", "[proxy_url_invalid] the proxy host or port is out of range");
    target.host = WideFromUtf8(authority);
    target.port = static_cast<unsigned short>(port);
    return target;
}

std::string DialErrorText(const std::wstring& host, unsigned short port, DWORD wsa_error)
{
    const char* text = "connection failed";
    const char* detail_code = "connect_failed";
    switch (wsa_error) {
    case WSAECONNREFUSED: detail_code = "connect_refused"; text = "connection refused"; break;
    case WSAETIMEDOUT: detail_code = "connect_timeout"; text = "connection timed out"; break;
    case ERROR_TIMEOUT: detail_code = "connect_timeout"; text = "connection timed out"; break;
    case WSAENETUNREACH: detail_code = "connect_network_unreachable"; text = "network unreachable"; break;
    case WSAEHOSTUNREACH: detail_code = "connect_network_unreachable"; text = "host unreachable"; break;
    case WSAEHOSTDOWN: detail_code = "connect_network_unreachable"; text = "host down"; break;
    case WSAHOST_NOT_FOUND: detail_code = "dns_failed"; text = "host not found"; break;
    default: break;
    }
    std::string message = "[" + std::string(detail_code) + "] " + Endpoint(host, port) + ": " + text;
    if (wsa_error) message += " (error " + std::to_string(wsa_error) + ")";
    return message;
}

DialedConnection Dial(const DialOptions& options, HANDLE shutdown_event)
{
    const auto started = std::chrono::steady_clock::now();
    DialedConnection connection;

    auto socket = std::make_unique<CActiveSock>(shutdown_event);
    const int connect_timeout = Remaining(options, started);
    socket->SetSendTimeoutSeconds(Seconds(connect_timeout));
    socket->SetRecvTimeoutSeconds(Seconds(connect_timeout));

    // The proxy is dialled instead of the target, and the target address is then
    // handed to it. There is no direct connection after a proxy failure: a proxy
    // that cannot be used is an error, never a reason to go around it.
    if (options.proxy) {
        const ProxyTarget& proxy = *options.proxy;
        if (!socket->Connect(proxy.host.c_str(), proxy.port)) {
            const DWORD code = socket->GetLastError();
            throw DialError("proxy_connect_refused", DialErrorText(proxy.host, proxy.port, code));
        }
        Socks5Handshake(*socket, proxy, options, started, options.host, options.port);
    } else if (!socket->Connect(options.host.c_str(), options.port)) {
        const DWORD code = socket->GetLastError();
        throw DialError("connect_failed", DialErrorText(options.host, options.port, code));
    }

    if (!options.ssl) {
        connection.socket = std::move(socket);
        return connection;
    }

    // SNI and the name the certificate must match are the same string; `sni`
    // exists for connecting to an IP literal by name.
    const std::wstring server_name = CertificateVerifier::SniName(options.host, options.sni);
    CertificateVerifier verifier(server_name, options.ca_file, options.tls_verify,
        options.tls_check_revocation);
    auto tls = std::make_unique<CSSLClient>(socket.get());
    tls->ServerCertAcceptable = [&verifier](PCCERT_CONTEXT certificate, const bool, const bool) {
        return verifier.Check(certificate);
    };
    tls->SelectClientCertificate = SelectClientCertificate;

    const int handshake_timeout = Remaining(options, started);
    socket->SetSendTimeoutSeconds(Seconds(handshake_timeout));
    socket->SetRecvTimeoutSeconds(Seconds(handshake_timeout));
    const HRESULT result = tls->Initialize(server_name.c_str());
    // The callback captures a local; the handshake is over, so nothing can call
    // it again. Clearing it also makes a later (impossible) call accept rather
    // than reach a destroyed object.
    tls->ServerCertAcceptable = nullptr;
    if (FAILED(result)) {
        // A certificate that was checked and REJECTED is reported with the
        // verifier's own reason. A handshake that broke before any certificate
        // arrived, or that failed after an accepted one, is an SSPI failure: it
        // says nothing about trust, so it must not be dressed up as one.
        if (verifier.Checked() && !verifier.Passed())
            throw DialError(verifier.Code().empty() ? "tls_handshake_failed" : verifier.Code(),
                verifier.Message());
        throw DialError("tls_handshake_failed", "[tls_handshake_failed] " + Endpoint(server_name, options.port)
            + ": TLS handshake failed (SSPI 0x" + [&] {
                char text[16] = { 0 };
                sprintf_s(text, "%08x", tls->LastSecurityStatus());
                return std::string(text);
            }() + ")"
            + (tls->LastExtendedError().empty() ? std::string()
                : ": " + Utf8(tls->LastExtendedError())));
    }
    if (options.tls_verify && !verifier.Checked())
        throw DialError("tls_no_certificate", "[tls_no_certificate] " + Endpoint(server_name, options.port)
            + ": the peer completed a TLS handshake without presenting a certificate to verify");

    connection.socket = std::move(socket);
    connection.tls = std::move(tls);
    return connection;
}