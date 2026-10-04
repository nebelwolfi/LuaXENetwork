// NOMINMAX first: framework.h has no <algorithm> in front of windows.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "framework.h"

#include "Dial.h"
#include "CertHelper.h"
#include "TlsVerify.h"

#include <chrono>
#include <string>

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

    if (!socket->Connect(options.host.c_str(), options.port)) {
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
        // A rejected certificate is reported with the verifier's own reason, not
        // with the SChannel HRESULT, which never says what was wrong. A
        // certificate that was checked and ACCEPTED and then failed the handshake
        // is not a verification failure, so only !Passed() comes here.
        if (!verifier.Passed())
            throw DialError(verifier.Code().empty() ? "tls_handshake_failed" : verifier.Code(),
                verifier.Message());
        throw DialError("tls_handshake_failed", "[tls_handshake_failed] " + Endpoint(server_name, options.port)
            + ": TLS handshake failed after the certificate was accepted (SSPI 0x" + [&] {
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