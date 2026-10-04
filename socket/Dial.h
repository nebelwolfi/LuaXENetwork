#pragma once
#include "ActiveSock.h"
#include "SSLClient.h"

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

// TB-287: one dial path for the whole module.
//
// Before this, every caller connected with CActiveSock::Connect itself and
// decided about TLS from the port number (main.cpp: `Port == 443 || force_ssl`),
// which meant port 8443 with ssl=true stayed plaintext and port 443 with
// ssl=false was upgraded to TLS. The choice now comes from the caller's `ssl`
// option and always, in both directions, on any port. The same function owns the
// certificate verification that CSSLClient used to skip.

struct ProxyTarget {
    std::wstring host;
    unsigned short port = 0;
    bool remote_dns = false;   // socks5h: the proxy resolves the target name
    std::string user;          // RFC 1929, raw bytes, never in an error message
    std::string password;      // RFC 1929, raw bytes, never in an error message
    bool has_credentials = false;
};

struct DialOptions {
    std::wstring host;
    unsigned short port = 80;
    bool ssl = false;
    std::wstring sni;          // empty: use host for SNI and for the name check
    std::optional<ProxyTarget> proxy;
    std::string ca_file;       // empty: the Windows root store
    bool tls_verify = true;
    bool tls_check_revocation = true;
    int connect_timeout_ms = 30000;
    int total_timeout_ms = 0;  // 0: no overall deadline
};

// A dial failure with a stable, greppable code. The message is what reaches Lua;
// it never contains a proxy password or a raw proxy URL.
class DialError : public std::runtime_error
{
public:
    DialError(std::string code, std::string message)
        : std::runtime_error(message)
        , code_(std::move(code))
    {
    }
    const std::string& Code() const { return code_; }

private:
    std::string code_;
};

struct DialedConnection {
    std::unique_ptr<CActiveSock> socket;
    std::unique_ptr<CSSLClient> tls;

    bool secure() const { return tls != nullptr; }
};

// Connects (directly or through a SOCKS5 proxy) and, when ssl is set, performs
// the TLS handshake with SNI = sni/host and verifies the certificate.
DialedConnection Dial(const DialOptions& options, HANDLE shutdown_event);

// "[code] message" for a WSA error code.
std::string DialErrorText(const std::wstring& host, unsigned short port, DWORD wsa_error);

// "socks5://[user:pass@]host:port" or "socks5h://...". socks5h sends the target
// name to the proxy (remote DNS); socks5 resolves it here. Throws DialError with
// the code "proxy_url_invalid" - a malformed proxy is never ignored.
ProxyTarget ParseProxyUrl(const std::string& url);