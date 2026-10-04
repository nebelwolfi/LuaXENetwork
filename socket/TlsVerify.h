#pragma once
#include <windows.h>
#include <schannel.h>

#include <string>
#include <vector>

// TB-287: real certificate verification for the network module's SChannel client.
//
// Before this, socket/CertHelper.h::CertAcceptable answered `true` for every
// certificate ("Any certificate will do"), so a completed TLS handshake proved
// nothing about who was on the other end: any interception certificate, expired,
// self-signed or issued for a different name was accepted. The chain is now
// built with CertGetCertificateChain and checked, the name is matched against the
// host the caller asked for (the SNI name), and the caller refuses a handshake
// whose certificate was never checked at all.
class CertificateVerifier
{
public:
    // host        the name the peer must present: the SNI name, or the target host
    // ca_file     optional PEM/DER file whose certificates are the ONLY accepted
    //             roots. Empty means the Windows root store.
    // verify      false installs a hook that accepts everything (tls_verify=false)
    CertificateVerifier(std::wstring host, std::string ca_file, bool verify, bool check_revocation);
    ~CertificateVerifier();
    CertificateVerifier(const CertificateVerifier&) = delete;
    CertificateVerifier& operator=(const CertificateVerifier&) = delete;

    // Installed as CSSLClient::ServerCertAcceptable. Records the first failure and
    // returns false, which makes SChannel fail the handshake.
    bool Check(PCCERT_CONTEXT certificate);

    // SChannel skips the hook entirely when the peer never sends a certificate,
    // so "checked" has to be asserted by the caller: a verification that never
    // ran is a failure, not a pass.
    bool Checked() const { return checked; }
    bool Passed() const { return !failed; }

    // Stable machine-readable reason, e.g. "tls_untrusted_root".
    const std::string& Code() const { return code; }

    // "<host>: <detail>" for the Lua error message; no credentials ever reach here.
    std::string Message() const;

    static std::wstring SniName(const std::wstring& host, const std::wstring& sni);

private:
    bool VerifyChain(PCCERT_CONTEXT certificate);
    bool VerifyName(PCCERT_CONTEXT certificate);
    void LoadRoots(const std::string& ca_file);
    void Fail(const char* code, const std::string& text);

    std::wstring host;
    std::string ca_file;
    bool verify{ true };
    bool check_revocation{ true };
    bool exclusive{ false };
    bool checked{ false };
    bool failed{ false };
    std::string code;
    std::string detail;
    HCERTSTORE roots{ nullptr };
    std::vector<std::vector<unsigned char>> root_hashes;
};