// framework.h first: it pulls <WS2tcpip.h> before <windows.h> can drag in winsock.h.
#include "framework.h"

#include "TlsVerify.h"

#include <wincrypt.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

// TB-287. Everything here is Windows cryptography: the module already reaches
// secur32/schannel through CSSLClient, and the chain engine is what actually
// knows the Windows root store.
//
// Four values are spelled out instead of using their symbolic names because the
// SDK header this module is built against does not declare them; all are fixed
// Win32 API constants:
//   CERT_NAME_SIMPLE_TYPE          = 4
//   CERT_X509_NAME_FORMAT_RFC2253  = 4
//   CERT_NAME_DNS_TYPE             = 6
//   CERT_NAME_IP_TYPE              = 7

namespace {

constexpr DWORD kCertNameSimpleType = 4;
constexpr DWORD kCertNameFormatRfc2253 = 4;
constexpr DWORD kCertNameDnsType = 6;
constexpr DWORD kCertNameIpType = 7;
// Win32 documents CERT_EXTENSION_PROP_ID as 13; the SDK header this module is
// built against declares neither it nor the property-id enum, so it is spelled
// out here.
constexpr DWORD kCertExtensionPropId = 13;

// One name out of the certificate itself, for when the SAN extension cannot be
// decoded: CERT_NAME_IP_TYPE yields an iPAddress SAN as text, CERT_NAME_DNS_TYPE
// a dNSName (comma separated when there is more than one).

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

std::wstring WideFromUtf8(const std::string& text)
{
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring wide(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

char LowerAscii(char character)
{
    return (character >= 'A' && character <= 'Z') ? static_cast<char>(character + ('a' - 'A')) : character;
}

bool AsciiEqualsInsensitive(const std::wstring& left, const std::wstring& right)
{
    if (left.size() != right.size()) return false;
    for (size_t index = 0; index < left.size(); ++index)
        if (LowerAscii(static_cast<char>(left[index])) != LowerAscii(static_cast<char>(right[index])))
            return false;
    return true;
}

// RFC 6125: one wildcard, in the left-most label, matching exactly one label -
// so "*.example.com" covers a.example.com but neither a.b.example.com (two
// labels) nor example.com.
bool MatchesWildcard(const std::wstring& host, const std::wstring& pattern)
{
    if (pattern.size() < 3 || pattern[0] != L'*' || pattern[1] != L'.') return false;
    const std::wstring suffix = pattern.substr(1); // ".example.com"
    if (host.size() <= suffix.size()) return false;
    if (host.find(L'.') == std::wstring::npos) return false; // no left-most label to match
    if (!AsciiEqualsInsensitive(host.substr(host.size() - suffix.size()), suffix)) return false;
    const std::wstring label = host.substr(0, host.size() - suffix.size());
    if (label.empty() || label.find(L'*') != std::wstring::npos) return false;
    return label.find(L'.') == std::wstring::npos;   // exactly one label
}

std::string IpText(const BYTE* bytes, DWORD size)
{
    char buffer[64] = { 0 };
    if (size == 4) {
        IN_ADDR address{};
        std::memcpy(&address, bytes, 4);
        if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer))) return buffer;
        return {};
    }
    if (size == 16) {
        IN6_ADDR address{};
        std::memcpy(&address, bytes, 16);
        if (inet_ntop(AF_INET6, &address, buffer, sizeof(buffer))) return buffer;
        return {};
    }
    return {};
}

// The canonical text of an IP literal, so "::1" and "0:0:0:0:0:0:0:1" compare equal.
std::string CanonicalIp(const std::wstring& host)
{
    const std::string narrow = Utf8(host);
    if (narrow.empty()) return {};
    char buffer[64] = { 0 };
    IN_ADDR v4{};
    if (inet_pton(AF_INET, narrow.c_str(), &v4) == 1)
        return inet_ntop(AF_INET, &v4, buffer, sizeof(buffer)) ? buffer : std::string();
    IN6_ADDR v6{};
    if (inet_pton(AF_INET6, narrow.c_str(), &v6) == 1)
        return inet_ntop(AF_INET6, &v6, buffer, sizeof(buffer)) ? buffer : std::string();
    return {};
}

bool IsIpLiteral(const std::wstring& host)
{
    return !CanonicalIp(host).empty();
}

std::string CertificateHash(PCCERT_CONTEXT certificate)
{
    if (!certificate || !certificate->pbCertEncoded || !certificate->cbCertEncoded) return {};
    DWORD size = 32;
    std::vector<BYTE> digest(size);
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
        certificate->pbCertEncoded, certificate->cbCertEncoded, digest.data(), &size))
        return {};
    digest.resize(size);
    static const char* digits = "0123456789abcdef";
    std::string text;
    text.reserve(digest.size() * 2);
    for (const BYTE byte : digest) {
        text += digits[byte >> 4];
        text += digits[byte & 0x0F];
    }
    return text;
}

// Names the certificate presents, read out of its DER.
//
// Two Win32 shortcuts are not enough here, and both failures matter:
//   * CertGetNameStringW(CERT_NAME_IP_TYPE) answers a single space on this
//     platform, so an iPAddress SAN cannot be seen through it at all, and the SSL
//     chain policy given "127.0.0.1" as the name to match accepts a certificate
//     that carries only a DNS name - an IP-literal connect would then trust any
//     certificate the chain engine accepts;
//   * decoding the certificate into the SDK header's CERT_INFO to reach the SAN
//     crashes, because that header's CERT_INFO is not what crypt32.dll fills.
// So the extension is read directly from the encoded bytes:
//
//   Certificate ::= SEQUENCE { tbsCertificate, ... }
//   TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serial, sigalg, issuer,
//                                 validity, subject, spki, ...,
//                                 [3] EXPLICIT extensions OPTIONAL }
//   Extensions ::= SEQUENCE OF Extension
//   Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOL OPTIONAL,
//                            extnValue OCTET STRING }
//   GeneralNames ::= SEQUENCE OF GeneralName      -- dNSName [2] IA5String,
//                                                     iPAddress [7] OCTET STRING
namespace {

// One tag-length-value: where the content starts and how long it is.
struct Tlv {
    const BYTE* content = nullptr;
    size_t size = 0;
    bool ok = false;
};

Tlv ReadTlv(const BYTE* data, size_t available)
{
    Tlv tlv;
    if (!data || available < 2) return tlv;
    size_t offset = 1;                       // the tag byte
    size_t length = data[1];                 // the first length byte
    if (length & 0x80) {
        // Long form: the low bits give the number of length bytes that follow,
        // and they start right after the one already read.
        const size_t count = length & 0x7F;
        if (count == 0 || count > 4 || available < 1 + count + 1) return tlv;
        length = 0;
        for (size_t index = 0; index < count; ++index)
            length = (length << 8) | data[offset + 1 + index];
        offset = 1 + count;
    }
    if (available < offset + 1 + length) return tlv;
    tlv.content = data + offset + 1;
    tlv.size = length;
    tlv.ok = true;
    return tlv;
}

bool IsOid(const BYTE* data, size_t size, std::initializer_list<BYTE> encoded)
{
    size_t index = 0;
    for (const BYTE byte : encoded) {
        if (index >= size || data[index] != byte) return false;
        ++index;
    }
    return true;
}

std::wstring FromAscii(const char* text, size_t size)
{
    std::wstring wide;
    wide.reserve(size);
    for (size_t index = 0; index < size; ++index)
        wide.push_back(static_cast<unsigned char>(text[index]));
    return wide;
}

// GeneralNames ::= SEQUENCE OF GeneralName, inside the extnValue OCTET STRING of
// the subjectAltName extension.
void ReadGeneralNames(const BYTE* data, size_t available, std::vector<std::wstring>& dns_names,
    std::vector<std::string>& ip_names)
{
    // The extnValue holds GeneralNames ::= SEQUENCE OF GeneralName, so the
    // sequence's own header comes first.
    const Tlv sequence = ReadTlv(data, available);
    if (!sequence.ok || data[0] != 0x30) return;
    const BYTE* cursor = sequence.content;
    size_t left = sequence.size;
    while (left > 0) {
        const BYTE* start = cursor;
        const Tlv entry = ReadTlv(cursor, left);
        if (!entry.ok) return;
        const size_t consumed = static_cast<size_t>((entry.content + entry.size) - start);
        if (consumed == 0 || consumed > left) return;
        const BYTE tag = start[0];
        if (tag == 0x82) {   // [2] dNSName, an IA5String: ASCII by definition
            dns_names.push_back(FromAscii(reinterpret_cast<const char*>(entry.content), entry.size));
        } else if (tag == 0x87) {   // [7] iPAddress, 4 or 16 raw bytes
            ip_names.push_back(IpText(entry.content, static_cast<DWORD>(entry.size)));
        }
        cursor = entry.content + entry.size;
        left -= consumed;
    }
}

bool ReadSanExtension(const BYTE* data, size_t available, std::vector<std::wstring>& dns_names,
    std::vector<std::string>& ip_names, std::string* trace = nullptr)
{
    const auto note = [trace](const std::string& text) { if (trace) *trace += text; };
    const BYTE* cursor = data;
    size_t left = available;
    int index = 0;
    while (left > 0) {
        const BYTE* start = cursor;
        const Tlv extension = ReadTlv(cursor, left);
        if (!extension.ok) { note(" ext" + std::to_string(index) + " unreadable"); return false; }
        const size_t consumed = static_cast<size_t>((extension.content + extension.size) - start);
        if (consumed == 0 || consumed > left) { note(" ext" + std::to_string(index) + " bad size"); return false; }
        const BYTE* inner = extension.content;
        size_t inner_left = extension.size;
        const Tlv oid = ReadTlv(inner, inner_left);
        if (!oid.ok) { note(" ext" + std::to_string(index) + " oid unreadable"); return false; }
        note(" x" + std::to_string(index) + "/" + std::to_string(start[0]) + "/" + std::to_string(oid.size));
        if (IsOid(oid.content, oid.size, { 0x55, 0x1D, 0x11 })) {   // 2.5.29.17
            const BYTE* next = oid.content + oid.size;
            // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
            // extnValue OCTET STRING }. The BOOLEAN is optional and DER omits it
            // when it is FALSE, so it is skipped only when it is really there.
            const Tlv first = ReadTlv(next, static_cast<size_t>((inner + inner_left) - next));
            if (!first.ok) { note(" san value unreadable"); return false; }
            if (first.content[0] == 0x01) next = first.content + first.size;
            const Tlv value = ReadTlv(next, static_cast<size_t>((inner + inner_left) - next));
            if (!value.ok || next[0] != 0x04) { note(" san not an octet string"); return false; }
            ReadGeneralNames(value.content, value.size, dns_names, ip_names);
            note(" san" + std::to_string(dns_names.size()) + "/" + std::to_string(ip_names.size()));
            return true;
        }
        cursor = extension.content + extension.size;
        left -= consumed;
        ++index;
    }
    note(" san not among " + std::to_string(index) + " extensions");
    return false;
}

// Names the certificate presents, read out of its DER. See the comment above:
// CertGetNameStringW reports no iPAddress SAN here and the chain policy accepts
// any trusted certificate for an IP-literal name, so the SAN is parsed here
// instead of being taken from either.
bool ReadAltNames(PCCERT_CONTEXT certificate, std::vector<std::wstring>& dns_names,
    std::vector<std::string>& ip_names, std::string* trace = nullptr)
{
    const auto note = [trace](const std::string& text) { if (trace) *trace += text; };
    if (!certificate || !certificate->pbCertEncoded) { note("no encoded bytes"); return false; }
    const BYTE* der = certificate->pbCertEncoded;
    const size_t total = certificate->cbCertEncoded;

    const Tlv outer = ReadTlv(der, total);            // Certificate ::= SEQUENCE
    if (!outer.ok) { note("outer unreadable"); return false; }
    const Tlv tbs = ReadTlv(outer.content, outer.size);   // TBSCertificate
    if (!tbs.ok) { note("tbs unreadable"); return false; }
    note("outer " + std::to_string(outer.size) + " tbs " + std::to_string(tbs.size));

    const BYTE* cursor = tbs.content;
    size_t left = tbs.size;
    int fields = 0;
    while (left > 0) {
        const BYTE* start = cursor;
        const Tlv field = ReadTlv(cursor, left);
        if (!field.ok) { note(" field " + std::to_string(fields) + " unreadable"); return false; }
        const size_t consumed = static_cast<size_t>((field.content + field.size) - start);
        if (consumed == 0 || consumed > left) { note(" field " + std::to_string(fields) + " bad size"); return false; }
        note(" f" + std::to_string(fields) + "=" + std::to_string(start[0]));
        if (start[0] == 0xA3) {                        // [3] EXPLICIT Extensions: its content
            // is the Extensions SEQUENCE itself, so there is one wrapper, not two.
            const Tlv extensions = ReadTlv(field.content, field.size);
            if (!extensions.ok) { note(" extensions unreadable"); return false; }
            note(" ext" + std::to_string(extensions.size));
            return ReadSanExtension(extensions.content, extensions.size, dns_names, ip_names, trace);
        }
        cursor = field.content + field.size;
        left -= consumed;
        ++fields;
    }
    note(" no [3] among " + std::to_string(fields) + " fields");
    return false;
}

} // namespace

std::string ChainStatusText(DWORD status)
{
    static const struct Named { DWORD bit; const char* name; } names[] = {
        { CERT_TRUST_IS_NOT_TIME_VALID, "expired or not yet valid" },
        { CERT_TRUST_IS_REVOKED, "revoked" },
        { CERT_TRUST_IS_NOT_SIGNATURE_VALID, "bad signature" },
        { CERT_TRUST_IS_NOT_VALID_FOR_USAGE, "not valid for this use" },
        { CERT_TRUST_IS_UNTRUSTED_ROOT, "untrusted root" },
        { CERT_TRUST_REVOCATION_STATUS_UNKNOWN, "revocation status unknown" },
        { CERT_TRUST_IS_CYCLIC, "certificate chain is cyclic" },
        { CERT_TRUST_INVALID_EXTENSION, "invalid certificate extension" },
        { CERT_TRUST_INVALID_BASIC_CONSTRAINTS, "invalid basic constraints" },
        { CERT_TRUST_IS_OFFLINE_REVOCATION, "revocation information unavailable" },
        { CERT_TRUST_IS_PARTIAL_CHAIN, "incomplete chain" },
        { CERT_TRUST_INVALID_POLICY_CONSTRAINTS, "invalid policy constraints" },
    };
    std::string text;
    for (const Named& entry : names) {
        if (!(status & entry.bit)) continue;
        if (!text.empty()) text += ", ";
        text += entry.name;
    }
    if (text.empty()) text = "certificate chain error";
    char digits[16] = { 0 };
    sprintf_s(digits, "%08x", static_cast<unsigned long>(status));
    return text + " (status 0x" + std::string(digits) + ")";
}

} // namespace

std::wstring CertificateVerifier::SniName(const std::wstring& host, const std::wstring& sni)
{
    return sni.empty() ? host : sni;
}

CertificateVerifier::CertificateVerifier(std::wstring host, std::string ca_file, bool verify, bool check_revocation)
    : host(std::move(host))
    , ca_file(std::move(ca_file))
    , verify(verify)
    , check_revocation(check_revocation)
{
    if (verify && !this->ca_file.empty()) LoadRoots(this->ca_file);
}

CertificateVerifier::~CertificateVerifier()
{
    if (roots) CertCloseStore(roots, 0);
}

void CertificateVerifier::Fail(const char* code_text, const std::string& text)
{
    if (failed) return; // keep the first reason: it is the one the caller sees
    failed = true;
    code = code_text;
    detail = text;
}

std::string CertificateVerifier::Message() const
{
    std::string text = "[" + (code.empty() ? std::string("tls_verify_failed") : code) + "] ";
    text += Utf8(host);
    if (!detail.empty()) text += ": " + detail;
    return text;
}

void CertificateVerifier::LoadRoots(const std::string& path)
{
    exclusive = true;
    roots = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, 0, 0, nullptr);
    if (!roots) {
        Fail("tls_ca_unreadable", "no in-memory certificate store could be opened for ca_file");
        return;
    }
    // CryptQueryObject reads a PEM bundle, a single DER certificate or a PKCS#7
    // file. Nothing is ever installed into a machine or user store: the
    // certificates go into the in-memory store above and nowhere else.
    DWORD encoding = 0, content = 0, format = 0;
    HCERTSTORE file_store = nullptr;
    const std::wstring wide_path = WideFromUtf8(path);
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wide_path.c_str(), CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_ALL, 0, &encoding, &content, &format, &file_store, nullptr, nullptr)
        || !file_store) {
        Fail("tls_ca_unreadable", "ca_file could not be opened or holds no certificate");
        return;
    }
    PCCERT_CONTEXT cursor = nullptr;
    while (PCCERT_CONTEXT next = CertEnumCertificatesInStore(file_store, cursor)) {
        CertAddCertificateContextToStore(roots, next, CERT_STORE_ADD_ALWAYS, nullptr);
        const std::string hash = CertificateHash(next);
        if (!hash.empty()) root_hashes.emplace_back(hash.begin(), hash.end());
        cursor = next;
    }
    CertCloseStore(file_store, 0);
    if (root_hashes.empty())
        Fail("tls_ca_unreadable", "ca_file contains no PEM or DER certificate");
}

bool CertificateVerifier::Check(PCCERT_CONTEXT certificate)
{
    checked = true;
    if (!verify) return true; // tls_verify=false: explicitly requested, nothing else to do
    if (failed) return false; // ca_file never loaded
    if (!certificate || !certificate->pbCertEncoded) {
        Fail("tls_no_certificate", "the peer sent no readable certificate");
        return false;
    }
    if (VerifyChain(certificate) && VerifyName(certificate)) return true;
    return false;
}

bool CertificateVerifier::VerifyChain(PCCERT_CONTEXT certificate)
{
    // RequestedUsage is what enforces the serverAuth EKU on the whole chain (and
    // is the portable way to do it: the header here has no CERT_EKU_* names).
    LPSTR usage_oid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
    CERT_CHAIN_PARA parameters{ sizeof(CERT_CHAIN_PARA) };
    parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &usage_oid;

    const DWORD flags = check_revocation ? CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                                         : CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;

    PCCERT_CHAIN_CONTEXT context = nullptr;
    if (!CertGetCertificateChain(nullptr, certificate, nullptr, roots, &parameters, flags, nullptr, &context)) {
        Fail("tls_chain_failed", "the certificate chain could not be built (error "
            + std::to_string(GetLastError()) + ")");
        return false;
    }
    struct ContextGuard {
        PCCERT_CHAIN_CONTEXT context;
        ~ContextGuard() { if (context) CertFreeCertificateChain(context); }
    } guard{ context };

    // Soft-fail revocation: "unknown" and "offline" are not failures, "revoked" is.
    constexpr DWORD soft = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;
    DWORD status = context->TrustStatus.dwErrorStatus & ~soft;

    if (exclusive) {
        // With an exclusive ca_file the chain engine cannot know that a root it
        // found in an additional store is trusted: a chain that ends at such a
        // root always carries CERT_TRUST_IS_UNTRUSTED_ROOT. So trust is decided
        // here, by identity, and that bit is dropped afterwards. It is also why
        // the root has to be one of the certificates the caller actually loaded:
        // the engine also searches the machine's root store.
        // Every chain the engine built is considered, so a cross-signed root
        // does not fail just because the engine preferred another path.
        bool rooted_in_our_file = false;
        for (DWORD index = 0; index < context->cChain && !rooted_in_our_file; ++index) {
            PCERT_SIMPLE_CHAIN chain = context->rgpChain[index];
            if (!chain || !chain->cElement || !chain->rgpElement[chain->cElement - 1]) continue;
            const std::string hash = CertificateHash(chain->rgpElement[chain->cElement - 1]->pCertContext);
            rooted_in_our_file = !hash.empty() && std::find(root_hashes.begin(), root_hashes.end(),
                std::vector<BYTE>(hash.begin(), hash.end())) != root_hashes.end();
        }
        if (!rooted_in_our_file) {
            Fail("tls_untrusted_root", "the certificate does not chain to a certificate in ca_file");
            return false;
        }
        status &= ~CERT_TRUST_IS_UNTRUSTED_ROOT;
    }

    if (status) {
        const char* code_text = "tls_untrusted_root";
        if (status & CERT_TRUST_IS_NOT_TIME_VALID) code_text = "tls_expired";
        else if (status & CERT_TRUST_IS_REVOKED) code_text = "tls_revoked";
        Fail(code_text, ChainStatusText(status));
        return false;
    }

    HTTPSPolicyCallbackData policy{ sizeof(HTTPSPolicyCallbackData) };
    policy.dwAuthType = AUTHTYPE_SERVER;
    // The SSL policy adds its own name check for DNS names (wildcards included).
    // It is deliberately not given an IP literal: on this platform it accepts any
    // trusted certificate for one, which VerifyName has already refused.
    if (!IsIpLiteral(host)) policy.pwszServerName = const_cast<LPWSTR>(host.c_str());
    CERT_CHAIN_POLICY_PARA policy_parameters{ sizeof(CERT_CHAIN_POLICY_PARA) };
    policy_parameters.pvExtraPolicyPara = &policy;
    CERT_CHAIN_POLICY_STATUS policy_status{ sizeof(CERT_CHAIN_POLICY_STATUS) };
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, context, &policy_parameters, &policy_status)) {
        Fail("tls_policy_failed", "the SSL chain policy could not be evaluated");
        return false;
    }
    if (policy_status.dwError) {
        // With an exclusive ca_file the policy reports the very thing this class
        // decided for itself above: that the root is not in a trusted root store.
        // Everything else it reports (name, usage, validity) still counts.
        const bool tolerated = exclusive && policy_status.dwError == 0x800B0109; // TRUST_E_CERTUNTRUSTEDROOT
        if (!tolerated) {
            char digits[16] = { 0 };
            sprintf_s(digits, "%08x", static_cast<unsigned long>(policy_status.dwError));
            Fail("tls_policy_failed", "SSL policy error 0x" + std::string(digits));
            return false;
        }
    }
    return true;
}

bool CertificateVerifier::VerifyName(PCCERT_CONTEXT certificate)
{
    std::vector<std::wstring> dns_names;
    std::vector<std::string> ip_names;
    std::string trace;
    const bool has_san = ReadAltNames(certificate, dns_names, ip_names, &trace);

    if (IsIpLiteral(host)) {
        // An IP literal is matched against the iPAddress SANs only: a certificate
        // issued for a DNS name is not valid for 127.0.0.1. The SSL chain policy
        // cannot be trusted with this one - given "127.0.0.1" as the name to
        // match it accepts a certificate that carries only a DNS name.
        const std::string target = CanonicalIp(host);
        for (const std::string& name : ip_names)
            if (!target.empty() && name == target) return true;
        if (ip_names.empty()) {
            Fail("tls_name_mismatch", std::string("the certificate carries no IP address subject "
                "alternative name (") + (has_san ? "a subjectAltName was found" : "no subjectAltName was found")
                + ", " + std::to_string(dns_names.size()) + " DNS names, walk[" + trace + "]");
        } else
            Fail("tls_name_mismatch", "the certificate is not valid for this IP address");
        return false;
    }

    for (const std::wstring& name : dns_names)
        if (AsciiEqualsInsensitive(name, host) || MatchesWildcard(host, name)) return true;
    if (!dns_names.empty()) {
        Fail("tls_name_mismatch", "no subject alternative name matches this host");
        return false;
    }
    // No DNS SAN at all: RFC 6125 allows the subject common name as a fallback,
// and only an EXACT match there - a wildcard in a common name is not accepted.
wchar_t common_name[256] = { 0 };
    if (CertGetNameStringW(certificate, kCertNameSimpleType, kCertNameFormatRfc2253,
        nullptr, common_name, static_cast<DWORD>(std::size(common_name)))) {
        std::wstring name(common_name);
        const auto comma = name.find(L',');
        if (comma != std::wstring::npos) name = name.substr(0, comma);
        if (AsciiEqualsInsensitive(name, host)) return true;
    }
    Fail("tls_name_mismatch", "the certificate carries no name for this host");
    return false;
}