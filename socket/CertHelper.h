#pragma once
#include <schannel.h>
static bool g_ShowCertInfo = false;
bool MatchCertificateName(PCCERT_CONTEXT pCertContext, LPCWSTR pszRequiredName);
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, std::wstring Title);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext, const bool isClientCert);
std::wstring GetCertName(PCCERT_CONTEXT pCertContext);
SECURITY_STATUS CertFindClientCertificate(PCCERT_CONTEXT & pCertContext, const LPCWSTR pszSubjectName = nullptr, bool fUserStore = true);
SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo, bool fUserStore = false);
SECURITY_STATUS CertFindServerCertificateUI(PCCERT_CONTEXT & pCertContext, LPCWSTR pszSubjectName, bool fUserStore = false);
SECURITY_STATUS CertFindServerCertificateByName(PCCERT_CONTEXT & pCertContext, LPCWSTR pszSubjectName, bool fUserStore = false);
SECURITY_STATUS CertFindCertificateBySignature(PCCERT_CONTEXT & pCertContext, char const * const signature, bool fUserStore = false);

HRESULT CertFindByName(PCCERT_CONTEXT & pCertContext, const LPCWSTR pszSubjectName, bool fUserStore = false);

// defined in source file CreateCertificate.cpp
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = nullptr, LPCWSTR FriendlyName = nullptr, LPCWSTR Description = nullptr, bool forClient = false);

// TB-287: the "any certificate will do" callback that used to live here is gone.
// Every TLS connection the module opens now goes through socket/TlsVerify.h,
// which builds the chain, matches the name, and refuses a handshake whose
// certificate was never checked at all. `tls_verify = false` on a request is
// the explicit opt-out; see README.md.

static SECURITY_STATUS SelectClientCertificate(PCCERT_CONTEXT& pCertContext, SecPkgContext_IssuerListInfoEx* pIssuerListInfo, bool Required)
{
	SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;

	if (Required) {
		if (pIssuerListInfo) {
			if (pIssuerListInfo->cIssuers != 0) {
				Status = CertFindFromIssuerList(pCertContext, *pIssuerListInfo);
			}
		}
		if (!pCertContext) {
			Status = CertFindClientCertificate(pCertContext);
		}
	}
	return Status;
}