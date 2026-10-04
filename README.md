# network

A WinHTTP-shaped HTTP client for LuaXE, built on Winsock and SChannel.

## BREAKING CHANGE in 0.4.0: certificates are verified

Before 0.4.0 this module completed a TLS handshake against **any** certificate:
`socket/CertHelper.h` had a callback that returned `true` unconditionally ("Any
certificate will do"). A TLS connection therefore proved nothing about who was on
the other end - an interception certificate, an expired one, or one issued for a
different name was all accepted.

**Every TLS connection now verifies the certificate.** If you talk to an endpoint
whose certificate cannot be verified, a request that used to succeed now fails
with a bracketed reason:

| code | meaning |
|---|---|
| `tls_untrusted_root` | the chain does not reach a trusted root (or, with `ca_file`, not one of your certificates) |
| `tls_expired` | the certificate is outside its validity window |
| `tls_revoked` | the certificate is revoked |
| `tls_name_mismatch` | the certificate carries no name for the host you asked for |
| `tls_ca_unreadable` | `ca_file` could not be read or holds no certificate |
| `tls_policy_failed` | the Windows SSL chain policy refused the chain |
| `tls_no_certificate` | the peer completed a handshake without presenting a certificate |
| `tls_wrong_usage` | the certificate is not valid for TLS server authentication |
| `tls_handshake_failed` | the handshake failed for a transport reason (SSPI status is included) |

Two escape hatches, both explicit per request:

```lua
-- Trust exactly these roots and nothing else (PEM or DER, one or many
-- certificates). The machine's root store is NOT consulted for this chain.
network.request("127.0.0.1:8443", {
    ssl = true, ca_file = "C:/certs/company-root.pem",
})

-- No verification at all. For a test fixture or a device you control; it is not
-- a default and it is never implied.
network.request("192.168.1.10:8443", { ssl = true, tls_verify = false })
```

`tls_revoke = false` restricts revocation checking to the local cache instead of
letting Windows fetch CRLs over the network (that fetch is not bounded by
`connect_timeout_ms`; it has its own Windows timeout).

## BREAKING CHANGE in 0.4.0: `ssl` decides, not the port

Before 0.4.0 TLS was chosen by `Port == 443`, and the `ssl` option was read only
in the single-table call form - so `network.request(host, 8443, { ssl = true })`
stayed plaintext, and `network.request(host, 443, { ssl = false })` was upgraded
to TLS anyway.

Now `ssl` is honoured in **every** call form (`request`, `send`, `get`,
`download`, `connect`) on **any** port:

```lua
network.request("example.com", 8443, { ssl = true })   -- TLS
network.request("example.com", 8443, { ssl = false })  -- plaintext
network.get("https://example.com/thing")               -- TLS (from the scheme)
network.get("http://example.com/thing", { ssl = true }) -- TLS (the option wins)
```

**Existing callers are unaffected**: when `ssl` is absent, port 443 still means
TLS, so nothing that worked before starts sending a key in clear. Pass `ssl`
explicitly for anything else.

`sni = "name"` sets the SNI and the name the certificate is verified against,
which is what you want when you connect to an IP literal:

```lua
network.request("192.0.2.10", 8443, { ssl = true, sni = "device.example" })
```

## SOCKS5 proxy

`proxy = "socks5://[user:pass@]host:port"` (or `socks5h://` for remote DNS) on
the same five functions. The client dials the proxy, does the RFC 1928 greeting,
RFC 1929 username/password when the proxy asks for it, and a CONNECT - then TLS
(if `ssl`) with SNI and verification for the **target**, then HTTP exactly as
before.

* `socks5` resolves the target here (IPv4 preferred, IPv6 as the fallback, like
  the module's own direct connect) and sends an address (ATYP 1/4).
* `socks5h` sends the target's name (ATYP 3, so at most 255 bytes) and lets the
  proxy resolve it.
* Credentials are percent-decoded (`pa%73s` is `pass`) and **never** appear in an
  error message.
* A malformed or unknown scheme is an error. There is **no fallback to a direct
  connection**: if the proxy cannot be used, the request fails.
* The handshake is bounded by the caller's deadline: `connect_timeout_ms` covers
  each step, and `total_timeout_ms`, when set, is one budget for the connect, the
  whole SOCKS5 conversation and the TLS handshake together.

| code | meaning |
|---|---|
| `proxy_url_invalid` | the proxy URL is malformed, or the scheme is not socks5/socks5h |
| `proxy_connect_refused` | the proxy port refused the connection |
| `proxy_connect_failed` | the proxy could not be connected to |
| `proxy_timeout` | the proxy did not answer a handshake step in time |
| `proxy_closed` | the proxy hung up during the handshake |
| `proxy_protocol_error` | the proxy answered something that is not SOCKS5 |
| `proxy_no_acceptable_auth` | the proxy accepts no method this client offers (or wants credentials and none were given) |
| `proxy_auth_failed` | the proxy rejected the username and password |
| `proxy_general_failure` | reply 01 |
| `proxy_not_allowed` | reply 02, not allowed by ruleset |
| `proxy_network_unreachable` | reply 03 |
| `proxy_host_unreachable` | reply 04, the proxy's own DNS or route failed |
| `proxy_target_refused` | reply 05, the target refused |
| `proxy_ttl_expired` | reply 06 |
| `proxy_command_unsupported` | reply 07 |
| `proxy_address_type_unsupported` | reply 08 |
| `proxy_reply_unknown` | any other reply code |
| `proxy_dns_failed` | socks5 could not resolve the target name locally |
| `proxy_target_name_invalid` | socks5h cannot carry that target name (not 1-255 bytes) |

Without a proxy, connection failures are `connect_refused`, `connect_timeout`,
`connect_network_unreachable`, `dns_failed` or `connect_failed`.

## What the certificate check does exactly

* Chain: `CertGetCertificateChain` against the Windows root store, with the
  serverAuth usage required, and revocation checked but **soft-failed** - an
  unreachable CRL or OCSP responder is ignored, a revoked certificate is not.
* `ca_file`: loaded into an in-memory store and used as the **only** accepted
  roots. The chain engine also searches the machine's store and marks a chain that
  ends in an additional-store root as untrusted, so trust is decided here by
  comparing the chain's root against the certificates that were loaded.
* Name: `subjectAltName` is read from the certificate's DER - `iPAddress` SANs
  for an IP literal (no fallback to a DNS name or a common name), `dNSName` with a
  single left-most-label wildcard for host names, and the subject common name
  only when the certificate carries no `dNSName` at all. This is hand-parsed
  because the Windows SDK header in use does not match what `crypt32.dll` fills
  (decoding a certificate into `CERT_INFO` crashes there, and
  `CertGetNameStringW(CERT_NAME_IP_TYPE)` answers a space).
* Windows' SSL chain policy gets the DNS name to check as well, but never an IP
  literal: on this platform it accepts any trusted certificate for one.
* A handshake that completes without presenting a certificate fails.

## capabilities

```lua
network.capabilities.ssl_any_port    -- true: ssl decides TLS on any port
network.capabilities.tls_verify      -- true: certificates are verified
network.capabilities.ca_file         -- true: ca_file is accepted
network.capabilities.sni_override    -- true: sni is accepted
network.capabilities.proxy_socks5    -- true: proxy = "socks5://..." is accepted
network.capabilities.structured_response
network.capabilities.stream_callbacks
network.capabilities.request_timeouts
network.capabilities.large_tls_writes
network.capabilities.response_limits
network.capabilities.listener_bind_address
```

## Building

    cmake -S . -B cmake-build-release -G Ninja -DCMAKE_BUILD_TYPE=Release ^
          -DCMAKE_C_COMPILER="<vs>/VC/Tools/Llvm/x64/bin/clang-cl.exe" ^
          -DCMAKE_CXX_COMPILER="<vs>/VC/Tools/Llvm/x64/bin/clang-cl.exe"
    cmake --build cmake-build-release

`-DNETWORK_EXTRA_COPY=OFF` skips the post-build copy into the Asklepios module
folder; the shared headers are looked up in `../../shared`, falling back to
`D:/LuaXE/shared` so a standalone checkout builds.

## Tests

    tests\build_and_test.cmd            (build, then the tests only if it built)
    tests\run_all.ps1 -Dll <network.dll> [-Script <one.lua>] [-KeepWork]

`run_all.ps1` starts `tests/fixtures/servers.ps1` for each script: TLS servers
from **openssl** `s_server`, an in-process plaintext recorder, a suite of SOCKS5
proxies (no-auth, user/pass, one per reply code, one that refuses every method,
one that hangs up, one that stays silent), and certificates generated by
`openssl` under the run's work directory.

**No key store is touched.** openssl keeps its keys in files, and `run_all.ps1`
fails if a key ledger ever appears. (This is also why the TLS servers are
openssl: .NET Framework's `SslStream` cannot serve a certificate generated at
run time, because a Pfx import on Windows 10+ always produces a CNG key and
`SslStream` then refuses it - the .NET side of the SEC_E_NO_CREDENTIALS finding.)

openssl is found at `C:\msys64\mingw64\bin\openssl.exe`, in `PATH`, or through
`-OpenSsl <path>`; it was OpenSSL 3.1.0 when this was written. Without it the
fixture cannot start and the run fails loudly - it never silently skips.

The work directory is `$GIRL_SCRATCH/network-tests-<pid>` when that is set and
`<module>/tmp/network-tests-<pid>` otherwise, and it is deleted at the end of the
run unless `-KeepWork` is given. `tests/tls_matrix.lua` covers TLS (29 checks) and
`tests/proxy_matrix.lua` the proxy (38). A check that cannot run on this machine -
the fixed ports 443 and 8443 when something else holds them - prints `SKIP` and is
listed in the summary; it never passes silently.