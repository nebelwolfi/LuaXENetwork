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

## Listener: parked accept and readiness read

Two costs used to sit on every request a listener served, and both were Windows
timer ticks (~15.6 ms each), not work:

* the accept loop could only ask "is a connection pending?", so a server paced
  itself with `sleep(10)` and every request waited for that sleep;
* `client.request` re-checked the socket once per tick, so a request that was
  **already buffered** still cost a tick before it was parsed.

Both now wait in the kernel (`WSAPoll`), which costs nothing while waiting and
returns the moment the socket becomes ready. **No `timeBeginPeriod` is called and
none should be**: the waits are readiness waits, not shorter sleeps.

```lua
local server = network.listen(8080, true)          -- non-blocking listener

while true do
    -- Drain whatever the kernel already has, then park for the next
    -- connection instead of sleeping a tick. 1000 ms is an upper bound, not
    -- a cost: the call returns the instant a connection lands.
    local served = server:accept(handler, 0)       -- 0 = do not wait, as before
    if not served then server:accept(handler, 1000) end
end
```

`server:accept(handler, timeout_ms)` parks the call in the kernel until a
connection is pending or `timeout_ms` passes.

| `timeout_ms` | meaning |
|---|---|
| absent | do not wait; accept a pending connection or return. Returns **no values**, exactly as it always did |
| `0` | the same (no) wait as absent, but the call reports `true`/`false` |
| `> 0` | wait up to that long for a connection (past a few minutes this is, in practice, the same as `< 0`) |
| `< 0` | wait indefinitely |

A **timed** call says what it did: `true` when it accepted a connection and ran
the handler, `false` when it accepted nothing - either because the timeout passed
or because the connection it waited for was gone by the time it took it. An
untimed call returns nothing, so existing callers are unaffected.

The timeout must be a whole number of milliseconds that fits in a signed 32-bit
integer; a fractional or out-of-range number (0.5, 2147483648) is an argument
error rather than a silent wrap into a different wait. A numeric *string* in the
handler slot keeps its old meaning (it is not a timeout), a non-number third
argument and any fourth argument are refused, and a call with nothing to run -
no handler and none registered with `async` - raises `No function provided`
**before** it would wait, so `accept(nil, -1)` cannot park forever on a typo.

**A parked accept blocks the whole Lua state** for up to `timeout_ms`: this is a
blocking C call, so nothing else in that state runs while it waits, and there is
no `SocketServer:close()` to interrupt it. Use it from the state that owns the
accept loop, and treat a negative timeout as "until a connection arrives".

A blocking listener (`network.listen(port, false)`) with a positive timeout waits
for a *pending* connection within the timeout and then takes the old blocking
`accept()`; if that connection disappears in between, the accept itself can still
block. With `0` (or no timeout) there is no wait to bound anything, and a
blocking listener's `accept()` does not return until a client connects - exactly
as before. A non-blocking listener - what the module returns for `true` - never
blocks outside the wait you asked for.

The registered-function form takes the timeout in place of the handler,
`server:accept(1000)`, with the same return values. **Its worker thread crashes
the process on this build (pre-existing, see the known limitations below), so the
form is documented for completeness, not recommended.**

**The request read is readiness-based.** `client.request` returns as soon as the
request is buffered - microseconds, not a tick - and as soon as the rest of a
split header or body arrives, still bounded by the same 1000 ms it always had
(a peer that says nothing yields `nil` in about a second, a peer that is cut off
mid-header still raises `Incomplete or oversized HTTP request header`).
`client:receive(n)` still waits for all `n` bytes, as it always did, and still
has no deadline: the peer has to send them or close. While nothing is buffered it
now parks at no CPU cost; while some but fewer than `n` bytes are buffered it
re-checks once per timer tick, because no readiness wait can wait for "more".

Measured on loopback (Windows, `tests`-independent harness: a .NET client with
`NoDelay`, sequential `Connection: close` requests after 20 warm-ups; every
"after" number is from the final build and one run per row):

| | before (base `8a05cbc`) | after |
|---|---|---|
| round trip p50 / p95, 200 requests, parked loop | 30.1 / 31.2 ms | **0.63 / 1.14 ms** |
| round trip p50 / p95, same loop still on `sleep(10)` | 30.1 / 31.2 ms | 14.5 / 15.6 ms |
| `client.request` read p50 / p95, parked loop | 15.7 / 16.4 ms | **0.29 / 0.48 ms** |
| 4 concurrent streams x 120 requests, p50 / p95 | 61.5 / 62.9 ms | **1.28 / 1.87 ms** |
| server CPU over 10 s idle | 0.016 s | 0.000 s |

The `sleep(10)` row is the read fix on its own: half the floor goes, the other
half is the loop's own pacing tick, which only the parked accept removes.

Both are plain-socket paths. TLS reads go through `CSSLClient::Recv` /
`CActiveSock::Recv` with a socket receive timeout, not through this wait, and a
listener socket cannot be a TLS socket: `ListenerContext` owns a `Socket`.

Known limitations, unchanged by this:

* `CBaseSock::ReceiveBytes` (`socket/BaseSock.cpp`) still has the old tick and
  has no caller at all. It must **not** be pointed at `Socket::WaitReadable` if
  it is ever revived on the SSL client, where `FIONREAD` counts encrypted bytes.
* **`server:async` crashes the process.** Handing a connection to its worker
  thread ends the whole process about half a second to a second later with exit
  code `0xE24C4A02` (LuaJIT's code for an error raised with no handler): the
  thread's protected call fails and the failure is reported with `luaL_error` on
  a detached thread, where nothing can catch it. Reproduced identically on the
  base commit `8a05cbc` with a handler that does nothing (`function(c) end`), so
  it is not from this change; the parked `accept(timeout_ms)` in front of it
  works, and `tests/listener_matrix.lua` covers only that part on purpose. Two
  more constraints of the form: a handler is shipped as dumped bytecode into a
  fresh state, so it cannot have upvalues and sees none of the registering
  state's globals. **Do not use `server:async` until this is fixed** - girl's
  own per-connection workers (TB-320) do not use it.
* `SocketServer::Accept` still throws a `const char*` for an accept error other
  than "would block" and "interrupted"; that escapes the Lua C call and ends the
  process. Pre-existing, and untouched here.
* There is no `close` on a listener: a parked accept can only be waited out.
* Listener and connection userdata are freed without their C++ destructor
  running (`lua::alloc` + the binding's `__gc`), so a `network.listen` socket and
  an accepted socket are never `closesocket`-ed before the process exits. A
  server that creates listeners repeatedly leaks one handle each time.
  Pre-existing; out of scope for this change.

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
network.capabilities.accept_timeout   -- accept(handler, timeout_ms) parks
network.capabilities.ready_read       -- the listener read is readiness-based
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
run unless `-KeepWork` is given. `tests/tls_matrix.lua` covers TLS (32 checks),
`tests/proxy_matrix.lua` the proxy (48) and `tests/listener_matrix.lua` the parked
accept and the readiness read (TB-396; it needs no fixture - every case is a
loopback listener and client inside the script). A check that cannot run on this machine -
the fixed ports 443 and 8443 when something else holds them - prints `SKIP` and is
listed in the summary; it never passes silently.