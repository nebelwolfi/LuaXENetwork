-- TB-287: the native SOCKS5 proxy. Run by tests/run_all.ps1 with the fixture's
-- ports as "name=value" arguments, like tls_matrix.lua.
local dll = assert(arg[1], "usage: proxy_matrix.lua <network.dll> <name=value>...")
local network = assert(package.loadlib(dll, "luaopen_network"))()

local ports = {}
for index = 2, #arg do
    local name, value = arg[index]:match("^([^=]+)=(.*)$")
    assert(name, "bad argument: " .. tostring(arg[index]))
    ports[name] = tonumber(value) or value
end
assert(ports.socks_open_port and ports.socks_report_dir, "the fixture must provide the SOCKS ports")

local failures, checks, skipped = {}, 0, 0
local function check(name, condition, detail)
    checks = checks + 1
    if condition then
        print("ok   " .. name)
    else
        print("FAIL " .. name .. (detail and (": " .. tostring(detail)) or ""))
        failures[#failures + 1] = name
    end
end
local function skip(name, why)
    skipped = skipped + 1
    print("SKIP " .. name .. " (" .. why .. ")")
end

-- Runs a request and returns response, error.
local function request(host, port, options)
    options = options or {}
    options.method = options.method or "GET"
    options.path = options.path or "/proxy"
    options.headers = options.headers or { Connection = "close" }
    options.connect_timeout_ms = options.connect_timeout_ms or 4000
    options.receive_timeout_ms = options.receive_timeout_ms or 4000
    options.send_timeout_ms = options.send_timeout_ms or 4000
    return pcall(function() return network.request(host, port, options) end)
end

local function expect_error(name, host, port, options, needle)
    local ok, value = request(host, port, options)
    if ok then
        check(name, false, "expected an error, got status " .. tostring(value and value.status))
        return ""
    end
    check(name, value:find(needle, 1, true) ~= nil, value)
    return value
end

-- What the proxy saw: the report file holds one line per step, so the checks
-- look at the last line that starts with the prefix they care about.
local function proxy_report(role, prefix)
    local path = ports.socks_report_dir .. "\\" .. role .. ".txt"
    local file = io.open(path, "rb")
    if not file then return "" end
    local found = ""
    for line in (file:read("*a") or ""):gmatch("[^\r\n]+") do
        if line:sub(1, #prefix) == prefix then found = line end
    end
    file:close()
    return found
end

local function proxy_url(port, credentials)
    return "socks5://" .. (credentials and (credentials .. "@") or "") .. "127.0.0.1:" .. port
end

-- 1. The build says so.
check("capability proxy_socks5", network.capabilities.proxy_socks5 == true)

-- 2. A plain request through an open proxy, and what the proxy was told.
do
    local ok, response = request("127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_open_port) })
    check("a request through a SOCKS5 proxy succeeds", ok and response.status == 200, response)
    check("the end server saw plaintext", ok and response.headers["x-transport"] == "plain",
        ok and response.headers["x-transport"])
    check("the body travelled through the proxy", ok and response.body:find("/proxy", 1, true) ~= nil,
        ok and response.body)
    check("socks5 sends the resolved address (ATYP 1)",
        proxy_report("socks-open", "connect 1 127.0.0.1 ") ~= "", proxy_report("socks-open", "connect "))
end

-- 3. socks5h hands the NAME to the proxy instead.
do
    local ok = request("localhost", ports.plain_port,
        { proxy = "socks5h://127.0.0.1:" .. ports.socks_open_port })
    check("socks5h succeeds with a hostname", ok, ok)
    check("socks5h sends the name (ATYP 3)",
        proxy_report("socks-open", "connect 3 localhost ") ~= "", proxy_report("socks-open", "connect "))
end

-- 4. Credentials, and their absence.
do
    local ok, response = request("127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_auth_port, "user:pass") })
    check("user/pass are accepted", ok and response.status == 200, response)
    check("the proxy saw the right user", proxy_report("socks-auth", "auth-ok user ") ~= "",
        proxy_report("socks-auth", "auth"))
    expect_error("a wrong password is refused", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_auth_port, "user:wrong") }, "[proxy_auth_failed]")
    expect_error("no credentials for a proxy that wants them", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_auth_port) }, "[proxy_no_acceptable_auth]")
    expect_error("a proxy that accepts no method", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_nomethod_port) }, "[proxy_no_acceptable_auth]")
end

-- 5. Percent-encoded credentials are decoded, and never appear in an error.
do
    local ok = request("127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_auth_port, "user:pa%73s") })
    check("percent-encoded credentials are decoded", ok, ok)
    local message = expect_error("a refused login does not leak the password", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_auth_port, "user:wrong%21secret") }, "[proxy_auth_failed]")
    check("no credential text in the error", not message:find("wrong", 1, true)
        and not message:find("secret", 1, true), message)
    local malformed = select(2, pcall(function()
        return network.request("127.0.0.1", ports.plain_port, { proxy = "socks5://user:pa%zz@127.0.0.1:1" })
    end))
    check("a malformed proxy URL is refused", tostring(malformed):find("[proxy_url_invalid]", 1, true) ~= nil,
        malformed)
    local scheme = select(2, pcall(function()
        return network.request("127.0.0.1", ports.plain_port, { proxy = "http://127.0.0.1:1" })
    end))
    check("an unknown proxy scheme is refused", tostring(scheme):find("[proxy_url_invalid]", 1, true) ~= nil, scheme)
end

-- 6. Every reply code has its own error.
do
    for code = 1, 8 do
        expect_error("reply 0x0" .. code .. " is reported", "127.0.0.1", ports.plain_port,
            { proxy = proxy_url(ports["rep" .. code]) }, "[proxy_")
    end
    expect_error("an unknown reply code is reported", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.rep9) }, "[proxy_reply_unknown]")
end

-- 7. Transport failures.
do
    expect_error("a proxy that hangs up is reported", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_close_port) }, "[proxy_closed]")
    expect_error("a silent proxy times out", "127.0.0.1", ports.plain_port,
        { proxy = proxy_url(ports.socks_silent_port), connect_timeout_ms = 1000 }, "[proxy_timeout]")
    -- Nothing listens on a port the fixture never opened, so every request that
    -- tries one has to fail at the TCP connect.
    local answered = nil
    for port = 45001, 45011 do
        local refused = select(1, pcall(function()
            return network.request("127.0.0.1", ports.plain_port,
                { proxy = "socks5://127.0.0.1:" .. port, connect_timeout_ms = 1000 })
        end))
        if refused then answered = port break end
    end
    check("a closed proxy port is refused", answered == nil, "port " .. tostring(answered) .. " answered")
end

-- 8. TLS through the proxy: the certificate is still verified against the TARGET.
-- The timeouts are longer here because the fixture may be restarting its
-- openssl TLS server after the rejected handshake in the second check.
do
    local relaxed = { connect_timeout_ms = 15000, receive_timeout_ms = 15000, send_timeout_ms = 15000 }
    local ok, response = request("127.0.0.1", ports.secure_port,
        { ssl = true, ca_file = ports.ca_pem, proxy = proxy_url(ports.socks_secure_port),
          connect_timeout_ms = relaxed.connect_timeout_ms,
          receive_timeout_ms = relaxed.receive_timeout_ms,
          send_timeout_ms = relaxed.send_timeout_ms })
    check("TLS through the proxy completes", ok and response.status == 200, response)
    check("the TLS body came back", ok and response.body:find("s_server", 1, true) ~= nil, ok and response.body:sub(1, 60))
    -- The rejection uses its own proxy and its own server: an aborted handshake
    -- leaves that one openssl server unable to serve the next connection.
    expect_error("an untrusted certificate through the proxy is refused", "127.0.0.1", ports.rogue_port,
        { ssl = true, proxy = proxy_url(ports.socks_rogue_port),
          connect_timeout_ms = relaxed.connect_timeout_ms,
          receive_timeout_ms = relaxed.receive_timeout_ms,
          send_timeout_ms = relaxed.send_timeout_ms }, "[tls_untrusted_root]")
end

-- 9. Streaming through the proxy: on_chunk must see the pieces, in order.
do
    local chunks = {}
    local ok, response = request("127.0.0.1", ports.plain_port, {
        path = "/stream",
        proxy = proxy_url(ports.socks_open_port),
        on_chunk = function(piece) chunks[#chunks + 1] = piece end,
    })
    check("a chunked response arrives through the proxy", ok and response.status == 200, response)
    check("on_chunk saw several pieces", #chunks >= 3, #chunks)
    check("the pieces arrive in order", table.concat(chunks) == "alpha beta gamma omega",
        table.concat(chunks))
    check("the body matches the chunks", ok and response.body == table.concat(chunks), ok and response.body)
end

-- 10. The old port rule still does not leak into a proxied request, and the
--     proxy is used for every port. (The non-443 TLS-through-proxy case is
--     checked in section 8, next to the other one, before anything aborts a
--     handshake on the shared TLS server.)
do
    if ports.port443 and ports.port443 > 0 then
        local ok443, response443 = request("127.0.0.1", ports.port443,
            { ca_file = ports.ca_pem, proxy = proxy_url(ports.socks_secure_port) })
        check("target port 443 through the proxy is TLS", ok443 and response443.status == 200
            and response443.body:find("s_server", 1, true) ~= nil, response443)
    else
        skip("target port 443 through the proxy", "no fixed-port 443 server")
    end
end

-- 11. network.connect takes the same proxy option.
do
    local ok, connection = pcall(function()
        return network.connect({ host = "127.0.0.1", port = ports.plain_port,
            ssl = false, proxy = proxy_url(ports.socks_open_port) })
    end)
    if ok then
        connection:close()
        check("connect() through a SOCKS5 proxy works", true)
    else
        check("connect() through a SOCKS5 proxy works", false, connection)
    end
    local refused = select(1, pcall(function()
        return network.connect({ host = "127.0.0.1", port = ports.plain_port,
            proxy = proxy_url(ports["rep5"]) })
    end))
    check("connect() reports a refused target through the proxy", refused == false)
end

print(string.format("proxy_matrix: %d checks, %d failures, %d skipped", checks, #failures, skipped))
if #failures > 0 then
    print("failed: " .. table.concat(failures, ", "))
    print("TB287 RESULT: fail")
    os.exit(1)
end
print("TB287 RESULT: pass")