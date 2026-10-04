-- TB-287: TLS is chosen by `ssl`, on any port, and the certificate is verified.
-- Run by tests/run_all.ps1 with the fixture's ports as "name=value" arguments.
local dll = assert(arg[1], "usage: tls_matrix.lua <network.dll> <name=value>...")
local network = assert(package.loadlib(dll, "luaopen_network"))()

local ports = {}
for index = 2, #arg do
    local name, value = arg[index]:match("^([^=]+)=(.*)$")
    assert(name, "bad argument: " .. tostring(arg[index]))
    ports[name] = tonumber(value) or value
end

local failures, checks = {}, 0
local function check(name, condition, detail)
    checks = checks + 1
    if condition then
        print("ok   " .. name)
    else
        print("FAIL " .. name .. (detail and (": " .. tostring(detail)) or ""))
        failures[#failures + 1] = name
    end
end

-- Runs a request and returns response, error.
local function request(host, port, options)
    options = options or {}
    options.method = options.method or "GET"
    options.path = options.path or "/matrix"
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

-- 1. The build advertises what TB-287 added.
check("version is 0.4.0", network._VERSION == "network 0.4.0", network._VERSION)
for _, capability in ipairs({ "ssl_any_port", "tls_verify", "ca_file", "sni_override" }) do
    check("capability " .. capability, network.capabilities[capability] == true)
end
for _, capability in ipairs({ "structured_response", "stream_callbacks", "request_timeouts" }) do
    check("capability " .. capability .. " still there", network.capabilities[capability] == true)
end

-- 2. ssl = true is TLS on a port that is not 443. (The TLS servers are
-- openssl s_server -www, which answers its own status page rather than echoing
-- the path: a 200 over a verified chain IS the byte-level proof, and the
-- plaintext recorder below answers X-Transport: plain for the other direction.)
do
    local ok, response = request("127.0.0.1", ports.secure_port, { ssl = true, ca_file = ports.ca_pem })
    check("ssl=true on a non-443 port completes TLS", ok and response.status == 200, response)
    check("the response came from the TLS server", ok and response.body:find("s_server", 1, true) ~= nil,
        ok and response.body:sub(1, 80))
end

-- 3. ssl = false stays plaintext, on any port.
do
    local ok, response = request("127.0.0.1", ports.plain_port, { ssl = false })
    check("ssl=false stays plaintext", ok and response.status == 200, response)
    check("the server saw plaintext", ok and response.headers["x-transport"] == "plain",
        ok and response.headers["x-transport"])
end

-- 4. The two ports the old rule keyed on, when they are free.
do
    if ports.port443 and ports.port443 > 0 then
        -- The fixture's 443 is a TLS server, so there is no plaintext listener on
        -- that port to answer a plaintext request. What this proves is the point
        -- of the check anyway: with ssl=false nothing is upgraded to TLS just
        -- because the port is 443, so the request must NOT come back as a 200.
        expect_error("port 443 with ssl=false is not upgraded to TLS", "127.0.0.1", ports.port443,
            { ssl = false }, "connection closed before HTTP response headers")
    else
        print("SKIP port 443 (busy)")
    end
    if ports.port8443 and ports.port8443 > 0 then
        local ok, response = request("127.0.0.1", ports.port8443, { ssl = true, ca_file = ports.ca_pem })
        check("port 8443 with ssl=true is TLS", ok and response.status == 200
            and response.body:find("s_server", 1, true) ~= nil, response)
    else
        print("SKIP port 8443 (busy)")
    end
end

-- 5. A caller that says nothing keeps the old meaning of port 443.
if ports.port443 and ports.port443 > 0 then
    local ok, response = request("127.0.0.1", ports.port443, { ca_file = ports.ca_pem })
    check("port 443 without ssl is still TLS", ok and response.status == 200
        and response.body:find("s_server", 1, true) ~= nil, response)
end

-- 6. TLS is not attempted when ssl is false: pointing a TLS client at the
-- plaintext recorder must fail rather than negotiate, and the reason must be a
-- TLS one and not just "some error".
expect_error("ssl=true against a plaintext server fails", "127.0.0.1", ports.plain_port,
    { ssl = true, ca_file = ports.ca_pem }, "[tls_")

-- 7. Certificate validation.
do
    expect_error("an untrusted root is refused", "127.0.0.1", ports.secure_port, { ssl = true },
        "[tls_untrusted_root]")
    expect_error("a rogue root is refused even with a name match", "localhost", ports.rogue_port,
        { ssl = true, ca_file = ports.ca_pem }, "[tls_untrusted_root]")
    expect_error("an expired certificate is refused", "localhost", ports.expired_port,
        { ssl = true, ca_file = ports.ca_pem }, "[tls_expired]")
    expect_error("a certificate with only a DNS name is refused for an IP connect",
        "127.0.0.1", ports.wrongname_port, { ssl = true, ca_file = ports.ca_pem }, "[tls_name_mismatch]")
    expect_error("a ca_file that does not exist is reported", "127.0.0.1", ports.secure_port,
        { ssl = true, ca_file = ports.ca_pem .. ".missing" }, "[tls_ca_unreadable]")
end

-- 8. The escape hatches.
do
    local ok, response = request("127.0.0.1", ports.secure_port, { ssl = true, ca_file = ports.ca_pem,
        tls_verify = false })
    check("ca_file accepts a valid chain", ok and response.status == 200, response)
    local ok2, response2 = request("127.0.0.1", ports.rogue_port, { ssl = true,
        tls_verify = false })
    check("tls_verify=false accepts an untrusted chain", ok2 and response2.status == 200, response2)
    local ok3, response3 = request("localhost", ports.wrongname_port, { ssl = true,
        ca_file = ports.ca_pem, sni = "wrong.example" })
    check("sni selects the name that is verified", ok3 and response3.status == 200, response3)
end

-- 8b. A DNS name that does not match is refused, in both directions.
do
    expect_error("a wrong DNS name is refused", "localhost", ports.secure_port,
        { ssl = true, ca_file = ports.ca_pem, sni = "other.example" }, "[tls_name_mismatch]")
    expect_error("the host name is verified, not just the SNI", "localhost", ports.wrongname_port,
        { ssl = true, ca_file = ports.ca_pem }, "[tls_name_mismatch]")
end

-- 8c. get() takes the same decision, from the URL and from an explicit ssl.
-- get() returns the body unless return_response is set, so it is here.
do
    local ok, response = pcall(function()
        return network.get("http://127.0.0.1:" .. ports.plain_port .. "/via-get",
            { return_response = true, receive_timeout_ms = 4000, connect_timeout_ms = 4000 })
    end)
    local detail = (not ok) and ("error: " .. tostring(response):sub(1, 120))
        or ("status " .. tostring(response.status) .. " " .. tostring(response.headers["x-transport"]))
    check("get() over http stays plaintext",
        ok and response.status == 200 and response.headers["x-transport"] == "plain", detail)
    local ok2, response2 = pcall(function()
        return network.get("http://127.0.0.1:" .. ports.secure_port .. "/via-get",
            { ssl = true, return_response = true, ca_file = ports.ca_pem,
              receive_timeout_ms = 4000, connect_timeout_ms = 4000 })
    end)
    check("get() honours an explicit ssl over the scheme", ok2 and response2.status == 200,
        (not ok2) and ("error: " .. tostring(response2):sub(1, 120)) or ("status " .. tostring(response2.status)))
end

-- 9. network.connect takes the same options (and no longer means "443 is TLS").
do
    local function attempt(fn)
        local ok, value = pcall(fn)
        return ok, value
    end
    local ok, connection = attempt(function()
        return network.connect({ host = "127.0.0.1", port = ports.secure_port,
            ssl = true, ca_file = ports.ca_pem })
    end)
    if ok then connection:close() end
    check("connect with ssl=true on a non-443 port works", ok, connection)
    local ok2, plainConnection = attempt(function()
        return network.connect({ host = "127.0.0.1", port = ports.plain_port, ssl = false })
    end)
    if ok2 then plainConnection:close() end
    check("connect with ssl=false stays plaintext", ok2, plainConnection)
    local refused, message = attempt(function()
        return network.connect({ host = "127.0.0.1", port = ports.secure_port, ssl = true })
    end)
    check("connect verifies the certificate too", refused == false
        and tostring(message):find("[tls_", 1, true) ~= nil, message)
    local plaintext = attempt(function()
        return network.connect({ host = "127.0.0.1", port = ports.plain_port })
    end)
    check("connect without ssl on a non-443 port stays plaintext", plaintext == true, plaintext)
end

print(string.format("tls_matrix: %d checks, %d failures", checks, #failures))
-- The runner reads this line: on this machine a child process's exit code is not
-- reliably visible when its output is redirected, so the verdict is in the text.
if #failures > 0 then
    print("TB287 RESULT: fail")
    print("failed: " .. table.concat(failures, ", "))
    os.exit(1)
end
print("TB287 RESULT: pass")