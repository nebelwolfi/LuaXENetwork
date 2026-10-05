-- TB-396: the parked accept and the readiness-based listener read.
--
-- Run by tests/run_all.ps1 (it picks up tests/*_matrix.lua) with the fixture's
-- ports as "name=value" arguments. This one needs NO fixture: every case is a
-- listener and a client inside this process, over loopback, and each one has a
-- deadline so a broken wait fails the case instead of hanging the run.
--
--   lxe run tests\listener_matrix.lua <network.dll> [name=value...]

local dll = assert(arg[1], "usage: listener_matrix.lua <network.dll> [name=value...]")
local network = assert(package.loadlib(dll, "luaopen_network"))()

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

local function ms()
    return os.clock() * 1000
end

-- A full HTTP request with the pieces a case wants to control.
local function request(method, path, headers, body)
    local text = method .. " " .. path .. " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    for key, value in pairs(headers or {}) do
        text = text .. key .. ": " .. value .. "\r\n"
    end
    if body then
        text = text .. "Content-Length: " .. #body .. "\r\n"
    end
    return text .. "\r\n" .. (body or "")
end

-- 1. What the build advertises.
check("accept_timeout capability", network.capabilities.accept_timeout == true)
check("ready_read capability", network.capabilities.ready_read == true)
check("version is still 0.4.0", network._VERSION == "network 0.4.0", network._VERSION)

-- 2. accept(handler, ms) with nothing pending parks, then reports false. It has
-- to WAIT (the old accept returned at once, so this is the whole point) and it
-- has to come back within its budget.
do
    local server = network.listen(0, true)
    local started = ms()
    local served = false
    local accepted = server:accept(function() served = true end, 200)
    local took = ms() - started
    check("a timed accept with nothing pending returns false", accepted == false, tostring(accepted))
    check("...and the handler was not run", served == false)
    check("...and it waited for its timeout (>= 190 ms)", took >= 190, string.format("%.1f ms", took))
    check("...and it came back promptly (< 1500 ms)", took < 1500, string.format("%.1f ms", took))
end

-- 3. accept(handler, 0) is the old "do not wait", but it REPORTS.
do
    local server = network.listen(0, true)
    local started = ms()
    local accepted = server:accept(function() end, 0)
    local took = ms() - started
    check("accept(handler, 0) with nothing pending returns false", accepted == false, tostring(accepted))
    check("...without waiting for anything", took < 100, string.format("%.1f ms", took))

    local client = network.connect("127.0.0.1", server.port)
    client:send(request("GET", "/zero"))
    local served, seen = false, nil
    local ok = server:accept(function(c) served = true seen = c.request end, 0)
    check("accept(handler, 0) takes a pending connection and returns true", ok == true, tostring(ok))
    check("...and the handler saw the request", served and seen ~= nil and seen.path == "/zero")
    client:close()
end

-- 4. An untimed accept still returns NO values: that is the contract every
-- existing caller relies on.
do
    local server = network.listen(0, true)
    check("accept(handler) with nothing pending returns no values",
        select("#", server:accept(function() end)) == 0)
    local client = network.connect("127.0.0.1", server.port)
    client:send(request("GET", "/untimed"))
    local seen = nil
    check("accept(handler) on a pending connection returns no values",
        select("#", server:accept(function(c) seen = c.request end)) == 0)
    check("...and the handler saw the request", seen ~= nil and seen.path == "/untimed")
    client:close()
end

-- 5. The whole point: a connection that lands while the loop is parked is taken
-- at once, and its request reads in microseconds, not on a timer tick.
do
    local server = network.listen(0, true)
    local client = network.connect("127.0.0.1", server.port)
    client:send(request("GET", "/fast?x=1"))
    local started, path, read_took = ms(), nil, nil
    local accepted = server:accept(function(c)
        local read_started = ms()
        local got = c.request
        read_took = ms() - read_started
        path = got and got.path
    end, 2000)
    local took = ms() - started
    client:close()
    check("a parked accept wakes on the connection", accepted == true, tostring(accepted))
    check("...within a few ms, not a timer tick", took < 50, string.format("%.2f ms", took))
    check("...and the request parsed", path == "/fast", tostring(path))
    check("...and the read itself cost under 5 ms", read_took and read_took < 5,
        read_took and string.format("%.3f ms", read_took))
end

-- 6. A request that arrives in pieces still completes, and the body is whole.
do
    local server = network.listen(0, true)
    local client = network.connect("127.0.0.1", server.port)
    client:send("POST /split HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello")
    local got = nil
    local accepted = server:accept(function(c)
        client:send(" world")
        got = c.request
    end, 2000)
    client:close()
    check("a split body completes", accepted == true and got ~= nil and got.body == "hello world",
        got and string.format("%q", got.body) or "nil")
end

-- 7. A peer that connects and says nothing: client.request is still bounded by
-- its own 1000 ms and yields nil rather than hanging.
do
    local server = network.listen(0, true)
    local client = network.connect("127.0.0.1", server.port)
    local started, value = ms(), "unset"
    server:accept(function(c) value = c.request end, 2000)
    local took = ms() - started
    client:close()
    check("a silent peer yields nil", value == nil, tostring(value))
    check("...inside its 1000 ms budget", took < 1600, string.format("%.1f ms", took))
end

-- 8. A peer that vanishes mid-header still raises the same error it always did.
do
    local server = network.listen(0, true)
    local client = network.connect("127.0.0.1", server.port)
    client:send("GET / HTTP/1.1\r\n")
    local ok, message = pcall(function()
        server:accept(function(c) local _ = c.request end, 2000)
    end)
    client:close()
    check("a cut-off header raises", not ok and tostring(message):find("Incomplete or oversized", 1, true) ~= nil,
        tostring(message))
end

-- 9. A timeout that would not survive the narrowing is refused, not wrapped.
-- Wrapping to a negative would park this state with no way out.
do
    local server = network.listen(0, true)
    local function refused(value)
        local ok, message = pcall(function() server:accept(function() end, value) end)
        return (not ok) and tostring(message)
    end
    check("a timeout above INT_MAX is refused", refused(2147483648) ~= nil, refused(2147483648))
    check("a fractional timeout is refused", refused(0.5) ~= nil, refused(0.5))
    check("a normal timeout still works", server:accept(function() end, 1) == false)
end

-- 10. A third argument that is not a timeout is refused rather than mistaken for
-- the handler's response (the pre-existing `lua_gettop(L) > 2` read).
do
    local server = network.listen(0, true)
    local ok, message = pcall(function() server:accept(function() end, "abc") end)
    check("a non-numeric third argument is refused", not ok and tostring(message):find("milliseconds", 1, true) ~= nil,
        tostring(message))
    local nil_ok = pcall(function() server:accept(function() end, nil) end)
    check("a nil third argument is still the old call", nil_ok)
end

-- 11. The capabilities are how a caller decides to use this at all, so the
-- untimed shape must keep working on a build that has both.
do
    local server = network.listen(0, true)
    local client = network.connect("127.0.0.1", server.port)
    client:send(request("GET", "/shape"))
    local reply = nil
    server:accept(function(c) reply = c.request end)
    client:close()
    check("an untimed accept still parses a request", reply ~= nil and reply.path == "/shape")
end

print(string.format("TB396 RESULT: %s", #failures == 0 and "pass" or "fail"))
if #failures > 0 then
    for _, name in ipairs(failures) do print("failed: " .. name) end
    os.exit(1)
end
print(string.format("%d checks", checks))