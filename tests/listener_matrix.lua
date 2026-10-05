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
    -- Loose bounds on purpose: these are single-shot measurements of a
    -- sub-millisecond operation on a box that may be busy. The regression that
    -- matters (no wait / no boolean) is caught by the checks above; the
    -- benchmark, not this suite, is where the latency is measured.
    check("...well under a timer tick's worth of waiting (< 200 ms)", took < 200, string.format("%.2f ms", took))
    check("...and the request parsed", path == "/fast", tostring(path))
    check("...and the read itself did not wait for a tick (< 50 ms)", read_took and read_took < 50,
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
        return (not ok) and tostring(message) or ""
    end
    local big, half = refused(2147483648), refused(0.5)
    check("a timeout above INT_MAX is refused", big:find("whole number", 1, true) ~= nil, big)
    check("a fractional timeout is refused", half:find("whole number", 1, true) ~= nil, half)
    check("a normal timeout still works", server:accept(function() end, 1) == false)
end

-- 10. A third argument that is not a timeout is refused rather than mistaken for
-- the handler's response (the pre-existing `lua_gettop(L) > 2` read), and a
-- fourth argument is refused rather than silently dropped.
do
    local server = network.listen(0, true)
    local ok, message = pcall(function() server:accept(function() end, "abc") end)
    check("a non-numeric third argument is refused", not ok and tostring(message):find("milliseconds", 1, true) ~= nil,
        tostring(message))
    local fourth_ok, fourth = pcall(function() server:accept(function() end, 10, "junk") end)
    check("a fourth argument is refused", not fourth_ok and tostring(fourth):find("at most three", 1, true) ~= nil,
        tostring(fourth))
    -- nil in slot 3 is the old call: no error AND no values.
    local nil_ok, nil_count = pcall(function() return select("#", server:accept(function() end, nil)) end)
    check("a nil third argument is still the old call (no values)", nil_ok and nil_count == 0, tostring(nil_count))
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

-- 12. Nothing to run is an error BEFORE the park: accept(nil, -1) or
-- accept(-1) with no registered handler would otherwise wait forever for what
-- is a typo. The bound here is the proof that it did not wait.
do
    local server = network.listen(0, true)
    local started = ms()
    local ok, message = pcall(function() server:accept(nil, 5000) end)
    local took = ms() - started
    check("accept(nil, ms) with no handler raises", not ok and tostring(message):find("No function provided", 1, true) ~= nil,
        tostring(message))
    check("...without parking first (< 1000 ms)", took < 1000, string.format("%.1f ms", took))
    local started2 = ms()
    local ok2 = pcall(function() server:accept(5000) end)
    check("accept(ms) with no handler raises without parking", not ok2 and ms() - started2 < 1000)
end

-- 13. The registered-function (async) form: accept(ms) with no handler in the
-- call, parked and timing out. It deliberately never hands a connection to the
-- module's worker thread: on this build - and on the base commit 8a05cbc - that
-- thread kills the whole process ~0.5-1 s later (exit 0xE24C4A02, an unhandled
-- luaL_error on a detached thread; README, known limitations). A suite that did
-- so would be testing that pre-existing crash, and a later case in this process
-- would pay for it (it did: a 150 ms wait measured 2.7 s).
do
    local server = network.listen(0, true)
    server:async(function(c) end)
    local started = ms()
    local idle = server:accept(150)
    local took = ms() - started
    check("async form: accept(ms) with nothing pending returns false", idle == false, tostring(idle))
    check("...after waiting for it (>= 140 ms, < 1500 ms)", took >= 140 and took < 1500, string.format("%.1f ms", took))
    local zero = server:accept(0)
    check("async form: accept(0) with nothing pending returns false at once", zero == false, tostring(zero))
end

-- 14. One listener, two parked accepts in a row: the wait must not leave the
-- listening socket unusable for the next one.
do
    local server = network.listen(0, true)
    local seen = {}
    for i = 1, 2 do
        local client = network.connect("127.0.0.1", server.port)
        client:send(request("GET", "/n" .. i))
        local accepted = server:accept(function(c)
            local got = c.request
            seen[#seen + 1] = got and got.path
        end, 2000)
        client:close()
        check("parked accept #" .. i .. " on one listener takes its connection", accepted == true, tostring(accepted))
    end
    check("...and both handlers saw their own request", seen[1] == "/n1" and seen[2] == "/n2",
        tostring(seen[1]) .. "," .. tostring(seen[2]))
end

-- 15. A BLOCKING listener (network.listen(port, false)) with a timeout and
-- nothing pending: the bounded wait is what comes back, not the old blocking
-- accept(). If this regresses it hangs, and run_all.ps1's per-script timeout
-- is what then fails the run.
do
    local server = network.listen(0, false)
    local started = ms()
    local accepted = server:accept(function() end, 150)
    local took = ms() - started
    check("a blocking listener's timed accept returns false", accepted == false, tostring(accepted))
    check("...inside its budget (< 1500 ms)", took < 1500, string.format("%.1f ms", took))
end

-- The verdict is the LAST line printed: run_all.ps1 decides on that text, so
-- nothing may run after a pass marker.
print(string.format("listener_matrix: %d checks, %d failures", checks, #failures))
if #failures > 0 then
    print("failed: " .. table.concat(failures, ", "))
    print("TB396 RESULT: fail")
    os.exit(1)
end
print("TB396 RESULT: pass")