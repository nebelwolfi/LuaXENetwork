local network = assert(import("network", "local"))
local port = assert(tonumber(os.getenv("NETWORK_SMOKE_PORT")), "set NETWORK_SMOKE_PORT")
local ok, err = pcall(network.request, "127.0.0.1", port, {
    method = "GET",
    path = "/timeout",
    headers = { Connection="close" },
    connect_timeout_ms = 5000,
    receive_timeout_ms = 1000,
    total_timeout_ms = 5000,
})

assert(not ok, "request unexpectedly succeeded")
assert(tostring(err):find("receive timed out after 1000 ms", 1, true), tostring(err))
assert(not tostring(err):find("Error receiving data: 0", 1, true), tostring(err))
print(network._VERSION .. " timeout smoke passed")
