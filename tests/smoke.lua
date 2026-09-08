local network = assert(import("network", "local"))
local port = assert(tonumber((arg and arg[1]) or os.getenv("NETWORK_SMOKE_PORT")),
    "usage: smoke.lua <local-port> (or set NETWORK_SMOKE_PORT)")
assert(type(network.request) == "function")
assert(network.capabilities and network.capabilities.request_timeouts)

local chunks, headers = {}, nil
local response = network.request("127.0.0.1", port, {
    method = "POST",
    path = "/smoke",
    body = string.rep("x", 20000),
    headers = { ["Content-Type"]="text/plain", Connection="close" },
    connect_timeout_ms = 5000,
    send_timeout_ms = 5000,
    receive_timeout_ms = 5000,
    total_timeout_ms = 10000,
    max_response_bytes = 1024,
    on_headers = function(value) headers = value end,
    on_chunk = function(value) chunks[#chunks + 1] = value end,
})

assert(response.status == 200, tostring(response.status))
assert(response.ok == true)
assert(response.headers["x-network-test"] == "passed")
assert(type(response.header_list) == "table" and #response.header_list >= 3)
assert(headers and headers.status == 200)
assert(response.body == "hello world", response.body)
assert(table.concat(chunks) == response.body)
assert(response.bytes_received > #response.body)
print(network._VERSION .. " smoke passed")
