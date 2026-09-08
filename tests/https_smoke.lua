local network = assert(import("network", "local"))
local chunks = 0
local response = network.request("example.com", 443, {
    method = "GET",
    path = "/",
    ssl = true,
    headers = { Accept="text/html", Connection="close" },
    connect_timeout_ms = 10000,
    receive_timeout_ms = 30000,
    total_timeout_ms = 60000,
    max_response_bytes = 1024 * 1024,
    on_chunk = function() chunks = chunks + 1 end,
})

assert(response.status == 200, tostring(response.status) .. " " .. tostring(response.reason))
assert(response.body:find("Example Domain", 1, true), "unexpected response body")
assert(chunks > 0, "HTTPS response did not invoke on_chunk")
local via_get = network.get("https://example.com/", {
    return_response = true,
    receive_timeout_ms = 30000,
    total_timeout_ms = 60000,
    max_response_bytes = 1024 * 1024,
})
assert(via_get.status == 200 and via_get.body:find("Example Domain", 1, true))
print(network._VERSION .. " HTTPS smoke passed")
