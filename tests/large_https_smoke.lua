local network = assert(import("network", "local"))
local body = string.rep("0123456789", 2000)
local response = network.request("postman-echo.com", 443, {
    method = "POST",
    path = "/post",
    ssl = true,
    headers = {
        ["Content-Type"] = "text/plain",
        Accept = "application/json",
        Connection = "close",
    },
    body = body,
    connect_timeout_ms = 10000,
    send_timeout_ms = 30000,
    receive_timeout_ms = 30000,
    total_timeout_ms = 60000,
    max_response_bytes = 1024 * 1024,
})

assert(response.status == 200, tostring(response.status) .. " " .. tostring(response.reason))
assert(response.body:find(body:sub(1, 100), 1, true), "echo response did not contain the posted body")
print(network._VERSION .. " large HTTPS POST smoke passed")
