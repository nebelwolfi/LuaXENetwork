# LuaXE Network

Windows HTTP/HTTPS, TCP, listener, async-connection, ping, and download support
for LuaXE. Import it with:

```lua
local network = import("network", "local")
```

## HTTP requests

`network.send` remains backward compatible and returns only the decoded
response body:

```lua
local body = network.send("example.com", 443, {
    method = "GET",
    path = "/",
    ssl = true,
    headers = { Accept = "text/html", Connection = "close" },
})
```

`network.request` accepts the same arguments and returns a structured response:

```lua
local response = network.request("api.example.com", 443, {
    method = "POST",
    path = "/v1/jobs",
    ssl = true,
    headers = { ["Content-Type"] = "application/json" },
    body = "{}",

    connect_timeout_ms = 30000,
    send_timeout_ms = 60000,
    receive_timeout_ms = 300000, -- maximum idle time between reads
    total_timeout_ms = 0,        -- zero disables the overall deadline
    max_response_bytes = 64 * 1024 * 1024,
    buffer_size = 16384,

    on_headers = function(metadata)
        print(metadata.status, metadata.headers["content-type"])
    end,
    on_chunk = function(chunk)
        io.write(chunk)          -- return false to cancel
    end,
    should_cancel = function()
        return false             -- polled between blocking reads
    end,
})

assert(response.ok)
print(response.status, response.reason)
print(response.body)
print(response.bytes_received, response.elapsed_ms)
```

Response header names are lowercase. Repeated values are joined with a comma in
`headers`; `header_list` preserves every original name/value pair for fields
such as `Set-Cookie`. Transfer-encoding chunks are decoded before `on_chunk`
and before the body is returned. HTTP status codes do not themselves raise Lua
errors, so the caller can inspect error bodies. Connection, TLS, timeout,
cancellation, malformed HTTP, content-length, and response-limit failures raise
descriptive Lua errors.

For compatibility, setting `return_response=true` on `network.send` also
selects the structured return value. `timeout_ms` and `read_timeout_ms` are
aliases for `receive_timeout_ms`.

The default idle receive timeout is five minutes. This is deliberately longer
than the old hard-coded 30 seconds so streaming reasoning/model APIs can remain
quiet between events without losing the request. Large HTTPS requests are split
across multiple TLS records instead of failing at approximately 16 KiB.

Feature detection is available through `network._VERSION` and
`network.capabilities`.

The `tests` directory contains focused smoke scripts for chunked responses and
callbacks, descriptive idle timeouts, ordinary HTTPS/get compatibility, and a
large HTTPS POST spanning multiple TLS records.

## Existing APIs

The existing `get`, `download`, `connect`, `listen`, `async`, `ping`, and
`last_error` functions remain available. `get(url, options)` and
`download(url, path, options)` accept the same timeout, response-limit, and
callback options; set `return_response=true` to receive metadata. `send`
retains its original body-only return value unless structured output is
explicitly requested.
