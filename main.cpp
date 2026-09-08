#include <pch.h>
#include <WinSock2.h>

#include "socket/framework.h"
#include "socket/Utilities.h"
#include "socket/ActiveSock.h"
#include "socket/Socket.h"
#include "socket/SSLClient.h"
#include "socket/EventWrapper.h"
#include "socket/CertHelper.h"
#include <iomanip>
#include <fstream>
#include "misc/misc.h"

#include <codecvt>
#include "misc/md5.h"
#include <memory>
#include <thread>
#include <chrono>
#include <shellapi.h>
#include "misc/json.hpp"
#include "misc/ping.h"
#include <mutex>
#include <future>
#include <filesystem>
#include <optional>

#include "connection.h"

std::string RequestBuilder(lua_State *L, std::string host, int idx = -1) {
    idx = lua_absindex(L, idx);
    if (lua_isstring(L, idx)) return lua_tostring(L, idx);
    std::string request;
    if (luaL_getfield(L, idx, "method") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        if (!request.empty()) request += " ";
    } else {
        request += "GET ";
    }
    lua_pop(L, 1);
    if (luaL_getfield(L, idx, "path") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        if (!request.empty()) request += " ";
    } else {
        request += "/ ";
    }
    lua_pop(L, 1);
    if (luaL_getfield(L, idx, "version") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "HTTP/1.1\r\n";
    }
    lua_pop(L, 1);
    request += "Host: " + host + "\r\n";
    if (auto header_type = luaL_getfield(L, idx, "headers"); header_type == LUA_TTABLE) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            request += lua_tostring(L, -2);
            request += ": ";
            request += lua_tostring(L, -1);
            request += "\r\n";
            lua_pop(L, 1);
        }
    } else if (header_type == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "Accept: */*\r\n";
    }
    lua_pop(L, 1);
    if (luaL_getfield(L, idx, "body") == LUA_TSTRING) {
        request += "Content-Length: ";
        request += std::to_string(lua_objlen(L, -1));
        request += "\r\n\r\n";
        request += lua_tostring(L, -1);
    } else {
        request += "\r\n";
    }
    lua_pop(L, 1);
    return request;
}

std::string ResponseBuilder(lua_State *L, int idx = 1) {
    idx = lua_absindex(L, idx);
    std::string request;
    if (luaL_getfield(L, idx, "version") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += " ";
    } else {
        request += "HTTP/1.1 ";
    }
    lua_getfield(L, idx, "status");
    if (lua_isnumber(L, -1)) {
        request += std::to_string(lua_tointeger(L, -1));
        request += " ";
    } else {
        request += "200 ";
    }
    if (luaL_getfield(L, idx, "reason") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "OK\r\n";
    }
    if (luaL_getfield(L, idx, "headers") == LUA_TTABLE) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            request += lua_tostring(L, -2);
            request += ": ";
            request += lua_tostring(L, -1);
            request += "\r\n";
            lua_pop(L, 1);
        }
    }
    if (luaL_getfield(L, idx, "body") == LUA_TSTRING) {
        request += "Content-Length: ";
        request += std::to_string(lua_objlen(L, -1));
        request += "\r\n\r\n";
        request += lua_tostring(L, -1);
    } else {
        request += "\r\n";
    }
    return request;
}

bool WorkOnBody(std::string& Body, std::string& ChunkedBody, int& CurrentChunkSize) {
    //printf("workonbody\n");
    if (CurrentChunkSize == 0) { // no chunksize yet, check for one
        auto EndOfLine = Body.find_first_of("\r\n");
        if (EndOfLine == std::string::npos) { // failed to get a chunksize, that should not really be possible
            //printf("failed to get a chunksize\n");
            return false;
        }
        //printf("Body: %s", Body.c_str());

        auto ChunkSize = Body.substr(0, EndOfLine);
        Body = Body.substr(EndOfLine + 2);
        CurrentChunkSize = std::stol(ChunkSize, nullptr, 16);
        if (CurrentChunkSize == 0) { // return since i got the last chunk
            //printf("got last chunk");
            CurrentChunkSize = -1;
            return false;
        } else {
            return true;
        }
    }

    if (Body.size() >= CurrentChunkSize + 2) { // body size is big enouth for chunkedbody
        ChunkedBody += Body.substr(0, CurrentChunkSize);
        //printf("ChunkedBody: %s", ChunkedBody.c_str());

        Body = Body.substr(CurrentChunkSize + 2);
        CurrentChunkSize = 0;
        return true;
    }

    return false;
}

std::string ResolveWebRequest(lua_State* L, const std::string& HostA, const std::wstring& HostW, int Port, const std::string& RequestString, bool force_ssl) {
    CEventWrapper ShutDownEvent;
    auto pActiveSock = std::make_unique<CActiveSock>(ShutDownEvent);
    pActiveSock->SetRecvTimeoutSeconds(30);
    pActiveSock->SetSendTimeoutSeconds(60);

    bool b = pActiveSock->Connect(HostW.c_str(), static_cast<USHORT>(Port));
    if (!b) {
        luaL_error(L, "Could not connect to the Server");
        return "";
    }
    std::unique_ptr<CSSLClient> pSSLClient;
    if (Port == 443 || force_ssl)
    {
        pSSLClient = std::make_unique<CSSLClient>(pActiveSock.get());
        pSSLClient->ServerCertAcceptable = CertAcceptable;
        pSSLClient->SelectClientCertificate = SelectClientCertificate;
        HRESULT hr = pSSLClient->Initialize(HostW.c_str());
        if (SUCCEEDED(hr)) {
            pSSLClient->Send(RequestString.c_str(), RequestString.size());
        } else {
            pActiveSock->Send(RequestString.c_str(), RequestString.size());
        }
    } else {
        pActiveSock->Send(RequestString.c_str(), RequestString.size());
    }

    int BufferBytesReceiving = 4096;
    int ContentLength = 0;
    bool GotHeaders = false;
    bool RequestFinished = false;
    bool IsChunked = false;
    bool AlreadyAddedNewMsg = false;
    int CurrentChunkSize = 0;
    std::string CompleteReceive = "";
    std::string Header = "";
    std::string Body = "";
    std::string ChunkedBody = "";

    try {
    while (!RequestFinished) {
        std::string ReceiveMsgBuffer;
        ReceiveMsgBuffer.resize(BufferBytesReceiving);
        ReceiveMsgBuffer.reserve(BufferBytesReceiving);
        int BytesReceived = 0;
        int res = 0;

        if (pSSLClient) {
            res = (BytesReceived = pSSLClient->Recv(&ReceiveMsgBuffer[0], BufferBytesReceiving));
        } else {
            res = (BytesReceived = pActiveSock->Recv(&ReceiveMsgBuffer[0], BufferBytesReceiving));
        }
        if (0 < res) {
            std::string ReceiveMsg = ReceiveMsgBuffer.substr(0, BytesReceived);
            CompleteReceive += ReceiveMsg;
            //printf("ReceivedMsg");
            if (!GotHeaders && CompleteReceive.find("\r\n\r\n") != std::string::npos) {
                Header = CompleteReceive.substr(0, CompleteReceive.find("\r\n\r\n"));
                Body = CompleteReceive.substr(CompleteReceive.find("\r\n\r\n") + 4);
                GotHeaders = true;

                if (Header.find("ncoding: chunked") != std::string::npos) {
                    IsChunked = true;
                }
                AlreadyAddedNewMsg = true;

                //printf("Header: %s", Header.c_str());
            }
            if (GotHeaders) {
                if (!AlreadyAddedNewMsg) {
                    CompleteReceive += ReceiveMsg;
                    Body += ReceiveMsg;
                }
                if (IsChunked) {
                    while (WorkOnBody(Body, ChunkedBody, CurrentChunkSize)) {
                        //lop
                    }

                    if (CurrentChunkSize == -1) {
                        RequestFinished = true;
                        Body = ChunkedBody;
                    }
                } else {
                    int ContentLengthStart = Header.find("Content-Length:");
                    if (ContentLengthStart == std::string::npos) {
                        ContentLengthStart = Header.find("Content-length:");
                        if (ContentLengthStart == std::string::npos) {
                            ContentLengthStart = Header.find("content-length:");
                            if (ContentLengthStart == std::string::npos) {
                                ContentLengthStart = Header.find("content-Length:");
                            }
                        }
                    }
                    if (ContentLengthStart == std::string::npos) {
                        if (Body.ends_with("0\r\n\r\n")) {
                            RequestFinished = true;
                        }
                    } else {
                        int ContentLengthEnd = Header.find("\r\n", ContentLengthStart + 16);
                        ContentLength = std::stoi(Header.substr(ContentLengthStart + 16, ContentLengthEnd - ContentLengthStart - 16));
                        if (Body.size() >= ContentLength) {
                            RequestFinished = true;
                        }
                    }
                }
            }
            AlreadyAddedNewMsg = false;
            ReceiveMsg.clear();
        }
        else if (res == 0)
        {
            //luaL_error(L, "Connection closed by server");
            //printf("Connection closed by server\n");
            RequestFinished = true;
        }
        else
        {
            luaL_error(L, "Error receiving data: %d", WSAGetLastError());
            RequestFinished = true;
        }
    }
    } catch (std::exception& e) {
        luaL_error(L, "Error receiving data: %s", e.what());
    }
    if (Body.size() < ContentLength) {
        luaL_error(L, "Content-Length mismatch! %d vs %d", Body.size(), ContentLength);
        return "";
    }
    if (Body.empty()) {
        //luaL_error(L, "No Body received");
        return "";
    }
    //printf("%s\n", Header.c_str());
    //printf("Body length: %d\n", Body.size());
    return Body;
}

struct HttpRequestOptions {
    int connect_timeout_ms = 30000;
    int send_timeout_ms = 60000;
    int receive_timeout_ms = 300000;
    int total_timeout_ms = 0;
    size_t max_response_bytes = 64ULL * 1024ULL * 1024ULL;
    size_t buffer_size = 16384;
    int request_index = 0;
    bool return_response = false;
};

struct HttpResponse {
    std::string body;
    std::string raw_headers;
    std::string version;
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;
    int status = 0;
    size_t bytes_received = 0;
    long long elapsed_ms = 0;
};

static long long RequestInteger(lua_State* L, int index, const char* name, long long fallback) {
    if (!index || !lua_istable(L, index)) return fallback;
    lua_getfield(L, index, name);
    const long long value = lua_isnumber(L, -1) ? static_cast<long long>(lua_tointeger(L, -1)) : fallback;
    lua_pop(L, 1);
    return value;
}

static bool RequestBoolean(lua_State* L, int index, const char* name, bool fallback) {
    if (!index || !lua_istable(L, index)) return fallback;
    lua_getfield(L, index, name);
    const bool value = lua_isboolean(L, -1) ? lua_toboolean(L, -1) != 0 : fallback;
    lua_pop(L, 1);
    return value;
}

static HttpRequestOptions ReadRequestOptions(lua_State* L, int index) {
    HttpRequestOptions options;
    if (!index || !lua_istable(L, index)) return options;
    options.request_index = lua_absindex(L, index);
    options.connect_timeout_ms = static_cast<int>(RequestInteger(L, index, "connect_timeout_ms", options.connect_timeout_ms));
    options.send_timeout_ms = static_cast<int>(RequestInteger(L, index, "send_timeout_ms", options.send_timeout_ms));
    options.receive_timeout_ms = static_cast<int>(RequestInteger(L, index, "receive_timeout_ms", options.receive_timeout_ms));
    options.receive_timeout_ms = static_cast<int>(RequestInteger(L, index, "read_timeout_ms", options.receive_timeout_ms));
    options.receive_timeout_ms = static_cast<int>(RequestInteger(L, index, "timeout_ms", options.receive_timeout_ms));
    options.total_timeout_ms = static_cast<int>(RequestInteger(L, index, "total_timeout_ms", options.total_timeout_ms));
    options.max_response_bytes = static_cast<size_t>(std::max<long long>(1,
        RequestInteger(L, index, "max_response_bytes", static_cast<long long>(options.max_response_bytes))));
    options.buffer_size = static_cast<size_t>(std::clamp<long long>(
        RequestInteger(L, index, "buffer_size", static_cast<long long>(options.buffer_size)), 1024, 1024 * 1024));
    options.return_response = RequestBoolean(L, index, "return_response", false);
    options.connect_timeout_ms = std::max(1000, options.connect_timeout_ms);
    options.send_timeout_ms = std::max(1000, options.send_timeout_ms);
    options.receive_timeout_ms = std::max(1000, options.receive_timeout_ms);
    options.total_timeout_ms = std::max(0, options.total_timeout_ms);
    return options;
}

static int TimeoutSeconds(int milliseconds) {
    return std::max(1, (milliseconds + 999) / 1000);
}

static std::string LowerAscii(std::string value) {
    for (char& character : value)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return value;
}

static std::string TrimAscii(std::string value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const auto finish = value.find_last_not_of(" \t\r\n");
    return value.substr(start, finish - start + 1);
}

static void ParseResponseHeaders(const std::string& block, HttpResponse& response) {
    response.raw_headers = block;
    const auto first_end = block.find("\r\n");
    const std::string status_line = block.substr(0, first_end);
    std::istringstream status(status_line);
    status >> response.version >> response.status;
    std::getline(status, response.reason);
    response.reason = TrimAscii(response.reason);
    if (response.version.rfind("HTTP/", 0) != 0 || response.status < 100 || response.status > 999)
        throw std::runtime_error("invalid HTTP response status line: " + status_line);

    size_t position = first_end == std::string::npos ? block.size() : first_end + 2;
    while (position < block.size()) {
        const auto finish = block.find("\r\n", position);
        const std::string line = block.substr(position,
            finish == std::string::npos ? std::string::npos : finish - position);
        position = finish == std::string::npos ? block.size() : finish + 2;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        response.headers.emplace_back(LowerAscii(TrimAscii(line.substr(0, colon))),
            TrimAscii(line.substr(colon + 1)));
    }
}

static std::string ResponseHeader(const HttpResponse& response, const std::string& name) {
    for (const auto& [key, value] : response.headers) if (key == name) return value;
    return "";
}

static void PushResponse(lua_State* L, const HttpResponse& response, bool include_body) {
    lua_newtable(L);
    if (include_body) {
        lua_pushlstring(L, response.body.data(), response.body.size());
        lua_setfield(L, -2, "body");
    }
    lua_pushinteger(L, response.status); lua_setfield(L, -2, "status");
    lua_pushboolean(L, response.status >= 200 && response.status < 300); lua_setfield(L, -2, "ok");
    lua_pushlstring(L, response.version.data(), response.version.size()); lua_setfield(L, -2, "version");
    lua_pushlstring(L, response.reason.data(), response.reason.size()); lua_setfield(L, -2, "reason");
    lua_pushlstring(L, response.raw_headers.data(), response.raw_headers.size()); lua_setfield(L, -2, "raw_headers");
    lua_pushinteger(L, static_cast<lua_Integer>(response.bytes_received)); lua_setfield(L, -2, "bytes_received");
    lua_pushinteger(L, static_cast<lua_Integer>(response.elapsed_ms)); lua_setfield(L, -2, "elapsed_ms");
    lua_newtable(L);
    for (const auto& [key, value] : response.headers) {
        lua_getfield(L, -1, key.c_str());
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            lua_pushlstring(L, value.data(), value.size());
            lua_setfield(L, -2, key.c_str());
        } else {
            const std::string prior = lua_tostring(L, -1);
            lua_pop(L, 1);
            const std::string joined = prior + ", " + value;
            lua_pushlstring(L, joined.data(), joined.size());
            lua_setfield(L, -2, key.c_str());
        }
    }
    lua_setfield(L, -2, "headers");
    lua_createtable(L, static_cast<int>(response.headers.size()), 0);
    int header_index = 1;
    for (const auto& [key, value] : response.headers) {
        lua_createtable(L, 2, 0);
        lua_pushlstring(L, key.data(), key.size()); lua_rawseti(L, -2, 1);
        lua_pushlstring(L, value.data(), value.size()); lua_rawseti(L, -2, 2);
        lua_rawseti(L, -2, header_index++);
    }
    lua_setfield(L, -2, "header_list");
}

static bool CallRequestCallback(lua_State* L, int request_index, const char* name, int arguments, int results) {
    if (!request_index) {
        if (arguments) lua_pop(L, arguments);
        return false;
    }
    lua_getfield(L, request_index, name);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        if (arguments) lua_pop(L, arguments);
        return false;
    }
    if (arguments) lua_insert(L, -1 - arguments);
    if (lua_pcall(L, arguments, results, 0) != 0) {
        const std::string error = lua_tostring(L, -1) ? lua_tostring(L, -1) : "unknown callback error";
        lua_pop(L, 1);
        throw std::runtime_error(std::string(name) + " callback failed: " + error);
    }
    return true;
}

static bool RequestCancelled(lua_State* L, int request_index) {
    if (!CallRequestCallback(L, request_index, "should_cancel", 0, 1)) return false;
    const bool cancelled = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    return cancelled;
}

static void EmitResponseHeaders(lua_State* L, int request_index, const HttpResponse& response) {
    if (!request_index) return;
    PushResponse(L, response, false);
    CallRequestCallback(L, request_index, "on_headers", 1, 0);
}

static void EmitResponseChunk(lua_State* L, int request_index, const std::string& chunk) {
    if (!request_index || chunk.empty()) return;
    lua_pushlstring(L, chunk.data(), chunk.size());
    if (!CallRequestCallback(L, request_index, "on_chunk", 1, 1)) return;
    const bool keep_going = !lua_isboolean(L, -1) || lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    if (!keep_going) throw std::runtime_error("request cancelled by on_chunk callback");
}

class HttpChunkDecoder {
public:
    explicit HttpChunkDecoder(size_t maximum) : maximum(maximum) {}

    std::vector<std::string> Feed(const std::string& data) {
        buffer += data;
        if (buffer.size() > maximum + 1024 * 1024)
            throw std::runtime_error("chunked response exceeded max_response_bytes while buffering");
        std::vector<std::string> chunks;
        while (!finished) {
            if (!remaining.has_value()) {
                const auto line_end = buffer.find("\r\n");
                if (line_end == std::string::npos) break;
                std::string size_text = TrimAscii(buffer.substr(0, line_end));
                buffer.erase(0, line_end + 2);
                const auto extension = size_text.find(';');
                if (extension != std::string::npos) size_text.resize(extension);
                size_text = TrimAscii(size_text);
                if (size_text.empty()) throw std::runtime_error("empty HTTP chunk size");
                size_t used = 0;
                const auto size = std::stoull(size_text, &used, 16);
                if (used != size_text.size()) throw std::runtime_error("invalid HTTP chunk size: " + size_text);
                if (size == 0) { finished = true; break; }
                if (size > maximum) throw std::runtime_error("HTTP chunk exceeds max_response_bytes");
                remaining = static_cast<size_t>(size);
            }
            if (buffer.size() < *remaining + 2) break;
            if (buffer.compare(*remaining, 2, "\r\n") != 0)
                throw std::runtime_error("HTTP chunk missing terminator");
            chunks.push_back(buffer.substr(0, *remaining));
            buffer.erase(0, *remaining + 2);
            remaining.reset();
        }
        return chunks;
    }

    bool Complete() const { return finished; }

private:
    std::string buffer;
    std::optional<size_t> remaining;
    bool finished = false;
    size_t maximum;
};

static std::string SocketErrorMessage(const char* operation, DWORD code, int timeout_ms) {
    if (code == ERROR_TIMEOUT || code == WSAETIMEDOUT)
        return std::string(operation) + " timed out after " + std::to_string(timeout_ms)
            + " ms (error " + std::to_string(code) + ")";
    char* message = nullptr;
    const DWORD length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0, reinterpret_cast<char*>(&message), 0, nullptr);
    const std::string detail = length && message ? TrimAscii(std::string(message, length))
                                                  : "unknown socket or TLS error";
    if (message) LocalFree(message);
    return std::string(operation) + " failed: " + detail + " (error " + std::to_string(code) + ")";
}

static HttpResponse ResolveHttpRequest(lua_State* L, const std::wstring& host, int port,
    const std::string& request, bool use_ssl, const HttpRequestOptions& options) {
    const auto started = std::chrono::steady_clock::now();
    const auto bounded_timeout = [&](int configured) {
        if (options.total_timeout_ms <= 0) return configured;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        const auto remaining = static_cast<long long>(options.total_timeout_ms) - elapsed;
        if (remaining <= 0)
            throw std::runtime_error("request total timeout exceeded after "
                + std::to_string(options.total_timeout_ms) + " ms");
        return static_cast<int>(std::min<long long>(configured, remaining));
    };
    CEventWrapper shutdown_event;
    auto socket = std::make_unique<CActiveSock>(shutdown_event);
    socket->SetRecvTimeoutSeconds(TimeoutSeconds(options.receive_timeout_ms));
    const int connect_timeout = bounded_timeout(options.connect_timeout_ms);
    socket->SetSendTimeoutSeconds(TimeoutSeconds(connect_timeout));
    if (!socket->Connect(host.c_str(), static_cast<USHORT>(port)))
        throw std::runtime_error(SocketErrorMessage("connect", socket->GetLastError(), connect_timeout));

    std::unique_ptr<CSSLClient> ssl;
    if (use_ssl) {
        ssl = std::make_unique<CSSLClient>(socket.get());
        ssl->ServerCertAcceptable = CertAcceptable;
        ssl->SelectClientCertificate = SelectClientCertificate;
        const HRESULT result = ssl->Initialize(host.c_str());
        if (FAILED(result))
            throw std::runtime_error("TLS handshake failed (error "
                + std::to_string(static_cast<unsigned long>(result)) + ")");
    }

    const int send_timeout = bounded_timeout(options.send_timeout_ms);
    socket->SetSendTimeoutSeconds(TimeoutSeconds(send_timeout));
    const int sent = ssl ? ssl->Send(request.data(), request.size()) : socket->Send(request.data(), request.size());
    if (sent == SOCKET_ERROR || static_cast<size_t>(sent) != request.size()) {
        const DWORD code = ssl ? ssl->GetLastError() : socket->GetLastError();
        throw std::runtime_error(SocketErrorMessage("send", code, send_timeout));
    }

    HttpResponse response;
    HttpChunkDecoder decoder(options.max_response_bytes);
    std::string pending_headers;
    bool got_headers = false;
    bool chunked = false;
    bool finished = false;
    std::optional<size_t> content_length;
    const bool head_request = request.rfind("HEAD ", 0) == 0;

    const auto append_body = [&](const std::string& chunk) {
        if (response.body.size() + chunk.size() > options.max_response_bytes)
            throw std::runtime_error("response exceeded max_response_bytes ("
                + std::to_string(options.max_response_bytes) + ")");
        response.body += chunk;
        EmitResponseChunk(L, options.request_index, chunk);
    };

    while (!finished) {
        if (RequestCancelled(L, options.request_index)) throw std::runtime_error("request cancelled");
        const int receive_timeout = bounded_timeout(options.receive_timeout_ms);
        socket->SetRecvTimeoutSeconds(TimeoutSeconds(receive_timeout));

        std::string receive_buffer(options.buffer_size, '\0');
        const int received = ssl ? ssl->Recv(receive_buffer.data(), receive_buffer.size())
                                 : socket->Recv(receive_buffer.data(), receive_buffer.size());
        if (received == SOCKET_ERROR) {
            const DWORD code = ssl ? ssl->GetLastError() : socket->GetLastError();
            if (ssl && code == SEC_I_CONTEXT_EXPIRED) { finished = true; break; }
            throw std::runtime_error(SocketErrorMessage("receive", code, receive_timeout));
        }
        if (received == 0) { finished = true; break; }
        response.bytes_received += static_cast<size_t>(received);
        std::string incoming(receive_buffer.data(), static_cast<size_t>(received));

        if (!got_headers) {
            pending_headers += incoming;
            if (pending_headers.size() > 1024 * 1024)
                throw std::runtime_error("HTTP response headers exceeded 1 MiB");
            const auto separator = pending_headers.find("\r\n\r\n");
            if (separator == std::string::npos) continue;
            incoming = pending_headers.substr(separator + 4);
            ParseResponseHeaders(pending_headers.substr(0, separator), response);
            pending_headers.clear();
            got_headers = true;
            EmitResponseHeaders(L, options.request_index, response);
            chunked = LowerAscii(ResponseHeader(response, "transfer-encoding")).find("chunked") != std::string::npos;
            const std::string length = ResponseHeader(response, "content-length");
            if (!length.empty()) content_length = static_cast<size_t>(std::stoull(length));
            if (content_length.has_value() && *content_length > options.max_response_bytes)
                throw std::runtime_error("Content-Length exceeds max_response_bytes");
            if (head_request || response.status == 204 || response.status == 304) finished = true;
        }

        if (finished) continue;
        if (chunked) {
            for (const auto& chunk : decoder.Feed(incoming)) append_body(chunk);
            finished = decoder.Complete();
        } else if (content_length.has_value()) {
            const size_t needed = *content_length > response.body.size()
                ? *content_length - response.body.size() : 0;
            append_body(incoming.substr(0, needed));
            finished = response.body.size() >= *content_length;
        } else {
            append_body(incoming);
        }
    }

    if (!got_headers) throw std::runtime_error("connection closed before HTTP response headers were received");
    if (chunked && !decoder.Complete())
        throw std::runtime_error("connection closed before the chunked response completed");
    if (content_length.has_value() && !head_request && response.status != 204 && response.status != 304
        && response.body.size() != *content_length)
        throw std::runtime_error("Content-Length mismatch: " + std::to_string(response.body.size())
            + " vs " + std::to_string(*content_length));
    response.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    return response;
}

static int WebRequestImpl(lua_State* L, bool force_response_table) {
    std::string HostA;
    std::wstring HostW;
    int Port = 443;
    bool force_ssl = false;
    int request_index = 0;
    if (lua_isstring(L, 1) && lua_gettop(L) > 1) {
        HostA = lua_tostring(L, 1);
        HostW = utf8_decode_lua(HostA);
        if (lua_isnumber(L, 2)) {
            Port = lua_tointeger(L, 2);
        } else if (lua_istable(L, 2)) {
            lua_getfield(L, 2, "port");
            if (lua_isnumber(L, -1)) {
                Port = lua_tointeger(L, -1);
            }
            lua_pop(L, 1);
        }
        if (lua_gettop(L) >= 3 && lua_istable(L, 3)) request_index = 3;
    } else if (lua_istable(L, 1)) {
        request_index = 1;
        if (luaL_getfield(L, 1, "host") == LUA_TSTRING) {
            HostA = lua_tostring(L, -1);
            HostW = utf8_decode_lua(HostA);
        } else {
            lua_pop(L, 1);
            luaL_error(L, "request.host is not a string");
            return 0;
        }
        lua_pop(L, 1);
        lua_getfield(L, 1, "port");
        if (lua_isnumber(L, -1)) {
            Port = lua_tointeger(L, -1);
        }
        lua_pop(L, 1);
        if (luaL_getfield(L, 1, "ssl") == LUA_TBOOLEAN) {
            force_ssl = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);
    } else {
        luaL_error(L, "missing 'host' parameter");
        return 0;
    }

    const int builder_index = request_index ? request_index : lua_gettop(L);
    const std::string RequestString = RequestBuilder(L, HostA + ":" + std::to_string(Port), builder_index);
    HttpRequestOptions options = ReadRequestOptions(L, request_index);
    if (force_response_table) options.return_response = true;
    try {
        const HttpResponse response = ResolveHttpRequest(L, HostW, Port, RequestString,
            force_ssl || Port == 443, options);
        if (options.return_response) PushResponse(L, response, true);
        else lua_pushlstring(L, response.body.data(), response.body.size());
        return 1;
    } catch (const std::exception& error) {
        return luaL_error(L, "%s", error.what());
    }
}

static int WebRequest(lua_State *L) {
    return WebRequestImpl(L, false);
}

static int WebRequestDetailed(lua_State *L) {
    return WebRequestImpl(L, true);
}

struct ParsedHttpUrl {
    std::string host;
    std::string path;
    int port;
    bool ssl;
};

static ParsedHttpUrl ParseHttpUrl(std::string url) {
    bool ssl = true;
    if (url.starts_with("http://")) { ssl = false; url.erase(0, 7); }
    else if (url.starts_with("https://")) { ssl = true; url.erase(0, 8); }
    else throw std::runtime_error("URL must use http:// or https://");
    const auto slash = url.find('/');
    std::string authority = slash == std::string::npos ? url : url.substr(0, slash);
    const std::string path = slash == std::string::npos ? "/" : url.substr(slash);
    int port = ssl ? 443 : 80;
    std::string host = authority;
    if (!authority.empty() && authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string::npos) throw std::runtime_error("invalid bracketed IPv6 URL");
        host = authority.substr(1, closing - 1);
        if (closing + 1 < authority.size()) {
            if (authority[closing + 1] != ':') throw std::runtime_error("invalid URL authority");
            port = std::stoi(authority.substr(closing + 2));
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            host = authority.substr(0, colon);
            port = std::stoi(authority.substr(colon + 1));
        }
    }
    if (host.empty() || port <= 0 || port > 65535) throw std::runtime_error("invalid URL host or port");
    return {host, path, port, ssl};
}

static std::string HttpHostHeader(const ParsedHttpUrl& target) {
    const bool ipv6 = target.host.find(':') != std::string::npos;
    const std::string host = ipv6 ? "[" + target.host + "]" : target.host;
    if ((target.ssl && target.port == 443) || (!target.ssl && target.port == 80)) return host;
    return host + ":" + std::to_string(target.port);
}

static int WebRequest_SimpleGET(lua_State *L) {
    try {
        const ParsedHttpUrl target = ParseHttpUrl(luaL_checkstring(L, 1));
        const int options_index = lua_istable(L, 2) ? 2 : 0;
        HttpRequestOptions options = ReadRequestOptions(L, options_index);
        const std::string request = "GET " + target.path
            + " HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\nHost: "
            + HttpHostHeader(target) + "\r\n\r\n";
        const HttpResponse response = ResolveHttpRequest(L, utf8_decode_lua(target.host), target.port,
            request, target.ssl, options);
        if (options.return_response) PushResponse(L, response, true);
        else lua_pushlstring(L, response.body.data(), response.body.size());
        return 1;
    } catch (const std::exception& error) {
        return luaL_error(L, "%s", error.what());
    }
}

static int WebRequest_SimpleDownload(lua_State *L) {
    try {
        const ParsedHttpUrl target = ParseHttpUrl(luaL_checkstring(L, 1));
        const std::filesystem::path local_path = luaL_checkstring(L, 2);
        const int options_index = lua_istable(L, 3) ? 3 : 0;
        HttpRequestOptions options = ReadRequestOptions(L, options_index);
        const std::string request = "GET " + target.path
            + " HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\nHost: "
            + HttpHostHeader(target) + "\r\n\r\n";
        const HttpResponse response = ResolveHttpRequest(L, utf8_decode_lua(target.host), target.port,
            request, target.ssl, options);
        std::error_code ec;
        if (!local_path.parent_path().empty() && !std::filesystem::exists(local_path.parent_path(), ec))
            std::filesystem::create_directories(local_path.parent_path(), ec);
        if (ec) throw std::runtime_error("failed to create download directory: " + ec.message());
        std::ofstream file(local_path, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
        if (!file.is_open()) throw std::runtime_error("failed to open download file for writing");
        file.write(response.body.data(), static_cast<std::streamsize>(response.body.size()));
        if (!file) throw std::runtime_error("failed while writing download file");
        file.close();
        if (options.return_response) { PushResponse(L, response, true); return 1; }
        return 0;
    } catch (const std::exception& error) {
        return luaL_error(L, "%s", error.what());
    }
}

int Listener_Create(lua_State *L) {
    int port = lua_tointeger(L, 1);
    new (lua::alloc<SocketServer>(L)) SocketServer(port, lua_toboolean(L, 2) ? NonBlockingSocket : BlockingSocket);
    return 1;
}

class ListenerContext {
private:
    std::unique_ptr<Socket> sock;
    std::string recv_buffer;
public:
    int onError = LUA_REFNIL;
    lua_State * onErrState = nullptr;
    ~ListenerContext() {
        if (onError != LUA_REFNIL)
            luaL_unref(onErrState, LUA_REGISTRYINDEX, onError);
    }

    void Accept(std::unique_ptr<Socket> s) {
        sock = std::move(s);
    }

    static int lua_Build(lua_State* L) {
        if (lua_isuserdata(L, 1)) lua_remove(L, 1);
        if (lua_istable(L, 1)) {
            std::string ReturnData = ResponseBuilder(L, 1);
            lua_pushlstring(L, ReturnData.c_str(), ReturnData.size());
            return 1;
        } else if (lua_isstring(L, 1)) {
            std::string ReturnData = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(lua_objlen(L, 1)) + "\r\n\r\n" + lua_tostring(L, 1);
            lua_pushlstring(L, ReturnData.c_str(), ReturnData.size());
            return 1;
        } else {
            lua_pushstring(L, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
            return 1;
        }
    }

    static int lua_Error(lua_State* L) {
        auto s = lua::check<ListenerContext>(L, 1);
        if (s->onError != LUA_REFNIL)
            luaL_unref(L, LUA_REGISTRYINDEX, s->onError);
        if (lua_isnoneornil(L, 2)) {
            s->onError = LUA_REFNIL;
            return 0;
        }
        s->onError = luaL_ref(L, LUA_REGISTRYINDEX);
        s->onErrState = L;
        return 0;
    }

    bool closed() {
        return sock->Closed();
    }
    static int lclosed(lua_State *L) {
        auto s = lua::check<ListenerContext>(L, 1);
        lua_pushboolean(L, s->sock->Closed());
        return 1;
    }
    void close() {
        sock->Close();
    }
    static int lclose(lua_State *L) {
        auto s = lua::check<ListenerContext>(L, 1);
        s->sock->Close();
        return 0;
    }
    //auto GetRemote() { return sock->GetRemote(); }
    static int GetRemote(lua_State *L) {
        auto s = lua::check<ListenerContext>(L, 1);
        new (lua::alloc<decltype(s->sock->GetRemote())>(L)) decltype(s->sock->GetRemote())(s->sock->GetRemote());
        return 1;
    }
    //auto GetLocal() { return sock->GetLocal(); }
    static int GetLocal(lua_State *L) {
        auto s = lua::check<ListenerContext>(L, 1);
        new (lua::alloc<decltype(s->sock->GetLocal())>(L)) decltype(s->sock->GetLocal())(s->sock->GetLocal());
        return 1;
    }
    //auto ReceiveBytes(unsigned long len) { return sock->ReceiveBytes(len); }
    static int ReceiveBytes(lua_State *L) {
        auto s = lua::check<ListenerContext>(L, 1);
        std::string recv;
        if (lua_isnumber(L, 2)) {
            recv = s->sock->ReceiveBytes(lua_tointeger(L, 2));
        } else {
            recv = s->sock->ReceiveBytes(0);
        }
        lua_pushlstring(L, recv.c_str(), recv.size());
        return 1;
    }
    auto SendBytes(std::string&& s) { return sock->SendBytes(std::move(s)); }

    static int lua_Send(lua_State *L) {
        auto sock = lua::check<ListenerContext>(L, 1);
        if (lua_isstring(L, 2)) {
            size_t len;
            lua_pushinteger(L, sock->SendBytes({ lua_tolstring(L, 2, &len), len }));
        } else if (lua_istable(L, 2)) {
            lua_pushinteger(L, sock->SendBytes(ResponseBuilder(L, 2)));
        } else {
            luaL_error(L, "Invalid argument");
        }
        return 1;
    }

    static int lua_Request(lua_State *L) {
        auto ctx = lua::check<ListenerContext>(L, 1);
        if (ctx->recv_buffer.empty())
            ctx->recv_buffer = ctx->ReceiveBytes(0);
        if (ctx->recv_buffer.empty())
            return 0;
        lua_newtable(L);
        lua_pushlstring(L, ctx->recv_buffer.c_str(), ctx->recv_buffer.size());
        lua_setfield(L, -2, "data");
        std::string method = ctx->recv_buffer.substr(0, ctx->recv_buffer.find(' '));
        lua_pushlstring(L, method.c_str(), method.size());
        lua_setfield(L, -2, "method");
        std::string path = ctx->recv_buffer.substr(ctx->recv_buffer.find(' ') + 1, ctx->recv_buffer.find(' ', ctx->recv_buffer.find(' ') + 1) - ctx->recv_buffer.find(' ') - 1);
        if (path.find('?') != std::string::npos) {
            auto query = path.substr(path.find('?') + 1);
            lua_pushlstring(L, query.c_str(), query.size());
            lua_setfield(L, -2, "query");
            path = path.substr(0, path.find('?'));
        }
        lua_pushlstring(L, path.c_str(), path.size());
        lua_setfield(L, -2, "path");
        std::string version = ctx->recv_buffer.substr(ctx->recv_buffer.find(' ', ctx->recv_buffer.find(' ') + 1) + 1, ctx->recv_buffer.find("\r\n") - ctx->recv_buffer.find(' ', ctx->recv_buffer.find(' ') + 1) - 1);
        lua_pushlstring(L, version.c_str(), version.size());
        lua_setfield(L, -2, "version");
        std::string headers = ctx->recv_buffer.substr(ctx->recv_buffer.find("\r\n") + 2, ctx->recv_buffer.find("\r\n\r\n") - ctx->recv_buffer.find("\r\n") - 2);
        lua_newtable(L);
        int i = 1;
        while (headers.find("\r\n") != std::string::npos) {
            std::string header = headers.substr(0, headers.find("\r\n"));
            lua_pushlstring(L, header.c_str(), header.size());
            lua_rawseti(L, -2, i);
            headers = headers.substr(headers.find("\r\n") + 2);
            i++;
        }
        lua_setfield(L, -2, "headers");
        std::string body = ctx->recv_buffer.substr(ctx->recv_buffer.find("\r\n\r\n") + 4);
        lua_pushlstring(L, body.c_str(), body.size());
        lua_setfield(L, -2, "body");
        return 1;
    }
};

class ConnectionContext {
private:
    CEventWrapper ShutDownEvent;
    std::unique_ptr<CActiveSock> pActiveSock;
    std::unique_ptr<CSSLClient> pSSLClient;
public:
    ConnectionContext(lua_State* L) {
        std::string HostA;
        std::wstring HostW;
        int Port = 443;
        bool block = true;
        if (lua_isstring(L, 1) && lua_gettop(L) > 1) {
            HostA = lua_tostring(L, 1);
            HostW = std::wstring(HostA.begin(), HostA.end());
            if (lua_isnumber(L, 2)) {
                Port = lua_tointeger(L, 2);
                block = lua_toboolean(L, 3);
            } else if (lua_istable(L, 2)) {
                lua_getfield(L, 2, "port");
                if (lua_isnumber(L, -1)) {
                    Port = lua_tointeger(L, -1);
                }
                lua_pop(L, 1);
                if (luaL_getfield(L, 2, "block") == LUA_TBOOLEAN) {
                    block = lua_toboolean(L, -1);
                }
                lua_pop(L, 1);
            } else if (lua_isboolean(L, 2)) {
                block = lua_toboolean(L, 2);
            }
        } else if (lua_istable(L, 1)) {
            if (luaL_getfield(L, 1, "host") == LUA_TSTRING) {
                HostA = lua_tostring(L, -1);
                HostW = utf8_decode_lua(HostA);
            } else {
                luaL_error(L, "request.host is not a string");
                return;
            }
            lua_pop(L, 1);
            lua_getfield(L, 1, "port");
            if (lua_isnumber(L, -1)) {
                Port = lua_tointeger(L, -1);
            }
            lua_pop(L, 1);
            if (luaL_getfield(L, 1, "block") == LUA_TBOOLEAN) {
                block = lua_toboolean(L, -1);
            }
            lua_pop(L, 1);
        } else {
            luaL_error(L, "missing 'host' parameter");
            return;
        }

        pActiveSock = std::make_unique<CActiveSock>(ShutDownEvent);

        if (!block) {
            u_long arg = 1;
            ioctlsocket(pActiveSock->ActualSocket, FIONBIO, &arg);

            int rc = 1;
            setsockopt(pActiveSock->ActualSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&rc, sizeof(int));
        }

        bool b = pActiveSock->Connect(HostW.c_str(), static_cast<USHORT>(Port));
        if (!b) {
            luaL_error(L, "Could not connect to the Server");
            return;
        }
        if (Port == 443)
        {
            pSSLClient = std::make_unique<CSSLClient>(pActiveSock.get());
            pSSLClient->ServerCertAcceptable = CertAcceptable;
            pSSLClient->SelectClientCertificate = SelectClientCertificate;
            HRESULT hr = pSSLClient->Initialize(HostW.c_str());
            if (!SUCCEEDED(hr))
                luaL_error(L, "Failed to initialize SSL");
        }
    }
    bool closed() {
        return pActiveSock->Closed();
    }
    static int lclosed(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        lua_pushboolean(L, s->pActiveSock->Closed());
        return 1;
    }
    void close() {
        pActiveSock->Disconnect();
    }
    static int lclose(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        s->pActiveSock->Disconnect();
        return 0;
    }
    static int GetRemote(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        new (lua::alloc<decltype(s->pActiveSock->GetRemote())>(L)) decltype(s->pActiveSock->GetRemote())(s->pActiveSock->GetRemote());
        return 1;
    }
    static int GetPort(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        sockaddr_storage sa = s->pActiveSock->GetLocal();
        if (sa.ss_family == AF_INET) {
            auto sa4 = (sockaddr_in*)&sa;
            lua_pushinteger(L, ntohs(sa4->sin_port));
        } else {
            auto sa6 = (sockaddr_in6*)&sa;
            lua_pushinteger(L, ntohs(sa6->sin6_port));
        }
        return 1;
    }
    static int ReceiveBytes(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        auto len = luaL_optinteger(L, 2, 0);
        std::string buffer;
        if (!len) {
            buffer.resize(1024);
            if (s->pSSLClient)
                s->pSSLClient->Recv(&buffer[0], 1024);
            else
                s->pActiveSock->Recv(&buffer[0], 1024);
        } else {
            buffer.resize(len);
            if (s->pSSLClient)
                s->pSSLClient->Recv(&buffer[0], len, len);
            else
                s->pActiveSock->Recv(&buffer[0], len, len);
        }
        lua_pushlstring(L, buffer.c_str(), buffer.size());
        return 1;
    }
    auto SendBytes(const std::string& s) {
        if (pSSLClient)
            return pSSLClient->Send(s.c_str(), s.size());
        else
            return pActiveSock->Send(s.c_str(), s.size());
    }

    static int lua_Send(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        if (lua_isstring(L, 2)) {
            s->SendBytes(lua_tostring(L, 2));
        } else if (lua_istable(L, 2)) {
            std::string r = ResponseBuilder(L, 2);
            s->SendBytes(r);
        } else {
            luaL_error(L, "Invalid argument");
        }
        return 0;
    }

    static int lua_Poll(lua_State *L) {
        auto ctx = lua::check<ConnectionContext>(L, 1);
        if (lua_gettop(L) > 1) {
            unsigned long want_recv = lua_tointeger(L, 2);
            unsigned long can_recv = 0;
            int ctl = ioctlsocket(ctx->pActiveSock->ActualSocket, FIONREAD, &can_recv);
            if (ctl == SOCKET_ERROR) {
                luaL_error(L, "Failed to poll socket: %d", WSAGetLastError());
                return 0;
            }
            if (can_recv >= want_recv) {
                lua_pushboolean(L, true);
                return 1;
            }
            if (can_recv > 0) {
                std::string buffer;
                buffer.reserve(want_recv);
                int rc = recv(ctx->pActiveSock->ActualSocket, buffer.data(), buffer.size(), MSG_PEEK);
                if (rc == SOCKET_ERROR) {
                    luaL_error(L, "Failed to poll socket: %d", WSAGetLastError());
                    return 0;
                }
                lua_pushboolean(L, true);
                return 1;
            }
            lua_pushboolean(L, false);
            return 1;
        } else {
            unsigned long max_recv = 0;
            int ctl = ioctlsocket(ctx->pActiveSock->ActualSocket, FIONREAD, &max_recv);
            if (ctl == SOCKET_ERROR) {
                luaL_error(L, "Failed to poll socket: %d", WSAGetLastError());
                return 0;
            }
            if (max_recv > 0) {
                int rc = recv(ctx->pActiveSock->ActualSocket, nullptr, 0, MSG_PEEK);
                if (rc == SOCKET_ERROR) {
                    luaL_error(L, "Failed to poll socket: %d", WSAGetLastError());
                    return 0;
                }
                lua_pushinteger(L, rc);
                return 1;
            }
            lua_pushinteger(L, max_recv);
            return 1;
        }
    }
};

int Connection_Create(lua_State *L) {
    new (lua::alloc<ConnectionContext>(L)) ConnectionContext(L);
    return 1;
}

int lua_networkclasses(lua_State* L);

void Listener_AsyncRun(std::unique_ptr<ListenerContext> sock, const std::string&& func) {
    auto L = lua::env::new_state();
    lua_networkclasses(L);
    if (luaL_loadbuffer(L, func.data(), func.size(), "=thread")) {
        luaL_error(L, "Failed to load thread: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
        return;
    }

    lua_insert(L, 1);
    lua::push(L, sock.get());
    if (lua::pcall(L, 1, LUA_MULTRET) != LUA_OK)
    {
        if (sock->onError != LUA_REFNIL) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, sock->onError);
            lua_pushvalue(L, -2);
            if (lua::pcall(L, 1, LUA_MULTRET)) {
                luaL_error(L, "Failed to execute error function: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        } else {
            luaL_error(L, "Failed to execute listener function: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
        }
    }
    if (lua_gettop(L) > 0) {
        // lua stack:
        // [1] = socketserver
        // [2] = result
        if (lua_istable(L, -1)) {
            sock->SendBytes(ResponseBuilder(L, -1));
        } else if (lua_isstring(L, -1)) {
            size_t len;
            sock->SendBytes({ lua_tolstring(L, -1, &len), len });
        } else {
            sock->SendBytes("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

int Listener_Accept(lua_State *L) {
    auto s = lua::check<SocketServer>(L, 1);
    if (lua_isnoneornil(L, 2) || !lua_isfunction(L, 2) && !lua_istable(L, 2) && !lua_isuserdata(L, 2)) {
        if (lua_rawgetp(L, LUA_REGISTRYINDEX, s) != LUA_TNIL) {
            size_t len;
            std::string buffer = { lua_tolstring(L, -1, &len), len };
            lua_pop(L, 1);
            auto sock = std::make_unique<ListenerContext>();
            sock->Accept(s->Accept());
            std::thread(Listener_AsyncRun, std::move(sock), std::move(buffer)).detach();
            return 0;
        }
        luaL_error(L, "No function provided");
        return 0;
    }
    // lua stack:
    // [1] = socketserver
    // [2] = func(sock)

    auto usock = s->Accept();
    if (!usock) {
        if (s->type_ == BlockingSocket)
            luaL_error(L, "Failed to accept connection");
        return 0;
    }

    // [3] = socket
    auto sock = new (lua::alloc<ListenerContext>(L)) ListenerContext();
    sock->Accept(std::move(usock));

    if (lua::pcall(L, 1, LUA_MULTRET)) {
        if (sock->onError != LUA_REFNIL) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, sock->onError);
            lua_pushvalue(L, -2);
            if (lua::pcall(L, 1, LUA_MULTRET)) {
                luaL_error(L, "Failed to execute error function: %s", lua_tostring(L, -1));
                return 0;
            }
        } else {
            luaL_error(L, "Failed to execute listener function: %s", lua_tostring(L, -1));
            return 0;
        }
    }

    if (lua_gettop(L) > 1) {
        // lua stack:
        // [1] = socketserver
        // [2] = result
        if (lua_istable(L, -1)) {
            sock->SendBytes(ResponseBuilder(L, -1));
        } else if (lua_isstring(L, -1)) {
            size_t len;
            sock->SendBytes({ lua_tolstring(L, -1, &len), len });
        } else {
            sock->SendBytes("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        }
        sock->close();
    }

    return 0;
}

int Listener_AcceptAsync(lua_State *L) {
    if (lua_isnoneornil(L, 2) || !lua_isfunction(L, 2) && !lua_istable(L, 2) && !lua_isuserdata(L, 2)) {
        luaL_error(L, "No function provided");
        return 0;
    }

    auto s = lua::check<SocketServer>(L, 1);

    luaL_checktype(L, -1, LUA_TFUNCTION);
    luaL_Buffer buf;
    luaL_buffinit(L, &buf);

    //printf("Dumping function %llX (%d, %llX)\n", s, lua_gettop(L), L);
    if (lua_dump(L, (lua_Writer)+[](lua_State* L, unsigned char* str, size_t len, struct luaL_Buffer* buf) {
            //printf("adding %d bytes to %llX (in %llX)... %d,%d,%d ... ", len, buf, buf->L, lua_gettop(buf->L), buf->lvl, buf->p - buf->buffer);
            luaL_addlstring(buf, (const char*)str, len);
            //printf("done\n");
            return 0;
        }, &buf) != LUA_OK) {
        //printf("Failed to dump function: %s\n", lua_tostring(L, -1));
        luaL_error(L, "Unable to transfer function: %s", lua_tostring(L, -1));
    }
    luaL_pushresult(&buf);

    lua_rawsetp(L, LUA_REGISTRYINDEX, s);

    return 0;
}

int lua_networkclasses(lua_State* L) {
    auto sasc = lua::bind::add<sockaddr_storage>(L, "sockaddr_storage");
    sasc.prop("ip", [](lua_State *L) -> int {
        auto s = lua::check<sockaddr_storage>(L, 1);
        char ip[INET6_ADDRSTRLEN];
        if (s->ss_family == AF_INET) {
            auto sa = (sockaddr_in*)s;
            inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
        } else {
            auto sa = (sockaddr_in6*)s;
            inet_ntop(AF_INET6, &sa->sin6_addr, ip, INET6_ADDRSTRLEN);
        }
        lua_pushstring(L, ip);
        return 1;
    });
    sasc.prop("port", [](lua_State *L) -> int {
        auto s = lua::check<sockaddr_storage>(L, 1);
        if (s->ss_family == AF_INET) {
            auto sa = (sockaddr_in*)s;
            lua_pushinteger(L, ntohs(sa->sin_port));
            return 1;
        } else {
            auto sa = (sockaddr_in6*)s;
            lua_pushinteger(L, ntohs(sa->sin6_port));
            return 1;
        }
    });

    auto lc = lua::bind::add<ListenerContext>(L, "ListenerContext");
    lc.prop("remote", &ListenerContext::GetRemote);
    lc.prop("listener", &ListenerContext::GetLocal);
    lc.prop("closed", &ListenerContext::lclosed);
    lc.fun("close", &ListenerContext::lclose);
    lc.fun("receive", &ListenerContext::ReceiveBytes);
    lc.fun("send", &ListenerContext::lua_Send);
    lc.prop("request", &ListenerContext::lua_Request);
    lc.fun("build", &ListenerContext::lua_Build);
    lc.fun("error", &ListenerContext::lua_Error);

    auto ssc = lua::bind::add<SocketServer>(L, "SocketServer");
    ssc.prop("port", [](lua_State *L) -> int {
        auto s = lua::check<SocketServer>(L, 1);
        lua_pushinteger(L, s->port_);
        return 1;
    });
    ssc.fun("accept", &Listener_Accept);
    ssc.fun("async", &Listener_AcceptAsync);

    auto cc = lua::bind::add<ConnectionContext>(L, "ConnectionContext");
    cc.prop("remote", &ConnectionContext::GetRemote);
    cc.prop("port", &ConnectionContext::GetPort);
    cc.prop("closed", &ConnectionContext::lclosed);
    cc.fun("close", &ConnectionContext::lclose);
    cc.fun("receive", &ConnectionContext::ReceiveBytes);
    cc.fun("send", &ConnectionContext::lua_Send);
    cc.fun("poll", &ConnectionContext::lua_Poll);

    return 0;
}

int lua_asyncclass(lua_State* L) {
    auto ac = lua::bind::add<IAsyncConnection*>(L, "CAsyncSocket");
    ac.meta_fun("__gc", [](lua_State *L) -> int {
        auto s = lua::check<IAsyncConnection*>(L, 1);
        if (*s) {
            delete *s;
            *s = nullptr;
        }
        return 0;
    });
    ac.fun("start", [](lua_State *L) {
        auto c = lua::check<IAsyncConnection*>(L, 1);
        if (!*c) return 0;
        auto s = *c;
        s->Start(luaL_checklstring(L, 2, nullptr));
        return 0;
    });
    ac.fun("poll", [](lua_State *L) {
        auto c = lua::check<IAsyncConnection*>(L, 1);
        if (!*c) return 0;
        auto s = *c;
        lua_pushboolean(L, s->Poll());
        return 1;
    });
    ac.fun("response", [](lua_State *L) {
        auto c = lua::check<IAsyncConnection*>(L, 1);
        if (!*c) return 0;
        auto s = *c;
        lua_pushlstring(L, s->Response().c_str(), s->Response().size());
        return 1;
    });
    return 0;
}

int Async_Create(lua_State *L) {
    auto host = luaL_checkstring(L, 1);
    auto port = luaL_checkinteger(L, 2);
    *lua::alloc<IAsyncConnection*>(L) = IAsyncConnection::Create(host, port);
    return 1;
}

int luaopen_network(lua_State* L) {
    lua::env::init(L);

    setvbuf(stdout, NULL, _IONBF, 0);

    lua_networkclasses(L);
    lua_asyncclass(L);

    lua_newtable(L);
    lua_pushstring(L, "network 0.2.0");
    lua_setfield(L, -2, "_VERSION");
    lua_newtable(L);
    lua_pushboolean(L, true); lua_setfield(L, -2, "structured_response");
    lua_pushboolean(L, true); lua_setfield(L, -2, "stream_callbacks");
    lua_pushboolean(L, true); lua_setfield(L, -2, "request_timeouts");
    lua_pushboolean(L, true); lua_setfield(L, -2, "large_tls_writes");
    lua_pushboolean(L, true); lua_setfield(L, -2, "response_limits");
    lua_setfield(L, -2, "capabilities");
    lua_pushcfunction(L, WebRequest);
    lua_setfield(L, -2, "send");
    lua_pushcfunction(L, WebRequestDetailed);
    lua_setfield(L, -2, "request");
    lua_pushcfunction(L, WebRequest_SimpleGET);
    lua_setfield(L, -2, "get");
    lua_pushcfunction(L, WebRequest_SimpleDownload);
    lua_setfield(L, -2, "download");
    lua_pushcfunction(L, Connection_Create);
    lua_setfield(L, -2, "connect");
    lua_pushcfunction(L, Listener_Create);
    lua_setfield(L, -2, "listen");
    lua_pushcfunction(L, Async_Create);
    lua_setfield(L, -2, "async");
    lua_pushcfunction(L, +[](lua_State* L) -> int {
        lua_pushinteger(L, WSAGetLastError());
        return 1;
    });
    lua_setfield(L, -2, "last_error");
    lua_pushcfunction(L, (+[](lua_State* L) -> int {
        auto host = luaL_checkstring(L, 1);
        auto retries = luaL_optinteger(L, 2, 1);
        auto [success, ping] = CPing::Ping(retries, host);
        if (success) {
            lua_pushinteger(L, ping);
            return 1;
        }
        return 0;
    }));
    lua_setfield(L, -2, "ping");
    return 1;
}
