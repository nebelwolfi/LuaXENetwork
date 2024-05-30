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
    if (CurrentChunkSize == 0) { // no chunksize yet, check for one
        auto EndOfLine = Body.find_first_of("\r\n");
        if (EndOfLine == std::string::npos) { // failed to get a chunksize, that should not really be possible
            return false;
        }
        //Log(Log::green, "%s", Body.c_str());

        auto ChunkSize = Body.substr(0, EndOfLine);
        Body = Body.substr(EndOfLine + 2);
        CurrentChunkSize = std::stol(ChunkSize, nullptr, 16);
        if (CurrentChunkSize == 0) { // return since i got the last chunk
            //Log(Log::red, "got last chunk");
            CurrentChunkSize = -1;
            return false;
        }
        else {
            return true;
        }
    }

    if (Body.size() >= CurrentChunkSize + 2) { // body size is big enouth for chunkedbody
        ChunkedBody += Body.substr(0, CurrentChunkSize);
        //Log(Log::blue, "%s", ChunkedBody.c_str());

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
        }
        else {
            res = (BytesReceived = pActiveSock->Recv(&ReceiveMsgBuffer[0], BufferBytesReceiving));
        }
        if (0 < res) {
            std::string ReceiveMsg = ReceiveMsgBuffer.substr(0, BytesReceived);
            CompleteReceive += ReceiveMsg;
            if (!GotHeaders && CompleteReceive.find("\r\n\r\n") != std::string::npos) {
                Header = CompleteReceive.substr(0, CompleteReceive.find("\r\n\r\n"));
                Body = CompleteReceive.substr(CompleteReceive.find("\r\n\r\n") + 4);
                GotHeaders = true;

                if (Header.find("Transfer-Encoding: chunked") != std::string::npos) {
                    IsChunked = true;
                }
                AlreadyAddedNewMsg = true;
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
                                if (ContentLengthStart == std::string::npos) {
                                    luaL_error(L, "No Content-Length found in Header");
                                    return "";
                                }
                            }
                        }
                    }
                    int ContentLengthEnd = Header.find("\r\n", ContentLengthStart + 16);
                    ContentLength = std::stoi(Header.substr(ContentLengthStart + 16, ContentLengthEnd - ContentLengthStart - 16));
                    if (Body.size() >= ContentLength) {
                        RequestFinished = true;
                    }
                }
            }
            AlreadyAddedNewMsg = false;
            ReceiveMsg.clear();
        }
        else if (res == 0)
        {
            //luaL_error(L, "Connection closed by server");
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

static int WebRequest(lua_State *L) {
    std::string HostA;
    std::wstring HostW;
    int Port = 443;
    bool force_ssl = false;
    if (lua_isstring(L, 1) && lua_gettop(L) > 1) {
        HostA = lua_tostring(L, 1);
        HostW = std::wstring(HostA.begin(), HostA.end());
        if (lua_isnumber(L, 2)) {
            Port = lua_tointeger(L, 2);
        } else if (lua_istable(L, 2)) {
            lua_getfield(L, 2, "port");
            if (lua_isnumber(L, -1)) {
                Port = lua_tointeger(L, -1);
            }
            lua_pop(L, 1);
        }
    } else if (lua_istable(L, 1)) {
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

    std::string RequestString = RequestBuilder(L, HostA + ":" + std::to_string(Port));
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString, force_ssl);
    lua_pushlstring(L, Response.c_str(), Response.size());
    return 1;
}

static int WebRequest_SimpleGET(lua_State *L) {
    std::string url = luaL_checkstring(L, 1);
    std::string HostA;
    if (url.starts_with("http://")) {
        url = url.substr(7);
    } else if (url.starts_with("https://")) {
        url = url.substr(8);
    }
    if (url.find('/') != std::string::npos) {
        HostA = url.substr(0, url.find('/'));
    } else {
        HostA = url;
    }
    int Port = 443;
    if (HostA.find(':') != std::string::npos) {
        Port = std::stoi(HostA.substr(HostA.find(':') + 1));
        HostA = HostA.substr(0, HostA.find(':'));
    }
    std::string path;
    if (url.find('/') != std::string::npos) {
        path = url.substr(url.find('/'));
    } else {
        path = "/";
    }
    std::wstring HostW = utf8_decode_lua(HostA);
    std::string RequestString = "GET " + path + " HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: none\r\nAccept-Language: en-US;q=0.8,en;q=0.7\r\nCache-Control: no-cache\r\nHost: " + HostA + "\r\n\r\n";
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString, false);
    lua_pushlstring(L, Response.c_str(), Response.size());
    return 1;
}

static int WebRequest_SimpleDownload(lua_State *L) {
    std::string url = luaL_checkstring(L, 1);
    std::string HostA;
    if (url.starts_with("http://")) {
        url = url.substr(7);
    } else if (url.starts_with("https://")) {
        url = url.substr(8);
    }
    if (url.find('/') != std::string::npos) {
        HostA = url.substr(0, url.find('/'));
    } else {
        HostA = url;
    }
    int Port = 443;
    if (HostA.find(':') != std::string::npos) {
        Port = std::stoi(HostA.substr(HostA.find(':') + 1));
        HostA = HostA.substr(0, HostA.find(':'));
    }
    std::wstring HostW = utf8_decode_lua(HostA);
    std::filesystem::path LocalPath = luaL_checkstring(L, 2);
    std::string RequestString = "GET " + url.substr(url.find('/')) + " HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US;q=0.8,en;q=0.7\r\nCache-Control: no-cache\r\nHost: " + HostA + "\r\n\r\n";
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString, false);
    std::error_code ec;
    if (!std::filesystem::exists(LocalPath.parent_path(), ec))
        std::filesystem::create_directories(LocalPath.parent_path(), ec);
    std::ofstream file(LocalPath, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
    if (!file.is_open()) {
        luaL_error(L, "Failed to open file for writing");
        return 0;
    }
    file << Response;
    file.close();
    return 0;
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
    //auto GetRemote() { return pActiveSock->GetRemote(); }
    static int GetRemote(lua_State *L) {
        auto s = lua::check<ConnectionContext>(L, 1);
        new (lua::alloc<decltype(s->pActiveSock->GetRemote())>(L)) decltype(s->pActiveSock->GetRemote())(s->pActiveSock->GetRemote());
        return 1;
    }
    //auto GetPort() {
    //    sockaddr_storage s = pActiveSock->GetLocal();
    //    if (s.ss_family == AF_INET) {
    //        auto sa = (sockaddr_in*)&s;
    //        return ntohs(sa->sin_port);
    //    } else {
    //        auto sa = (sockaddr_in6*)&s;
    //        return ntohs(sa->sin6_port);
    //    }
    //}
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
    /*auto ReceiveBytes(unsigned long len) {
        std::string buffer;
        if (!len) {
            buffer.resize(1024);
            if (pSSLClient)
                pSSLClient->Recv(&buffer[0], 1024);
            else
                pActiveSock->Recv(&buffer[0], 1024);
        } else {
            buffer.resize(len);
            if (pSSLClient)
                pSSLClient->Recv(&buffer[0], len, len);
            else
                pActiveSock->Recv(&buffer[0], len, len);
        }
        return buffer;
    }*/
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

int luaopen_network(lua_State* L) {
    lua::env::init(L);

    setvbuf(stdout, NULL, _IONBF, 0);

    lua_networkclasses(L);

    lua_newtable(L);
    lua_pushcfunction(L, WebRequest);
    lua_setfield(L, -2, "send");
    lua_pushcfunction(L, WebRequest_SimpleGET);
    lua_setfield(L, -2, "get");
    lua_pushcfunction(L, WebRequest_SimpleDownload);
    lua_setfield(L, -2, "download");
    lua_pushcfunction(L, Connection_Create);
    lua_setfield(L, -2, "connect");
    lua_pushcfunction(L, Listener_Create);
    lua_setfield(L, -2, "listen");
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