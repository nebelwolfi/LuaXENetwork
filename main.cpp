#include <pch.h>
#include <WinSock2.h>

#include "socket/framework.h"
#include "socket/Utilities.h"
#include "socket/ActiveSock.h"
#include "socket/SSLClient.h"
#include "socket/EventWrapper.h"
#include "socket/CertHelper.h"
#include <iomanip>
#include <fstream>
#include "misc/misc.h"

#include <codecvt>
#include "misc/md5.h"
#include "connection/Socket.h"
#include <thread>
#include <chrono>
#include <shellapi.h>
#include "misc/json.hpp"
#include <mutex>
#include <future>
#include <filesystem>

std::string RequestBuilder(lua_State *L, int idx = 1) {
    idx = lua_absindex(L, idx);
    std::string request;
    if (luaL_getfield(L, idx, "method") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        if (!request.empty()) request += " ";
    } else {
        request += "GET ";
    }
    if (luaL_getfield(L, idx, "path") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        if (!request.empty()) request += " ";
    } else {
        request += "/ ";
    }
    if (luaL_getfield(L, idx, "version") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "HTTP/1.1\r\n";
    }
    if (luaL_getfield(L, idx, "accept") == LUA_TSTRING) {
        request += "Accept: ";
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "Accept: */*\r\n";
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

std::string ResponseBuilder(lua_State *L, int idx = 1) {
    idx = lua_absindex(L, idx);
    std::string request;
    if (luaL_getfield(L, idx, "version") == LUA_TSTRING) {
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "HTTP/1.1 200 OK\r\n";
    }
    if (luaL_getfield(L, idx, "accept") == LUA_TSTRING) {
        request += "Accept: ";
        request += lua_tostring(L, -1);
        request += "\r\n";
    } else {
        request += "Accept: */*\r\n";
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
            //std::cout << "Failed to get Chunksize" << std::endl;
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

std::string ResolveWebRequest(lua_State* L, const std::string& HostA, const std::wstring& HostW, int Port, const std::string& RequestString) {
    CEventWrapper ShutDownEvent;
    auto pActiveSock = std::make_unique<CActiveSock>(ShutDownEvent);
    pActiveSock->SetRecvTimeoutSeconds(30);
    pActiveSock->SetSendTimeoutSeconds(60);

    bool b = pActiveSock->Connect(HostW.c_str(), static_cast<USHORT>(Port));
    if (!b) {
        luaL_error(L, "Could not connect to the Server");
        return "";
    }
    auto pSSLClient = std::make_unique<CSSLClient>(pActiveSock.get());
    pSSLClient->ServerCertAcceptable = CertAcceptable;
    pSSLClient->SelectClientCertificate = SelectClientCertificate;
    HRESULT hr = pSSLClient->Initialize(HostW.c_str());
    if (!SUCCEEDED(hr)) {
        luaL_error(L, "Failed to Init SSL %llX", hr);
        return "";
    }
    pSSLClient->Send(RequestString.c_str(), RequestString.size());

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

    while (!RequestFinished) {
        std::string ReceiveMsgBuffer;
        ReceiveMsgBuffer.resize(BufferBytesReceiving);
        ReceiveMsgBuffer.reserve(BufferBytesReceiving);
        int BytesReceived = 0;

        int res = (BytesReceived = pSSLClient->Recv(&ReceiveMsgBuffer[0], BufferBytesReceiving));
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
            luaL_error(L, "Connection closed by server");
            RequestFinished = true;
        }
        else
        {
            luaL_error(L, "Error receiving data");
            RequestFinished = true;
        }
    }
    if (Body.size() < ContentLength) {
        luaL_error(L, "Content-Length mismatch! %d vs %d", Body.size(), ContentLength);
        return "";
    }
    if (Body.empty()) {
        luaL_error(L, "No Body received");
        return "";
    }
    return Body;
}

static int WebRequest(lua_State *L) {
    std::string HostA;
    std::wstring HostW;
    int Port = 443;
    if (lua_isstring(L, 1)) {
        HostA = lua_tostring(L, 1);
        HostW = std::wstring(HostA.begin(), HostA.end());
        if (lua_isnumber(L, 2)) {
            Port = lua_tointeger(L, 2);
        } else if (lua_istable(L, 2)) {
            if (luaL_getfield(L, 2, "port") == LUA_TNUMBER) {
                Port = lua_tointeger(L, -1);
            }
        }
    } else if (lua_istable(L, 1)) {
        if (luaL_getfield(L, 1, "host") == LUA_TSTRING) {
            HostA = lua_tostring(L, -1);
            HostW = utf8_decode(HostA);
        } else {
            luaL_error(L, "Host is not a string");
            return 0;
        }
        if (luaL_getfield(L, 1, "port") == LUA_TNUMBER) {
            Port = lua_tointeger(L, -1);
        }
    } else {
        luaL_error(L, "Host is not a string");
        return 0;
    }

    std::string RequestString = RequestBuilder(L);
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString);
    lua_pushstring(L, Response.c_str());
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
    std::wstring HostW = utf8_decode(HostA);
    std::string RequestString = "GET " + path + " HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: none\r\nAccept-Language: en-US;q=0.8,en;q=0.7\r\nCache-Control: no-cache\r\nHost: " + HostA + "\r\n\r\n";
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString);
    lua_pushstring(L, Response.c_str());
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
    std::wstring HostW = utf8_decode(HostA);
    std::filesystem::path LocalPath = luaL_checkstring(L, 2);
    std::string RequestString = "GET " + url.substr(url.find('/')) + " HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US;q=0.8,en;q=0.7\r\nCache-Control: no-cache\r\nHost: " + HostA + "\r\n\r\n";
    std::string Response = ResolveWebRequest(L, HostA, HostW, Port, RequestString);
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
    LuaBinding::State S(L);
    S.alloc<SocketServer>(port, BlockingSocket);
    return 1;
}

int Listener_Accept(lua_State *L) {
    LuaBinding::State S(L);
    auto s = S.at(1).as<SocketServer*>();
    Socket* sock = s->Accept();

    std::string CurrentReceive = "";
    while (!s->stop) {
        std::string Receive = sock->ReceiveLine();
        if (Receive.empty()) break;
        if (Receive.size() > 0) {
            CurrentReceive += Receive;
            if (CurrentReceive.substr(CurrentReceive.size() - 4) == "\r\n\r\n") {
                lua_pushvalue(L, 2);
                lua_newtable(L);
                lua_pushstring(L, CurrentReceive.c_str());
                lua_setfield(L, -2, "request");
                lua_pushcfunction(L, +[](lua_State*L) -> int {
                    if (lua_istable(L, 1)) {
                        std::string ReturnData = ResponseBuilder(L, 1);
                        lua_pushstring(L, ReturnData.c_str());
                        return 1;
                    } else if (lua_isstring(L, 1)) {
                        std::string ReturnData = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(lua_objlen(L, 1)) + "\r\n\r\n" + lua_tostring(L, 1);
                        lua_pushstring(L, ReturnData.c_str());
                        return 1;
                    } else {
                        lua_pushstring(L, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
                        return 1;
                    }
                });
                lua_setfield(L, -2, "build");
                if (LuaBinding::pcall(L, 1, 1)) {
                    sock->SendBytes("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
                    delete sock;
                    luaL_error(L, "Failed to execute listener function: %s", lua_tostring(L, -1));
                    return 0;
                }
                if (lua_istable(L, -1)) {
                    std::string ReturnData = ResponseBuilder(L, -1);
                    sock->SendBytes(ReturnData);
                } else if (lua_isstring(L, -1)) {
                    sock->SendBytes(lua_tostring(L, -1));
                } else {
                    sock->SendBytes("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
                }
                lua_pop(L, 1);
                CurrentReceive.clear();
            }
        }
    }
    delete sock;
    return 0;
}

int Listener_Stop(lua_State *L) {
    LuaBinding::State S(L);
    auto s = S.at(1).as<SocketServer*>();
    s->stop = true;
    return 0;
}

int luaopen_network(lua_State* L) {
    LuaBinding::State S(L);
    auto ssc = S.addClass<SocketServer>("SocketServer");
    ssc.prop("port", &SocketServer::port_);
    ssc.cfun("accept", &Listener_Accept);
    ssc.cfun("stop", &Listener_Stop);

    lua_newtable(L);
    lua_pushcfunction(L, WebRequest);
    lua_setfield(L, -2, "request");
    lua_pushcfunction(L, WebRequest_SimpleGET);
    lua_setfield(L, -2, "get");
    lua_pushcfunction(L, WebRequest_SimpleDownload);
    lua_setfield(L, -2, "download");
    lua_pushcfunction(L, Listener_Create);
    lua_setfield(L, -2, "listener");
    return 1;
}