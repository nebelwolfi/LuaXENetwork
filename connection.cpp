#include <pch.h>
#include <WinSock2.h>

#include "socket/framework.h"
#include "socket/Utilities.h"
#include "socket/ActiveSock.h"
#include "socket/Socket.h"
#include "socket/SSLClient.h"
#include "socket/EventWrapper.h"
#include "socket/CertHelper.h"

#include "connection.h"

class AsyncConnection final : public IAsyncConnection {
    static size_t s_active_connections;
    static WSADATA* s_wsaData;

public:
    SOCKET Socket = INVALID_SOCKET;
    bool valid = false;

    std::string request, response;
    int connection_state = 0;

    const char* host_name;
    unsigned short port;

    WSABUF* recvbuffer = nullptr;
    WSABUF* sendbuffer = nullptr;
    OVERLAPPED* send_overlapped = nullptr;
    OVERLAPPED* recv_overlapped = nullptr;
    sockaddr_in* hint = nullptr;

    uint64_t start_time = 0;

    AsyncConnection(const char* host_name, unsigned short port) : host_name(host_name), port(port) {
        start_time = GetTickCount64();

        hint = static_cast<sockaddr_in *>(malloc(sizeof(sockaddr_in)));
        memset(hint, 0, sizeof(sockaddr_in));

        sendbuffer = static_cast<WSABUF *>(malloc(sizeof(WSABUF)));

        recvbuffer = static_cast<WSABUF *>(malloc(sizeof(WSABUF)));
        recvbuffer->len = 65536; // TCP_MAX_SIZE
        recvbuffer->buf = static_cast<CHAR *>(malloc(recvbuffer->len));
        memset(recvbuffer->buf, 0, recvbuffer->len);

        send_overlapped = static_cast<OVERLAPPED *>(malloc(sizeof(OVERLAPPED)));
        memset(send_overlapped, 0, sizeof(OVERLAPPED));
        recv_overlapped = static_cast<OVERLAPPED *>(malloc(sizeof(OVERLAPPED)));
        memset(recv_overlapped, 0, sizeof(OVERLAPPED));

        if (!s_active_connections) {
            if (!s_wsaData) {
                s_wsaData = static_cast<WSADATA *>(malloc(sizeof(WSADATA)));
                memset(s_wsaData, 0, sizeof(WSADATA));
            }
            WSAStartup(MAKEWORD(2u, 2u), s_wsaData);
        }

        s_active_connections++;

        connection_state = 0;

        Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Socket == INVALID_SOCKET) {
            return;
        }

        u_long iMode = 1;
        ioctlsocket(Socket, FIONBIO, &iMode);

        linger l{};
        l.l_onoff = 1;
        l.l_linger = 0;
        setsockopt(Socket, SOL_SOCKET, SO_LINGER, (char *) &l, sizeof(linger));
        setsockopt(Socket, SOL_SOCKET, 0x7010 /*SO_UPDATE_CONNECT_CONTEXT*/, nullptr, 0);
        int rc = 1;
        setsockopt(Socket, IPPROTO_TCP, TCP_NODELAY, (char *) &rc, sizeof(int));

        if (!hint->sin_port) {
            auto host = gethostbyname(host_name);
            if (!host) {
                return;
            }

            hint->sin_family = AF_INET;
            hint->sin_port = htons((unsigned short) port);
            hint->sin_addr.s_addr = *((unsigned long *) (host->h_addr));
        }
        valid = true;
    }

    ~AsyncConnection() final {
        valid = false;
        if (Socket != INVALID_SOCKET) {
            closesocket(Socket);
            Socket = INVALID_SOCKET;
        }
        if (!--s_active_connections) {
            WSACleanup();
            if (s_wsaData) {
                free(s_wsaData);
                s_wsaData = nullptr;
            }
        }
        if (recvbuffer && recvbuffer->buf) {
            free(recvbuffer->buf);
            recvbuffer->buf = nullptr;
        }
        if (recvbuffer) {
            free(recvbuffer);
            recvbuffer = nullptr;
        }
        if (sendbuffer) {
            free(sendbuffer);
            sendbuffer = nullptr;
        }
        if (send_overlapped) {
            free(send_overlapped);
            send_overlapped = nullptr;
        }
        if (recv_overlapped) {
            free(recv_overlapped);
            recv_overlapped = nullptr;
        }
        if (hint) {
            free(hint);
            hint = nullptr;
        }
    }

    std::string const& Response() final {
        return response;
    }

    void Reconnect() {
        connection_state = 0;
    }

    void Start(std::string r) final {
        if (!valid) return;

        this->request = std::move(r);

        auto err = connect(Socket, (sockaddr *)hint, sizeof(*hint));
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error == WSAEISCONN) {
                connection_state = 1;
            }
        }
    }

    bool Send() {
        if (request.empty()) {
            return false;
        }

        sendbuffer->buf = const_cast<char *>(request.c_str());
        sendbuffer->len = request.size();

        DWORD bytes_sent = 0;
        auto err = WSASend(Socket, sendbuffer, 1, &bytes_sent, 0, send_overlapped, nullptr);
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error != WSA_IO_PENDING) {
                return false;
            }
        }

        DWORD bytes_written = 0;
        err = WSAGetOverlappedResult(Socket, send_overlapped, &bytes_written, FALSE, nullptr);
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error != WSA_IO_INCOMPLETE) {
                return false;
            }
        }
        if (bytes_written == 0) {
            return false;
        }

        return true;
    }

    bool Recv() {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(Socket, &readfds);
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        auto err = select(0, &readfds, nullptr, nullptr, &timeout);
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error != WSAEWOULDBLOCK) {
                return false;
            }
        }
        if (!__WSAFDIsSet(Socket, &readfds)) {
            return false;
        }

        DWORD flags = 0;
        DWORD bytes_received = 0;
        err = WSARecv(Socket, recvbuffer, 1, &bytes_received, &flags, recv_overlapped, nullptr);
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error != WSA_IO_PENDING) {
                return false;
            }
        }

        DWORD bytes_read = 0;
        err = WSAGetOverlappedResult(Socket, recv_overlapped, &bytes_read, FALSE, &flags);
        if (err == SOCKET_ERROR) {
            auto last_error = WSAGetLastError();
            if (last_error != WSA_IO_INCOMPLETE) {
                return false;
            }
        }
        if (bytes_read == 0) {
            return true;
        }

        response.append(recvbuffer->buf, bytes_read);
        return false;
    }

    bool Poll() final {
        if (!valid) {
            return false;
        }
        if (connection_state == 0) {
            Start(request);
            return false;
        }
        if (connection_state == 1) {
            if (!Send()) {
                return false;
            }
            connection_state = 2;
        }
        if (connection_state == 2) {
            if (start_time + 30000 < GetTickCount64()) {
                Reconnect();
                return false;
            }
            if (!Recv()) {
                return false;
            }
            connection_state = 3;
        }
        return true;
    }
};

size_t AsyncConnection::s_active_connections = 0;
WSADATA* AsyncConnection::s_wsaData = nullptr;
IAsyncConnection* IAsyncConnection::Create(const char* host_name, unsigned short port) {
    return new AsyncConnection(host_name, port);
}