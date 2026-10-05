#include "Socket.h"

#include <algorithm>
#include <climits>
#include <iostream>
#include <thread>
#include <chrono>
#include <WS2tcpip.h>


using namespace std;

int Socket::nofSockets_ = 0;

void Socket::Start() {
	if (!nofSockets_) {
		WSADATA info;
		if (WSAStartup(MAKEWORD(2, 0), &info)) {
			throw "Could not start WSA";
		}
	}
	++nofSockets_;
}

void Socket::End() {
	WSACleanup();
}

Socket::Socket() : s_(0) {
	Start();
	// UDP: use SOCK_DGRAM instead of SOCK_STREAM
	s_ = socket(AF_INET, SOCK_STREAM, 0);

	if (s_ == INVALID_SOCKET) {
		throw "INVALID_SOCKET";
	}

	refCounter_ = new int(1);
}

Socket::Socket(SOCKET s) : s_(s) {
	Start();
	refCounter_ = new int(1);
};

Socket::~Socket() {
	if (!--(*refCounter_)) {
		Close();
		delete refCounter_;
	}

	--nofSockets_;
	if (!nofSockets_) End();
}

Socket::Socket(const Socket& o) {
	refCounter_ = o.refCounter_;
	(*refCounter_)++;
	s_ = o.s_;

	nofSockets_++;
}

Socket& Socket::operator=(Socket& o) {
	(*o.refCounter_)++;

	refCounter_ = o.refCounter_;
	s_ = o.s_;

	nofSockets_++;

	return *this;
}

void Socket::Close() {
    if (!closed)
	    closesocket(s_);
    closed = true;
}

bool Socket::Closed() {
    if (closed) return true;
    int error_code;
    int error_code_size = sizeof(error_code);
    getsockopt(s_, SOL_SOCKET, SO_ERROR, (char*)&error_code, &error_code_size);
    if (error_code != 0) {
        return true;
    }
    return false;
}

// TB-396: wait until this socket has something to read - data, EOF or an error
// - or until timeoutMs passes. A negative timeout waits indefinitely. Unlike the
// sleep_for(1ms) this replaces, the wait happens in the kernel: it costs nothing
// while it waits and it returns the instant the socket becomes readable, so no
// caller pays a Windows timer tick (~15.6 ms) on top of its own latency.
bool Socket::WaitReadable(int timeoutMs) {
	if (closed || s_ == INVALID_SOCKET) return false;
	WSAPOLLFD descriptor{};
	descriptor.fd = s_;
	descriptor.events = POLLRDNORM;
	// POLLHUP and POLLERR are reported whatever the events mask asks for, so a
	// peer that closes or resets mid-request wakes this instead of sitting out
	// the timeout. revents is deliberately not read: the caller re-probes and
	// recognises EOF for itself.
	const auto started = std::chrono::steady_clock::now();
	for (;;) {
		int wait = timeoutMs;
		if (timeoutMs >= 0) {
			// Every attempt gets what is LEFT of the budget, so an interrupted
			// wait cannot stretch it. A 0 budget is the caller polling.
			const auto spent = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - started).count();
			const long long remaining = static_cast<long long>(timeoutMs) - spent;
			if (remaining <= 0) return false;
			wait = static_cast<int>(std::min<long long>(remaining, INT_MAX));
		}
		const int ready = WSAPoll(&descriptor, 1, wait);
		if (ready > 0) return true;
		if (ready == SOCKET_ERROR) {
			// WSAEINTR is this thread being interrupted, not the socket
			// failing: wait again with what is left of the budget rather than
			// report a dead connection that is still there.
			if (WSAGetLastError() == WSAEINTR) continue;
			// Deliberately NOT `closed = true`: Close() only closes a socket it
			// believes is still open, so claiming it closed here would skip the
			// closesocket and leak the handle. A socket that really died is
			// reported by the caller's next ioctlsocket.
			return false;
		}
		return false;   // timed out (0)
	}
}

std::string Socket::ReceiveBytes(unsigned long max_recv, unsigned long timeoutMs) {
	std::string ret;
    unsigned long can_recv = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    for (;;) {
        int ctl = ioctlsocket(s_, FIONREAD, &can_recv);
        if (ctl == SOCKET_ERROR) {
            return "";
        }
        if (!can_recv) {
            char probe;
            const int peek = recv(s_, &probe, 1, MSG_PEEK);
            if (peek == 0) { closed = true; return ""; }
            if (peek == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) return "";
        }
        // max_recv == 0 means "whatever has arrived", so one byte is enough;
        // otherwise the caller asked for a count that must be buffered before
        // anything is consumed. Either way, once this holds there is nothing to
        // wait for and nothing to sleep for.
        const bool satisfied = max_recv ? (can_recv >= max_recv) : (can_recv > 0);
        if (satisfied) break;
        if (timeoutMs && std::chrono::steady_clock::now() >= deadline) return "";
        if (can_recv > 0) {
            // Something IS readable, just not the count the caller asked for,
            // and no readiness primitive can wait for "more": the socket is
            // readable RIGHT NOW, so WSAPoll would return immediately and this
            // loop would spin a core at it. This is the one state that keeps
            // the paced re-check - the old sleep - because it cannot park.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        // Park in the kernel for the rest. The deadline above already rejected
        // an expired budget, so this is always time that is actually left; a 0
        // timeout still means "wait indefinitely", now parked instead of
        // spinning.
        int remaining = -1;
        if (timeoutMs) {
            // Rounded UP: truncating would turn the last fraction of a
            // millisecond into a 0 (poll) budget and spin the tail out.
            const auto left = std::chrono::ceil<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            remaining = left > 0 ? static_cast<int>(std::min<long long>(left, INT_MAX)) : 0;
        }
        WaitReadable(remaining);
    }
    if (can_recv && !max_recv)
        max_recv = can_recv;

    while (max_recv > 0) {
        ret.resize(ret.size() + max_recv);
        int len = recv(s_, ret.data() + ret.size() - max_recv, max_recv, 0);
        if (len == 0) {
            return ret;
        }
        if (len == -1) {
            return "";
        }
        //printf("Requested %d, received %d\n", max_recv, len);
        max_recv -= len;
    }

	return ret;
}

std::string Socket::ReceiveLine() {
	std::string ret;
	while (1) {
		char r;

		switch (recv(s_, &r, 1, 0)) {
		case 0: // not connected anymore;
				// ... but last line sent
				// might not end in \n,
				// so return ret anyway.
			return ret;
		case -1:
			return "";
			//      if (errno == EAGAIN) {
			//        return ret;
			//      } else {
			//      // not connected anymore
			//      return "";
			//      }
		}

		ret += r;
		if (r == '\n')  return ret;
	}
}

int Socket::SendBytes(std::string&& s) {
	int r = send(s_, s.c_str(), s.length(), 0);
    if (r == SOCKET_ERROR) {
        auto err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return 0;
        } else if (err == WSAECONNRESET) {
            closed = true;
            return -1;
        }
    }
    return r;
}

sockaddr_storage Socket::GetLocal() {
    sockaddr_storage sa;
    int len = sizeof(sa);
    getsockname(s_, (sockaddr*)&sa, &len);
    return sa;
}

sockaddr_storage Socket::GetRemote() {
    sockaddr_storage sa;
    int len = sizeof(sa);
    getpeername(s_, (sockaddr*)&sa, &len);
    return sa;
}

SocketServer::SocketServer(int port, TypeSocket type, const std::string& bindAddress) {
	sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));

	sa.sin_family = PF_INET;
	sa.sin_port = htons(port);
	s_ = socket(AF_INET, SOCK_STREAM, 0);
	if (s_ == INVALID_SOCKET) {
		throw "INVALID_SOCKET";
	}

    type_ = type;
	if (type == NonBlockingSocket) {
		u_long arg = 1;
		ioctlsocket(s_, FIONBIO, &arg);
	}

	if (inet_pton(AF_INET, bindAddress.c_str(), &sa.sin_addr) != 1) {
		closesocket(s_);
		throw std::runtime_error("invalid IPv4 bind address: " + bindAddress);
	}

	/* bind the socket to the internet address */
	if (bind(s_, (sockaddr *)&sa, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		const int error = WSAGetLastError();
		closesocket(s_);
		throw std::runtime_error("bind failed (Winsock " + std::to_string(error) + ")");
	}

	if (listen(s_, SOMAXCONN) == SOCKET_ERROR) {
		const int error = WSAGetLastError();
		closesocket(s_);
		throw std::runtime_error("listen failed (Winsock " + std::to_string(error) + ")");
	}

    // find out which port was really used
    int sa_len = sizeof(sa);
    if (getsockname(s_, (sockaddr*)&sa, &sa_len) == -1) {
		const int error = WSAGetLastError();
		closesocket(s_);
		throw std::runtime_error("getsockname failed (Winsock " + std::to_string(error) + ")");
    }
    port_ = ntohs(sa.sin_port);
}

std::unique_ptr<Socket> SocketServer::Accept() {
	SOCKET new_sock = accept(s_, 0, 0);
	if (new_sock == INVALID_SOCKET) {
		int rc = WSAGetLastError();
		if (rc == WSAEWOULDBLOCK) {
			return nullptr; // non-blocking call, no request pending
		}
		else {
			throw "Invalid Socket";
		}
	}
	if (type_ == NonBlockingSocket) {
		u_long nonblocking = 1;
		ioctlsocket(new_sock, FIONBIO, &nonblocking);
	}

	return std::make_unique<Socket>(new_sock);
}

SocketClient::SocketClient(const std::string& host, int port) : Socket() {
	std::string error;

	hostent *he;
	if ((he = gethostbyname(host.c_str())) == 0) {
		error = strerror(errno);
		throw error;
	}

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = *((in_addr *)he->h_addr);
	memset(&(addr.sin_zero), 0, 8);

	if (::connect(s_, (sockaddr *)&addr, sizeof(sockaddr))) {
		error = strerror(WSAGetLastError());
		throw error;
	}
}

SocketSelect::SocketSelect(Socket const * const s1, Socket const * const s2, TypeSocket type) {
	FD_ZERO(&fds_);
	FD_SET(const_cast<Socket*>(s1)->s_, &fds_);
	if (s2) {
		FD_SET(const_cast<Socket*>(s2)->s_, &fds_);
	}

	TIMEVAL tval;
	tval.tv_sec = 0;
	tval.tv_usec = 1;

	TIMEVAL *ptval;
	if (type == NonBlockingSocket) {
		ptval = &tval;
	}
	else {
		ptval = 0;
	}

	if (select(0, &fds_, (fd_set*)0, (fd_set*)0, ptval) == SOCKET_ERROR)
		throw "Error in select";
}

bool SocketSelect::Readable(Socket const* const s) {
	if (FD_ISSET(s->s_, &fds_)) return true;
	return false;
}
