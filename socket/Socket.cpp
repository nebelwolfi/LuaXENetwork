#include "Socket.h"

#include <iostream>
#include <thread>
#include <chrono>


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

std::string Socket::ReceiveBytes(unsigned long max_recv) {
	std::string ret;

    while (!max_recv) {
        int ctl = ioctlsocket(s_, FIONREAD, &max_recv);
        if (ctl == SOCKET_ERROR) {
            return "";
        }
        //printf("ioctlsocket returned %d, max_recv = %d\n", ctl, max_recv);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

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

void Socket::SendLine(std::string s) {
	s += '\n';
	send(s_, s.c_str(), s.length(), 0);
}

void Socket::SendBytes(const std::string& s) {
	send(s_, s.c_str(), s.length(), 0);
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

SocketServer::SocketServer(int port, TypeSocket type) {
	sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));

	sa.sin_family = PF_INET;
	sa.sin_port = htons(port);
	s_ = socket(AF_INET, SOCK_STREAM, 0);
	if (s_ == INVALID_SOCKET) {
		throw "INVALID_SOCKET";
	}

	if (type == NonBlockingSocket) {
		u_long arg = 1;
		ioctlsocket(s_, FIONBIO, &arg);
	}

	sa.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

	/* bind the socket to the internet address */
	if (bind(s_, (sockaddr *)&sa, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		closesocket(s_);
		throw "INVALID_SOCKET";
	}

	listen(s_, SOMAXCONN);

    // find out which port was really used
    int sa_len = sizeof(sa);
    if (getsockname(s_, (sockaddr*)&sa, &sa_len) == -1) {
        throw "INVALID_SOCKET";
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