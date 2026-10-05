#ifndef SOCKET_H
#define SOCKET_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")

#include <WinSock2.h>

#include <string>
#include <memory>

enum TypeSocket { BlockingSocket, NonBlockingSocket };

class Socket {
public:

	virtual ~Socket();
	Socket(const Socket&);
	Socket& operator=(Socket&);

	std::string ReceiveLine();
	std::string ReceiveBytes(unsigned long, unsigned long timeoutMs = 0);

	// TB-396: park in the kernel until this socket is readable (data, EOF or an
	// error) or the timeout passes. A negative timeout waits indefinitely, 0
	// polls. This is the wait the listener side uses - the accepted-socket
	// reads and the accept wait both go through it - so neither pays a Windows
	// timer tick to notice that something arrived. (SocketSelect below is the
	// module's older select-based twin and is not on that path.)
	bool WaitReadable(int timeoutMs);

	void   Close();

	int   SendBytes(std::string&&);

    sockaddr_storage GetLocal();
    sockaddr_storage GetRemote();

    bool closed = false;

protected:
	friend class SocketServer;
	friend class SocketSelect;

public:
	Socket(SOCKET s);
    bool Closed();

protected:
    Socket();

	SOCKET s_;

	int* refCounter_;

private:
	static void Start();
	static void End();
	static int  nofSockets_;
};

class SocketClient : public Socket {
public:
	SocketClient(const std::string& host, int port);
};

class SocketServer : public Socket {
public:
	SocketServer(int port, TypeSocket type = BlockingSocket,
		const std::string& bindAddress = "127.0.0.1");

    std::unique_ptr<Socket> Accept();

    int port_;
    TypeSocket type_;
};

class SocketSelect {
	// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/wsapiref_2tiq.asp
public:
	SocketSelect(Socket const * const s1, Socket const * const s2 = NULL, TypeSocket type = BlockingSocket);

	bool Readable(Socket const * const s);

private:
	fd_set fds_;
};



#endif
