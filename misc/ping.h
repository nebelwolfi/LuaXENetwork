//
// Ping.h
//

#pragma pack(1)

#define ICMP_ECHOREPLY	0
#define ICMP_ECHOREQ	8

class CPing
{
public:
    static std::pair<bool, uint32_t> Ping(UINT nRetries,LPCSTR pstrHost);
    static int  WaitForEchoReply(SOCKET s);
    // ICMP Echo Request/Reply functions
    static int		SendEchoRequest(SOCKET, LPSOCKADDR_IN);
    static DWORD	RecvEchoReply(SOCKET, LPSOCKADDR_IN, u_char *);
    static u_short in_cksum(u_short *addr, int len);

protected:
    static void WSAError(LPCSTR pstrFrom);

};



// IP Header -- RFC 791
typedef struct tagIPHDR
{
    u_char  VIHL;			// Version and IHL
    u_char	TOS;			// Type Of Service
    short	TotLen;			// Total Length
    short	ID;				// Identification
    short	FlagOff;		// Flags and Fragment Offset
    u_char	TTL;			// Time To Live
    u_char	Protocol;		// Protocol
    u_short	Checksum;		// Checksum
    struct	in_addr iaSrc;	// Internet Address - Source
    struct	in_addr iaDst;	// Internet Address - Destination
}IPHDR, *PIPHDR;


// ICMP Header - RFC 792
typedef struct tagICMPHDR
{
    u_char	Type;			// Type
    u_char	Code;			// Code
    u_short	Checksum;		// Checksum
    u_short	ID;				// Identification
    u_short	Seq;			// Sequence
    char	Data;			// Data
}ICMPHDR, *PICMPHDR;


#define REQ_DATASIZE 32		// Echo Request Data size

// ICMP Echo Request
typedef struct tagECHOREQUEST
{
    ICMPHDR icmpHdr;
    DWORD	dwTime;
    char	cData[REQ_DATASIZE];
}ECHOREQUEST, *PECHOREQUEST;


// ICMP Echo Reply
typedef struct tagECHOREPLY
{
    IPHDR	ipHdr;
    ECHOREQUEST	echoRequest;
    char    cFiller[256];
}ECHOREPLY, *PECHOREPLY;


#pragma pack()

