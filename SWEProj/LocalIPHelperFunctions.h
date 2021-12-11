#include <string>
#include <pcap.h>
#include "Packet_Structs.h"
#pragma once

//this was very confusing, implementation was originally pulled from https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut2.html, then refactored into a 
//way that gets at least the IPv4 into a workable format. ip6tos needs work. These functions are used to return addresses local to the interface that is being sniffed
//this is used to build out an instantiation of the UserInfo Class.


#define IPTOSBUFFERS    12


std::string ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	std::string s(address);

	return s;
}
ip_address iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	ip_address ipv4;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	ipv4.byte1 = p[0];
	ipv4.byte2 = p[1];
	ipv4.byte3 = p[2];
	ipv4.byte4 = p[3];
	return ipv4;
}