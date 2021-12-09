#pragma once
#include <pcap.h>
#include "Packet_Structs.h"
#include <string>
//IP6 packet
class IP6Packet
{
	public:
		IP6Packet(const u_char* packetData);
		ip6_header* ip6Header;
		Ethernet_header* ethernetHeader;
		TCPheader* TCPHeader;
		int type;
		std::string toString();
		std::string HexDump();
};

