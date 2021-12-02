#pragma once
#include <pcap.h>
#include "Packet_Structs.h"
#include <string>

class Packet
{
public:
	Packet(const u_char* packetData);
	ip_header* ip4Header;
	Ethernet_header* ethernetHeader;
	TCPheader* TCPHeader;
	int type;
	std::string toString();
	std::string HexDump();
};

