#include "IP6Packet.h"
IP6Packet::IP6Packet(const u_char* packetData)
{
	ip6Header = (ip6_header*)(packetData + 14);
	TCPHeader = (TCPheader*)(packetData + sizeof(Ethernet_header) + sizeof(ip_header) - 2);
	ethernetHeader = (Ethernet_header*)(packetData);
	type = 6;
}

std::string IP6Packet::toString()
{
	return std::string();
}

std::string IP6Packet::HexDump()
{
	return std::string();
}


