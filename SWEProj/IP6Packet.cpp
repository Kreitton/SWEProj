#include "IP6Packet.h"
IP6Packet::IP6Packet(const u_char* packetData)
{
	ip6Header = (ip6_header*)(packetData + 14);//points to IPv6 header
	TCPHeader = (TCPheader*)(packetData + sizeof(Ethernet_header) + sizeof(ip6_header) - 2);//points to TCP header
	ethernetHeader = (Ethernet_header*)(packetData);//points to Ethernet header
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


