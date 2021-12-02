#include "Packet.h"

Packet::Packet(const u_char* packetData)
{
	ip4Header = (ip_header*)(packetData + 14);
	TCPHeader = (TCPheader*)(packetData + sizeof(Ethernet_header) + sizeof(ip_header) - 2);
	ethernetHeader = (Ethernet_header*)(packetData);
	type = 4;
}

std::string Packet::toString()
{
	return std::string();
}

std::string Packet::HexDump()
{
	return std::string();
}
