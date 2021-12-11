#include "Packet.h"

Packet::Packet(const u_char* packetData)
{
	ip4Header = (ip_header*)(packetData + 14); //point to where the IPv4 header starts
	TCPHeader = (TCPheader*)(packetData + sizeof(Ethernet_header) + sizeof(ip_header) - 2);//points to where the TCP header starts
	ethernetHeader = (Ethernet_header*)(packetData);//points to where the ethernet header starts.
	type = 4;
}

std::string Packet::toString()//to be implemented, might be useful for output to be able to dump all relative information in a packet
{
	return std::string();
}

std::string Packet::HexDump()//Wireshark does this, might be usefull.
{
	return std::string();
}
