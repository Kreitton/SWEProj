#pragma once
#include <pcap.h>

typedef struct ip_address {//size 4
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
typedef struct ip6_address {//size 16
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
}ip6_address;

typedef struct ip_header { //20 bytes in size
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
			// Option + Padding
}ip_header;
typedef struct ip6_header {// size 40
	u_int ver_traf_flow;
	u_short payload_len;
	u_char next_header;
	u_char hop_limit;
	ip6_address saddr;
	ip6_address daddr;
}ip6_header;
typedef struct Dummy_struct {
	ip_address  one;
	ip_address  two;
	ip_address  three;
	ip_address  four;
	ip_address  five;
	ip_address  six;
	ip_address  seven;
	ip_address  eight;
	ip_address  nine;
	ip_address  ten;
	ip_address  eleven;
}Dummy_struct;

typedef struct udp_header { // 
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;
typedef struct Ethernet_header { // size 14 , sizeof() returns 16 for reasons I don't quite understand.
	u_int first4;
	u_int second4;
	u_int third4;
	u_short last2;
}Ethernet_header;
typedef struct TCPheader { //size 12
	u_char sport;
	u_char sport2;
	u_char dport;
	u_char dport2;
	u_int seq_num;
	u_int ack_num;
}TCPheader;