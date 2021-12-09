#pragma once
#include <string>
#include "Packet_Structs.h"
#include <vector>
#include <pcap.h>
#include <string>
class UserInfo
{
private:
	std::string myUserName;
	std::string myComputerName;
	ip_address localIPAddress;
	ip_address subnetAddress;
	ip_address broadcastAddress;
public:
	std::vector<std::string> localIP6Addresses;
	UserInfo();
	UserInfo(pcap_if_t*);
	void setUserName();
	void setComputerName();
	std::string getUserName();
	std::string getComputerName();
	pcap_addr_t* usedInterfaceAddresses;
	void setIP4Address();
	void setIP6Address();
	pcap_if_t* usedInterface;
	ip_address getLocalIPAddress();
	ip_address getSubnetAddress();
	ip_address getBroadcastIPAddress();
	std::string toString();
};

