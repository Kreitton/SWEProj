#pragma once
#include <string>
#include "Packet_Structs.h"
#include <vector>
#include <pcap.h>
class UserInfo
{
private:
	std::string userName;
	std::string computerName;
public:
	std::vector<ip6_address> localIP6Addresses;
	std::vector<ip_address> localIP4Addresses;
	UserInfo(pcap_addr_t*);
	void setUserName();
	void setComputerName();
	std::string getUserName();
	std::string getComputerName();
	pcap_addr_t* usedInterface;
	void setIP4Address();
	void setIP6Address();
};

