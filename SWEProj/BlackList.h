#pragma once
#include "Packet_Structs.h"
#include <vector>
#include "UserInfo.h";
class BlackList
{
public:
	std::vector<ip_address> IPv4addresses;
	std::vector<std::string> hostNames;
	std::vector<ip6_address> IPv6addresses;
	BlackList(UserInfo);
	BlackList();
	void generateAddresses(UserInfo);
};

