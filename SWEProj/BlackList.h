#pragma once
#include "Packet_Structs.h"
#include <vector>
#include "UserInfo.h";
class BlackList
{
public:
	std::vector<ip_address> IPv4addresses;
	std::vector<std::string> hostNames;
	BlackList(UserInfo);
	void generateAddresses(UserInfo);
};

