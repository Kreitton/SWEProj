#pragma once
#include "Packet_Structs.h"
#include <vector>
#include "UserInfo.h";
class BlackList
{
public:
	std::vector<ip_address> IPv4addresses;
	BlackList(UserInfo);
	void generateAddresses(UserInfo);
};

