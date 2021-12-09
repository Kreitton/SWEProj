#include "UserInfo.h"
#include "LocalIPHelperFunctions.h"
#define NAME_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)
TCHAR ComputerName[NAME_BUFFER_SIZE];
DWORD sizeName = NAME_BUFFER_SIZE;
UserInfo::UserInfo()
{
}
UserInfo::UserInfo(pcap_if_t* usedInterface)
{
	this->usedInterface = usedInterface;
	this->usedInterfaceAddresses = usedInterface->addresses;
	setUserName();
	setComputerName();
	setIP4Address();
}

void UserInfo::setUserName()
{
	if (GetComputerName(ComputerName, &sizeName))
	{
		std::wstring test(&ComputerName[0]);
		std::string ComputerName(test.begin(), test.end());
		this->userName = ComputerName;
	}
	this->userName = " ";
}

void UserInfo::setComputerName()
{
	if (GetUserName(ComputerName, &sizeName))
	{
		std::wstring test(&ComputerName[0]);
		std::string UserName(test.begin(), test.end());
		this->userName = UserName;
	}
	this->userName =  " ";
}

std::string UserInfo::getUserName()
{
	return this->userName;
}

std::string UserInfo::getComputerName()
{
	return this->computerName;
}

void UserInfo::setIP4Address()
{
	char ip6str[128];
	for (usedInterfaceAddresses; usedInterfaceAddresses; usedInterfaceAddresses = usedInterfaceAddresses->next) {
		//printf("\tAddress Family: #%d\n", usedInterface->addr->sa_family);

		switch (usedInterfaceAddresses->addr->sa_family)
		{
		case AF_INET:
			//printf("\tAddress Family Name: AF_INET\n");
			if (usedInterfaceAddresses->addr)
				this->localIPAddress = iptos(((struct sockaddr_in*)usedInterfaceAddresses->addr)->sin_addr.s_addr);// printf("\tAddress: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr)));
			if (usedInterfaceAddresses->netmask)
				this->subnetAddress = iptos(((struct sockaddr_in*)usedInterfaceAddresses->netmask)->sin_addr.s_addr);//  printf("\tNetmask: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr)));
			if (usedInterfaceAddresses->broadaddr)
				this->broadcastAddress = iptos(((struct sockaddr_in*)usedInterfaceAddresses->broadaddr)->sin_addr.s_addr);  //printf("\tBroadcast Address: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr)));
			
			break;

		case AF_INET6:
			//printf("\tAddress Family Name: AF_INET6\n");
			if (usedInterfaceAddresses->addr)
				this->localIP6Addresses.push_back(ip6tos(usedInterfaceAddresses->addr, ip6str, sizeof(ip6str)));
			break;

		default:
			//printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
}

void UserInfo::setIP6Address()
{
}

ip_address UserInfo::getLocalIPAddress()
{
	return this->localIPAddress;
}

ip_address UserInfo::getSubnetAddress()
{
	return this->subnetAddress;
}

ip_address UserInfo::getBroadcastIPAddress()
{
	return this->broadcastAddress;
}

std::string UserInfo::toString()
{
	return std::string();
}
