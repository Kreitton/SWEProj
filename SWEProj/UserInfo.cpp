#include "UserInfo.h"
#include "LocalIPHelperFunctions.h"
#define NAME_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)
TCHAR ComputerName[NAME_BUFFER_SIZE];
DWORD sizeName = NAME_BUFFER_SIZE;
UserInfo::UserInfo(pcap_if_t* usedInterface)
{
	this->usedInterface = usedInterface;
	this->usedInterfaceAddresses = usedInterface->addresses;
	setUserName();
	setComputerName();
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
	for (usedInterfaceAddresses; usedInterfaceAddresses; usedInterfaceAddresses = usedInterfaceAddresses->next) {
		//printf("\tAddress Family: #%d\n", usedInterface->addr->sa_family);

		switch (usedInterfaceAddresses->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (usedInterfaceAddresses->addr)
				localIPAddress = iptos(((struct sockaddr_in*)usedInterfaceAddresses->addr)->sin_addr.s_addr);// printf("\tAddress: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr)));
			if (usedInterfaceAddresses->netmask)
				std::cout << "\tSubnet Address: " << IPaddressToString(iptos(((struct sockaddr_in*)usedInterfaceAddresses->netmask)->sin_addr.s_addr)) << "\n";//  printf("\tNetmask: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr)));
			if (usedInterfaceAddresses->broadaddr)
				std::cout << "\tBroadcast Address: " << IPaddressToString(iptos(((struct sockaddr_in*)usedInterfaceAddresses->broadaddr)->sin_addr.s_addr)) << "\n";  //printf("\tBroadcast Address: %s\n", IPaddressToString(iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr)));
			
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				std::cout << "IP6 Addresses: " << ip6tos(a->addr, ip6str, sizeof(ip6str)) << "\n";
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
}

void UserInfo::setIP6Address()
{
}