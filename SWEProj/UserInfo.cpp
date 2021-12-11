#include "UserInfo.h"
#include "LocalIPHelperFunctions.h"
#include <WinBase.h>
#include <tchar.h>
#include <string>
#define NAME_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)
TCHAR computerName[NAME_BUFFER_SIZE];
DWORD sizeName = NAME_BUFFER_SIZE;
UserInfo::UserInfo()//this is a dummy constructor that does nothing, not ideal, its for instantiating a global version of the class that can be repointed later
{
}
UserInfo::UserInfo(pcap_if_t* usedInterface)//this is the actual constructor takes a pcap_if_t pointer which points to the used interface
{
	this->usedInterface = usedInterface;
	this->usedInterfaceAddresses = usedInterface->addresses;
	setUserName();
	setComputerName();
	setIP4Address();
}

void UserInfo::setComputerName()//set the computername property to the name of the computer
{
	if (GetComputerName(computerName, &sizeName))
	{
		std::wstring test(&computerName[0]);
		std::string ComputerName(test.begin(), test.end());
		this->myComputerName = ComputerName;
		return;
	}
	
	this->myComputerName = " ";
}

void UserInfo::setUserName()//set the Username property to the username that is logged into the computer
{
	if (GetUserName(computerName, &sizeName))
	{
		std::wstring test(&computerName[0]);
		std::string UserName(test.begin(), test.end());
		this->myUserName = UserName;
		return;
	}
	this->myUserName =  " ";
}

std::string UserInfo::getUserName()//returns the private property username
{
	return this->myUserName;
}

std::string UserInfo::getComputerName()//returns the private property computer name
{
	return this->myComputerName;
}

void UserInfo::setIP4Address()//this actuall gets both IPv4 addresses formated correctly, and string representations of local IPv6 addresses, I'd like to eventually split
//this function into two and have the IPv6 return formated, but I haven't figured out how to yet without a lot of annoying string manipulation.
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

ip_address UserInfo::getLocalIPAddress()//gets the private local IPv4 address
{
	return this->localIPAddress;
}

ip_address UserInfo::getSubnetAddress()//gest the private subnetmask
{
	return this->subnetAddress;
}

ip_address UserInfo::getBroadcastIPAddress()//gets the private broadcast address
{
	return this->broadcastAddress;
}

std::string UserInfo::toString()//to be implemented, might be usefull in output emails to have all information of the user that broke a rule.
{
	return std::string();
}
