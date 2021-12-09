#include "UserInfo.h"
#define NAME_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)
TCHAR ComputerName[NAME_BUFFER_SIZE];
DWORD sizeName = NAME_BUFFER_SIZE;
UserInfo::UserInfo(pcap_addr_t* usedInterface)
{
	this->usedInterface = usedInterface;
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
}

void UserInfo::setIP6Address()
{
}
