#include "BlackList.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include "ComparisonOperatorOverloads.h"
using namespace std;

BlackList::BlackList(UserInfo user)
{
	generateAddresses(user);
}
BlackList::BlackList()
{

}

void BlackList::generateAddresses(UserInfo user)
{

	ip_address ip;
	ip6_address ip6;
	ifstream infile;
	string path = "C:\\Users\\" + user.getUserName() + "\\SWEProj\\IP4blacklist.txt";//dynamically create path to the black list using the UserName returned in UserInfo class
	infile.open( path );
	while (infile)//read in the file, loop through it and take each individual number delimited by commas and put them into and IPv4 address
	{
		string s;
		if (!getline(infile, s)) break;//read each row separately
		istringstream ss(s);
		vector<string> record;
		while (ss)
		{
			string s;
			if (!getline(ss, s, ',')) break;
			record.push_back(s);
		}
		
		ip.byte1 = stoi(record[0], 0);
		ip.byte2 = stoi(record[1], 0);
		ip.byte3 = stoi(record[2], 0);
		ip.byte4 = stoi(record[3], 0);
		this->IPv4addresses.push_back(ip);//push the created ip address onto a vector of ipaddresses to be checked against.
	}
	
	if(!infile.eof())
	{
		cout << "IPv4 BlackList Not found";
	}
	infile.close();
	path = "C:\\Users\\" + user.getUserName() + "\\SWEProj\\hostnames.txt";//dynamically create path to the black list using the UserName returned in UserInfo class
	infile.open(path);
	while (infile)
	{
		string s;
		if (!getline(infile, s)) break;//read in each individual row
		istringstream ss(s);
		vector<string> record;
		while (ss)
		{
			string s;
			if (!getline(ss, s)) break;
			record.push_back(s);
		}
		this->hostNames.push_back(s);//push the string hostname onto a string vector to be checked against for the blacklist.
	}
	if (!infile.eof())
	{
		cout << "hostnames blacklist not found";
	}
	infile.close();
	path = "C:\\Users\\" + user.getUserName() + "\\SWEProj\\IP6blacklist.txt";//dynamically create path to the black list using the UserName returned in UserInfo class
	infile.open(path);
	while (infile)//read in the file, loop through it and take each individual byte in Hex format delimited by commas and put them into and IPv6 address
	{
		string s;
		if (!getline(infile, s)) break;//each row should be a separate IPv6 address
		istringstream ss(s);
		vector<string> record;
		while (ss)
		{
			string s;
			if (!getline(ss, s, ',')) break;//rows are delimited each byte by commas
			record.push_back(s);
		}

		ip6.byte1 = stoi(record[0], 0, 16);
		ip6.byte2 = stoi(record[1], 0, 16);
		ip6.byte3 = stoi(record[2], 0, 16);
		ip6.byte4 = stoi(record[3], 0, 16);
		ip6.byte5 = stoi(record[4], 0, 16);
		ip6.byte6 = stoi(record[5], 0, 16);
		ip6.byte7 = stoi(record[6], 0, 16);
		ip6.byte8 = stoi(record[7], 0, 16);
		ip6.byte9 = stoi(record[8], 0, 16);
		ip6.byte10 = stoi(record[9], 0, 16);
		ip6.byte11 = stoi(record[10], 0, 16);
		ip6.byte12 = stoi(record[11], 0, 16);
		ip6.byte13 = stoi(record[12], 0, 16);
		ip6.byte14 = stoi(record[13], 0, 16);
		ip6.byte15 = stoi(record[14], 0, 16);
		ip6.byte16 = stoi(record[15], 0, 16);
		this->IPv6addresses.push_back(ip6);//push the created IPv6 onto a vector to check against.
	}
	if (!infile.eof())
	{
		cout << "IPv6 blacklist not found";
	}
}

bool BlackList::checkBlackListIPv4(ip_address addr)//these functions below take in an address either IPv4 or IPv6 and check them against the vector storing the blacklist
{//they are boolean return values if the IP matches the black list return true that the blacklist has been violated.
	
	for (int i = 0; i < this->IPv4addresses.size(); i++)
	{
		if (addr == this->IPv4addresses[i])
		{
			return true;
		}
	}
	return false;
}

bool BlackList::checkBlackListIPv6(ip6_address addr)
{
	
	for (int i = 0; i < this->IPv6addresses.size(); i++)
	{
		if (addr == this->IPv6addresses[i])
		{
			return true;
		}
	}
	return false;
}

bool BlackList::checkBlackListHostName(std::string)//not sure how to implement hostname checking yet, probably will breakdown the hostname into IPs using DNS
//then afterwards check against those IPs, not sure if this will be final implementation though, need to talk to stephen.
{
	return false;
}
