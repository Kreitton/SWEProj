#include "BlackList.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
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
	string path = "C:\\Users\\" + user.getUserName() + "\\Documents\\IP4blacklist.txt";
	infile.open( path );
	while (infile)
	{
		string s;
		if (!getline(infile, s)) break;
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
		this->IPv4addresses.push_back(ip);
	}
	
	if(!infile.eof())
	{
		cout << "IPv4 BlackList Not found";
	}
	infile.close();
	path = "C:\\Users\\" + user.getUserName() + "\\Documents\\hostnames.txt";
	infile.open(path);
	while (infile)
	{
		string s;
		if (!getline(infile, s)) break;
		istringstream ss(s);
		vector<string> record;
		while (ss)
		{
			string s;
			if (!getline(ss, s)) break;
			record.push_back(s);
		}
		this->hostNames.push_back(s);
	}
	if (!infile.eof())
	{
		cout << "hostnames blacklist not found";
	}
	infile.close();
	path = "C:\\Users\\" + user.getUserName() + "\\Documents\\ipv6.txt";
	infile.open(path);
	while (infile)
	{
		string s;
		if (!getline(infile, s)) break;
		istringstream ss(s);
		vector<string> record;
		while (ss)
		{
			string s;
			if (!getline(ss, s, ',')) break;
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
		this->IPv6addresses.push_back(ip6);
	}
	if (!infile.eof())
	{
		cout << "IPv6 blacklist not found";
	}
}
