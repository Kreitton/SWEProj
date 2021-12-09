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

void BlackList::generateAddresses(UserInfo user)
{

	ip_address ip;
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
}
