#include "pcap.h"
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <string>
#include <pcap/pcap.h>// was mising this in our earlier GitHub repo, is needed to call loopback function pcap_loop() at the bottom of this file
#include <WinBase.h> //getting usernames/computer names
#include <tchar.h> //using usernames/computernames and converting them to string
#include <string>
#include <bitset>
#include <vector>
#include <sstream>
#include "Packet.h"
#include <Winsock2.h>
#include "EmailFunctions.h"
#include "UserInfo.h"
#include "BlackList.h"
#pragma comment(lib, "ws2_32")



//fair amount of code is lifted from here https://nmap.org/npcap/guide/npcap-tutorial.html
UserInfo user;
BlackList blacklist;
long usedBytes = 0;
int dataTrigger = 100000; //100KB
int dataWarning = 0;

pcap_t* adhandle; // this is a descriptor of an open capture instance, and is abstracted away from us it handles the instance with functions inside of pcap



std::string ChartoBinary(char input)
{
	std::string binaryString = std::bitset<8>(input).to_string();
	
	return binaryString;
}
u_int PortResolution(u_char part1, u_char part2) // this function ends up not being needed, I used it for testing when I was having issues with determining ports, leaving here just in case I need it again
{
	std::string firstByte = ChartoBinary(part1);
	std::string secondByte = ChartoBinary(part2);
	std::string portBinary = firstByte + secondByte;
	u_int portNumber = std::stoi(portBinary, 0, 2);
	//std::cout << portBinary << "\n";
	return portNumber;
}
std::vector<int> BinarytoDecimal(std::string input, int lengthFirst, int lengthSecond) //for cutting up bits in instances where things pulled from the wire are less than a single byte, most notably for packet type check
{//returns a vector of two intergers that are made out of two substrings that represent the binary pulled from the byte
	std::vector<int> values;
	std::string first = input.substr(0, lengthFirst);
	std::string second = input.substr(lengthFirst, lengthSecond);
	values.push_back(std::stoi(first, 0, 2));
	values.push_back(std::stoi(second, 0, 2));
	return values;

}
std::string Ipv4IPheaderToString(ip_header* header)
{
	std::string s;
	s = std::to_string(header->ver_ihl);
	s.append("Version");
	return " ";
}
std::string IPaddressToString(ip_address address)
{
	std::string s;
	s.append(std::to_string(address.byte1));
	s.append(".");
	s.append(std::to_string(address.byte2));
	s.append(".");
	s.append(std::to_string(address.byte3));
	s.append(".");
	s.append(std::to_string(address.byte4));

	return s;
}
//(which + 1 == IPTOSBUFFERS ? 0 : which + 1)
std::string ZeroPaddingHelper(u_char byte)
{
	if (byte < 10)
	{
		return "0";
	}
	return "";
}
bool operator==(const ip6_address addr1, const ip6_address addr2)
{
	if (addr1.byte1 == addr2.byte1)
	{
		if (addr1.byte1 == addr2.byte1)
		{
			if (addr1.byte1 == addr2.byte1)
			{
				if (addr1.byte1 == addr2.byte1)
				{
					if (addr1.byte1 == addr2.byte1)
					{
						if (addr1.byte1 == addr2.byte1)
						{
							if (addr1.byte1 == addr2.byte1)
							{
								if (addr1.byte1 == addr2.byte1)
								{

								}
							}
						}
					}
				}
			}
		}
	}
	return true;
}
std::string IP6addressToString(ip6_address address)
{
	u_char* bytePtr = (u_char*)&address;
	std::stringstream shorts;
	std::string s;
	shorts << std::hex << (int)address.byte1;
	shorts << ZeroPaddingHelper(address.byte2);
	shorts << std::hex << (int)address.byte2;
	shorts << ":";
	shorts << std::hex << (int)address.byte3;
	shorts << ZeroPaddingHelper(address.byte4);
	shorts << std::hex << (int)address.byte4;
	shorts << ":";
	shorts << std::hex << (int)address.byte5;
	shorts << ZeroPaddingHelper(address.byte6);
	shorts << std::hex << (int)address.byte6;
	shorts << ":";
	shorts << std::hex << (int)address.byte7;
	shorts << ZeroPaddingHelper(address.byte8);
	shorts << std::hex << (int)address.byte8;
	shorts << ":";
	shorts << std::hex << (int)address.byte9;
	shorts << ZeroPaddingHelper(address.byte10);
	shorts << std::hex << (int)address.byte10;
	shorts << ":";
	shorts << std::hex << (int)address.byte11;
	shorts << ZeroPaddingHelper(address.byte12);
	shorts << std::hex << (int)address.byte12;
	shorts << ":";
	shorts << std::hex << (int)address.byte13;
	shorts << ZeroPaddingHelper(address.byte14);
	shorts << std::hex << (int)address.byte14;
	shorts << ":";
	shorts << std::hex << (int)address.byte15;
	shorts << ZeroPaddingHelper(address.byte16);
	shorts << std::hex << (int)address.byte16;
	s = shorts.str();
	return s;
}

int inNetwork(ip_address hostAddress, ip_address networkAddress, ip_address subnet)
{
	int inNetwork = 1;

	int hostAddr[4];
	int netAddr[4];
	int subAddr[4];
	int compAddr[4];

	hostAddr[0] = (int)hostAddress.byte1;
	hostAddr[1] = (int)hostAddress.byte2;
	hostAddr[2] = (int)hostAddress.byte3;
	hostAddr[3] = (int)hostAddress.byte4;

	netAddr[0] = (int)networkAddress.byte1;
	netAddr[1] = (int)networkAddress.byte2;
	netAddr[2] = (int)networkAddress.byte3;
	netAddr[3] = (int)networkAddress.byte4;

	subAddr[0] = (int)subnet.byte1;
	subAddr[1] = (int)subnet.byte2;
	subAddr[2] = (int)subnet.byte3;
	subAddr[3] = (int)subnet.byte4;

	compAddr[0] = hostAddr[0] & subAddr[0];
	compAddr[1] = hostAddr[1] & subAddr[1];
	compAddr[2] = hostAddr[2] & subAddr[2];
	compAddr[3] = hostAddr[3] & subAddr[3];

	for (int i = 0; i < 4; i++)
	{
		if (netAddr[i] != compAddr[i])
			inNetwork = 0;
	}

	return inNetwork;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) //callback function declaration for use in pcap_loop(), plt_data is the packet itself that we are grabbing
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	ip_header* ih;
	ip6_header* i6h;
	Dummy_struct* dumb;
	Ethernet_header* eh;
	(VOID)(param);
	ih = (ip_header*)(pkt_data+14);//convert our packet data to a pointer to the ip_header struct
	
	
	//dumb = (Dummy_struct*)(pkt_data);

	u_char version = ih->ver_ihl;
	std::vector<int> arr = BinarytoDecimal(ChartoBinary(version), 4, 4);

	std::cout << "size: " << arr[0] << "\n";
	if (arr[0] == 4)
	{
		Packet packet(pkt_data);
		std::cout << "Source Address: " << IPaddressToString(packet.ip4Header->saddr);
		std::cout << "\nDestination Address: " << IPaddressToString(packet.ip4Header->daddr);
		std::cout << "\nSource Port: " << PortResolution(packet.TCPHeader->sport, packet.TCPHeader->sport2);
		std::cout << "\nDestination Port: " << PortResolution(packet.TCPHeader->dport, packet.TCPHeader->dport2) << "\n";
	}
	else if(arr[0] == 6)
	{
		i6h = (ip6_header*)(pkt_data + 14);
		TCPheader* ihTCP = (TCPheader*)(pkt_data + sizeof(Ethernet_header) + sizeof(ip6_header)-2);
		ip6_address SourceIP = i6h->saddr;
		std::cout << "length: " << header->len << "\n";
		std::cout << IP6addressToString(SourceIP) << "\n";
		ip6_address DestinationIP = i6h->daddr;
		std::cout << IP6addressToString(DestinationIP) << "\n";
		u_int sport = PortResolution(ihTCP->sport, ihTCP->sport2);
		u_int dport = PortResolution(ihTCP->dport, ihTCP->dport2);
		std::cout << "Source Port: " << sport << "\n";
		std::cout << "Destination Port: " << dport << "\n";
		if (IP6addressToString(i6h->daddr).compare(IP6addressToString(blacklist.IPv6addresses[0])) != 0)
		{
			cout << "black list violation: " << IP6addressToString(DestinationIP);
			pcap_breakloop(adhandle);
		}
	}
	

	/* std::cout << IPaddressToString(dumb->one) << "\n"
		<< IPaddressToString(dumb->two) << "\n"
		<< IPaddressToString(dumb->three) << "\n"
		<< IPaddressToString(dumb->four) << "\n"
		<< IPaddressToString(dumb->five) << "\n"
		<< IPaddressToString(dumb->six) << "\n"
		<< IPaddressToString(dumb->seven) << "\n"
		<< IPaddressToString(dumb->eight) << "\n"
		<< IPaddressToString(dumb->nine) << "\n"
		<< IPaddressToString(dumb->ten) << "\n"
		<< IPaddressToString(dumb->eleven); */
	
	usedBytes += (long)header->len;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	//std::cout << (int)sourceIP.byte1 << "." << (int)sourceIP.byte2 << "." << (int)sourceIP.byte3 << "." << (int)sourceIP.byte4 << "\n";
	
	if (usedBytes > dataTrigger && dataWarning < 10)
	{	
		writeData(usedBytes);
		usedBytes = 0;
		dataWarning++;
		cout << endl << "Data Warning Number: " << dataWarning << endl;
	}
	if (dataWarning >= 10)
	{
		sendEmail("2");
		dataWarning = 0;
		pcap_breakloop(adhandle);
	}
	
	

	
}

int main()
{
	buildFiles();

	pcap_if_t* alldevs; //item in a list of network intefaces
	pcap_if_t* d;  //item in a list of network intefaces
	int inum;
	int i = 1; //incrementor used in a loop later
	//BlackList b;
	char errbuf[PCAP_ERRBUF_SIZE]; //a char array for an error buffer
	//std::cout << IPaddressToString(b.addresses[0]);
	//std::string s = ChartoBinary(255);
	//std::cout << ChartoBinary(255) << "\n";
	//std::vector<int> arr = BinarytoDecimal(s, 4, 4);
	//std::cout << sizeof(Ethernet_header);// I don't understand why this returns 16, I was expecting 14 :D, it caused me no end of grief. 
	//std::cout << sizeof(ip_header);
	//for (int k = 0; k < arr.size(); k++)
	{
		//std::cout << arr[k] << "\n";
	}
	


	if (pcap_findalldevs(&alldevs, errbuf) == -1) // pcap_findalldevs is a function that locates all networking interfaces, takes a pcap_if_t struct and an errorbuf if there's an error
	{ ///man page is here https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html 
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf); //if findalldevs returns -1 then return the error storred in errbuf
		exit(1);//exit the program
	}

	for (d = alldevs; d; d = d->next) // loop setup to loop through our struc in findalldevs()
	{
		printf("%d. %s", i++, d->name); //we're going to print out the name of the network device and prior to the name we will have a number, to create an ordered list to choose from 
		if (d->description)
			printf(" (%s)\n", d->description);//if a description exists then get the description of the device found
		else
			printf(" (No description available)\n");//else no description available
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");//if there are no devices found, so i still == 0
		return -1;//end the program
	}

	printf("Enter the interface number (1-%d):", i-1); //ask the user to enter the number for the interface we want to work on.
	scanf_s("%d", &inum);//store the number in inum

	while (inum < 1 || inum > i-1) // if the user entered 0 or less(not possible as a device in our list, or a number greater than the total number of interfaces
	{
		printf("\nInterface number out of range.\n");//you're outside the range of available interfaces
		printf("Enter the interface number (1-%d):", (i-1));
		scanf_s("%d", &inum); //ask again for the interface
		
	}
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // we're going to select an adapter now to feed our handler, how this works we've got a for loop on our pcap_if_t struct and our incrementor
	//i, based on the value in inum, we will move through our list of interfaces i times, so if we wanted interface 5 in the list, this loop will move through d 5 times until it gets to the 5th 
	//interface, once d is pointing at this inteface we can uses the properties of that struct to feed pcap_open below.

	
	/* Open the device */
	if ((adhandle = pcap_open(d->name,	65536, 0, 1000, NULL, errbuf)) == NULL) // pcap_open returns NULL if it fails
	{// we have a few things going on in here see docs here https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#ga2b64c7b6490090d1d37088794f1f1791 for pcap_open()
	// it takes 5 parameters, a const char *, which is the name of our device, the size of the length of packet to be retained in bytes, we use 65536 as that ensures we will receive an entire packet
	// see here, if unfamiliar with packet sizing and how large they can be https://stackoverflow.com/questions/43931288/understanding-the-tcp-packet-size-limit-with-udp-packet-size-limit-what-it-mea
	// 2^16 butes = 65536, note we are dealing with full packets, not segments of packets, we read the packet in its totality not segments of it as it comes through
	// next is our flags, which is an int, the options are 1,2,4,8,16  these are defined for us with names dependent on what they do, we're using hte promiscuous flag so we can see all packets
	//if you're unsure what this means refer to this doc https://en.wikipedia.org/wiki/Promiscuous_mode. Next we have another integer which is our read_timeout what this does is it allows us to wait
	//a specified number of miliseconds and then grab multiple packets from the OS, not all OSs support this, if its not supported its ignored.
	// next is a struct pcap_rmtauth * for authorization, this only matters on remote machines if this is being run on a local host leave it null. if you're curious what that struct entails docuumentation
	// is available here https://www.winpcap.org/docs/docs_412/html/structpcap__rmtauth.html. finally we have our error buffer which as before is a char *. 
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name); // if we tried to open and fail give this
		pcap_freealldevs(alldevs);//free all devs
		return -1;//end program
	}
	pcap_addr_t* a;

	UserInfo MakeUser(d);
	user = MakeUser;
	BlackList Blacklist(user);
	blacklist = Blacklist;
	
	//std::cout << user.getUserName() << "\n";
	
	printf("\nlistening on %s...\n", d->description); // if we succeeded then print we're listening on d->description(the interface we chose before). 


	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);// we can get rid of the devs now as we've opened our sniffing session.

	pcap_loop(adhandle, 0, packet_handler, NULL);
	//this is a loopback function, it takes our pcap_t *adhandle, an int for number of packets to process before saving, 0 = infinity, and it will run
	//until the program is stopped or we break the loop with pcap_breakloop(), or an error occurs, takes our callback function(cool story, I didn't know callback functions could be used like this
	// in c/c++ I use them a lot in server side Javascript. Finaly we have a u_char *user argument which is used to a u_char* to our the specified function. 
	//documentation for this setup can be found here https://nmap.org/npcap/guide/wpcap/pcap_loop.html
	

	return 0;
}
