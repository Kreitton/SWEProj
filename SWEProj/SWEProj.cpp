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
#include "IP6Packet.h"
#pragma comment(lib, "ws2_32")



//main() logic for starting the sniffer comes from  https://nmap.org/npcap/guide/npcap-tutorial.html it is refactored in places, but a lot is from there to get the
//sniffer going, comments throughout explaining what exactly is happening to open the sniffer.
UserInfo user;
BlackList blacklist;
long usedBytes = 0;

int maxData = 10000000; //1MB
int dataWarning = 0;
int dataFlag = 0;

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

int networkCheck(ip_address testAddress, ip_address broadcastAddress, ip_address subnet)//returns 1 if out of network, returns 0 if in network
{
	int outNetwork = 0;

	int testAddr[4];
	int broadAddr[4];
	int subAddr[4];
	int netAddr[4];
	int compAddr[4];

	testAddr[0] = (int)testAddress.byte1;
	testAddr[1] = (int)testAddress.byte2;
	testAddr[2] = (int)testAddress.byte3;
	testAddr[3] = (int)testAddress.byte4;

	broadAddr[0] = (int)broadcastAddress.byte1;
	broadAddr[1] = (int)broadcastAddress.byte2;
	broadAddr[2] = (int)broadcastAddress.byte3;
	broadAddr[3] = (int)broadcastAddress.byte4;

	subAddr[0] = (int)subnet.byte1;
	subAddr[1] = (int)subnet.byte2;
	subAddr[2] = (int)subnet.byte3;
	subAddr[3] = (int)subnet.byte4;

	netAddr[0] = broadAddr[0] & subAddr[0];
	netAddr[1] = broadAddr[1] & subAddr[1];
	netAddr[2] = broadAddr[2] & subAddr[2];
	netAddr[3] = broadAddr[3] & subAddr[3];

	compAddr[0] = testAddr[0] & subAddr[0];
	compAddr[1] = testAddr[1] & subAddr[1];
	compAddr[2] = testAddr[2] & subAddr[2];
	compAddr[3] = testAddr[3] & subAddr[3];

	for (int i = 0; i < 4; i++)
	{
		if (netAddr[i] != compAddr[i])
		{
			outNetwork = 1;
			return outNetwork;
		}
	}

	/*
	cout << endl << "Test Address: " << testAddr[0] << "." << testAddr[1] << "." << testAddr[2] << "." << testAddr[3] << endl;
	cout << "Broadcast Address: " << broadAddr[0] << "." << broadAddr[1] << "." << broadAddr[2] << "." << broadAddr[3] << endl;
	cout << "Subnet Address: " << subAddr[0] << "." << subAddr[1] << "." << subAddr[2] << "." << subAddr[3] << endl;
	cout << "Network Address: " << netAddr[0] << "." << netAddr[1] << "." << netAddr[2] << "." << netAddr[3] << endl;
	cout << "Compare Address: " << compAddr[0] << "." << compAddr[1] << "." << compAddr[2] << "." << compAddr[3] << endl;
	cout << "outNetwork: " << outNetwork << endl << endl;
	*/

	return outNetwork;
}


void dataWatch()
{
	if (usedBytes > maxData / 100)
	{
		writeData(usedBytes);
		usedBytes = 0;
		dataWarning++;
		cout << endl << "Data Warning Number: " << dataWarning << endl;

		if (dataWarning >= 100)
		{
			pcap_breakloop(adhandle);
			sendEmail("3");
			dataWarning = 0;
			return;
		}
		else if (dataWarning >= 75 && dataFlag == 1)
		{
			sendEmail("2");
			dataFlag++;
			return;
		}
		else if (dataWarning >= 50 && dataFlag == 0)
		{
			sendEmail("1");
			dataFlag++;
			return;
		}
	}
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) //callback function declaration for use in pcap_loop(), pkt_data is the packet itself that we are grabbing
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	ip_header* ih; //declartion of an IPv4 header assigned later
	ip6_header* i6h; //declaration of an IPv6 header no longer used in code can be removed if desired
	Dummy_struct* dumb; //declare dummy struct, I was having issues getting correct data this was used for testing
	Ethernet_header* eh; // declartion of an Ethernet_Header also no longer used
	ih = (ip_header*)(pkt_data+14);//convert our packet data to a pointer to the ip_header struct this is needed to return what packet structure we're going to be
	//looking at
	
	
	
	//dumb = (Dummy_struct*)(pkt_data);

	u_char version = ih->ver_ihl; // this take the first byte in the IP_header that was declared, the first half of the first byte returns
	std::vector<int> arr = BinarytoDecimal(ChartoBinary(version), 4, 4);

	std::cout << "size: " << arr[0] << "\n";
	if (arr[0] == 4)
	{
		Packet packet(pkt_data);
		std::cout << "Source Address: " << IPaddressToString(packet.ip4Header->saddr);
		std::cout << "\nDestination Address: " << IPaddressToString(packet.ip4Header->daddr);
		std::cout << "\nSource Port: " << PortResolution(packet.TCPHeader->sport, packet.TCPHeader->sport2);
		std::cout << "\nDestination Port: " << PortResolution(packet.TCPHeader->dport, packet.TCPHeader->dport2) << "\n";

		if ((networkCheck(packet.ip4Header->saddr, user.getBroadcastIPAddress(), user.getSubnetAddress()) == 1) || (networkCheck(packet.ip4Header->daddr, user.getBroadcastIPAddress(), user.getSubnetAddress()) == 1))
		{
			cout << "Out of Network" << endl << endl;
			dataWatch();
		}
		else
		{
			cout << "In Network" << endl << endl;
		}
		if (blacklist.checkBlackListIPv4(packet.ip4Header->daddr) || blacklist.checkBlackListIPv4(packet.ip4Header->saddr))
		{
			cout << "BlackList violation email sent";
			pcap_breakloop(adhandle);
		}

	}
	else if(arr[0] == 6)
	{
		i6h = (ip6_header*)(pkt_data + 14);
		IP6Packet packet(pkt_data);
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
		if (blacklist.checkBlackListIPv6(packet.ip6Header->saddr) || blacklist.checkBlackListIPv6(packet.ip6Header->daddr))
		{
			cout << "BlackList violation email sent";
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
