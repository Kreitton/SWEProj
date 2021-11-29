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


#define NAME_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)
//fair warning this code is almost entirely lifted from a demo found here https://nmap.org/npcap/guide/npcap-tutorial.html, commenting is mine(kevin Granlund) Code is not, I originally tried doing this all without a tutorial and kept having issues once I started reading packets
//Got frustarated after a few hours and did some googlefu and found the below, I edited a few lines, but not much, as far as I'm concerned for our project this is fine, as we want to implement PCAP in a windows enviroment
//not reinvent the wheel(otherwise why use libraries at all) There is still a bunch we'll need to do with this, but this gets us to a point where we can begin using the packet_handler function as what amounts to a psuedo main()
//I expect we'll be extending this and breaking apart packets for some inspection as they're grabbed off of the wire.

long usedBytes = 0;
TCHAR computerName[NAME_BUFFER_SIZE];
DWORD size = NAME_BUFFER_SIZE;
pcap_t* adhandle; // this is a descriptor of an open capture instance, and is abstracted away from us it handles the instance with functions inside of pcap
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;
typedef struct Dummy_struct {
	ip_address  one;        
	ip_address  two;             
	ip_address  three;         
	ip_address  four; 
	ip_address  five;      
	ip_address  six;          
	ip_address  seven;          
	ip_address  eight;           
	ip_address  nine;      
	ip_address  ten;      
	ip_address  eleven;         
}Dummy_struct;

typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;
typedef struct Ethernet_header {
	u_int first4;
	u_int second4;
	u_int third4;
	u_short last2;
}Ethernet_header;

std::string ChartoBinary(char input)
{
	std::string binaryString = std::bitset<8>(input).to_string();
	
	return binaryString;
}
std::vector<int> BinarytoDecimal(std::string input, int lengthFirst, int lengthSecond)
{
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
	s = std::to_string(address.byte1);
	s.append(".");
	s.append(std::to_string(address.byte2));
	s.append(".");
	s.append(std::to_string(address.byte3));
	s.append(".");
	s.append(std::to_string(address.byte4));
	return s;
}

std::string getComputerName()
{
	if (GetComputerName(computerName, &size))
	{
		std::wstring test(&computerName[0]);
		std::string ComputerName(test.begin(), test.end());
		return ComputerName;
	}
	return " ";
}
std::string getUserName()
{
	if (GetUserName(computerName, &size))
	{
		std::wstring test(&computerName[0]);
		std::string UserName(test.begin(), test.end());
		return UserName;
	}
	return " ";
}
void SendEmail(std::string computer, std::string user)
{
	std::cout << "email Sent";
	
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) //callback function declaration for use in pcap_loop(), plt_data is the packet itself that we are grabbing
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	ip_header* ih;
	Dummy_struct* dumb;
	Ethernet_header* eh;
	(VOID)(param);
	ih = (ip_header*)(pkt_data+14);//convert our packet data to a pointer to the ip_header struct
	//dumb = (Dummy_struct*)(pkt_data);

	u_char version = ih->ver_ihl;
	std::vector<int> arr = BinarytoDecimal(ChartoBinary(version), 4, 4);

	std::cout << arr[1] << "\n";
	if (arr[1] == 4)
	{
		ip_address DestinationIP = ih->daddr;
		std::cout << IPaddressToString(DestinationIP) << "\n";
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
		
	if (usedBytes > 100000)
	{	
		SendEmail(getComputerName(), getUserName());
		pcap_breakloop(adhandle);
	}
	
	
	

	
}

int main()
{
	pcap_if_t* alldevs; //item in a list of network intefaces
	pcap_if_t* d;  //item in a list of network intefaces
	int inum;
	int i = 1; //incrementor used in a loop later
	
	char errbuf[PCAP_ERRBUF_SIZE]; //a char array for an error buffer
	std::string s = ChartoBinary(255);
	std::cout << ChartoBinary(255) << "\n";
	std::vector<int> arr = BinarytoDecimal(s, 4, 4);
	for (int k = 0; k < arr.size(); k++)
	{
		std::cout << arr[k] << "\n";
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
	if ((adhandle = pcap_open(d->name,	65536,PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) // pcap_open returns NULL if it fails
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

	printf("\nlistening on %s...\n", d->description); // if we succeeded then print we're listening on d->description(the interface we chose before). 


	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);// we can get rid of the devs now as we've opened our sniffing session.

	pcap_loop(adhandle, 25, packet_handler, NULL);
	//this is a loopback function, it takes our pcap_t *adhandle, an int for number of packets to process before saving, 0 = infinity, and it will run
	//until the program is stopped or we break the loop with pcap_breakloop(), or an error occurs, takes our callback function(cool story, I didn't know callback functions could be used like this
	// in c/c++ I use them a lot in server side Javascript. Finaly we have a u_char *user argument which is used to a u_char* to our the specified function. 
	//documentation for this setup can be found here https://nmap.org/npcap/guide/wpcap/pcap_loop.html
	

	return 0;
}
