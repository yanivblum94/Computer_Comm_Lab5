#include <iostream>

#include "L2.h"
#include "L3.h"
#include "L4.h"
#include "NIC.h"
#include "L2_ARP.h"

using namespace std;

int main(int argc, char* argv[])
{
	/* ADD YOUR IMPLEMENTATION HERE, ADDITIONAL VARIABLES FOR ARP MAYBE */
	L2_ARP* arp = new L2_ARP(true);
	NIC* nic = new NIC(true, true, "icmp or arp");
	L2* Datalink = new L2(true);
	L3* Network = new L3(true);
	L4* Transport = new L4(true);
	nic->setUpperInterface(Datalink);
	nic->setNICsARP(arp);
	arp->setNIC(nic);
	Datalink->setNIC(nic);
	Datalink->setUpperInterface(Network);
	Network->setUpperInterface(Transport);
	Network->setLowerInterface(Datalink);
	Transport->setLowerInterface(Network);

	nic->connect(0U);

	char* test = { "NetlabPingPongTest!\n" };
	size_t testLen = string(test).length();

	/*
	* The IP address to sent the ICMP request. Can be from your local LAN (find it using Wireshark)
	* Or a remote server such as www.google.com (find the IP address using nslookup).
	* Input must be in a dotted notation, for example:
	* 74.125.21.105 or 10.0.0.1
	* Make sure both option work as you need to support them both.
	*/
	string dstIP = "8.8.8.8";
	if (argc == 2)
		dstIP = string(argv[1]);

	/* L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.*/
	Transport->sendToL4((byte*)test, testLen, dstIP, "");
	byte* readData = new byte[testLen];

	testLen = Transport->readFromL4(readData, testLen);
	pthread_mutex_lock(&NIC::print_mutex);
	cout << string((char*)readData, testLen) << endl;
	pthread_mutex_unlock(&NIC::print_mutex);

	delete nic;
	delete arp;
	delete Datalink;
	delete Transport;
	delete Network;
	delete[] readData;

	return testLen;
}

