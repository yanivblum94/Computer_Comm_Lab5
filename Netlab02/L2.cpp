#include "L2.h"
#include "L3.h"
#include "NIC.h"
#include "L2_ARP.h"
#include "Types.h"
#include <vector>
#include "stdint.h"
#include <pthread.h>
#include <fstream>
#include <winsock2.h>
#include <string>
#include <iostream>


using namespace std;

#define FAILURE_CODE 0
#define MIN_DATA_LEN 60 
#define MAX_DATA_LEN 1514
#define ETHERNET_HEADER_LEN 14 
#define MAC_LENGTH 6
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_IP 0x0800
#define IP_LOCALHOST "127.0.0.1"


uint64_t source_mac = 0;
/**
* Implemented for you
*/
L2::L2(bool debug) : debug(debug) { }

/**
* Implemented for you
*/
void L2::setUpperInterface(L3* upperInterface) { this->upperInterface = upperInterface; }

/**
* Implemented for you
*/
void L2::setNIC(NIC* nic) {
	uint32_t i_mac[6];
	byte* bytes = (byte*)&source_mac;
	this->nic = nic;
	sscanf(nic->myMACAddr.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[0], &i_mac[1], &i_mac[2], &i_mac[3], &i_mac[4], &i_mac[5]);
	for (int i = 0; i < MAC_LENGTH; i++) {
		bytes[i] = (unsigned char)i_mac[i];
	}
}

/**
* Implemented for you
*/
NIC* L2::getNIC() { return nic; }

/**
* Implemented for you
*/
std::string L2::getLowestInterface() { return nic->getLowestInterface(); }

void PrintUsingMutex(string str, NIC* nic) {
	pthread_mutex_lock(&(nic->print_mutex));
	cout << str;
	pthread_mutex_unlock(&(nic->print_mutex));
}

void PrintHeader(NIC* nic, uint16_t type, unsigned char* dst_mac, unsigned char* src_mac, int mode) {
	pthread_mutex_lock(&nic->print_mutex);
	if (mode == 1) {
		cout << "Ethernet packet sent!\n";
	}
	cout << "< Ethernet :: ";
	cout << "Destination MAC = ";
	for (int i = 0; i < MAC_LENGTH; i++)
	{
		printf("%.2x", dst_mac[i]);
		if (i != MAC_LENGTH - 1)
		{
			cout << ":";
		}
	}

	cout << " Source MAC = ";
	for (int i = 0; i < MAC_LENGTH; i++)
	{
		printf("%.2x", src_mac[i]);
		if (i != MAC_LENGTH - 1)
		{
			std::cout << ":";
		}
	}

	cout << " , Type = 0x" << std::hex << type << std::dec;
	if (mode == 1) {
		cout << " , >\n\n";
	}
	else {
		cout << " , >\n";
	}
	
	pthread_mutex_unlock(&nic->print_mutex);
}

int L2::recvFromL2(byte* recvData, size_t recvDataLen)
{
	int res = 0;
	uint64_t dest_mac = 0;
	uint64_t src_mac = 0;
	uint16_t type;
	bool isValid = true;
	bool isEqual = true;
	byte* bytes, * source, * dest, * mymac, * buf;

	if (recvDataLen > MAX_DATA_LEN)// Check if the size of length is too big
	{
		if (debug)
		{
			PrintUsingMutex("Packet length is too large, Dropping Packet...\n", nic);
		}
		return FAILURE_CODE;
	}

	else if (recvDataLen < MIN_DATA_LEN)// Check if the size of length is too small
	{
		if (debug)
		{
			PrintUsingMutex("Packet length is too small, Dropping Packet...\n", nic);
		}

		return FAILURE_CODE;
	}

	if (debug)
	{
		PrintUsingMutex("Ethernet packet received\n", nic);
	}

	// extract the destination mac from the header
	
	bytes = (byte*)&dest_mac;
	for (int i = 0; i < MAC_LENGTH; i++) {
		bytes[i] = recvData[i];
	}

	bytes = (byte*)&src_mac;
	for (int i = 0; i < MAC_LENGTH ; i++) {
		bytes[i] = recvData[i + MAC_LENGTH];
	}

	type = (((uint16_t)recvData[MAC_LENGTH * 2]) << 8) + recvData[13];
	if (debug)// print the header if debug
	{
		unsigned char* dst_mac_char = (unsigned char*)(&dest_mac);
		unsigned char* src_mac_char = (unsigned char*)(&src_mac);
		PrintHeader(nic, type, dst_mac_char, src_mac_char, 0);
	}

	// Extract local MAC and broadcase MAC for testing

	source = (byte*)&src_mac;
	dest = (byte*)&dest_mac;
	mymac = (byte*)&source_mac;
	for (int i = 0; i < MAC_LENGTH; i++) { // check address
		if (source[i] != mymac[i]) {
			isEqual = false;
		}

		if (dest[i] != 255 && dest[i] != mymac[i]) {
			isValid = false;
			break;
		}
	}

	if (isEqual) {
		if (debug)
		{
			PrintUsingMutex("Packet source MAC is me, Dropping Packet...\n\n", nic);
		}

		return FAILURE_CODE;
	}

	if (!isValid)
	{
		if (debug)
		{
			PrintUsingMutex("Destination MAC does not match the local device, Dropping Packet...\n", nic);
		}
		return FAILURE_CODE;
	}

	buf = new byte[recvDataLen - ETHERNET_HEADER_LEN];
	memcpy(buf, recvData + ETHERNET_HEADER_LEN, recvDataLen - ETHERNET_HEADER_LEN);

	if (type == ETHERNET_TYPE_ARP)
	{
		nic->getARP()->in_arpinput(buf, recvDataLen - ETHERNET_HEADER_LEN);
	}

	else if (type == ETHERNET_TYPE_IP)
	{
		res = upperInterface->recvFromL3(buf, recvDataLen - ETHERNET_HEADER_LEN);
	}

	
	else if (debug)
	{
		pthread_mutex_lock(&(nic->print_mutex));
		cout << "Type " << type << " not supported! Dropping Packet...\n";
		pthread_mutex_unlock(&(nic->print_mutex));
	}

	delete[] buf;
	return res != 0 ? recvDataLen : 0;
}

int L2::sendToL2(byte* sendData, size_t sendDataLen, uint16_t family, string spec_mac, uint16_t spec_type, string dst_addr)
{
	char temp_str[1024] = { 0 };
	uint8_t mac_adr_c[MAC_LENGTH];
	uint16_t type = htons(ETHERNET_TYPE_IP);
	uint32_t my_mac[MAC_LENGTH];
	uint32_t my_ip = inet_addr(nic->myIP.c_str());
	uint32_t network_mask = inet_addr(nic->myNetmask.c_str());
	uint32_t dest_ip;
	uint64_t dest_mac;
	const byte* ip_adr;
	byte* header_ethernet;
	int res, size;

	if (family == AF_INET) {
		//locate dest IP if was not given
		if (dst_addr.compare("") == 0)
		{
			ip_adr = (sendData + 16);
			sprintf(temp_str, "%u.%u.%u.%u", ip_adr[0], ip_adr[1], ip_adr[2], ip_adr[3]);
			dst_addr = (std::string)temp_str;
		}

		dest_ip = inet_addr(dst_addr.c_str());
		if ((my_ip & network_mask) != (dest_ip & network_mask) && dst_addr.compare(IP_LOCALHOST) != 0)
		{
			dst_addr = nic->myDefaultGateway;
		}

		std::string str_dest_mac = nic->getARP()->arpresolve(dst_addr, sendData, sendDataLen);

		// print error and throw packet because can not find mac address
		if (str_dest_mac.compare("") == 0)
		{
			if (debug)
			{
				pthread_mutex_lock(&NIC::print_mutex);
				std::cout << "Can not find mac address " + dst_addr + ": packet saved!\n\n";
				pthread_mutex_unlock(&NIC::print_mutex);
			}

			return sendDataLen;
		}

		sscanf(str_dest_mac.c_str(), "%x:%x:%x:%x:%x:%x", &my_mac[5], &my_mac[4], &my_mac[3], &my_mac[2], &my_mac[1], &my_mac[0]);
		for (int i = 0; i < MAC_LENGTH; i++)
			mac_adr_c[i] = (unsigned char)my_mac[i];
		dest_mac = *((uint64_t*)mac_adr_c);
	}
	else if (family == AF_UNSPEC) {
		sscanf(spec_mac.c_str(), "%x:%x:%x:%x:%x:%x", &my_mac[0], &my_mac[1], &my_mac[2], &my_mac[3], &my_mac[4], &my_mac[5]);
		for (int i = 0; i < MAC_LENGTH; i++) {
			mac_adr_c[i] = (unsigned char)my_mac[i];
		}

		dest_mac = *((uint64_t*)mac_adr_c);
		type = htons(spec_type);
	}

	// create new buffer of size 46 filled with 0 and copy data from the original payload there if the data is too short, .
	size = ETHERNET_HEADER_LEN + ((sendDataLen < 46) ? 46 : sendDataLen);
	// create Ethernet header
	header_ethernet = new byte[size];
	memset(header_ethernet, 0, size);
	memcpy(header_ethernet, (byte*)(&dest_mac), 6);
	memcpy(header_ethernet + 6, (byte*)(&source_mac), 6);
	memcpy(header_ethernet + 12, &type, 2);
	memcpy(header_ethernet + 14, sendData, sendDataLen);

	if (debug) // print the header
	{

		unsigned char* dest_mac_char = (unsigned char*)(&dest_mac);
		unsigned char* src_mac_char = (unsigned char*)(&source_mac);
		PrintHeader(nic, type, dest_mac_char, src_mac_char, 1);
	}

	res = nic->lestart(header_ethernet, size);
	delete[] header_ethernet;
	return res != 0 ? sendDataLen : 0;
}

/**
* Implemented for you
*/
L2::~L2() {}