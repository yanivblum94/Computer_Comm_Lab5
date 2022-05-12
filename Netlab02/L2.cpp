#include "L2.h"
#include "L3.h"
#include "NIC.h"
#include <iostream>
#include <fstream>
#include <winsock2.h>
#include "L2_ARP.h"
#include "Types.h"
#include <string>
#include <vector>
#include "stdint.h"
#include <pthread.h>

using namespace std;

#define FAILURE_CODE 0
#define MIN_DATA_LEN 60 
#define MAX_DATA_LEN 1514
#define ETHERNET_HEADER_SIZE 14 
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
	uint64_t dest_mac = 0;
	byte* bytes = (byte*)&dest_mac;
	for (int i = 0; i < MAC_LENGTH; i++) {
		bytes[i] = recvData[i];
	}

	uint64_t src_mac = 0;
	bytes = (byte*)&src_mac;
	for (int i = 0; i < MAC_LENGTH ; i++) {
		bytes[i] = recvData[i + MAC_LENGTH];
	}

	uint16_t type = (((uint16_t)recvData[MAC_LENGTH * 2]) << 8) + recvData[13];
	if (debug)// print the header if debug
	{
		unsigned char* dst_mac_char = (unsigned char*)(&dest_mac);
		unsigned char* src_mac_char = (unsigned char*)(&src_mac);
		PrintHeader(nic, type, dst_mac_char, src_mac_char, 0);
	}

	// Extract local MAC and broadcase MAC for testing
	bool valid = true;
	bool eq = true;
	byte* source = (byte*)&src_mac;
	byte* dest = (byte*)&dest_mac;
	byte* mymac = (byte*)&source_mac;
	for (int i = 0; i < MAC_LENGTH; i++) { // check address
		if (mymac[i] != source[i]) {
			eq = false;
		}

		if (mymac[i] != dest[i] && dest[i] != 255) {
			valid = false;
			break;
		}
	}

	if (!valid)
	{
		if (debug)
		{
			PrintUsingMutex("Destination MAC does not match the local device, Dropping Packet...\n", nic);
		}
		return FAILURE_CODE;
	}

	if (eq) {
		if (debug)
		{
			PrintUsingMutex("Packet source MAC is me, Dropping Packet...\n\n", nic);
		}

		return FAILURE_CODE;
	}

	byte* buf = new byte[recvDataLen - ETHERNET_HEADER_SIZE];
	memcpy(buf, recvData + ETHERNET_HEADER_SIZE, recvDataLen - ETHERNET_HEADER_SIZE);

	if (type == ETHERNET_TYPE_ARP)
	{
		nic->getARP()->in_arpinput(buf, recvDataLen - ETHERNET_HEADER_SIZE);
	}

	else if (type == ETHERNET_TYPE_IP)
	{
		res = upperInterface->recvFromL3(buf, recvDataLen - ETHERNET_HEADER_SIZE);
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
	uint8_t mac_c[MAC_LENGTH];
	uint32_t i_mac[MAC_LENGTH];
	uint64_t dest_mac;
	char str[1024] = { 0 };
	uint16_t type = htons(ETHERNET_TYPE_IP);
	uint32_t my_ip = inet_addr(nic->myIP.c_str());
	uint32_t network_mask = inet_addr(nic->myNetmask.c_str());
	if (family == AF_INET) {
		//locate dest IP if was not given
		if (dst_addr.compare("") == 0)
		{
			const byte* ip = (sendData + 16);
			sprintf(str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
			dst_addr = (std::string)str;
		}

		uint32_t dest_ip = inet_addr(dst_addr.c_str());
		if (dst_addr.compare(IP_LOCALHOST) != 0 && (my_ip & network_mask) != (dest_ip & network_mask))
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

		sscanf(str_dest_mac.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[5], &i_mac[4], &i_mac[3], &i_mac[2], &i_mac[1], &i_mac[0]);
		for (int i = 0; i < MAC_LENGTH; i++)
			mac_c[i] = (unsigned char)i_mac[i];
		dest_mac = *((uint64_t*)mac_c);
	}
	else if (family == AF_UNSPEC) {
		sscanf(spec_mac.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[0], &i_mac[1], &i_mac[2], &i_mac[3], &i_mac[4], &i_mac[5]);
		for (int i = 0; i < MAC_LENGTH; i++) {
			mac_c[i] = (unsigned char)i_mac[i];
		}

		dest_mac = *((uint64_t*)mac_c);
		type = htons(spec_type);
	}

	// create new buffer of size 46 filled with 0 and copy data from the original payload there if the data is too short, .
	int size = ETHERNET_HEADER_SIZE + ((sendDataLen < 46) ? 46 : sendDataLen);
	// create Ethernet header
	byte* eth_head = new byte[size];
	memset(eth_head, 0, size);
	memcpy(eth_head, (byte*)(&dest_mac), 6);
	memcpy(eth_head + 6, (byte*)(&source_mac), 6);
	memcpy(eth_head + 12, &type, 2);
	memcpy(eth_head + 14, sendData, sendDataLen);

	if (debug) // print the header
	{

		unsigned char* dest_mac_char = (unsigned char*)(&dest_mac);
		unsigned char* src_mac_char = (unsigned char*)(&source_mac);
		PrintHeader(nic, type, dest_mac_char, src_mac_char, 1);
	}

	int res = nic->lestart(eth_head, size);
	delete[] eth_head;
	return res != 0 ? sendDataLen : 0;
}

/**
* Implemented for you
*/
L2::~L2() {}