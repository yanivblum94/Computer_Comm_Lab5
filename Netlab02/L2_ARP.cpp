#include "L2_ARP.h"	
#include "NIC.h"
#include <vector>
#include <thread>
#include <winsock2.h>
#include <iostream>
#include "Types.h"

using namespace std;

#define FAILURE_CODE 0
#define IP_LOCALHOST "127.0.0.1"
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_IP 0x0800

#define ETHERNET_HEADER_SIZE 14 
#define ARP_DATA_SIZE 46
#define MAC_LENGTH 6


struct send_tuple
{
	byte* send_data;
	size_t send_data_len;
} typedef send_tuple;

class ArpTableEntry
{
public:
	time_t LastUsedTime;
	time_t LastSendTime;
	string DestMAC;
	string DestIp;
	bool Result;
	int Count;
	vector<send_tuple*>* VectorOfWaiters;
	ArpTableEntry(bool res, string dest_ip, string dest_mac);
	~ArpTableEntry();
};
// Class variables
bool Timeout = true;
vector<ArpTableEntry*> EntriesVector;
pthread_mutex_t Mutex_T;
pthread_t Thread_T;

ArpTableEntry::ArpTableEntry(bool res, string dest_ip, string dest_mac)
{
	this->LastUsedTime = time(0);
	this->LastSendTime = time(0);
	this->DestMAC = dest_mac;
	this->DestIp = dest_ip;
	this->Result = res;
	this->Count = 1;
	this->VectorOfWaiters = new vector<send_tuple*>();
}
ArpTableEntry::~ArpTableEntry() {
	for (vector<send_tuple*>::iterator data_iterator = VectorOfWaiters->begin();
		data_iterator != VectorOfWaiters->end();
		data_iterator++)
	{
		delete[] VectorOfWaiters;
		delete[](*data_iterator)->send_data;
		delete (*data_iterator);
	}
}
void PrintUsingMutexArp(string str, NIC* nic) {
	pthread_mutex_lock(&(nic->print_mutex));
	cout << str;
	pthread_mutex_unlock(&(nic->print_mutex));
}

void* CreateTimeout(void* data)
{
	Sleep(1000);
	L2_ARP* arp_obj = (L2_ARP*)data;
	while (Timeout)
	{
		Sleep(1000); // check every 1 sec
		pthread_mutex_lock(&(Mutex_T));
		for (vector<ArpTableEntry*>::iterator table_it = EntriesVector.begin(); table_it != EntriesVector.end();)
		{
			time_t now = time(NULL);
			ArpTableEntry* entry = (*table_it);
			double last_send_diff = difftime(now, entry->LastSendTime);
			double last_use_diff = difftime(now, entry->LastUsedTime);
			// if last time was used is lower than 100 secs
			if (last_use_diff < 100.0) {
				if (!entry->Result)
				{
					if (entry->Count < 5)
						if (last_send_diff >= 1) {
							{
								pthread_mutex_lock(&arp_obj->getNIC()->print_mutex);
								cout << "resend For IP (1-second) '" << entry->DestIp << "' initiated.\n";
								pthread_mutex_unlock(&arp_obj->getNIC()->print_mutex);
								arp_obj->arprequest(entry->DestIp);
								entry->LastSendTime = now;
								entry->Count = entry->Count + 1;
							}
						}
						else if (last_send_diff >= 20.0) {
							pthread_mutex_lock(&arp_obj->getNIC()->print_mutex);
							cout << "flood timeout occured for IP (20-second) '" << entry->DestIp << "'\n";
							cout << "resend For IP (1-second) '" << entry->DestIp << "' initiated.\n";
							pthread_mutex_unlock(&arp_obj->getNIC()->print_mutex);
							arp_obj->arprequest(entry->DestIp);
							entry->LastSendTime = now;
							entry->Count = 1;
						}
				}
				table_it++;
			}
			else {
				pthread_mutex_lock(&arp_obj->getNIC()->print_mutex);
				cout << "Timeout on ARP entry for IP occured!  '" << entry->DestIp << "'. Dropping entry!\n";
				pthread_mutex_unlock(&arp_obj->getNIC()->print_mutex);

				// go over all saved data and delete
				for (vector<send_tuple*>::iterator data_iterator = entry->VectorOfWaiters->begin();
					data_iterator != entry->VectorOfWaiters->end();
					data_iterator++)
				{
					delete[](*data_iterator)->send_data;
					delete (*data_iterator);
				}

				delete (*table_it);
				table_it = EntriesVector.erase(table_it);
			}
		}

		pthread_mutex_unlock(&Mutex_T);
	}

	return 0;
}

/**
* Implemented for you
*/
L2_ARP::L2_ARP(bool debug) : debug(debug) {
	pthread_mutex_init(&Mutex_T, NULL);
	pthread_create(&Thread_T, NULL, CreateTimeout, this);
}

L2_ARP::~L2_ARP()
{
	Timeout = false;
	Sleep(1000);
	pthread_join(Thread_T, NULL);
	// delete mutex and arp table vector
	pthread_mutex_destroy(&Mutex_T);
	for (vector<ArpTableEntry*>::iterator it = EntriesVector.begin(); it != EntriesVector.end(); it++)
	{
		delete (*it);
	}
}

void PrintARP(int hardware, int protocol_type, int hardware_len, int protocol_len, string sender_mac, string sender_ip, string target_mac, string target_ip) {
	cout << "< ARP ::";
	cout << " , HardwareType = " << hardware;
	cout << " , ProtocolType = 0x" << std::hex << protocol_type << std::dec;
	cout << " , HardwareLength = " << (uint16_t)hardware_len;
	cout << " , ProtocolLength = " << (uint16_t)protocol_len;
	cout << " , SenderMAC = " << sender_mac;
	cout << " , SenderIP = " << sender_ip;
	cout << " , TargetMAC = " << target_mac;
	cout << " , TargetIP = " << target_ip;
	cout << " , >\n\n";
}

/**
* Implemented for you
*/
NIC* L2_ARP::getNIC() { return nic; }
void L2_ARP::setNIC(NIC* nic) { this->nic = nic; }

int L2_ARP::arprequest(string ip_addr)
{
	uint32_t i_mac[MAC_LENGTH];
	uint8_t mac_c[MAC_LENGTH];
	uint64_t source_mac;
	string brod = "ff:ff:ff:ff:ff:ff";
	sscanf(nic->myMACAddr.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[5], &i_mac[4], &i_mac[3], &i_mac[2], &i_mac[1], &i_mac[0]);
	for (int i = 0; i < MAC_LENGTH; i++)
		mac_c[i] = (unsigned char)i_mac[5 - i];
	source_mac = *((uint64_t*)mac_c);

	pthread_mutex_lock(&(nic->print_mutex));
	cout << "Sending ARP Packet: " << ip_addr << "?\n";

	// print ARP request
	PrintARP(1, ETHERNET_TYPE_IP, MAC_LENGTH, 4, nic->myMACAddr, nic->myIP, brod, ip_addr);
	pthread_mutex_unlock(&(nic->print_mutex));

	byte* buf = new byte[ARP_DATA_SIZE];
	memset(buf, 0, ARP_DATA_SIZE);
	*((uint16_t*)(buf)) = htons(1);
	*((uint16_t*)(buf + 2)) = htons(ETHERNET_TYPE_IP);
	*((uint8_t*)(buf + 4)) = MAC_LENGTH;
	*((uint8_t*)(buf + 5)) = 4;
	*((uint16_t*)(buf + 6)) = htons(1);
	*((uint64_t*)(buf + 8)) = source_mac;
	*((uint32_t*)(buf + 14)) = inet_addr(nic->myIP.c_str());
	*((uint32_t*)(buf + 24)) = inet_addr(ip_addr.c_str());

	int res = this->nic->getUpperInterface()->sendToL2(buf, 28, AF_UNSPEC, brod, ETHERNET_TYPE_ARP, ip_addr);
	delete[] buf;
	return res;
}

void L2_ARP::CreateNewTableEntry(string ip_addr, byte* send_data, size_t send_data_len) {
	ArpTableEntry* entry = new ArpTableEntry(false, ip_addr, "");
	send_tuple* tup = new send_tuple();
	tup->send_data = new byte[send_data_len];
	memcpy(tup->send_data, send_data, send_data_len);
	tup->send_data_len = send_data_len;
	entry->VectorOfWaiters->push_back(tup);
	EntriesVector.push_back(entry);
	arprequest(entry->DestIp);
}

void CreateNewTuple(ArpTableEntry* entry, byte* send_data, size_t send_data_len) {
	send_tuple* tup = new send_tuple();
	tup->send_data = new byte[send_data_len];
	memcpy(tup->send_data, send_data, send_data_len);
	tup->send_data_len = send_data_len;
	entry->VectorOfWaiters->push_back(tup);
}

string L2_ARP::arpresolve(string ip_addr, byte* send_data, size_t send_data_len)
{
	if (ip_addr.compare(IP_LOCALHOST) == 0 || ip_addr.compare(nic->myIP) == 0) {
		return nic->myMACAddr;
	}

	pthread_mutex_lock(&Mutex_T);
	ArpTableEntry* entry = (ArpTableEntry*)(this->arplookup(ip_addr, false));
	string res = "";
	if (entry == NULL)
	{
		CreateNewTableEntry(ip_addr, send_data, send_data_len);
	}
	else {
		// if found lookup
		if (!entry->Result)
		{
			CreateNewTuple(entry, send_data, send_data_len);
		}
		else
		{
			entry->LastUsedTime = time(0);
			res = entry->DestMAC;
		}
	}

	pthread_mutex_unlock(&Mutex_T);
	return res;
}


void* L2_ARP::arplookup(string ip_addr, bool create)
{
	for (vector<ArpTableEntry*>::iterator it = EntriesVector.begin(); it != EntriesVector.end(); it++) {
		if ((*it)->DestIp.compare(ip_addr) == 0) {
			return *it;
		}
	}

	return NULL;
}

string ConvertIpToString(unsigned char* bytes, char buf[50]) {
	sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	return string(buf);
}

string ConvertMACToString(unsigned char* bytes) {
	char buf[50];
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return string(buf);
}

int L2_ARP::in_arpinput(byte* recvData, size_t recvDataLen)
{
	PrintUsingMutexArp("ARP packet was received!\n", nic);
	// check if the packet is vaild
	if (recvDataLen != ARP_DATA_SIZE)
	{
		PrintUsingMutexArp("ARP packet is corrupt. Dropping packet...!\n", nic);
		return FAILURE_CODE;
	}

	// Read data from buffer
	uint16_t hardware_type = htons(*((uint16_t*)recvData));
	uint16_t protocol_type = htons(*((uint16_t*)(recvData + 2)));
	uint8_t hardware_length = *((uint8_t*)(recvData + 4));
	uint16_t protocol_length = *((uint8_t*)(recvData + 5));
	uint16_t operation = htons(*((uint16_t*)(recvData + 6)));

	//convert ip to string
	string sender_ip;
	string target_ip;
	char buf[50];
	unsigned char* bytes = recvData + ETHERNET_HEADER_SIZE;
	sender_ip = ConvertIpToString(bytes, buf);
	bytes = recvData + 24;
	target_ip = ConvertIpToString(bytes, buf);

	string mac_sender;
	string mac_target;
	bytes = recvData + 8;
	mac_sender = ConvertMACToString(bytes);
	bytes = recvData + 18;
	mac_target = ConvertMACToString(bytes);

	// print message 
	pthread_mutex_lock(&(nic->print_mutex));
	PrintARP(hardware_type, protocol_type, hardware_length, protocol_length, mac_sender, sender_ip, mac_target, target_ip);
	pthread_mutex_unlock(&(nic->print_mutex));

	// check valid
	int res = 0;
	if (protocol_type != ETHERNET_TYPE_IP || hardware_type != 1 || protocol_length != 4 || hardware_length != MAC_LENGTH)
	{
		PrintUsingMutexArp("ARP Protocol Or Hardware Type Not Supported, Dropping Packet...!\n", nic);
		return res;
	}

	// check operation
	if (operation != 1 && operation != 2)
	{
		PrintUsingMutexArp("ARP Operation is not supported. Dropping Packet...!\n", nic);
		return res;
	}

	// find ip
	if (operation == 2) {
		pthread_mutex_lock(&Mutex_T);
		ArpTableEntry* entry = (ArpTableEntry*)arplookup(sender_ip, false);
		if (entry != NULL)
		{
			entry->DestMAC = mac_sender;
			entry->Result = true;
			for (vector<send_tuple*>::iterator data_iterator = entry->VectorOfWaiters->begin();
				data_iterator != entry->VectorOfWaiters->end();
				data_iterator++)
			{
				PrintUsingMutexArp("Sending packet!\n", nic);
				res += this->nic->getUpperInterface()->sendToL2((*data_iterator)->send_data,
					(*data_iterator)->send_data_len, AF_UNSPEC, entry->DestMAC, ETHERNET_TYPE_IP, entry->DestIp);
				delete[](*data_iterator)->send_data;
				delete (*data_iterator);
			}

			entry->VectorOfWaiters->clear();
			entry->LastUsedTime = time(0);
		}
		else {
			PrintUsingMutexArp("Adding IP/MAC pair to ARP table.\n", nic);

			if (sender_ip.compare(nic->myIP) != 0 && sender_ip.compare(IP_LOCALHOST) != 0)
			{
				entry = new ArpTableEntry(true, sender_ip, mac_sender);
				EntriesVector.push_back(entry);
			}
		}

		pthread_mutex_unlock(&Mutex_T);
	}

	if (operation == 1)
	{
		if (target_ip.compare(nic->myIP) == 0)
		{
			return (int)SendArpReply(sender_ip, nic->myIP, mac_sender, nic->myMACAddr);
		}
		else
		{
			PrintUsingMutexArp("Target IP does not match host IP, Dropping packet...!\n", nic);
			return FAILURE_CODE;
		}
	}

	return res;
}

void* L2_ARP::SendArpReply(string itaddr, string isaddr, string hw_tgt, string hw_snd)
{
	uint8_t mac_c[MAC_LENGTH];
	uint32_t i_mac[MAC_LENGTH];
	uint64_t source_mac, dest_mac;
	// convert mac to int
	sscanf(hw_tgt.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[5], &i_mac[4], &i_mac[3], &i_mac[2], &i_mac[1], &i_mac[0]);
	for (int i = 0; i < MAC_LENGTH; i++) {
		mac_c[i] = (unsigned char)i_mac[i];
	}

	source_mac = *((uint64_t*)mac_c);
	sscanf(hw_snd.c_str(), "%x:%x:%x:%x:%x:%x", &i_mac[5], &i_mac[4], &i_mac[3], &i_mac[2], &i_mac[1], &i_mac[0]);
	for (int i = 0; i < MAC_LENGTH; i++) {
		mac_c[i] = (unsigned char)i_mac[i];
	}

	dest_mac = *((uint64_t*)mac_c);

	// print the ARP reply 
	pthread_mutex_lock(&(nic->print_mutex));
	cout << "Sending ARP Reply: I am " << isaddr << "!\n";
	PrintARP(1, ETHERNET_TYPE_IP, MAC_LENGTH, 4, hw_tgt, itaddr, hw_snd, isaddr);
	pthread_mutex_unlock(&(nic->print_mutex));

	// Create reply
	byte* buf = new byte[ARP_DATA_SIZE];
	memset(buf, 0, ARP_DATA_SIZE);
	*((uint16_t*)(buf)) = htons(1);
	*((uint16_t*)(buf + 2)) = htons(ETHERNET_TYPE_IP);
	*((uint8_t*)(buf + 4)) = MAC_LENGTH;
	*((uint8_t*)(buf + 5)) = 4;
	*((uint16_t*)(buf + 6)) = htons(2);
	*((uint64_t*)(buf + 8)) = source_mac;
	*((uint32_t*)(buf + 14)) = inet_addr(itaddr.c_str());
	*((uint64_t*)(buf + 18)) = dest_mac;
	*((uint32_t*)(buf + 24)) = inet_addr(isaddr.c_str());
	int res = this->nic->getUpperInterface()->sendToL2(buf, ARP_DATA_SIZE, AF_UNSPEC, hw_tgt, ETHERNET_TYPE_ARP, itaddr);
	delete[] buf;
	return (void*)res;
}



