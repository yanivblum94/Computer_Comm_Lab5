//Yaniv Blum 312253586
//Gai Greenberg 205431224

#include "L3.h"
#include "L2.h"
#include <iostream>
#include <winsock2.h>

using namespace std;

#define DebugPrint(str) if(debug) cout << str 
#define PRINT_COMMA DebugPrint(" , ")

#define FAIL_CODE 0
#define SUCCESS_CODE 1

//Masks
#define CHECK_SUM_MASK 0xFFFF
#define CHECK_SUM_SIZE_MASK 0x80000000
#define CHECK_SUM_SHIFT_RIGHT 16
#define IHL_MASK 0xF

//offsets
#define TYPE_OF_SERVICE_OFFSET 1
#define TOTAL_LENGTH_OFFSET 2
#define IDENTIFICATIONS_OFFSET 4
#define FLAGS_OFFSET 6
#define TTL_OFFSET 8
#define PROTOCOL_OFFSET 9
#define HEADER_CHECK__SUM_OFFSET 10
#define SRC_ADDRESS_OFFSET 12
#define DST_ADDRESS_OFFSET 16

//constants
#define IP_VERSION 4 //ipv4
#define IP_NO_FRAG_FLAG 2//2 bytes
#define TTL 64// 64 bytes
#define ICMP_PROTOCOL 1//1 byte
#define IP_TOS 0
#define IP_HEADER_SIZE 20 //20 bytes
#define ETHERNET_HEADER_LEN 14// 14 bytes
#define IP_MAX_FRAME_SIZE 1500//MTU


class IP_packet {
public:
	//members
	struct header_IP {
		uint8_t version : 4;
		uint8_t ihl : 4;
		uint8_t type_of_service;
		uint16_t total_len;
		uint16_t identifications;
		uint8_t flags : 3;
		uint16_t fragmentation_offset : 13;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t header_checksum;
		uint32_t src_addr;
		uint32_t dst_addr;
	};
	struct header_IP Header;
	byte* DataLayer4;
	size_t DataLayer4Len;
	
	//methods
	//ctors and dtor
	IP_packet::IP_packet(bool debug);
	IP_packet(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug);
	~IP_packet();

	//regular methods
	void SetIPHeader(byte* buff);
	uint16_t GetChecksum();
	int ConverPacketFromBinary(byte* binary_data, int data_size);
	bool CheckBinaryPacket(byte* binary_data, int data_size);
	bool IsPacketValid();
	void PrintPacket();
	void PrintIPAddress(byte* adr);

private:
	bool debug;
};

IP_packet::IP_packet(bool debug)
{
	this->debug = debug;
}

IP_packet::IP_packet(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug)
{
	//data
	this->DataLayer4 = sendData;
	this->DataLayer4Len = sendDataLen;
	this->Header.total_len = (uint16_t)(IP_HEADER_SIZE + this->DataLayer4Len);

	//IP's
	this->Header.src_addr = inet_addr(srcIP.c_str());
	this->Header.dst_addr = inet_addr(destIP.c_str());
	// debug
	this->debug = debug;

	//constants
	this->Header.version = IP_VERSION;
	this->Header.ihl = IP_HEADER_SIZE / sizeof(word);
	this->Header.type_of_service = IP_TOS;
	this->Header.flags = IP_NO_FRAG_FLAG;
	this->Header.ttl = TTL;
	this->Header.protocol = ICMP_PROTOCOL;
	this->Header.fragmentation_offset = 0;
	this->Header.identifications = 0;

	//calculated CRC
	this->Header.header_checksum = GetChecksum();
}


IP_packet::~IP_packet() {}

void IP_packet::SetIPHeader(byte* buff)
{
	header_IP hdr = this->Header;
	*buff = (hdr.version << 4) + hdr.ihl; //1st byte
	*(buff + TYPE_OF_SERVICE_OFFSET) = hdr.type_of_service;
	*((uint16_t*)(buff + TOTAL_LENGTH_OFFSET)) = htons(hdr.total_len);
	*((uint16_t*)(buff + IDENTIFICATIONS_OFFSET)) = htons(hdr.identifications);
	uint16_t flags_byte = hdr.flags;
	flags_byte = flags_byte << 13; //13 bits offset
	flags_byte += hdr.fragmentation_offset;
	*((uint16_t*)(buff + FLAGS_OFFSET)) = htons(flags_byte);
	*(buff + TTL_OFFSET) = hdr.ttl;
	*(buff + PROTOCOL_OFFSET) = hdr.protocol;
	*((uint16_t*)(buff + HEADER_CHECK__SUM_OFFSET)) = htons(hdr.header_checksum);
	*((uint32_t*)(buff + SRC_ADDRESS_OFFSET)) = hdr.src_addr;
	*((uint32_t*)(buff + DST_ADDRESS_OFFSET)) = hdr.dst_addr;
}


uint16_t IP_packet::GetChecksum()
{
	uint32_t res = 0;
	//get binary header 
	byte* data = new byte[IP_HEADER_SIZE];
	SetIPHeader(data);
	const byte* hdr = data;
	int header_len = IP_HEADER_SIZE;
	do {
		res += *((uint16_t*)hdr);
		if (res & CHECK_SUM_SIZE_MASK) {
			res = (res >> CHECK_SUM_SHIFT_RIGHT) + (res & CHECK_SUM_MASK);
		}
		header_len -= 2;
		hdr += 2;
	} while (header_len > 1);

	if (header_len != 0) 
		res += *hdr;
	
	while (res >> CHECK_SUM_SHIFT_RIGHT) {
		res = (res >> CHECK_SUM_SHIFT_RIGHT) + (res & CHECK_SUM_MASK);
	}

	delete[] data;
	return htons(~res);
}

int IP_packet::ConverPacketFromBinary(byte* binary_data, int data_size) {
	if (!CheckBinaryPacket(binary_data, data_size)) {
		DebugPrint("[ERROR!] packet is invalid\n");
		return 0;
	}

	this->Header.type_of_service = *(binary_data + TYPE_OF_SERVICE_OFFSET);
	this->Header.total_len = ntohs(*((uint16_t*)(binary_data + TOTAL_LENGTH_OFFSET)));
	this->Header.identifications = ntohs(*((uint16_t*)(binary_data + IDENTIFICATIONS_OFFSET)));
	uint16_t flags_byte = ntohs(*((uint16_t*)(binary_data + FLAGS_OFFSET)));
	this->Header.flags = flags_byte >> 13;
	this->Header.fragmentation_offset = flags_byte & 0x1FFFF;
	this->Header.ttl = *(binary_data + TTL_OFFSET);
	this->Header.protocol = *(binary_data + PROTOCOL_OFFSET);
	this->Header.header_checksum = ntohs(*((uint16_t*)(binary_data + HEADER_CHECK__SUM_OFFSET)));
	this->Header.src_addr = *((uint32_t*)(binary_data + SRC_ADDRESS_OFFSET));
	this->Header.dst_addr = *((uint32_t*)(binary_data + DST_ADDRESS_OFFSET));
	this->DataLayer4Len = data_size - IP_HEADER_SIZE;
	this->DataLayer4 = binary_data + IP_HEADER_SIZE;
	return SUCCESS_CODE;
}


bool IP_packet::IsPacketValid()
{
	bool res = true;

	//check if it's icmp
	if (this->Header.protocol != ICMP_PROTOCOL) {
		DebugPrint("ERROR! protocol is not ICMP\n");
		res = false;
	}

	// CRC check (should be 0)
	if (this->GetChecksum() != 0) {
		DebugPrint("ERROR! Incorrect header_checksum\n");
		res = false;
	}


	//check if the length of data is longest then max length allowed
	if (this->DataLayer4Len > (IP_MAX_FRAME_SIZE - IP_HEADER_SIZE)) {
		DebugPrint("ERROR! Data Length Too big\n");
		res = false;
	}

	//if time_to_live is 0
	if (this->Header.ttl == 0) {
		DebugPrint("ERROR! Time To Live Is Zero\n");
		res = false;
	}

	return res;
}

bool IP_packet::CheckBinaryPacket(byte* binary_data, int data_size) {

	this->Header.version = *binary_data >> 4;
	if (this->Header.version != IP_VERSION) {
		DebugPrint("[ERROR!] packet version is not supported (not IP_VERSION)\n");
		return false;
	}

	this->Header.ihl = *binary_data & IHL_MASK;

	if (this->Header.ihl != IP_HEADER_SIZE / sizeof(word)) {
		DebugPrint("[ERROR!] incorrect ihl\n");
		return false;
	}

	if (data_size < IP_HEADER_SIZE) {
		DebugPrint("[ERROR!] packet size is smaller than IP_HEADER_SIZE\n");
		return false;
	}

	return true;
}


void IP_packet::PrintIPAddress(byte* adr){
	for (int i = 0; i < 4; i++)
	{
		DebugPrint((uint16_t)adr[i]);
		if (i < 3)
			DebugPrint(".");
	}
}

void IP_packet::PrintPacket() {
	header_IP hdr = this->Header;
	DebugPrint("< IP(" << std::dec << (((uint16_t)hdr.ihl) * sizeof(word)) << " bytes) :: ");
	DebugPrint("version = " << (uint16_t)hdr.version << " , ");
	DebugPrint("Header length = " << (uint16_t)hdr.ihl << " , ");
	DebugPrint("DiffServicesCP = " << (hdr.type_of_service >> 2) << " , ");
	DebugPrint("ExpCongestionNot = " << (hdr.type_of_service & 0x3) << " , ");
	DebugPrint("Total length = " << hdr.total_len << " , ");
	DebugPrint("Identifications = 0x");
	DebugPrint(std::hex << hdr.identifications << std::dec);
	PRINT_COMMA;
	DebugPrint("Flags = " << (uint16_t)hdr.flags << " , ");
	DebugPrint("Fragment Offset = " << hdr.fragmentation_offset << " , ");
	DebugPrint("TTL = " << (uint16_t)hdr.ttl << " , ");
	DebugPrint("Protocol= 0x");
	DebugPrint(std::hex << (uint16_t)hdr.protocol << std::dec);
	PRINT_COMMA;
	DebugPrint("Check Sum = 0x");
	DebugPrint(std::hex << hdr.header_checksum << std::dec);
	PRINT_COMMA;
	byte* src = (byte*)&(hdr.src_addr);
	byte* dst = (byte*)&(hdr.dst_addr);
	DebugPrint("Source IP = ");
	PrintIPAddress(src);
	PRINT_COMMA;
	DebugPrint("Destination IP = ");
	PrintIPAddress(dst);
	DebugPrint(" , >\n");
}

/*	
	L3 constructor, use it to initiate variables and data structure that you wish to use. 
	Should remain empty by default (if no global class variables are beeing used).
*/
L3::L3(bool debug) { this->debug = debug; }

/*	
	sendToL3 is called by the upper layer via the upper layer's L3 pointer.
	sendData is the pointer to the data L4 wish to send.
	sendDataLen is the length of that data.
	srcIP is the machines IP address that L4 supplied.
	destIP is the destination IP address that L4 supplied.
	debug is to enable print (use true)
*/
int L3::sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP) {
	byte* buff = new byte[IP_MAX_FRAME_SIZE];
	IP_packet* packet = new IP_packet(sendData, sendDataLen, srcIP, destIP, debug); //new packet
	if (!packet->IsPacketValid()) { //if packet is invalid
		delete packet;
		return FAIL_CODE;
	}
	packet->SetIPHeader(buff);
	memcpy(buff + IP_HEADER_SIZE, packet->DataLayer4, packet->DataLayer4Len);
	int res = lowerInterface->sendToL2(buff, IP_HEADER_SIZE + sendDataLen, AF_INET, "", 0);
	delete packet;
	delete[] buff;
	return res;
}

/*
	recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
	recvData is the pointer to the data L4 wish to receive.
	recvDataLen is the length of that data.
	debug is to enable print (use true)
*/
int L3::recvFromL3(byte *recvData, size_t recvDataLen) {
	byte *buff = new byte[recvDataLen - IP_HEADER_SIZE];
	int res = 0;
	if (recvDataLen > 0) {
		if (debug) {
			cout << " IP packet received" << endl;
		}
		if (recvDataLen < IP_HEADER_SIZE || recvDataLen > IP_MAX_FRAME_SIZE) {
			if (debug) { 
				cout << " IP packet size" << endl; 
			}
		}
		// Validate packet
		else {
			IP_packet* packet = new IP_packet(debug); //empty packet
			if (packet->ConverPacketFromBinary(recvData, recvDataLen) != 0 && packet->IsPacketValid()) {
				if (debug) {
					packet->PrintPacket();
				}

				memcpy(buff, recvData + IP_HEADER_SIZE, recvDataLen - IP_HEADER_SIZE);
				res = upperInterface->recvFromL4(buff, recvDataLen - IP_HEADER_SIZE);
			}
			delete packet;
		}
	}
	else if (debug) { cout << " L3::recvFromL3() : No Packets recieved." << endl; }

	delete[] buff;
	return res;
}

/*
	Implemented for you
*/
void L3::setLowerInterface(L2* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
	Implemented for you
*/
void L3::setUpperInterface(L4* upperInterface){ this->upperInterface = upperInterface; }

/*
	Implemented for you
*/
std::string L3::getLowestInterface(){ return lowerInterface->getLowestInterface(); }