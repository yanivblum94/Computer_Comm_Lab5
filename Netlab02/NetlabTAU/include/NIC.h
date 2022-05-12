/*
* Author: Tom Mahler
* Date: May 2015
*/
#ifndef NIC_H_
#define NIC_H_
#include "Types.h"
#include <stdint.h>
#include <pthread.h>
#include <string>

class L2;
class L2_ARP;
class NIC_Cable;

/**
* \class NIC
* \brief Represents a virtual Network Interface Card.
*/
class NIC {
public:

	/**
	* \brief Constructs a virtual NIC.
	*
	* \param debug \a (bool)
	* \parblock
	* Decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	* \param promisc_mode \a (bool) 
	* \parblock
	* Dcides the whether the NIC is in promiscuous mode (which opens the NIC to
	* read any packet that comes in) or not (in which the NIC drops any packet 
	* which is not destined for the NIC's MAC address and not a broadcast)
	* Default value is true.
	* \endparblock
	* \param filter \a (string)
	* \parblock
	* Enables the use of explicit filters, following the syntax of of pcap filter
	* found in <a href="https://www.winpcap.org/docs/docs_40_2/html/group__language.html">Winpcap filtering expression syntax</a> 
	* Note that this is given to you \b ONLY for debuging purposes. Final submission must
	* Support default values.
	* Default value is "".
	* \endparblock
	*/
	NIC(bool debug = false, bool promisc_mode = true, std::string filter = "");

	/**
	* \brief NIC destructor.
	*
	* Disconects the NIC, destroy print_mutex, destroy cable and deletes the interface.
	* L2_ARP *NICsARP and L2 *upperInterface; are \b not destroyed. That means after calling this function,
	* \b you are responsible to delete them.
	*/
	~NIC();

	/**
	* \brief Virtualy connects the cable to the NIC.
	*
	* In other wards, turns the NIC on.
	* 
	* \param count \a (uint32_t) Limit the number of packets to read. Default value is 0 meaning constantly reading received packets.
	*/
	void connect(uint32_t count = 0U);

	/**
	* \brief Virtualy disconnects the cable from the NIC.
	*
	* In other wards, turns the NIC off.
	*/
	void disconnect();


	/**
	* \brief NIC input routine.
	*
	* This method reads the packet from the wire and call recvFromL2
	* for further proccess.
	*
	* \param recvData \a (byte*) The data read from the wire.
	* \param recvDataLen \a (size_t) The length of the read data.
	* \retval int the return value in bytes of recvFromL2.
	*/
	int leread(byte *recvData, size_t recvDataLen);

	/**
	* \brief NIC output routine.
	*
	* This method writes the data on the wire.
	*
	* \param sendData \a (byte*) The data to be sent.
	* \param sendDataLen \a (size_t) The length of the data to be sent.
	* \retval int the number of bytes that were sent.
	*/
	int lestart(byte *sendData, size_t sendDataLen);

	/**
	* \brief Getter for the name of the lowest interface.
	*
	* \retval string the name of the lowest interface.
	*/
	std::string getLowestInterface();

	/**
	* \brief Getter for the pointer to the L2 to be used by this layer.
	*
	* \retval L2* the pointer to the L2 to be used by this layer.
	*/
	L2 * getUpperInterface();

	/**
	* \brief Setter for the pointer to the L2 to be used by this layer.
	*
	* \param upperInterface \a (L2*) the L2 to be used by this layer.
	*/
	void setUpperInterface(L2* upperInterface);
	
	/**
	* \brief Getter for the pointer to the L2_ARP to be used by this layer.
	*
	* \retval L2_ARP* the pointer to the L2_ARP to be used by this layer.
	*/
	L2_ARP * getARP();

	/**
	* \brief Setter for the pointer to the L2_ARP to be used by this layer.
	*
	* \param NICsARP \a (L2_ARP*) the L2_ARP to be used by this layer.
	*/
	void setNICsARP(L2_ARP* NICsARP);

	/**
	* NIC's MAC address in format of xx:xx:xx:xx:xx:xx
	*/
	static std::string myMACAddr;

	/**
	* NIC's IP address in format of xxx.xxx.xxx.xxx
	*/
	static std::string myIP;
	
	/**
	* NIC's mask in format of xxx.xxx.xxx.xxx
	*/
	static std::string myNetmask;

	/**
	* NIC's broadcast IP address (in local LAN) in format of xxx.xxx.xxx.xxx
	*/
	static std::string myBcast;

	/**
	* NIC's Default Gateway address in format of xxx.xxx.xxx.xxx
	*/
	static std::string myDefaultGateway;

	/**
	* NIC's mutex for printing. Must be locked before printing and unlocked afterwards.
	*/
	static pthread_mutex_t print_mutex;

private:
	bool debug;
	L2* upperInterface;
	L2_ARP* NICsARP;
	NIC_Cable* cable;
};


#endif /* NIC_H_ */