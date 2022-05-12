/*
* Author: Tom Mahler
* Date: May 2015
*/
#ifndef L2_ARP_H_
#define L2_ARP_H_
#include "L2.h"


class NIC;

/**
* \class L2_ARP
* \brief Address Resolution Protocol.
* 
* See RFC 826 for protocol description. ARP packets are variable
* in size; the arp header defines the fixed-length portion.
* Protocol type values are the same as those for 10 Mb/s Ethernet.
* It is followed by the variable-sized fields ar_sha, arp_spa,
* arp_tha and arp_tpa in that order, according to the lengths
* specified. Field names used correspond to RFC 826.
*/
class L2_ARP{
public:

	/**
	* \brief Constructs an ARP interface.
	*
	* \param debug \a (bool)
	* \parblock
	* decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	*/
	L2_ARP(bool debug);
	
	/**
	* \brief ARP destructor.
	*
	* Deletes the interface. nic is \b not destroyed. That means after calling this function,
	* \b you are responsible to delete it.
	*/
	~L2_ARP();

	/**
	* \brief Setter for the pointer to the NIC to be used by this layer.
	*
	* \param nic \a (NIC*) the NIC to be used by this layer.
	*/
	void setNIC(NIC* nic);

	/**
	* \brief Broadcast an ARP request.
	*
	* Caller specifies:
	*	- arp header source ip address
	*	- arp header target ip address
	*	- arp header source Ethernet address
	* 
	* \param ip_addr \a (string) Target ip address.
	* \retval The number of bytes sent.
	*/
	int arprequest(std::string ip_addr);

	/**
	* \brief Resolve an IP address into an Ethernet address.
	*
	* If there is no entry in the arp table, set one up and 
	* broadcast a request for the IP address.
	* Hold onto this data and resend it once the address
	* is finally resolved. 
	* A return value of "" indicates that the packet has been
	* taken over here, either now or for later transmission,
	* else, returns the resolved destination MAC address which
	* indicates the packet should be sent normally.
	* 
	* \param ip_addr \a (string) Target ip address.
	* \param sendData \a (byte*) Data to hold onto if the address is not yet resolved.
	* \param sendDataLen \a (size_t) Length of data to hold onto if the address is not yet resolved.
	* \retval string The resolved MAC address ("" if not yet resolved).
	*/
	std::string arpresolve(std::string ip_addr, byte* sendData, size_t sendDataLen);

	/**
	* \brief Lookup and/or create a new entry in the arp table.
	*
	* Implementation is your's to decide, everything written on this function is only a suggestion:
	* 	- You can (and should) add more functions to help creating and maintaing the table.
	* 	- Its highly recommended to change the return type \a (void*) to your implementation of an ARP table entry.
	* 	- You can add more arguments to the input, or change the existing to whatever you want.
	*
	* \param ip_addr \a (string) Target ip address.
	* \param create \a (bool) Decides whether to create the entry if one does not exists.
	* \param ADITIONAL \a (...) ADD YOUR IMPLEMENTATION HERE
	* \retval YOUR_ARP_ENTRY The entery containg the ip_addr (NULL if not yet resolved).
	*/
	void* arplookup(std::string ip_addr, bool create);

	/**
	* \brief ARP for Internet protocols on 10 Mb/s Ethernet.
	*
	* Algorithm is that given in RFC 826.
	* Called by recvFromL2 when an ARP packet arrives.
	* If the arriving packet is an ARP Reply, then the method should
	* check if a packet is beeing held onto (as a result of an 
	* unresolved prior arpresolve call), resolve the MAC address,
	* send the held packet and free the held packet from the ARP entry.
	* If the arriving packet is an ARP Request, then the method should
	* generate an ARP Reply and send it to whoever requested it.
	* In addition, sanity checks should be performed on the sender
	* protocol address, to catch impersonators.
	*
	* \param recvData \a (byte*) The data to be sent.
	* \param recvDataLen \a (size_t) The length of the data to be sent.
	* \retval int the number of bytes that were received.
	*/
	int in_arpinput(byte *recvData, size_t recvDataLen);

	/**
	* \brief Send an ARP Reply.
	*
	* Implementation is your's to decide, everything written on this function is only a suggestion:
	* 	- You can (and should) add more functions to help creating and maintaing the table.
	* 	- Its highly recommended to change the return type \a (void*) to your implementation of an ARP table entry.
	* 	- You can add more arguments to the input, or change the existing to whatever you want.
	*
	* \param itaddr \a (string) Target ip address.
	* \param isaddr \a (string) Sender ip address.
	* \param hw_tgt \a (string) Target hardware (MAC) address.
	* \param hw_snd \a (string) Sender hardware (MAC) address.
	* \param ADITIONAL \a (...) ADD YOUR IMPLEMENTATION HERE
	* \retval YOUR_RETURN_VALUE
	*/
	void* SendArpReply(std::string itaddr, std::string isaddr, std::string hw_tgt, std::string hw_snd);

private:
	bool debug;
	NIC * nic;

	/* ADD YOUR ARP TABLE AND ADDITIONAL VARIABLES HERE */
};


#endif /* L2_ARP_H_ */