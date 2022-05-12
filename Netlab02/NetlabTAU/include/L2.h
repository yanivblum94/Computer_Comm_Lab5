#ifndef L2_H_
#define L2_H_
#include "Types.h"
#include <pthread.h>
#include <string>

class L3;
class NIC;

/**
* \class L2
* \brief Represents a Layer 2 interface (Ethernet).
*/
class L2 {
public:

	/**
	* \brief Constructs an L2 interface.
	*
	* \param debug \a (bool)
	* \parblock
	* Decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	*/
	L2(bool debug = false);

	/**
	* \brief L2 destructor.
	*
	* Deletes the interface. nic and upperInterface are \b not destroyed. That means after calling this function,
	* \b you are responsible to delete them.
	*/
	~L2();

	/**
	* \brief L2 output routine.
	*
	* This method wrap data of type <b>family</b> with an Ethernet header
	* and sends the data to lestart. In addition, might use ARP
	* to resolve the destination MAC address.
	*
	* \param sendData \a (byte*) The data to be sent.
	* \param sendDataLen \a (size_t) The length of the data to be sent.
	* \param family \a (uint16_t)
	* \parblock
	* Family type of the data. Supported types are <b>AF_INET</b>, <b>AF_UNSPEC</b>
	* and maybe others (however others are not mandatory).
	* \endparblock
	* \param spec_mac \a (string)
	* \parblock
	* Some protocols, such as ARP, need to specify the Ethernet destination and type explicitly.
	* This case is indicated by the family type of the data. Ergo, it isn't necessary to call
	* arpresolve (as for AF_INET) because the Ethernet destination address has been provided
	* explicitly by the caller.
	* \endparblock
	* \param spec_type \a (uint16_t) explict type specification (along the explict MAC specification).
	* \param dst_addr \a (string) [OPTIONAL] The IP destination address to which the data is sent. Can be used by ARP or left as "".
	* \retval int the number of bytes that were sent (or held for future send).
	*/
	int sendToL2(byte* sendData, size_t sendDataLen, uint16_t family, std::string spec_mac, uint16_t spec_type, std::string dst_addr = "");

	/**
	* \brief L2 input routine.
	*
	* This method was called by the leread (member function of the NIC class).
	* It unwraps the Ethernet header of the received data, drops invalid packets,
	* passes the unwraped data to the correct upper interface (i.e ARP and IP in
	* our case) and possibly prints relevant information.
	*
	* \param recvData \a (byte*) The received data.
	* \param recvDataLen \a (size_t) The length of the received data.
	* \retval int the number of bytes that were received.
	*/
	int recvFromL2(byte* recvData, size_t recvDataLen);

	/**
	* \brief Setter for the pointer to the NIC to be used by this layer.
	*
	* \param nic \a (NIC*) the NIC to be used by this layer.
	*/
	void setNIC(NIC* nic);

	/**
	* \brief Getter for the pointer to the NIC used by this layer.
	*
	* \retval NIC* the NIC used by this layer.
	*/
	NIC* getNIC();

	/**
	* \brief Setter for the pointer to the L3 to be used by this layer.
	*
	* \param upperInterface \a (L3*) the L3 to be used by this layer.
	*/
	void setUpperInterface(L3* upperInterface);

	/**
	* \brief Getter for the name of the lowest interface.
	*
	* \retval string the name of the lowest interface.
	*/
	std::string getLowestInterface();

private:
	bool debug;
	L3* upperInterface;
	NIC* nic;
};

#endif /* L2_H_ */


