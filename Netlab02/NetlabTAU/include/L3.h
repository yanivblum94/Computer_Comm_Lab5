/*
* Author: Tom Mahler
* Date: May 2015
*/
#ifndef L3_H_
#define L3_H_
#include "Types.h"
#include <string>

class L2;
class L4;

/**
* \class L3
* \brief Represents a Layer 3 interface (IP).
*/
class L3{
public:

	/**
	* \brief Constructs an L3 interface.
	*
	* May use it to initiate variables and data structure that you wish to use.
	* Should remain empty by default (if no global class variables are beeing used).
	* 
	* \param debug \a (bool)
	* \parblock
	* Decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	*/
	L3(bool debug);

	/**
	* \brief L3 output routine.
	*
	* This method wrap data with an IP header specifically for an ICMP request
	* packet and sends the data to sendToL2.
	*
	* \param sendData \a (byte*) The data to be sent.
	* \param sendDataLen \a (size_t) The length of the data to be sent.
	* \param srcIP \a (string) The source IP address (from NIC::myIP).
	* \param destIP \a (string) The destination IP address (from the main).
	* \retval int the number of bytes that were sent (from sendToL2).
	*/
	int sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP);

	/**
	* \brief L3 input routine.
	*
	* This method was called by the recvFromL2 (member function of the L2 class).
	* It unwraps the IP header of the received data, drops invalid packets,
	* passes the unwraped data to the correct upper interface and possibly prints
	* relevant information.
	*
	* \param recvData \a (byte*) The received data.
	* \param recvDataLen \a (size_t) The length of the received data.
	* \retval int the number of bytes that were received.
	*/
	int recvFromL3(byte *recvData, size_t recvDataLen);

	/**
	* \brief Setter for the pointer to the L2 to be used by this layer.
	*
	* \param lowerInterface \a (L2*) the L2 to be used by this layer.
	*/
	void setLowerInterface(L2* lowerInterface);

	/**
	* \brief Setter for the pointer to the L4 to be used by this layer.
	*
	* \param upperInterface \a (L4*) the L4 to be used by this layer.
	*/
	void setUpperInterface(L4* upperInterface);

	/**
	* \brief Getter for the name of the lowest interface.
	*
	* \retval string the name of the lowest interface.
	*/
	std::string getLowestInterface();

private:
	bool debug;
	L2* lowerInterface;
	L4* upperInterface;
};





#endif /* L3_H_ */