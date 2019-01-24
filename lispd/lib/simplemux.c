#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>			// for printing uint_64 numbers
#include <stdbool.h>			// for using the bool type#include <time.h>
#include <rohc/rohc.h>			
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>
#include "simplemux.h"
#include "../liblisp/liblisp.h"
#include "lmlog.h"

extern data_simplemux_t conf_sm[10],conf_sm_pre[10]; // save previous config
extern int numdsm;

/* compression */

static struct rohc_comp *compressor;           					// the ROHC compressor
static struct rohc_decomp *decompressor;           				// the ROHC decompressor


/*  Info log*/
static FILE *log_file;											// file descriptor of the log file 
static unsigned long int tun2net;								// number of packets read from tun
static unsigned long int net2tun;								// number of packets read from net


/* debugging */
extern int debug_level;		//	LCRIT   1   /* critical conditions -> Exit program */
							//  LERR    2   /* error conditions -> Not exit but should be considered by user */
							//  LWRN    3   /* warning conditions -> Low level errors. Program doesn't finish */
							//  LINF    4   /* informational -> Initial configuration, SMRs, interface change status*/
							//  LDBG_1  5   /* low debug-level messages -> Control message */
							//  LDBG_2  6   /* medium debug-level messages -> Errors in received packets. Wrong AFI, ...  */
							//  LDBG_3  7   /* high debug-level messages -> Log for each received or generated packet */



/**************************************************************************
 * FromByte: return an array of booleans from a char                      *
 **************************************************************************/
// stores in 'b' the value 'true' or 'false' depending on each bite of the byte c
// b[0] is the less significant bit
// example: print the byte corresponding to an asterisk
/*bool bits2[8];
FromByte('*', bits2);
LMLOG(LDBG_1, "byte:%c%c%c%c%c%c%c%c\n", bits2[0], bits2[1], bits2[2], bits2[3], bits2[4], bits2[5], bits2[6], bits2[7]);
if (bits2[4]) {
	LMLOG(LDBG_1, "1\n");
} else {
	LMLOG(LDBG_1, "0\n");
}*/
void FromByte(unsigned char c, bool b[8])
{
	int i;
	for (i=0; i < 8; ++i)
		b[i] = (c & (1<<i)) != 0;
}


/**************************************************************************
 * PrintByte: prints the bits of a byte                                   *
 **************************************************************************/
void PrintByte(int level, int num_bits, bool b[8])
{
	// num_bits is the number of bits to print
	// if 'num_bits' is smaller than 7, the function prints an 'x' instead of the value

	int i;
	char print_b[9]="\0";
	
	for (i= 7 ; i>= num_bits ; i--) {
		print_b[7-i] = 'x';
	}
	
	for (i= num_bits - 1 ; i>=0 ; i--) {
		if (b[i]) {
			print_b[7 - i] = '1';
		} else {
			print_b[7 - i] = '0';
		}
	}

	LMLOG(level, "%s",print_b);

	/*for (i= 7 ; i>= num_bits ; i--) {
			LMLOG(level, "x");
	}
	for (i= num_bits -1 ; i>=0; i--) {
		if (b[i]) {
			LMLOG(level, "1");
		} else {
			LMLOG(level, "0");
		}
	}*/

}


/**************************************************************************
************ dump a packet ************************************************
**************************************************************************/
void dump_packet (int packet_size, unsigned char packet[BUFSIZE])
{
	int j;
	int new_line = 1;
	char acum[80]="\0";
	char acum_aux[80]="\0";

	for(j = 0; j < packet_size; j++)
	{
		if (new_line == 1) {
			sprintf(acum,"%02x ", packet[j]);
			new_line = 0;
		}
		if(j != 0 && ((j + 1) % 16) == 0)
		{
			LMLOG(LDBG_2, "   %s",acum);
			new_line = 1;
		}
		// separate in groups of 8 bytes
		else if((j != 0 ) && ((j + 1) % 8 == 0 ) && (( j + 1 ) % 16 != 0))
		{
			strcat (acum,"  ");
		}
		else if(j != 0 && ((j ) % 16) != 0) {
			sprintf(acum_aux,"%02x ", packet[j]);
			strcat (acum,acum_aux);
		}
	}
	
	if(j != 0 && ((j ) % 16) != 0) /* be sure to go to the line */
	{
		LMLOG(LDBG_2, "   %s",acum);
	}

	/*for(j = 0; j < packet_size; j++)
	{
		LMLOG(LDBG_2, "%02x ", packet[j]);
		if(j != 0 && ((j + 1) % 16) == 0)
		{
			LMLOG(LDBG_2, "\n");
			if ( j != (packet_size -1 )) LMLOG(LDBG_2,"   ");
		}
		// separate in groups of 8 bytes
		else if((j != 0 ) && ((j + 1) % 8 == 0 ) && (( j + 1 ) % 16 != 0))
		{
			LMLOG(LDBG_2, "  ");
		}
	}
	if(j != 0 && ((j ) % 16) != 0) // be sure to go to the line 
	{
		LMLOG(LDBG_2, "\n");
	}*/
}


/**************************************************************************
 * GetTimeStamp: Get a timestamp in microseconds from the OS              *
 **************************************************************************/
uint64_t GetTimeStamp() {
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return tv.tv_sec*(uint64_t)1000000+tv.tv_usec;
}

/**************************************************************************
 * return an string with the date and the time in format %Y-%m-%d_%H.%M.%S*
 **************************************************************************/
int date_and_time(char buffer[25])
{
	time_t timer;
	struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);
	strftime(buffer, 25, "%Y-%m-%d_%H.%M.%S", tm_info);
	return EXIT_SUCCESS;
}


/**************************************************************************
 *                   build the multiplexed packet                         *
 **************************************************************************/
// it takes all the variables where packets are stored, and builds a multiplexed packet
// the variables are:
//	- prot[MAXPKTS][SIZE_PROTOCOL_FIELD]	the protocol byte of each packet
//	- size_separators_to_mux[MAXPKTS]		the size of each separator (1 or 2 bytes). Protocol byte not included
//	- separators_to_mux[MAXPKTS][2]			the separators
//	- size_packets_to_mux[MAXPKTS]			the size of each packet to be multiplexed
//	- packets_to_mux[MAXPKTS][BUFSIZE]		the packet to be multiplexed

// the multiplexed packet is stored in mux_packet[BUFSIZE]
// the length of the multiplexed packet is returned by this function
uint16_t build_multiplexed_packet ( int num_packets, int single_prot, unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD], uint16_t size_separators_to_mux[MAXPKTS], unsigned char separators_to_mux[MAXPKTS][3], uint16_t size_packets_to_mux[MAXPKTS], unsigned char packets_to_mux[MAXPKTS][BUFSIZE], unsigned char mux_packet[BUFSIZE])
{
	int k, l;
	int length = 0;

	// for each packet, write the protocol field (if required), the separator and the packet itself
	for (k = 0; k < num_packets ; k++) {

		if ( PROTOCOL_FIRST ) {
			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
			}
	
			// add the separator
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}
		} else {
			// add the separator
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}
			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
			}
		}

		// add the bytes of the packet itself
		for (l = 0; l < size_packets_to_mux[k] ; l++) {
			mux_packet[length] = packets_to_mux[k][l];
			length ++;
		}
	}
	return length;
}


/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//	- prot[MAXPKTS][SIZE_PROTOCOL_FIELD]	the protocol byte of each packet
//	- size_separators_to_mux[MAXPKTS]		the size of each separator (1 or 2 bytes). Protocol byte not included
//	- separators_to_mux[MAXPKTS][2]			the separators
//	- size_packets_to_mux[MAXPKTS]			the size of each packet to be multiplexed
//	- packets_to_mux[MAXPKTS][BUFSIZE]		the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet ( int num_packets, int single_prot, unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD], uint16_t size_separators_to_mux[MAXPKTS], unsigned char separators_to_mux[MAXPKTS][3], uint16_t size_packets_to_mux[MAXPKTS], unsigned char packets_to_mux[MAXPKTS][BUFSIZE])
{
	int k, l;
	int length = 0;

	// for each packet, read the protocol field (if present), the separator and the packet itself
	for (k = 0; k < num_packets ; k++) {

		// count the 'Protocol' field if necessary
		if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					length ++;
				}
		}
	
		// count the separator
		for (l = 0; l < size_separators_to_mux[k] ; l++) {
			length ++;
		}

		// count the bytes of the packet itself
		for (l = 0; l < size_packets_to_mux[k] ; l++) {
			length ++;
		}
	}
	return length;
}



/**************************************************************************************/	
/***************** TUN to NET: compress and multiplex *********************************/
/**************************************************************************************/

// This function return: 0 if a muxed packet is NOT built
//	 1, if a muxed packet is built to be sent	
//	 2, if a previous muxed packet is built to be sent because maximum size is reached. This function must be called again, using the same input parameters. 

int mux_packets (unsigned char *packet_in, uint32_t size_packet_in, data_simplemux_t *data_simplemux, unsigned char *out_muxed_packet, uint16_t *out_total_length, int aux_protocol)

{

	// value to return by this function
	int result = 0;											
	
	// variables for controlling the arrival and departure of packets

	int interface_mtu;						// the maximum transfer unit of the interface 
	int user_mtu;							// the MTU specified by the user (it must be <= interface_mtu) 
	int selected_mtu;						// the MTU that will be used in the program

	int limit_numpackets_tun;					// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
	int size_threshold;						// if the number of bytes stored is higher than this, a muxed packet is sent  
	int size_max;							// maximum value of the packet size               

	uint64_t timeout;						// (microseconds) if a packet arrives and the timeout has expired (time from the   
									// previous sending), the sending is triggered. default 100 seconds 
	uint64_t period;						// period. If it expires, a packet is sent  

	uint64_t time_last_sent_in_microsec;				// moment when the last multiplexed packet was sent


	// variables for storing the packets to multiplex

	int num_pkts_stored_from_tun;					// number of packets received and not sent from tun (stored)
	uint16_t total_length;						// total length of the built multiplexed packet
	unsigned char protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];		// protocol field of each packet
	uint16_t size_separators_to_multiplex[MAXPKTS];			// stores the size of the Simplemux separator. It does not include the "Protocol" field
	unsigned char separators_to_multiplex[MAXPKTS][3];		// stores the header ('protocol' not included) received from tun, before sending it to the network
	uint16_t size_packets_to_multiplex[MAXPKTS];			// stores the size of the received packet
	unsigned char packets_to_multiplex[MAXPKTS][BUFSIZE];		// stores the packets received from tun, before storing it or sending it to the network
	unsigned char muxed_packet[BUFSIZE];				// stores the multiplexed packet
	int size_muxed_packet;						// acumulated size of the multiplexed packet
	int first_header_written;					// it indicates if the first header has been written or not
	int drop_packet = 0;
	int predicted_size_muxed_packet;				// size of the muxed packet if the arrived packet was added to it
	int single_protocol;						// it is 1 when the Single-Protocol-Bit of the first header is 1
	int maximum_packet_length;					// the maximum lentgh of a packet. It may be 64 (first header) or 128 (non-first header)
	int limit_length_two_bytes;					// the maximum length of a packet in order to express it in 2 bytes. It may be 8192 or 16384 (non-first header)
 
 
  
  
	//indexes and counters
	int l,j,k;

	// very long unsigned integers for storing the system clock in microseconds
	uint64_t time_in_microsec;							// current time
	uint64_t time_difference;							// difference between two timestamps

	/* variables for the log file */
	bool bits[8];									// it is used for printing the bits of a byte in debug mode

	// ROHC header compression variables			
	int ROHC_mode;									// it is 0 if ROHC is not used   
											// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
											// it is 2 for ROHC Bidirectional Optimistic mode
											// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)
  int IPSEC_mode; 
                  //it is 0 in order to not use IPsec at all
                  //it is 1 in order to securize everything with IPsec through port 4344
                  //2: to check if traffic is already secure or not
                  
  float percentage_packets_secure; //minimun rate of packets in a muxed packet to introduce security or not. If calculated
                                   //ratio is < percentage_packets_secure, then packets will be sent trough IPsec port 
  
  int IPSEC_policy; 
  
  static int counter_secure_packets = 0;
  static int counter_non_secure_packets = 0;
  
	unsigned char ip_buffer[BUFSIZE];						// the buffer that will contain the IPv4 packet to compress
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFSIZE);	
	unsigned char rohc_buffer[BUFSIZE];						// the buffer that will contain the resulting ROHC packet
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFSIZE);
	rohc_status_t status;
  

	// Begin Initialize -----------------------------------------------------------------
	//-----------------------------------------------------------------------------------

	ROHC_mode = data_simplemux->ROHC_mode;	

	limit_numpackets_tun = data_simplemux->limit_numpackets_tun;		// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
										// limit of the number of packets for triggering a muxed packet 
	IPSEC_mode = data_simplemux->IPSEC_mode;
  
    percentage_packets_secure = data_simplemux->percentage_packets_secure;  
    if (IPSEC_mode == 2) {
    LMLOG (LDBG_1, "Percentage Packets Secure : %f\t ", percentage_packets_secure);
  }
	timeout = data_simplemux->timeout;					// timeout for triggering a muxed packet
										// (microseconds) if a packet arrives and the timeout has expired (time from the  
										// previous sending), the sending is triggered. default 100 seconds
	period = data_simplemux->period;							//Period for triggering a muxed packet 
	time_last_sent_in_microsec = data_simplemux->time_last_sent_in_microsec;		// moment when the last multiplexed packet was sent

	
	interface_mtu = data_simplemux->interface_mtu;	// the maximum transfer unit of the interface
	user_mtu = data_simplemux->user_mtu;			// the MTU specified by the user (it must be <= interface_mtu)
	/*** check if the user has specified a bad MTU ***/
	LMLOG (LDBG_1, "Local interface MTU: %i\t ", interface_mtu);
	if ( user_mtu > 0 ) {
		LMLOG (LDBG_1, "User-selected MTU: %i", user_mtu);
	}
	if (user_mtu > interface_mtu) {
		LMLOG (LCRIT, "Error: The MTU specified by the user is higher than the MTU of the interface\n");
		exit (1);
	} else {
		// if the user has specified a MTU, I use it instead of network MTU
		if (user_mtu > 0) {
			selected_mtu = user_mtu;
			// otherwise, use the MTU of the local interface
		} else {
			selected_mtu = interface_mtu;
		}
	}
	if (selected_mtu > BUFSIZE ) {
		LMLOG (LDBG_1, "Selected MTU: %i\t Size of the buffer for packet storage: %i", selected_mtu, BUFSIZE);
		LMLOG (LCRIT,"Error: The MTU selected is higher than the size of the buffer defined.\nCheck #define BUFSIZE at the beginning of this application\n");
		exit (1);
	}


	size_max = selected_mtu - IPv4_HEADER_SIZE - UDP_HEADER_SIZE - LISP_HEADER_SIZE;
	size_threshold = data_simplemux->size_threshold;	// if the number of bytes stored is higher than this, a muxed packet is sent
	   							// the size threshold has not been established by the user 
	if (size_threshold == 0 ) {
		size_threshold = size_max;
		//LMLOG (LDBG_1, "Size threshold established to the maximum: %i.", size_max);
	}
	// the user has specified a too big size threshold
	if (size_threshold > size_max ) {
		LMLOG (LDBG_1, "Warning: Size threshold too big: %i. Automatically set to the maximum: %i", size_threshold, size_max);
		size_threshold = size_max;
	}
		

	/*** set the triggering parameters according to user selections (or default values) ***/
	// there are four possibilities for triggering the sending of the packets:
	// - a threshold of the acumulated packet size. Two different options apply:
	// 		-	the size of the multiplexed packet has exceeded the size threshold specified by the user,
	//			but not the MTU. In this case, a packet is sent and a new period is started with the
	//			buffer empty.
	//		-	the size of the multiplexed packet has exceeded the MTU (and the size threshold consequently).
	//			In this case, a packet is sent without the last one. A new period is started, and the last 
	//			packet is stored as the first packet of the next period.
	// - a number of packets
	// - a timeout. A packet arrives. If the timeout has been reached, a muxed packet is triggered
	// - a period. If the period has been reached, a muxed packet is triggered

	// if ( timeout < period ) then the timeout has no effect
	// as soon as one of the conditions is accomplished, all the accumulated packets are sent

	// if no limit of the number of packets is set, then it is set to the maximum
	if (( (size_threshold < size_max) || (timeout < MAXTIMEOUT) || (period < MAXTIMEOUT) ) && (limit_numpackets_tun == 0))
		limit_numpackets_tun = MAXPKTS;

	// if no option is set by the user, it is assumed that every packet will be sent immediately
	if (( (size_threshold == size_max) && (timeout == MAXTIMEOUT) && (period == MAXTIMEOUT)) && (limit_numpackets_tun == 0))
		limit_numpackets_tun = 1;

	LMLOG(LDBG_1, "Multiplexing policies: size threshold: %i. numpackets: %i. timeout: %d period: %d", size_threshold, limit_numpackets_tun, timeout, period);
	
	switch(ROHC_mode) {
		case 0:
			LMLOG (LDBG_1, "ROHC not activated");
			break;
		case 1:
			LMLOG (LDBG_1, "ROHC Unidirectional Mode");
			break;
		case 2:
			LMLOG (LDBG_1, "ROHC Bidirectional Optimistic Mode");
			break;
		/*case 3:
			LMLOG (LDBG_1, "ROHC Bidirectional Reliable Mode\n");
			break;*/
	}
 

	switch(IPSEC_mode) {
		case 0:
			LMLOG (LDBG_1, "IPSEC mode 0");
			break;
		case 1:
			LMLOG (LDBG_1, "IPSEC mode 1");
			break;
		case 2:
			LMLOG (LDBG_1, "IPSEC mode 2");
			break;		
	}
 

	// variables for storing the packets to multiplex
	size_muxed_packet = data_simplemux->size_muxed_packet;						// acumulated size of the multiplexed packet
	first_header_written = data_simplemux->first_header_written;				// it indicates if the first header has been written or not


	num_pkts_stored_from_tun = data_simplemux->num_pkts_stored_from_tun ;	// number of packets received and not sent from tun (stored)

	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(protocol[j], data_simplemux->protocol[j], SIZE_PROTOCOL_FIELD*sizeof(unsigned char)); // protocol field of each packet
	
	memcpy(size_separators_to_multiplex, data_simplemux->size_separators_to_multiplex, MAXPKTS*sizeof(uint16_t));	// stores the size of the Simplemux separator. It does not include the "Protocol" field

	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(separators_to_multiplex[j], data_simplemux->separators_to_multiplex[j], 3*sizeof(unsigned char)); // stores the header ('protocol' not included) received from tun, before sending it to the network
	
	memcpy(size_packets_to_multiplex, data_simplemux->size_packets_to_multiplex, MAXPKTS*sizeof(uint16_t));			// stores the size of the received packet
	
	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(packets_to_multiplex[j], data_simplemux->packets_to_multiplex[j], BUFSIZE*sizeof(unsigned char)); // stores the packets received from tun, before storing it or sending it to the network

	// End Initialize--------------------------------------------------------------------
	//-----------------------------------------------------------------------------------

	/**************************************************************************************/	
	/***************** TUN to NET: compress and multiplex *********************************/
	/**************************************************************************************/

	if ((packet_in != NULL) && (size_packet_in != 0)) {
	
		//LMLOG(LINF, "Entro porque ha llegado un pkt");
		// data arrived at tun: read it, and check if the stored packets should be written to the network  

		/* read the packet from tun, store it in the array, and store its size */
		memcpy(packets_to_multiplex[num_pkts_stored_from_tun], packet_in, size_packet_in);
		size_packets_to_multiplex[num_pkts_stored_from_tun] = size_packet_in;
	
		/* increase the counter of the number of packets read from tun*/
		tun2net++;	

		if (debug_level > 1 ) LMLOG (LDBG_2,"\n");
		LMLOG(LDBG_1, "NATIVE PACKET #%d: Read packet from tun: %d bytes\n", tun2net, size_packets_to_multiplex[num_pkts_stored_from_tun]);

		// print the native packet received
		if (debug_level) {
			LMLOG(LDBG_2, "   ");
			// dump the newly-created IP packet on terminal
			dump_packet ( size_packets_to_multiplex[num_pkts_stored_from_tun], packets_to_multiplex[num_pkts_stored_from_tun] );
		}

		// write in the log file
		if ( log_file != NULL ) {
			fprintf (log_file, "%"PRIu64"\trec\tnative\t%i\t%lu\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
			fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
		}

		// check if this packet (plus the tunnel and simplemux headers ) is bigger than the MTU. Drop it in that case
		drop_packet = 0;	
		if ( size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE + 3 > selected_mtu ) {
				drop_packet = 1;

				LMLOG(LDBG_1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE + 3, selected_mtu);

				// write the log file
				if ( log_file != NULL ) {
					//fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%lu\tto\t%s\t%i\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE + 3, 
					//tun2net, inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), /*ntohs(remote.sin_port),*/ num_pkts_stored_from_tun);
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
				}
			}


		// the length of the packet is adequate
		if ( drop_packet == 0 ) {
  
      
      if (IPSEC_mode == 2) {
       
         if ((aux_protocol == 50) || (aux_protocol == 51)) {
      
         counter_secure_packets ++;
         LMLOG(LDBG_1, "Secure packet with protocol: %d, counter_secure_packets: %d", aux_protocol, counter_secure_packets);
           
      } else {
      
         counter_non_secure_packets ++;
         LMLOG(LDBG_1, "Non-secure packet with protocol: %d, counter_non_secure_packets: %d", aux_protocol, counter_non_secure_packets);
      }
      
    }    


			/******************** compress the headers if the ROHC option has been set ****************/
			if ( ROHC_mode > 0 ) {
				// header compression has been selected by the user

				// copy the length read from tun to the buffer where the packet to be compressed is stored
				ip_packet.len = size_packets_to_multiplex[num_pkts_stored_from_tun];

				// copy the packet
				memcpy(rohc_buf_data_at(ip_packet, 0), packets_to_multiplex[num_pkts_stored_from_tun], size_packets_to_multiplex[num_pkts_stored_from_tun]);

				// reset the buffer where the rohc packet is to be stored
				rohc_buf_reset (&rohc_packet);

				// compress the IP packet
				status = rohc_compress4(compressor, ip_packet, &rohc_packet);

				// check the result of the compression
				if(status == ROHC_STATUS_SEGMENT) {
					/* success: compression succeeded, but resulting ROHC packet was too
						* large for the Maximum Reconstructed Reception Unit (MRRU) configured
						* with \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
						* first ROHC segment and \ref rohc_comp_get_segment can be used to
						* retrieve the next ones. */
				}

				else if (status == ROHC_STATUS_OK) {
					/* success: compression succeeded, and resulting ROHC packet fits the
					* Maximum Reconstructed Reception Unit (MRRU) configured with
					* \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
					* rohc_packet_len bytes of the ROHC packet */

					// since this packet has been compressed with ROHC, its protocol number must be 142
					// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol[num_pkts_stored_from_tun][0] = 142;
					} else {	// SIZE_PROTOCOL_FIELD == 2 
						protocol[num_pkts_stored_from_tun][0] = 0;
						protocol[num_pkts_stored_from_tun][1] = 142;
					}

					// Copy the compressed length and the compressed packet over the packet read from tun
					size_packets_to_multiplex[num_pkts_stored_from_tun] = rohc_packet.len;
					for (l = 0; l < size_packets_to_multiplex[num_pkts_stored_from_tun] ; l++) {
						packets_to_multiplex[num_pkts_stored_from_tun][l] = rohc_buf_byte_at(rohc_packet, l);
					}

					/* dump the ROHC packet on terminal */
					if (debug_level >= 1 ) {
						LMLOG(LDBG_1, " ROHC-compressed to %i bytes\n", rohc_packet.len);
					}
					if (debug_level == 2) {
						LMLOG(LDBG_2, "   ");
						dump_packet ( rohc_packet.len, rohc_packet.data );
					}

				} else {
					/* compressor failed to compress the IP packet */
					/* Send it in its native form */

					// I don't have to copy the native length and the native packet, because they
					// have already been stored in 'size_packets_to_multiplex[num_pkts_stored_from_tun]' and 'packets_to_multiplex[num_pkts_stored_from_tun]'

					// since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP'
					// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol[num_pkts_stored_from_tun][0] = 4;
					} else {	// SIZE_PROTOCOL_FIELD == 2 
						protocol[num_pkts_stored_from_tun][0] = 0;
						protocol[num_pkts_stored_from_tun][1] = 4;
					}
					fprintf(stderr, "compression of IP packet failed\n");

					// print in the log file
					if ( log_file != NULL ) {
						fprintf (log_file, "%"PRIu64"\terror\tcompr_failed. Native packet sent\t%i\t%lu\\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
						fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
					}

					LMLOG(LDBG_2, "  ROHC did not work. Native packet sent: %i bytes:\n   ", size_packets_to_multiplex[num_pkts_stored_from_tun]);
					//goto release_compressor;
				}

			} else {
				// header compression has not been selected by the user

				// since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP' 
				// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
				if ( SIZE_PROTOCOL_FIELD == 1 ) {
					protocol[num_pkts_stored_from_tun][0] = 4;
				} else {	// SIZE_PROTOCOL_FIELD == 2 
					protocol[num_pkts_stored_from_tun][0] = 0;
					protocol[num_pkts_stored_from_tun][1] = 4;
				}
			}
			
			/*** Calculate if the size limit will be reached when multiplexing the present packet ***/
			// if the addition of the present packet will imply a multiplexed packet bigger than the size limit:
			// - I send the previously stored packets
			// - I store the present one
			// - I reset the period

			// calculate if all the packets belong to the same protocol
			single_protocol = 1;
			for (k = 1; k < num_pkts_stored_from_tun ; k++) {
				for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
					if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
				}
			}

			// calculate the size without the present packet
			predicted_size_muxed_packet = predict_size_multiplexed_packet (num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex);

			// I add the length of the present packet:

			// separator and length of the present packet
			if (first_header_written == 0) {
				// this is the first header, so the maximum length is 64
				if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 64 ) {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				} else {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				}
			} else {
				// this is not the first header, so the maximum length is 128
				if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 128 ) {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				} else {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				}
			}

			if (predicted_size_muxed_packet > size_max ) {
				// if the present packet is muxed, the max size of the packet will be overriden. So I first empty the buffer
				//i.e. I build and send a multiplexed packet not including the current one

				LMLOG(LDBG_2, "\n");			 
				LMLOG(LDBG_1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);

       if (IPSEC_mode == 2) {
        float rate = 0.0;
        rate = ((float) counter_secure_packets/limit_numpackets_tun);
        if ((rate < percentage_packets_secure ) || ((rate == 0) && (percentage_packets_secure == 0))){
        LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending with IPSEC", rate);
        data_simplemux->mux_tuple.IPSEC_policy = 1; 
        } else {
          LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending without IPSEC", rate);
         data_simplemux->mux_tuple.IPSEC_policy = 0;      
        }
        counter_secure_packets = 0;
        counter_non_secure_packets = 0;
      }    

				// add the Single Protocol Bit in the first header (the most significant bit)
				// it is '1' if all the multiplexed packets belong to the same protocol
				if (single_protocol == 1) {
					separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
					size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
				} else {
					size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
				}

				// build the multiplexed packet without the current one
				total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);

				if (single_protocol) {
					LMLOG(LDBG_2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
				} else {
					LMLOG(LDBG_2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
				}
				LMLOG(LDBG_2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);
				LMLOG(LDBG_1, " Sending muxed packet without this one: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);


				/************************************************************* RETURN ***********************************************************************/
				// send the multiplexed packet without the current one 
				memcpy(out_muxed_packet, muxed_packet,total_length);
				*out_total_length = total_length; 
				result = 2;
				// write the log file
				if ( log_file != NULL ) {
						fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE, tun2net, 
							inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), /*ntohs(remote.sin_port),*/ num_pkts_stored_from_tun);
						fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
				}

				/************************************************************************************************************************************/

				// I have sent a packet, so I restart the period: update the time of the last packet sent
				time_in_microsec = GetTimeStamp();
				time_last_sent_in_microsec = time_in_microsec;


				// I have emptied the buffer, so I have to
				//move the current packet to the first position of the 'packets_to_multiplex' array
				for (l = 0; l < BUFSIZE; l++ ) {
					packets_to_multiplex[0][l]=packets_to_multiplex[num_pkts_stored_from_tun][l];
				}

				// move the current separator to the first position of the array
				for (l = 0; l < 2; l++ ) {
					separators_to_multiplex[0][l]=separators_to_multiplex[num_pkts_stored_from_tun][l];
				}

				// move the length to the first position of the array
				size_packets_to_multiplex[0] = size_packets_to_multiplex[num_pkts_stored_from_tun];
				size_separators_to_multiplex[0] = size_separators_to_multiplex[num_pkts_stored_from_tun];
				for (j=1; j < MAXPKTS; j++) size_packets_to_multiplex [j] = 0;


				// I have sent a packet, so I set to 0 the "first_header_written" bit
				first_header_written = 0;

				// reset the length and the number of packets
				size_muxed_packet = 0;
				num_pkts_stored_from_tun = 0;

				// Update simplemux data  -----------------------------------------------------------
				//-----------------------------------------------------------------------------------

				data_simplemux->time_last_sent_in_microsec = time_last_sent_in_microsec;	// moment when the last multiplexed packet was sent

				// variables for storing the packets to multiplex
				data_simplemux->size_muxed_packet = size_muxed_packet;						// acumulated size of the multiplexed packet
				data_simplemux->first_header_written = first_header_written;				// it indicates if the first header has been written or not

				data_simplemux->num_pkts_stored_from_tun = num_pkts_stored_from_tun ;		// number of packets received and not sent from tun (stored)

				for (j = 0 ; j < MAXPKTS ; ++j) 
					memcpy(data_simplemux->protocol[j], protocol[j], SIZE_PROTOCOL_FIELD*sizeof(unsigned char)); // protocol field of each packet
	
				memcpy(data_simplemux->size_separators_to_multiplex, size_separators_to_multiplex, MAXPKTS*sizeof(uint16_t));
                                 	// stores the size of the Simplemux separator. It does not include the "Protocol" field

				for (j = 0 ; j < MAXPKTS ; ++j) 
					memcpy(data_simplemux->separators_to_multiplex[j], separators_to_multiplex[j], 3*sizeof(unsigned char));
                                       // stores the header ('protocol' not included) received from tun, before sending it to the network
	
				memcpy(data_simplemux->size_packets_to_multiplex, size_packets_to_multiplex, MAXPKTS*sizeof(uint16_t));
                		       // stores the size of the received packet
	
				for (j = 0 ; j < MAXPKTS ; ++j) 
					memcpy(data_simplemux->packets_to_multiplex[j], packets_to_multiplex[j], BUFSIZE*sizeof(unsigned char));
                                              // stores the packets received from tun, before storing it or sending it to the network

				// End Update simplemux data --------------------------------------------------------
				//-----------------------------------------------------------------------------------

				return(result);

			}	/*** end check if size limit would be reached ***/


			// update the size of the muxed packet, adding the size of the current one
			size_muxed_packet = size_muxed_packet + size_packets_to_multiplex[num_pkts_stored_from_tun];

			// I have to add the multiplexing separator.
			//   - It is 1 byte if the length is smaller than 64 (or 128 for non-first separators) 
			//   - It is 2 bytes if the length is 64 (or 128 for non-first separators) or more
			//   - It is 3 bytes if the length is 8192 (or 16384 for non-first separators) or more
			if (first_header_written == 0) {
				// this is the first header
				maximum_packet_length = 64;
				limit_length_two_bytes = 8192;
			} else {
				// this is a non-first header
				maximum_packet_length = 128;
				limit_length_two_bytes = 16384;
			}

			// check if the length has to be one, two or three bytes
			// I am assuming that a packet will never be bigger than 1048576 (2^20) bytes for a first header,
			// or 2097152 (2^21) bytes for a non-first one)

			// one-byte separator
			if (size_packets_to_multiplex[num_pkts_stored_from_tun] < maximum_packet_length ) {

				// the length can be written in the first byte of the separator (expressed in 6 or 7 bits)
				size_separators_to_multiplex[num_pkts_stored_from_tun] = 1;

				// add the length to the string.
				// since the value is < maximum_packet_length, the most significant bits will always be 0
				separators_to_multiplex[num_pkts_stored_from_tun][0] = size_packets_to_multiplex[num_pkts_stored_from_tun];

				// increase the size of the multiplexed packet
				size_muxed_packet ++;


				// print the  Mux separator (only one byte)
				if(debug_level) {
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][0], bits);
					LMLOG(LDBG_2, " Mux separator of 1 byte: (%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
					if (first_header_written == 0) {
						PrintByte(LDBG_2, 7, bits);			// first header
					} else {
						PrintByte(LDBG_2, 8, bits);			// non-first header
					}
					LMLOG(LDBG_2, "\n");
				}


			// two-byte separator
			} else if (size_packets_to_multiplex[num_pkts_stored_from_tun] < limit_length_two_bytes ) {

				// the length requires a two-byte separator (length expressed in 13 or 14 bits)
				size_separators_to_multiplex[num_pkts_stored_from_tun] = 2;

				// first byte of the Mux separator
				// It can be:
				// - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
				// - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
				// get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
				// add 64 (or 128) in order to put a '1' in the second (or first) bit
				if (first_header_written == 0) {
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 128 ) + 64;	// first header
				} else {
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 128 ) + 128;	// non-first header
				}

				// second byte of the Mux separator
				// Length: the 7 less significant bytes of the length. Use modulo 128
				separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 128;

				// LXT bit has to be set to 0, because this is the last byte of the length
				// if I do nothing, it will be 0, since I have used modulo 128

				// increase the size of the multiplexed packet
				size_muxed_packet = size_muxed_packet + 2;

				// print the two bytes of the separator
				if(debug_level) {
					// first byte
					FromByte(separators_to_multiplex[0][num_pkts_stored_from_tun], bits);
					LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
					if (first_header_written == 0) {
						PrintByte(LDBG_2, 7, bits);			// first header
					} else {
						PrintByte(LDBG_2, 8, bits);			// non-first header
					}

					// second byte
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][1], bits);
					LMLOG(LDBG_2, " (%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][1]);
					PrintByte(LDBG_2, 8, bits);
					LMLOG(LDBG_2, "\n");
				}	

			// three-byte separator
			} else {

				// the length requires a three-byte separator (length expressed in 20 or 21 bits)
				size_separators_to_multiplex[num_pkts_stored_from_tun] = 3;
//FIXME
				// first byte of the Mux separator
				// It can be:
				// - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
				// - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
				// get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
				// add 64 (or 128) in order to put a '1' in the second (or first) bit

				if (first_header_written == 0) {
					// first header
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 16384 ) + 64;

				} else {
					// non-first header
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 16384 ) + 128;	
				}


				// second byte of the Mux separator
				// Length: the 7 second significant bytes of the length. Use modulo 16384
				separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 16384;

				// LXT bit has to be set to 1, because this is not the last byte of the length
				separators_to_multiplex[num_pkts_stored_from_tun][0] = separators_to_multiplex[num_pkts_stored_from_tun][0] + 128;


				// third byte of the Mux separator
				// Length: the 7 less significant bytes of the length. Use modulo 128
				separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 128;

				// LXT bit has to be set to 0, because this is the last byte of the length
				// if I do nothing, it will be 0, since I have used modulo 128


				// increase the size of the multiplexed packet
				size_muxed_packet = size_muxed_packet + 3;

				// print the three bytes of the separator
				if(debug_level) {
					// first byte
					FromByte(separators_to_multiplex[0][num_pkts_stored_from_tun], bits);
					LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
					if (first_header_written == 0) {
						PrintByte(LDBG_2, 7, bits);			// first header
					} else {
						PrintByte(LDBG_2, 8, bits);			// non-first header
					}

					// second byte
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][1], bits);
					LMLOG(LDBG_2, " (%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][1]);
					PrintByte(LDBG_2, 8, bits);
					LMLOG(LDBG_2, "\n");

					// third byte
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][2], bits);
					LMLOG(LDBG_2, " (%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][2]);
					PrintByte(LDBG_2, 8, bits);
					LMLOG(LDBG_2, "\n");
				}
			}


			// I have finished storing the packet, so I increase the number of stored packets
			num_pkts_stored_from_tun ++;

			// I have written a header of the multiplexed bundle, so I have to set to 1 the "first header written bit"
			if (first_header_written == 0) first_header_written = 1;
			

			//LMLOG (LDBG_1,"\n");
			LMLOG(LDBG_1, " Packet stopped and multiplexed: accumulated %d pkts: %d bytes.", num_pkts_stored_from_tun , size_muxed_packet);
			time_in_microsec = GetTimeStamp();
			time_difference = time_in_microsec - time_last_sent_in_microsec;		
			LMLOG(LDBG_1, " Time since last trigger: %" PRIu64 " usec\n", time_difference);//PRIu64 is used for printing uint64_t numbers


			// check if a multiplexed packet has to be sent

			// if the packet limit or the size threshold are reached, send all the stored packets to the network
			// do not worry about the MTU. if it is reached, a number of packets will be sent
			if ((num_pkts_stored_from_tun == limit_numpackets_tun) || (size_muxed_packet > size_threshold) || (time_difference > timeout )) {

				// a multiplexed packet has to be sent

				// calculate if all the packets belong to the same protocol
				single_protocol = 1;
				for (k = 1; k < num_pkts_stored_from_tun ; k++) {
					for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
						if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
					}
				}


				// Add the Single Protocol Bit in the first header (the most significant bit)
				// It is 1 if all the multiplexed packets belong to the same protocol
				if (single_protocol == 1) {
					separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
					size_muxed_packet = size_muxed_packet + 1;				// one byte corresponding to the 'protocol' field of the first header
				} else {
					size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;	// one byte per packet, corresponding to the 'protocol' field
				}

				// write the debug information
				if (debug_level) {
					LMLOG(LDBG_2, "\n");
					LMLOG(LDBG_1, "SENDING TRIGGERED: ");
					if (num_pkts_stored_from_tun == limit_numpackets_tun) {
						LMLOG(LDBG_1, "num packet limit reached\n");
                               
            
            if (IPSEC_mode == 2) {               
             float rate = 0.0;
             
             rate = ((float) counter_secure_packets/limit_numpackets_tun);
             if ((rate < percentage_packets_secure ) || ((rate == 0) && (percentage_packets_secure == 0))){
                LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending with IPSEC", rate);
                data_simplemux->mux_tuple.IPSEC_policy = 1; 
             } else {
                LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending without IPSEC", rate);
                data_simplemux->mux_tuple.IPSEC_policy = 0;      
             }
                counter_secure_packets = 0;
                counter_non_secure_packets = 0;    
            }                                       
          }   
                          
					if (size_muxed_packet > size_threshold)
						LMLOG(LDBG_1," size threshold reached\n");
					if (time_difference > timeout)
						LMLOG(LDBG_1, "timeout reached\n");

					if (single_protocol) {
						LMLOG(LDBG_2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
					} else {
						LMLOG(LDBG_2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
					}
					LMLOG(LDBG_2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);
					LMLOG(LDBG_1, " Writing %i packets to network: %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);								
				}

				// build the multiplexed packet including the current one
				total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);


				/************************************************************* RETURN ***********************************************************************/
				// send the multiplexed packet  
				memcpy(out_muxed_packet, muxed_packet,total_length);
				*out_total_length = total_length;
				result = 1;

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%i", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE, tun2net, 
					inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), /*ntohs(remote.sin_port),*/ num_pkts_stored_from_tun);
					if (num_pkts_stored_from_tun == limit_numpackets_tun)
						fprintf(log_file, "\tnumpacket_limit");
					if (size_muxed_packet > size_threshold)
						fprintf(log_file, "\tsize_limit");
					if (time_difference > timeout)
						fprintf(log_file, "\ttimeout");
					fprintf(log_file, "\n");
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
				}
                /************************************************************************************/

				// I have sent a packet, so I set to 0 the "first_header_written" bit
				first_header_written = 0;

				// reset the length and the number of packets
				size_muxed_packet = 0 ;
				num_pkts_stored_from_tun = 0;

				// restart the period: update the time of the last packet sent
				time_last_sent_in_microsec = time_in_microsec;
			}
		}
	}
	/*************************************************************************************/	
	/******************** Period expired: multiplex **************************************/
	/*************************************************************************************/	
	else if ((packet_in == NULL) && (size_packet_in == 0)) {
		//LMLOG(LINF, "Entro porque se ha cumplido el periodo");
		// The period has expired
		// Check if there is something stored, and send it
		// since there is no new packet, here it is not necessary to compress anything

		time_in_microsec = GetTimeStamp();
		if ( num_pkts_stored_from_tun > 0 ) {

			// There are some packets stored

			// calculate the time difference
			time_difference = time_in_microsec - time_last_sent_in_microsec;		
			
    
      if (IPSEC_mode == 2) {
        float rate = 0.0;
        rate = ((float) counter_secure_packets/limit_numpackets_tun);
        if ((rate < percentage_packets_secure ) || ((rate == 0) && (percentage_packets_secure == 0))){
        LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending with IPSEC", rate);
        data_simplemux->mux_tuple.IPSEC_policy = 1; 
        } else {
          LMLOG(LDBG_1, "calculated rate (secure packets/total packets) = %f, sending without IPSEC", rate);
         data_simplemux->mux_tuple.IPSEC_policy = 0;      
        }
        counter_secure_packets = 0;
        counter_non_secure_packets = 0;
      }
            
			// calculate if all the packets belong to the same protocol
			single_protocol = 1;
			for (k = 1; k < num_pkts_stored_from_tun ; k++) {
				for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
					if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
				}
			}
			if (debug_level) {
				LMLOG(LDBG_2, "\n");
				LMLOG(LDBG_1, "SENDING TRIGGERED. Period expired. Time since last trigger: %" PRIu64 " usec\n", time_difference);
				if (single_protocol) {
					LMLOG(LDBG_2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
				} else {
					LMLOG(LDBG_2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
				}
				LMLOG(LDBG_2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);
				LMLOG(LDBG_1, " Writing %i packets to network: %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE);	
			}

			// Add the Single Protocol Bit in the first header (the most significant bit)
			// It is 1 if all the multiplexed packets belong to the same protocol
			if (single_protocol == 1) {
				separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
				size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
			} else {
				size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
			}
			// build the multiplexed packet
			total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);
			/************************************************************* RETURN ***********************************************************************/
			// send the multiplexed packet  
			memcpy(out_muxed_packet, muxed_packet,total_length);
			*out_total_length = total_length;
			//LMLOG(LINF," total_length periodo:%d",*out_total_length);
			result = 1;
			// write the log file
			if ( log_file != NULL ) {
				fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE, tun2net, 
				inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), num_pkts_stored_from_tun);	
			}              
            /************************************************************************************/

			// I have sent a packet, so I set to 0 the "first_header_written" bit
			first_header_written = 0;

			// reset the length and the number of packets
			size_muxed_packet = 0 ;
			num_pkts_stored_from_tun = 0;

		} else {
			// No packet arrived
			LMLOG(LDBG_2, "Period expired. Nothing to be sent\n");
		}

		// restart the period
		time_last_sent_in_microsec = time_in_microsec;

	}
	else {
		LMLOG(LCRIT, "Invalid input parameters in mux_packets function\n");
		exit(1);
	}

	// Update simplemux data  -----------------------------------------------------------
	//-----------------------------------------------------------------------------------

	data_simplemux->time_last_sent_in_microsec = time_last_sent_in_microsec;	// moment when the last multiplexed packet was sent

	// variables for storing the packets to multiplex
	data_simplemux->size_muxed_packet = size_muxed_packet;				// acumulated size of the multiplexed packet
	data_simplemux->first_header_written = first_header_written;			// it indicates if the first header has been written or not

	data_simplemux->num_pkts_stored_from_tun = num_pkts_stored_from_tun ;		// number of packets received and not sent from tun (stored)

	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(data_simplemux->protocol[j], protocol[j], SIZE_PROTOCOL_FIELD*sizeof(unsigned char)); // protocol field of each packet
	
	memcpy(data_simplemux->size_separators_to_multiplex, size_separators_to_multiplex, MAXPKTS*sizeof(uint16_t));	
              // stores the size of the Simplemux separator. It does not include the "Protocol" field

	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(data_simplemux->separators_to_multiplex[j], separators_to_multiplex[j], 3*sizeof(unsigned char)); 
                      // stores the header ('protocol' not included) received from tun, before sending it to the network
	
	memcpy(data_simplemux->size_packets_to_multiplex, size_packets_to_multiplex, MAXPKTS*sizeof(uint16_t));
	      // stores the size of the received packet
	
	for (j = 0 ; j < MAXPKTS ; ++j) 
		memcpy(data_simplemux->packets_to_multiplex[j], packets_to_multiplex[j], BUFSIZE*sizeof(unsigned char)); 
                      // stores the packets received from tun, before storing it or sending it to the network
	
	// End Update simplemux data --------------------------------------------------------
	//-----------------------------------------------------------------------------------

//LMLOG(LINF, "salgo de mux_packets II %d\n",result);
	return(result);

}

/**************************************************************************
 **************************************************************************
 **************************************************************************
 *                  INITIALIZE SIMPLEMUX DATA                             *
 **************************************************************************
 **************************************************************************
 *************************************************************************/

/*************************************************************************
 * Functions for ROCH initilization **************************************
 *************************************************************************/
/**
 * @brief The RTP detection callback which does detect RTP stream.
 * it assumes that UDP packets belonging to certain ports are RTP packets
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rtp_detect(const unsigned char *const ip __attribute__((unused)),
                      const unsigned char *const udp,
                      const unsigned char *const payload __attribute__((unused)),
                      const unsigned int payload_size __attribute__((unused)),
                      void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if(udp == NULL)
	{
		return false;
	}

	// get the UDP destination port 
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	// is the UDP destination port in the list of ports reserved for RTP traffic by default (for compatibility reasons)
	for(i = 0; i < default_rtp_ports_nr; i++)
	{
		if(ntohs(udp_dport) == default_rtp_ports[i])
		{
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}
/*
 Generate a random number
*/
static int gen_random_num(const struct rohc_comp *const comp,
							void *const user_context)
{
	return rand();
}

/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt	An optional private context, may be NULL
 * @param level		The priority level of the trace
 * @param entity	The entity that emitted the trace among:
 *					\li ROHC_TRACE_COMP
 *					\li ROHC_TRACE_DECOMP
 * @param profile	The ID of the ROHC compression/decompression profile
 *					the trace is related to
 * @param format	The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
								const rohc_trace_level_t level,
								const rohc_trace_entity_t entity,
								const int profile,
								const char *const format,
								...)
{
	// Only prints ROHC messages if debug level is > 2
	if ( debug_level > 2 ) {
		va_list args;
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}

/*
 Initialize ROHC
 */

void initialize_compressor_and_decompressor ()
{
	unsigned int seed;
	rohc_status_t status;

	int ROHC_mode = 1;	/* FIXME: now only is 1	*/	
									// it is 0 if ROHC is not used
									// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
									// it is 2 for ROHC Bidirectional Optimistic mode
									// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)


	// If ROHC has been selected, I have to initialize it
	// see the API here: https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/

	//* initialize the random generator
	seed = time(NULL);
	srand(seed);

	// Create a ROHC compressor with Large CIDs and the largest MAX_CID possible for large CIDs 
	compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, gen_random_num, NULL);
	if(compressor == NULL)
	{
		LMLOG(LCRIT, "failed create the ROHC compressor\n");
		goto error;
	}

	LMLOG(LDBG_1, "ROHC compressor created. Profiles: ");

	// Set the callback function to be used for detecting RTP.
	// RTP is not detected automatically. So you have to create a callback function "rtp_detect" where you specify the conditions.
	// In our case we will consider as RTP the UDP packets belonging to certain ports
	if(!rohc_comp_set_rtp_detection_cb(compressor, rtp_detect, NULL))
	{
		        LMLOG(LCRIT, "failed to set RTP detection callback\n");
		        goto error;
	}

	// set the function that will manage the ROHC compressing traces (it will be 'print_rohc_traces')
	if(!rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL))
	{
		LMLOG(LCRIT, "failed to set the callback for traces on compressor\n");
		goto release_compressor;
	}

	// Enable the ROHC compression profiles 
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED))
	{
		LMLOG(LCRIT, "failed to enable the Uncompressed compression profile\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "Uncompressed. ");
	}

	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
	{
		LMLOG(LCRIT, "failed to enable the IP-only compression profile\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "IP-only. ");
	}

	if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP, ROHC_PROFILE_UDPLITE, -1))
	{
		LMLOG(LCRIT, "failed to enable the IP/UDP and IP/UDP-Lite compression profiles\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "IP/UDP. IP/UDP-Lite. ");
	}

	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP))
	{
		LMLOG(LCRIT, "failed to enable the RTP compression profile\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "RTP (UDP ports 1234, 36780, 33238, 5020, 5002). ");
	}

	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP))
	{
		LMLOG(LCRIT, "failed to enable the ESP compression profile\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "ESP. ");
	}

	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP))
	{
		LMLOG(LCRIT, "failed to enable the TCP compression profile\n");
		goto release_compressor;
	} else {
		LMLOG(LDBG_1, "TCP. ");
	}
	LMLOG(LDBG_1, "\n");

	// Create a ROHC decompressor to operate:
	//  - with large CIDs use ROHC_LARGE_CID, ROHC_LARGE_CID_MAX
	//  - with small CIDs use ROHC_SMALL_CID, ROHC_SMALL_CID_MAX maximum of 5 streams (MAX_CID = 4),
	//  - ROHC_O_MODE: Bidirectional Optimistic mode (O-mode)
	//  - ROHC_U_MODE: Unidirectional mode (U-mode).    
	if ( ROHC_mode == 1 ) {
		decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);		// Unidirectional mode
	} else if ( ROHC_mode == 2 ) {
		decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);		// Bidirectional Optimistic mode
	}//else if ( ROHC_mode == 3 ) {
		//decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);	// Bidirectional Reliable mode (not implemented yet)
	//}

	if(decompressor == NULL)
	{
		LMLOG(LCRIT, "failed create the ROHC decompressor\n");
		goto release_decompressor;
	}

	LMLOG(LDBG_1, "ROHC decompressor created. Profiles: ");

	// set the function that will manage the ROHC decompressing traces (it will be 'print_rohc_traces')
	if(!rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL))
	{
		LMLOG(LCRIT, "failed to set the callback for traces on decompressor\n");
		goto release_decompressor;
	}

	// enable rohc decompression profiles
	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the Uncompressed decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "Uncompressed. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_IP, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the IP-only decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "IP-only. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the IP/UDP decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "IP/UDP. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDPLITE, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the IP/UDP-Lite decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "IP/UDP-Lite. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_RTP, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the RTP decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "RTP. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_ESP,-1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the ESP decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "ESP. ");
	}

	status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_TCP, -1);
	if(!status)
	{
		LMLOG(LCRIT, "failed to enable the TCP decompression profile\n");
		goto release_decompressor;
	} else {
		LMLOG(LDBG_1, "TCP. ");
	}

	LMLOG(LDBG_1, "\n");
	
	return;

//******* labels ************
release_compressor:
	rohc_comp_free(compressor);

release_decompressor:
	rohc_decomp_free(decompressor);
	
error:
	LMLOG(LCRIT, "an error occured during program execution, abort program\n");
	exit(1);
}



/*************************************************************************
 * Function for muxed data initilization *******************************
 *************************************************************************/

void muxed_init() 
{
	int i,j;
	char log_file_name[25]="";            				

	// Initialize ROCH -----------------------------------------------------------------
	compressor = NULL;           				// the ROHC compressor
	
	decompressor = NULL;           				// the ROHC decompressor

	initialize_compressor_and_decompressor();

	// Info log (name of the log file is assigned automatically)

	log_file = NULL;
	tun2net = 0;				
	net2tun = 0;				

	date_and_time(log_file_name);
	log_file = fopen(log_file_name, "w");
	if (log_file == NULL) 
			LMLOG(LERR,"Error: cannot open the log file simplemux!\n");
	int afi,res;
	struct in_addr ipbin;
	
	afi = ip_afi_from_char("0.0.0.0");
    res=inet_pton(afi,"0.0.0.0",&ipbin);

	for (i = 0 ; i < 10 ; i++) { /* FIXME: use realloc to include more than 10 elements */
		// Initialize ROCH mode  -----------------------------------------------------------------
			
		conf_sm[i].ROHC_mode = 0;
		conf_sm[i].IPSEC_mode = 0;
		// initialize addresses
		ip_addr_init(&(conf_sm[i].mux_tuple.src_addr),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.dst_addr),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.srloc.ip),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.drloc.ip),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.src_net),&ipbin,afi);	
		ip_addr_init(&(conf_sm[i].mux_tuple.dst_net),&ipbin,afi);
		conf_sm[0].port_dst = 0;
		conf_sm[0].port_src = 0;	
		
		// Initialize limits  -----------------------------------------------------------------
		
		conf_sm[i].limit_numpackets_tun = 0;		// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
								// limit of the number of packets for triggering a muxed packet 

		conf_sm[i].timeout = MAXTIMEOUT;		// timeout for triggering a muxed packet
								// (microseconds) if a packet arrives and the timeout has expired (time from the  
								// previous sending), the sending is triggered. default 100 seconds

		conf_sm[i].period = MAXTIMEOUT;					//Period for triggering a muxed packet 
		conf_sm[i].time_last_sent_in_microsec = GetTimeStamp();		// moment when the last multiplexed packet was sent

		conf_sm[i].IPSEC_mode = 0; //Mode for security
   	conf_sm[i].mux_tuple.IPSEC_policy = 0; 
    conf_sm[i].percentage_packets_secure = 0; //Minimun ratio of packets 
    
		conf_sm[i].interface_mtu = 0;				// the maximum transfer unit of the interface
		conf_sm[i].user_mtu = 0;				// the MTU specified by the user (it must be <= interface_mtu)


		conf_sm[i].size_threshold = 0;				// if the number of bytes stored is higher than this, a muxed packet is sent
			
		// Variables for storing the packets to multiplex
		conf_sm[i].size_muxed_packet = 0;		// acumulated size of the multiplexed packet
		conf_sm[i].first_header_written = 0;		// it indicates if the first header has been written or not


		conf_sm[i].num_pkts_stored_from_tun = 0;	// number of packets received and not sent from tun (stored)

		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].protocol[j], 0, SIZE_PROTOCOL_FIELD*sizeof(unsigned char)); // protocol field of each packet
		
		memset(conf_sm[i].size_separators_to_multiplex, 0, MAXPKTS*sizeof(uint16_t));     	// stores the size of the Simplemux separator. It does not include the "Protocol" field

		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].separators_to_multiplex[j], 0, 3*sizeof(unsigned char));	// stores the header ('protocol' not included) received from tun, before sending it to the network
		
		memset(conf_sm[i].size_packets_to_multiplex, 0, MAXPKTS*sizeof(uint16_t));		// stores the size of the received packet
		
		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].packets_to_multiplex[j], 0, BUFSIZE*sizeof(unsigned char));	// stores the packets received from tun, before storing it or sending it to the network
	}
	// End Initialize--------------------------------------------------------------------
	//-----------------------------------------------------------------------------------
}

/*************************************************************************
 * Function for muxed data reset *******************************
 *************************************************************************/
//AÑADIDO RUBÉN
void muxed_reset() 
{
	int i,j; 

	int afi,res;
	struct in_addr ipbin;
	
	afi = ip_afi_from_char("0.0.0.0");
    res=inet_pton(afi,"0.0.0.0",&ipbin); 

	for (i = 0 ; i < 10 ; i++) { /* FIXME: use realloc to include more than 10 elements */
		// Initialize ROCH mode  -----------------------------------------------------------------
			
		conf_sm[i].ROHC_mode = 0;
    conf_sm[i].IPSEC_mode = 0; 
		//reset addresses
		ip_addr_init(&(conf_sm[i].mux_tuple.src_addr),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.dst_addr),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.srloc.ip),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.drloc.ip),&ipbin,afi);
		ip_addr_init(&(conf_sm[i].mux_tuple.src_net),&ipbin,afi);	
		ip_addr_init(&(conf_sm[i].mux_tuple.dst_net),&ipbin,afi);
		
		conf_sm[0].port_dst = 0;
		conf_sm[0].port_src = 0;
		
		// Initialize limits  -----------------------------------------------------------------
		
		conf_sm[i].limit_numpackets_tun = 0;		// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
								// limit of the number of packets for triggering a muxed packet 

		conf_sm[i].timeout = MAXTIMEOUT;		// timeout for triggering a muxed packet
								// (microseconds) if a packet arrives and the timeout has expired (time from the  
								// previous sending), the sending is triggered. default 100 seconds

		conf_sm[i].period = MAXTIMEOUT;					//Period for triggering a muxed packet 
		conf_sm[i].time_last_sent_in_microsec = GetTimeStamp();		// moment when the last multiplexed packet was sent

		conf_sm[i].IPSEC_mode = 0;
    conf_sm[i].mux_tuple.IPSEC_policy = 0; 
    conf_sm[i].percentage_packets_secure = 0; 
		conf_sm[i].interface_mtu = 0;				// the maximum transfer unit of the interface
		conf_sm[i].user_mtu = 0;				// the MTU specified by the user (it must be <= interface_mtu)


		conf_sm[i].size_threshold = 0;				// if the number of bytes stored is higher than this, a muxed packet is sent
			
		// Variables for storing the packets to multiplex
		conf_sm[i].size_muxed_packet = 0;		// acumulated size of the multiplexed packet
		conf_sm[i].first_header_written = 0;		// it indicates if the first header has been written or not


		conf_sm[i].num_pkts_stored_from_tun = 0;	// number of packets received and not sent from tun (stored)

		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].protocol[j], 0, SIZE_PROTOCOL_FIELD*sizeof(unsigned char)); // protocol field of each packet
		
		memset(conf_sm[i].size_separators_to_multiplex, 0, MAXPKTS*sizeof(uint16_t));     	// stores the size of the Simplemux separator. It does not include the "Protocol" field

		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].separators_to_multiplex[j], 0, 3*sizeof(unsigned char));	// stores the header ('protocol' not included) received from tun, before sending it to the network
		
		memset(conf_sm[i].size_packets_to_multiplex, 0, MAXPKTS*sizeof(uint16_t));		// stores the size of the received packet
		
		for (j = 0 ; j < MAXPKTS ; ++j) 
			memset(conf_sm[i].packets_to_multiplex[j], 0, BUFSIZE*sizeof(unsigned char));	// stores the packets received from tun, before storing it or sending it to the network
	}
	// End Initialize--------------------------------------------------------------------
	//-----------------------------------------------------------------------------------
}


/**************************************************************************
 *       SOCKET FOR IPSEC                                     *  
 **************************************************************************/
int socket_for_ipsec ( data_simplemux_t *data_simplemux, const void *pkt, int plen, ip_addr_t *dip) {

  int socket_ipsec;
  int result_bind;
  int src_port = IPSEC_MUX_DATA_PORT;
  int port_dest = IPSEC_MUX_DATA_PORT;
  lisp_addr_t *addr;
  lisp_addr_t *addr_dest;
   
  socket_ipsec = open_udp_datagram_socket(AF_INET);  
  addr = &(data_simplemux-> mux_tuple.srloc);
  addr_dest = &(data_simplemux-> mux_tuple.drloc);
  
  result_bind = bind_socket (socket_ipsec, AF_INET, addr ,src_port);
  
  if (result_bind != 0)
    LMLOG(LDBG_1, "bind_socket: %s",strerror(errno));      
  else 
    LMLOG(LDBG_1, "bind_socket: Binded socket %d to source address %s and port %d",socket_ipsec, lisp_addr_to_char(&(data_simplemux->mux_tuple.srloc)),src_port);

  int send = send_datagram_packet (socket_ipsec, pkt, plen, addr_dest, port_dest);
  close (socket_ipsec);
  LMLOG(LDBG_1, "socket ipsec %d closed", socket_ipsec);
  
}

/**************************************************************************
 *       Send multiplexed packet encapsulated in LISP packet              *
 **************************************************************************/

int mux_output_unicast (lbuf_t *b, data_simplemux_t *data_simplemux)
{	
		int IPSEC_mode = data_simplemux->IPSEC_mode;
	
	switch (IPSEC_mode){
		
		case 0: //No security needed 
		  LMLOG(LINF,"Sending packet through port 4343");    
			lisp_data_encap(b, MUX_DATA_PORT, MUX_DATA_PORT, &(data_simplemux->mux_tuple.srloc), &(data_simplemux->mux_tuple.drloc), IPSEC_mode);
      return(send_raw_packet(data_simplemux->mux_tuple.out_sock, lbuf_data(b), lbuf_size(b),lisp_addr_ip(&(data_simplemux->mux_tuple.drloc))));
			break;
			
		case 1: //Always need security
      LMLOG(LINF,"Sending packet through port 4344");     
			lisp_data_encap(b, IPSEC_MUX_DATA_PORT, IPSEC_MUX_DATA_PORT, &(data_simplemux->mux_tuple.srloc), &(data_simplemux->mux_tuple.drloc), IPSEC_mode); 
      return (socket_for_ipsec(data_simplemux, lbuf_data(b), lbuf_size(b),lisp_addr_ip(&(data_simplemux->mux_tuple.drloc)))); 
			break;
			
		case 2: //Analize if security is needed
			
		  if ((data_simplemux->mux_tuple.IPSEC_policy)== 0) { 
        IPSEC_mode=0;
        LMLOG(LINF,"Sending packet through port 4343");
				lisp_data_encap(b, MUX_DATA_PORT, MUX_DATA_PORT, &(data_simplemux->mux_tuple.srloc), &(data_simplemux->mux_tuple.drloc),IPSEC_mode);
        return(send_raw_packet(data_simplemux->mux_tuple.out_sock, lbuf_data(b), lbuf_size(b),lisp_addr_ip(&(data_simplemux->mux_tuple.drloc))));
			} else { //Packet needs security
        IPSEC_mode = 1;
        LMLOG(LINF,"Sending packet through port 4344");
				lisp_data_encap(b, IPSEC_MUX_DATA_PORT, IPSEC_MUX_DATA_PORT, &(data_simplemux->mux_tuple.srloc), &(data_simplemux->mux_tuple.drloc),IPSEC_mode);
        return (socket_for_ipsec(data_simplemux, lbuf_data(b), lbuf_size(b),lisp_addr_ip(&(data_simplemux->mux_tuple.drloc)))); 
			}
			break;		
	}
}
  
///**************************************************************************
// *       Back up the previous config params               				  *
// **************************************************************************/

void muxed_param_backup ()
{	int i;

	for (i = 0 ; i < 10 ; i++) { /* FIXME: use realloc to include more than 10 elements */
	
		conf_sm_pre[i] = conf_sm[i]; // save previous config
		
	}
}

/**************************************************************************
 *       Show the changes of conf_sm[0] "simplemux data struct"           *
 **************************************************************************/
void muxed_param_changed ()
{	
	int i;
	
	for (i = 0 ; i < 10 ; i++) { /* FIXME: use realloc to include more than 10 elements */
	
	int ruleChanged = 0;
	
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.src_addr),ip_addr_to_char(&conf_sm[i].mux_tuple.src_addr)) != 0) {
		LMLOG(LINF, "Rule %d changed",i);
		ruleChanged = 1;
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.src_addr),"0.0.0.0")!=0)
			LMLOG(LINF, "\tIpsrc: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.src_addr));
	}
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.dst_addr),ip_addr_to_char(&conf_sm[i].mux_tuple.dst_addr)) != 0) {
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.dst_addr),"0.0.0.0")!=0)
			LMLOG(LINF, "\tIpdst: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.dst_addr));
	}
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.srloc.ip),ip_addr_to_char(&conf_sm[i].mux_tuple.srloc.ip)) != 0) {
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.srloc.ip),"0.0.0.0")!=0)
			LMLOG(LINF, "\tLispsrc: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.srloc.ip));
	}
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.drloc.ip),ip_addr_to_char(&conf_sm[i].mux_tuple.drloc.ip)) != 0) {
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.drloc.ip),"0.0.0.0")!=0)
			LMLOG(LINF, "\tLispdst: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.drloc.ip));
	}
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.src_net),ip_addr_to_char(&conf_sm[i].mux_tuple.src_net)) != 0) {
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.src_net),"0.0.0.0")!=0)
			LMLOG(LINF, "\tNetsrc: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.src_net));
	}
	if(strcmp(ip_addr_to_char(&conf_sm_pre[i].mux_tuple.dst_net),ip_addr_to_char(&conf_sm[i].mux_tuple.dst_net)) != 0) {
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		if(strcmp(ip_addr_to_char(&conf_sm[i].mux_tuple.dst_addr),"0.0.0.0")!=0)
			LMLOG(LINF, "\tNetdst: %s",ip_addr_to_char(&conf_sm[i].mux_tuple.dst_net));
	}
	if(conf_sm_pre[i].limit_numpackets_tun!=conf_sm[i].limit_numpackets_tun){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		LMLOG(LINF, "\tNum-pkt: %d",conf_sm[i].limit_numpackets_tun);
	}
	if(conf_sm_pre[i].user_mtu!=conf_sm[i].user_mtu){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		LMLOG(LINF, "\tMtu-user: %d",conf_sm[i].user_mtu);
	}
	if(conf_sm_pre[i].interface_mtu!=conf_sm[i].interface_mtu){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tMtu-int: %d",conf_sm[i].interface_mtu);}
	if(conf_sm_pre[i].size_threshold!=conf_sm[i].size_threshold){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tThreshold: %d",conf_sm[i].size_threshold);}
	if(conf_sm_pre[i].timeout!=conf_sm[i].timeout){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tTimeout: %d",conf_sm[i].timeout);}
	if(conf_sm_pre[i].period!=conf_sm[i].period){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tPeriod: %d",conf_sm[i].period);}
	if(conf_sm_pre[i].ROHC_mode!=conf_sm[i].ROHC_mode){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tROHC-mode: %d",conf_sm[i].ROHC_mode);}
 
 if(conf_sm_pre[i].IPSEC_mode!=conf_sm[i].IPSEC_mode){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tIPSEC_mode: %d",conf_sm[i].IPSEC_mode);}
 
 if(conf_sm_pre[i].percentage_packets_secure!=conf_sm[i].percentage_packets_secure){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tRate packets secure: %f",conf_sm[i].percentage_packets_secure);} 
  
	if(conf_sm_pre[i].port_dst!=conf_sm[i].port_dst){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
	LMLOG(LINF, "\tPort-dst: %d",conf_sm[i].port_dst);}
	if(conf_sm_pre[i].port_src!=conf_sm[i].port_src){
		if(ruleChanged == 0){
			LMLOG(LINF, "Rule %d changed",i);
			ruleChanged = 1;
		}
		LMLOG(LINF, "\tPort-src: %d",conf_sm[i].port_src);
	}
	}
	LMLOG(LINF, "");
}	

/**************************************************************************
 *       Process the timers of all "simplemux data structs"               *
 **************************************************************************/
	
void muxed_timer_process_all ()
{
	int i;
	uint64_t time_in_microsec;					// current time
	unsigned char out_muxed_packet[BUFSIZE];	// stores the multiplexed packet
	uint16_t out_total_length = 0;					// total length of the built multiplexed packet

	unsigned char lisp_mux_buffer[BUFSIZE];		// buffer lisp to send mux packet	
	lbuf_t lisp_buffer;							// buffer lisp to send mux packet	
	uint32_t lisp_data_length = 0;					// length of the built multiplexed packet

	time_in_microsec = GetTimeStamp();
	for (i = 0 ; i < numdsm ;  ++i) {
		if (conf_sm[i].period < (time_in_microsec - conf_sm[i].time_last_sent_in_microsec)) {
			/*LMLOG(LINF,"Se cumple periodo, time: %" PRIu64 ", sent: %" PRIu64 ", period: %" PRIu64 ", indice i %d",
		              time_in_microsec, conf_sm[i].time_last_sent_in_microsec, conf_sm[i].period, i);
                        */
			//if (mux_packets (NULL, 0, &(conf_sm[i]), out_muxed_packet, (uint16_t *)(&out_total_length)) == 1){	
        
			if (mux_packets (NULL, 0, &(conf_sm[i]), out_muxed_packet, &out_total_length, 0) == 1){	
				//Build lisp buffer	
				//LMLOG(LINF," total_length periodo:%d",out_total_length);
		 		lbuf_use_stack(&lisp_buffer, &lisp_mux_buffer, (uint32_t)BUFSIZE);
				lbuf_reserve(&lisp_buffer, MUX_STACK_OFFSET);
				memcpy (lbuf_data(&lisp_buffer), out_muxed_packet, out_total_length);
				lisp_data_length = out_total_length;
				lbuf_set_size(&lisp_buffer, lisp_data_length);				
				//Encapsulate output multiplexed packet in a LISP packet and sent it
       

				mux_output_unicast(&lisp_buffer,&conf_sm[i]);  
			}
		}
	}
}

//
///**************************************************************************
// *        Lookup mux_tuple from packet tuple and forward entry            *
// **************************************************************************/
//
//int lookup_mux_tuple (packet_tuple_t *tpl, fwd_entry_t *fe, data_simplemux_t *data_simplemux)
data_simplemux_t * lookup_mux_tuple (packet_tuple_t *tpl, fwd_entry_t *fe)
{
	int i;
	ip_addr_t src_net;
	ip_addr_t dst_net;
	struct in_addr src_sin_addr;
	struct in_addr dst_sin_addr;

//LMLOG(LINF,"entro en lookup");

	// Lookup by IP source address of the packet AND IP destination address of the packet
	for (i = 0 ; i < numdsm ;  ++i) {
		if ( (ip_addr_cmp(&(conf_sm[i].mux_tuple.src_addr), &(tpl->src_addr.ip)) == 0) &&
			 (ip_addr_cmp(&(conf_sm[i].mux_tuple.dst_addr), &(tpl->dst_addr.ip)) == 0) ) {
			return (&(conf_sm [i]));
		}
	}
//LMLOG(LINF,"ha pasado comp 2 dir and");

	// Lookup by IP source address of the packet OR IP destination address of the packet
	for (i = 0 ; i < numdsm ;  ++i) {
		if ( (ip_addr_cmp(&(conf_sm[i].mux_tuple.src_addr), &(tpl->src_addr.ip)) == 0) ||
			 (ip_addr_cmp(&(conf_sm[i].mux_tuple.dst_addr), &(tpl->dst_addr.ip)) == 0) ) {
			return (&(conf_sm [i]));
		}
	}
//LMLOG(LINF,"ha pasado comp 2 dir or ");

	// IP source address AND IP destination address of the packet belong to one source net AND one destination net, respectively
	for (i = 0 ; i < numdsm ;  ++i) {
		src_sin_addr.s_addr = htonl(ntohl((tpl->src_addr.ip.addr.v4.s_addr) & (0xFFFFFFFF << (32 - conf_sm[i].mux_tuple.src_mask))));  // Get source net in struct in_addr format 
		ip_addr_init (&src_net, &src_sin_addr, AF_INET); // Get source net in ip_address_t format 
	
		dst_sin_addr.s_addr = htonl(ntohl((tpl->dst_addr.ip.addr.v4.s_addr) & (0xFFFFFFFF << (32 - conf_sm[i].mux_tuple.dst_mask))));  // Get destination net in struct in_addr format 
		ip_addr_init (&dst_net, &dst_sin_addr, AF_INET); // Get destination net in ip_address_t format 

		if ( (ip_addr_cmp(&(conf_sm[i].mux_tuple.src_net),&src_net) == 0) &&
			 (ip_addr_cmp(&(conf_sm[i].mux_tuple.dst_net),&dst_net)) == 0)  {
			return (&(conf_sm [i]));
		}
	}
//LMLOG(LINF,"ha pasado comp 2 redes and "   );

	// IP source address AND IP destination address of the packet belong to one source net AND one destination net, respectively
	for (i = 0 ; i < numdsm ;  ++i) {
		src_sin_addr.s_addr = htonl(ntohl((tpl->src_addr.ip.addr.v4.s_addr) & (0xFFFFFFFF << (32 - conf_sm[i].mux_tuple.src_mask))));  // Get source net in struct in_addr format 
		ip_addr_init (&src_net, &src_sin_addr, AF_INET); // Get source net in ip_address_t format 
	
		dst_sin_addr.s_addr = htonl(ntohl((tpl->dst_addr.ip.addr.v4.s_addr) & (0xFFFFFFFF << (32 - conf_sm[i].mux_tuple.dst_mask))));  // Get destination net in struct in_addr format 
		ip_addr_init (&dst_net, &dst_sin_addr, AF_INET); // Get destination net in ip_address_t format 

		if ( (ip_addr_cmp(&(conf_sm[i].mux_tuple.src_net),&src_net) == 0) ||
			 (ip_addr_cmp(&(conf_sm[i].mux_tuple.dst_net),&dst_net)) == 0)  {
			return (&(conf_sm [i]));
		}
	}
//LMLOG(LINF,"ha pasado comp 2 redes or "   );
  
	// Dir fuente y dir destino del túnel 
	for (i = 0 ; i < numdsm ;  ++i) {
		if ( (lisp_addr_cmp(&(conf_sm[i].mux_tuple.srloc), fe->srloc) == 0) &&
			 (lisp_addr_cmp(&(conf_sm[i].mux_tuple.drloc), fe->drloc) == 0)) {
			return (&(conf_sm [i]));
		}
	}
	
//LMLOG(LINF,"ha pasado comp 2 puertos or "   );

  
	// Puerto fuente y Puerto destino 
	for (i = 0 ; i < numdsm ;  ++i) {
		if (( conf_sm[i].port_src == tpl->src_port) &&
			 (conf_sm[i].port_dst == tpl->dst_port)) {
			return (&(conf_sm [i]));
		}
	}
	
//LMLOG(LINF,"ha pasado comp 2 puertos and "   );
  
	// Puerto fuente y Puerto destino 
	for (i = 0 ; i < numdsm ;  ++i) {
		if (( conf_sm[i].port_src == tpl->src_port) ||
			 (conf_sm[i].port_dst == tpl->dst_port)) {
			return (&(conf_sm [i]));
		}
	}

	//LMLOG(LINF,"ha pasado todos los comp tunel");

	//return (-1);
	return (NULL);
}


/**************************************************************************
 *                 Multiplex the received packets from tun                *
 **************************************************************************/

int mux_tun_output_unicast (lbuf_t *b, packet_tuple_t *tuple, fwd_entry_t *fe)
{
	unsigned char out_muxed_packet[BUFSIZE];	// stores the multiplexed packet
	uint16_t out_total_length = 0;				// total length of the built multiplexed packet
	

	unsigned char lisp_mux_buffer[BUFSIZE];		// buffer lisp to send mux packet	
	lbuf_t lisp_buffer;							// buffer lisp to send mux packet	
	uint32_t lisp_data_length = 0;					// length of the built multiplexed packet


	data_simplemux_t *data_simplemux = NULL;	// stores the data simplemux lookup

  int protocol = tuple->protocol;
	// Lookup mux_tuple from packet tuple and forward entry
	if ((data_simplemux = lookup_mux_tuple (tuple, fe)) != NULL) {
		// Put tunnel data in data_simplemux_t
		lisp_addr_copy(&(data_simplemux->mux_tuple.srloc), fe->srloc); 
		lisp_addr_copy(&(data_simplemux->mux_tuple.drloc), fe->drloc); 
		data_simplemux->mux_tuple.out_sock = *(fe->out_sock);
     // Multiplex packets
		switch(mux_packets ((unsigned char*)lbuf_data(b), lbuf_size(b), data_simplemux, out_muxed_packet, &out_total_length, protocol)) 
		{
		 case 0: // A muxed packet is NOT built
			break;
		 case 1: // A muxed packet is built to be sent
			// Build lisp buffer
		 	lbuf_use_stack(&lisp_buffer, &lisp_mux_buffer, (uint32_t)BUFSIZE);
			lbuf_reserve(&lisp_buffer,MUX_STACK_OFFSET);
			memcpy (lbuf_data(&lisp_buffer), out_muxed_packet, out_total_length);
			lisp_data_length = out_total_length;
			lbuf_set_size(&lisp_buffer, lisp_data_length);
			// Encapsulate output multiplexed packet in a LISP packet and sent it      
			mux_output_unicast(&lisp_buffer,data_simplemux); 
			break;
		 case 2: // A previous muxed packet is built to be sent because maximum size is reached. This function must be called again, using the same input parameters.
			// Build lisp buffer
		 	lbuf_use_stack(&lisp_buffer, &lisp_mux_buffer, (uint32_t)BUFSIZE);
			lbuf_reserve(&lisp_buffer,MUX_STACK_OFFSET);
			memcpy (lbuf_data(&lisp_buffer), out_muxed_packet, out_total_length);
			lisp_data_length = out_total_length;
			lbuf_set_size(&lisp_buffer, lisp_data_length);
			// Encapsulate output multiplexed packet in a LISP packet and sent it
			mux_output_unicast(&lisp_buffer,data_simplemux); 
			// Multiplex again
			switch(mux_packets ((unsigned char*)lbuf_data(b), lbuf_size(b), data_simplemux, out_muxed_packet, &out_total_length, protocol))
			{
			 case 0:
				break;
			 case 1:
				// Build lisp buffer
		 		lbuf_use_stack(&lisp_buffer, &lisp_mux_buffer, (uint32_t)BUFSIZE);
				lbuf_reserve(&lisp_buffer,MUX_STACK_OFFSET);
				memcpy (lbuf_data(&lisp_buffer), out_muxed_packet, out_total_length);
				lisp_data_length = out_total_length;
				lbuf_set_size(&lisp_buffer, lisp_data_length);
				// Encapsulate output multiplexed packet in a LISP packet and sent it
				mux_output_unicast(&lisp_buffer,data_simplemux);
				break;
			 case 2:
				LMLOG(LCRIT, "Invalid loop when mux_packets function is called\n");
				return (-1);
				break;
			}
			break;
		}
	}
	else { 
			LMLOG(LERR, "mux_tuple has not been lookup\n");
			return (-1);
	}

	return(0);
}


/*****************************************************************************/
/***************** NET to tun. demux and decompress **************************/
/*****************************************************************************/

void demux_packets (unsigned char *packet_in, uint32_t size_packet_in, int tun_receive_fd)
{
	// variables for storing the packets to demultiplex
	uint16_t nread_from_net;					// number of bytes read from network which will be demultiplexed
	unsigned char buffer_from_net[BUFSIZE];				// stores the packet received from the network, before sending it to tun
        unsigned char protocol_rec;	
	unsigned char demuxed_packet[BUFSIZE];				// stores each demultiplexed packet
	int num_demuxed_packets;					// a counter of the number of packets inside a muxed one
	int first_header_read;						// it is 0 when the first header has not been read
	int position;							// for reading the arrived multiplexed packet
	int LXT_position;						// the position of the LXT bit. It may be 6 (non-first header) or 7 (first header)
	int single_protocol_rec;					// it is the bit Single-Protocol-Bit received in a muxed packet
	int maximum_packet_length;					// the maximum lentgh of a packet. It may be 64 (first header) or 128 (non-first header)
	int packet_length;						// the length of each packet inside the multiplexed bundle

	//indexes and counters
	int l;

	/* variables for the log file */
	bool bits[8];							// it is used for printing the bits of a byte in debug mode

	// ROHC header compression variables			
	int ROHC_mode;							// it is 0 if ROHC is not used   
									// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
									// it is 2 for ROHC Bidirectional Optimistic mode
									// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)

	unsigned char ip_buffer_d[BUFSIZE];				// the buffer that will contain the resulting IP decompressed packet
	struct rohc_buf ip_packet_d = rohc_buf_init_empty(ip_buffer_d, BUFSIZE);
	unsigned char rohc_buffer_d[BUFSIZE];				// the buffer that will contain the ROHC packet to decompress
	struct rohc_buf rohc_packet_d = rohc_buf_init_empty(rohc_buffer_d, BUFSIZE);
	rohc_status_t status;


	/* structures to handle ROHC feedback */
	unsigned char rcvd_feedback_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet received
	struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcvd_feedback_buffer_d, BUFSIZE);

	unsigned char feedback_send_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet to be sent
	struct rohc_buf feedback_send = rohc_buf_init_empty(feedback_send_buffer_d, BUFSIZE);
	
	// data arrived at the network interface: read, demux, decompress and forward it

	nread_from_net = size_packet_in;
	memcpy(buffer_from_net, packet_in, size_packet_in);
	
	/* increase the counter of the number of packets read from the network */
	net2tun++;

	//LMLOG(LDBG_1, "MUXED PACKET #%lu: Read muxed packet from %s: %i bytes\n", net2tun, inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), /*ntohs(remote.sin_port),*/ nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE );				

	// write the log file
	if ( log_file != NULL ) {
		//fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + LISP_HEADER_SIZE, net2tun/*, inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), ntohs(remote.sin_port)*/);
		fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
	}

	// if the packet comes from the multiplexing port, I have to demux it and write each packet to the tun interface
	position = 0; //this is the index for reading the packet/frame
	num_demuxed_packets = 0;

	first_header_read = 0;

	while (position < nread_from_net) {

		if ( PROTOCOL_FIRST ) {
			/* read the separator */
			// - read 'protocol', the SPB and LXT bits

			// check if this is the first separator or not
			if (first_header_read == 0) {		// this is the first separator

				// the first thing I expect is a 'protocol' field
				if ( SIZE_PROTOCOL_FIELD == 1 ) {
					protocol_rec = buffer_from_net[position];
					position ++;
				} else {	// SIZE_PROTOCOL_FIELD == 2
					protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
					position = position + 2;
				}

				// after the first byte I will find a Mux separator, so I check the next byte
				// Since this is a first header:
				//	- SPB will be stored in 'bits[7]'
				//	- LXT will be stored in 'bits[6]'
				FromByte(buffer_from_net[position], bits);

				// check the Single Protocol Bit (SPB, one bit), which only appears in the first
				// Simplemux header.  It would is set to 0 if all the multiplexed
				// packets belong to the same protocol (in this case, the "protocol"
				// field will only appear in the first Simplemux header).  It is set to
				// 1 when each packet MAY belong to a different protocol.
				if (bits[7]) {
					single_protocol_rec = 1;
				} else {
					single_protocol_rec = 0;
				}

				// as this is a first header, the length extension bit is the second one, and the 
				// maximum length of a single-byte packet is 64 bytes
				LXT_position = 6;
				maximum_packet_length = 64;

				// if I am here, it means that I have read the first separator
				first_header_read = 1;
									
			} else {
				// Non-first header

				if (single_protocol_rec == 1) {
					// all the packets belong to the same protocol, so the first byte belongs to the Mux separator, so I check it
					FromByte(buffer_from_net[position], bits);
				} else {
					// each packet belongs to a different protocol, so the first thing I find is the 'Protocol' field
					// and the second one belongs to the Mux separator, so I check it
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol_rec = buffer_from_net[position];
						position ++;
					} else {	// SIZE_PROTOCOL_FIELD == 2
						protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
						position = position + 2;
					}

					// get the value of the bits of the first byte
					// as this is a non-first header:
					//	- LXT will be stored in 'bits[7]'
					FromByte(buffer_from_net[position], bits);
				}

				// as this is a non-first header, the length extension bit is the first one (7), and the
				// maximum length of a single-byte packet is 128 bytes
				LXT_position = 7;
				maximum_packet_length = 128;
			}

			// I have demuxed another packet
			num_demuxed_packets ++;
			//LMLOG(LDBG_2, "\n");

			LMLOG(LDBG_1, " DEMUXED PACKET #%i", num_demuxed_packets);
			//if ((debug_level == 1) && (ROHC_mode == 0) ) LMLOG (LDBG_1,"\n");
			LMLOG(LDBG_2, ": ");

			// read the length
			// Check the LXT (length extension) bit.
			// if this is a first header, the length extension bit is the second one (6), and the maximum
			// length of a single-byte packet is 64 bytes

			if (bits[LXT_position]== false) {
				// if the LXT bit is 0, it means that the separator is one-byte
				// I have to convert the six less significant bits to an integer, which means the length of the packet
				// since the two most significant bits are 0, the length is the value of the char
				packet_length = buffer_from_net[position] % maximum_packet_length;
				LMLOG(LDBG_2, " Mux separator of 1 byte: (%02x) ", buffer_from_net[position]);
        PrintByte(LDBG_2, 8, bits);

				position ++;

			} else {
				// if the second bit (LXT) of the first byte is 1, it means that the separator is not one-byte

				// check the bit 7 of the second byte
				FromByte(buffer_from_net[position+1], bits);

				// If the LXT bit is 0, this is a two-byte length
				if (bits[7] == 0) {

					// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
					// I do the product by 128, because the next byte includes 7 bits of the length
					packet_length = ((buffer_from_net[position] % maximum_packet_length) * 128 );
					// I add the value of the 7 less significant bits of the second byte
					packet_length = packet_length + (buffer_from_net[position+1] % 128);
					if (debug_level ) {
						LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", buffer_from_net[position]);
						PrintByte(LDBG_2, 8, bits);
						FromByte(buffer_from_net[position+1], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+1]);
						PrintByte(LDBG_2, 8, bits);	
					}					
					position = position + 2;


				// If the LXT bit is 1, this is a three-byte length
				} else {
					// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
					// I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
					packet_length = ((buffer_from_net[position] % maximum_packet_length) * 16384 );
					// I get the 6 (or 7) less significant bits of the second byte by using modulo 128
					// I do the product by 128, because the next byte includes 7 bits of the length
					packet_length = packet_length + ((buffer_from_net[position+1] % 128) * 128 );
					// I add the value of the 7 less significant bits of the second byte
					packet_length = packet_length + (buffer_from_net[position+2] % 128);
					if (debug_level ) {
						LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", buffer_from_net[position]);
						PrintByte(LDBG_2, 8, bits);
						FromByte(buffer_from_net[position+1], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+1]);
						PrintByte(LDBG_2, 8, bits);	
						FromByte(buffer_from_net[position+2], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+2]);
						PrintByte(LDBG_2, 8, bits);
					}					
					position = position + 3;
				}
			}

			LMLOG(LDBG_1, ": total %i bytes\n", packet_length);


		} else { 	// 'Protocol' field goes after the separator

			// read the SPB and LXT bits and 'protocol', 

			// check if this is the first separator or not
			if (first_header_read == 0) {

				// in the first byte I will find a Mux separator, so I check it
				// Since this is a first header:
				//	- SPB will be stored in 'bits[7]'
				//	- LXT will be stored in 'bits[6]'
				FromByte(buffer_from_net[position], bits);

				// check the Single Protocol Bit (SPB, one bit), which only appears in the first
				// Simplemux header.  It would is set to 0 if all the multiplexed
				// packets belong to the same protocol (in this case, the "protocol"
				// field will only appear in the first Simplemux header).  It is set to
				// 1 when each packet MAY belong to a different protocol.
				if (bits[7]) {
					single_protocol_rec = 1;
				} else {
					single_protocol_rec = 0;
				}

				// as this is a first header, the length extension bit is the second one, and the 
				// maximum length of a single-byte packet is 64 bytes
				LXT_position = 6;
				maximum_packet_length = 64;

			} else {	// Non-first header

				// get the value of the bits of the first byte
				// as this is a non-first header:
				//	- LXT will be stored in 'bits[7]'
				FromByte(buffer_from_net[position], bits);
							
				// as this is a non-first header, the length extension bit is the first one (7), and the
				// maximum length of a single-byte packet is 128 bytes
				LXT_position = 7;
				maximum_packet_length = 128;
			}

			// I have demuxed another packet
			num_demuxed_packets ++;
			//LMLOG(LDBG_2, "\n");

			LMLOG(LDBG_1, " DEMUXED PACKET #%i", num_demuxed_packets);
			LMLOG(LDBG_2, ": ");

			// read the length
			// Check the LXT (length extension) bit.
			if (bits[LXT_position]== false) {
				// if the LXT bit is 0, it means that the separator is one-byte

				// I have to convert the 6 (or 7) less significant bits to an integer, which means the length of the packet
				// since the two most significant bits are 0, the length is the value of the char
				packet_length = buffer_from_net[position] % maximum_packet_length;
				LMLOG(LDBG_2, " Mux separator of 1 byte: (%02x) ", buffer_from_net[position]);
				PrintByte(LDBG_2, 8, bits);

				position ++;

			} else {
				// if the second bit (LXT) of the first byte is 1, it means that the separator is not one-byte

				// check the bit 7 of the second byte
				FromByte(buffer_from_net[position+1], bits);

				// If the LXT bit is 0, this is a two-byte length
				if (bits[7] == 0) {
					// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
					// I do the product by 128, because the next byte includes 7 bits of the length
					packet_length = ((buffer_from_net[position] % maximum_packet_length) * 128 );
					// I add the value of the 7 less significant bits of the second byte
             
					packet_length = packet_length + (buffer_from_net[position+1] % 128);
					if (debug_level ) {
						LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", buffer_from_net[position]);
						PrintByte(LDBG_2, 8, bits);
						FromByte(buffer_from_net[position+1], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+1]);
						PrintByte(LDBG_2, 8, bits);	
					}					
					position = position + 2;


				// If the LXT bit of the second byte is 1, this is a three-byte length
				} else {
					// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
					// I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
					packet_length = ((buffer_from_net[position] % maximum_packet_length) * 16384 );
					// I get the 6 (or 7) less significant bits of the second byte by using modulo 128
					// I do the product by 128, because the next byte includes 7 bits of the length
					packet_length = packet_length + ((buffer_from_net[position+1] % 128) * 128 );
					// I add the value of the 7 less significant bits of the second byte
					packet_length = packet_length + (buffer_from_net[position+2] % 128);
					if (debug_level ) {
						LMLOG(LDBG_2, " Mux separator of 2 bytes: (%02x) ", buffer_from_net[position]);
						PrintByte(LDBG_2, 8, bits);
						FromByte(buffer_from_net[position+1], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+1]);
						PrintByte(LDBG_2, 8, bits);	
						FromByte(buffer_from_net[position+2], bits);
						LMLOG(LDBG_2, " (%02x) ",buffer_from_net[position+2]);
						PrintByte(LDBG_2, 8, bits);
					}					
					position = position + 3;
				}
			}

			LMLOG(LDBG_1, ": total %i bytes\n", packet_length);


			// check if this is the first separator or not
			if (first_header_read == 0) {		// this is the first separator. The protocol field will always be present
				// the next thing I expect is a 'protocol' field
				if ( SIZE_PROTOCOL_FIELD == 1 ) {
					protocol_rec = buffer_from_net[position];
					position ++;
				} else {	// SIZE_PROTOCOL_FIELD == 2
					protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
					position = position + 2;
				}

				// if I am here, it means that I have read the first separator
				first_header_read = 1;

			} else {			// non-first separator. The protocol field may or may not be present
				if ( single_protocol_rec == 0 ) {
					// each packet belongs to a different protocol, so the first thing is the 'Protocol' field
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol_rec = buffer_from_net[position];
						position ++;
					} else {	// SIZE_PROTOCOL_FIELD == 2
						protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
						position = position + 2;
					}
				}
			}
		}

		// copy the packet to a new string
		for (l = 0; l < packet_length ; l++) {
			demuxed_packet[l] = buffer_from_net[l + position ];
		}
		position = position + packet_length;

		// Check if the position has gone beyond the size of the packet (wrong packet)
		if (position > nread_from_net) {
			// The last length read from the separator goes beyond the end of the packet
			LMLOG (LDBG_1, "  The length of the packet does not fit. Packet discarded\n");

			// write the log file
			if ( log_file != NULL ) {
				// the packet is bad so I add a line
				fprintf (log_file, "%"PRIu64"\terror\tdemux_bad_length\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun );	
				fflush(log_file);
			}
						
		} else {

			/************ decompress the packet ***************/

			// if the number of the protocol is NOT 142 (ROHC) I do not decompress the packet
			if ( protocol_rec != 142 ) {
				// non-compressed packet
				// dump the received packet on terminal
				ROHC_mode = 0;
				if (debug_level) {
					//LMLOG(LDBG_1, " Received ");
					LMLOG(LDBG_2, "   ");
					dump_packet ( packet_length, demuxed_packet );
				}

			} else {
				// ROHC-compressed packet
				ROHC_mode = 1; ///*********************************************** FIXME: now only is 1	 *******************************************************
				// I cannot decompress the packet if I am in no-ROHC mode
				if ( ROHC_mode == 0 ) {
					LMLOG(LDBG_1," ROHC packet received, but not in ROHC mode. Packet dropped\n");

					// write the log file
					if ( log_file != NULL ) {
						fprintf (log_file, "%"PRIu64"\tdrop\tno_ROHC_mode\t%i\t%lu\n", GetTimeStamp(), packet_length, net2tun);	// the packet may be good, but the decompressor is not in ROHC mode
						fflush(log_file);
					}
				} else {
					// reset the buffers where the rohc packets, ip packets and feedback info are to be stored
					rohc_buf_reset (&ip_packet_d);
					rohc_buf_reset (&rohc_packet_d);
					rohc_buf_reset (&rcvd_feedback);
					rohc_buf_reset (&feedback_send);

					// Copy the compressed length and the compressed packet
					rohc_packet_d.len = packet_length;
						
					// Copy the packet itself
					for (l = 0; l < packet_length ; l++) {
						rohc_buf_byte_at(rohc_packet_d, l) = demuxed_packet[l];
					}

					// dump the ROHC packet on terminal
					if (debug_level == 1) {
						LMLOG(LDBG_1, " ROHC. ");
					}
					if (debug_level == 2) {
						LMLOG(LDBG_2, " ");
						LMLOG(LDBG_2, " ROHC packet\n   ");
						dump_packet (packet_length, demuxed_packet);
					}

					// decompress the packet
					status = rohc_decompress3 (decompressor, rohc_packet_d, &ip_packet_d, &rcvd_feedback, &feedback_send);

					// if bidirectional mode has been set, check the feedback
					if ( ROHC_mode > 1 ) {

						// check if the decompressor has received feedback, and it has to be delivered to the local compressor
						if ( !rohc_buf_is_empty( rcvd_feedback) ) { 
							LMLOG(LDBG_3, "Feedback received from the remote compressor by the decompressor (%i bytes), to be delivered to the local compressor\n", rcvd_feedback.len);
							// dump the feedback packet on terminal
							if (debug_level) {
								LMLOG(LDBG_2, "  ROHC feedback packet received\n   ");

								dump_packet (rcvd_feedback.len, rcvd_feedback.data );
							}


							// deliver the feedback received to the local compressor
							//https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
							if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
								LMLOG(LDBG_3, "Error delivering feedback received from the remote compressor to the compressor\n");
							} else {
								LMLOG(LDBG_3, "Feedback from the remote compressor delivered to the compressor: %i bytes\n", rcvd_feedback.len);
							}
						} else {
							LMLOG(LDBG_3, "No feedback received by the decompressor from the remote compressor\n");
						}

						// check if the decompressor has generated feedback to be sent by the feedback channel to the other peer
						if ( !rohc_buf_is_empty( feedback_send ) ) { 
							LMLOG(LDBG_3, "Generated feedback (%i bytes) to be sent by the feedback channel to the peer\n", feedback_send.len);

							// dump the ROHC packet on terminal
							if (debug_level) {
								LMLOG(LDBG_2, "  ROHC feedback packet generated\n   ");
								dump_packet (feedback_send.len, feedback_send.data );
							}


							// send the feedback packet to the peer
							/*if (sendto(feedback_fd, feedback_send.data, feedback_send.len, 0, (struct sockaddr *)&feedback_remote, sizeof(feedback_remote))==-1) {
								perror("sendto()");
							} else {
								LMLOG(LDBG_3, "Feedback generated by the decompressor (%i bytes), sent to the compressor\n", feedback_send.len);
							}*/
						} else {
							LMLOG(LDBG_3, "No feedback generated by the decompressor\n");
						}
					}

					// check the result of the decompression

					// decompression is successful
					if ( status == ROHC_STATUS_OK) {

						if(!rohc_buf_is_empty(ip_packet_d))	{	// decompressed packet is not empty
								
							// ip_packet.len bytes of decompressed IP data available in ip_packet
							packet_length = ip_packet_d.len;

							// copy the packet
							memcpy(demuxed_packet, rohc_buf_data_at(ip_packet_d, 0), packet_length);

							//dump the IP packet on the standard output
							LMLOG(LDBG_2, "  ");
							LMLOG(LDBG_1, "IP packet resulting from the ROHC decompression: %i bytes\n", packet_length);
							LMLOG(LDBG_2, "   ");

							if (debug_level) {
								// dump the decompressed IP packet on terminal
								dump_packet (ip_packet_d.len, ip_packet_d.data );
							}

						} else {
							/* no IP packet was decompressed because of ROHC segmentation or
								* feedback-only packet:
								*  - the ROHC packet was a non-final segment, so at least another
								*    ROHC segment is required to be able to decompress the full
								*    ROHC packet
								*  - the ROHC packet was a feedback-only packet, it contained only
								*    feedback information, so there was nothing to decompress */
							LMLOG(LDBG_1, "  no IP packet decompressed\n");

							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\trec\tROHC_feedback\t%i\t%lu\tfrom\n", GetTimeStamp(), nread_from_net, net2tun/*, inet_ntoa(data_simplemux->mux_tuple.drloc.ip.addr.v4), ntohs(remote.sin_port)*/);	// the packet is bad so I add a line
								fflush(log_file);
							}
						}
					}

					else if ( status == ROHC_STATUS_NO_CONTEXT ) {

						// failure: decompressor failed to decompress the ROHC packet 
						LMLOG(LDBG_1, "  decompression of ROHC packet failed. No context\n");
						//fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

						// write the log file
						if ( log_file != NULL ) {
							// the packet is bad
							fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
							fflush(log_file);
						}
					}

					else if ( status == ROHC_STATUS_OUTPUT_TOO_SMALL ) {	// the output buffer is too small for the compressed packet

						// failure: decompressor failed to decompress the ROHC packet 
						LMLOG(LDBG_1, "  decompression of ROHC packet failed. Output buffer is too small\n");
						//fprintf(stderr, "  decompression of ROHC packet failed. Output buffer is too small\n");

						// write the log file
						if ( log_file != NULL ) {
							// the packet is bad
							fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Output buffer is too small\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
							fflush(log_file);
						}
					}

					else if ( status == ROHC_STATUS_MALFORMED ) {			// the decompression failed because the ROHC packet is malformed 

						// failure: decompressor failed to decompress the ROHC packet 
						LMLOG(LDBG_1, "  decompression of ROHC packet failed. No context\n");
						//fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

						// write the log file
						if ( log_file != NULL ) {
							// the packet is bad
							fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. No context\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
							fflush(log_file);
						}
					}

					else if ( status == ROHC_STATUS_BAD_CRC ) {			// the CRC detected a transmission or decompression problem

						// failure: decompressor failed to decompress the ROHC packet 
						LMLOG(LDBG_1, "  decompression of ROHC packet failed. Bad CRC\n");
						//fprintf(stderr, "  decompression of ROHC packet failed. Bad CRC\n");

						// write the log file
						if ( log_file != NULL ) {
							// the packet is bad
							fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Bad CRC\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
							fflush(log_file);
						}
					}

					else if ( status == ROHC_STATUS_ERROR ) {				// another problem occurred

						// failure: decompressor failed to decompress the ROHC packet 
						LMLOG(LDBG_1, "  decompression of ROHC packet failed. Other error\n");
						//fprintf(stderr, "  decompression of ROHC packet failed. Other error\n");

						// write the log file
						if ( log_file != NULL ) {
							// the packet is bad
							fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Other error\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
							fflush(log_file);
						}
					}
				}

			} /*********** end decompression **************/

			// write the demuxed (and perhaps decompressed) packet to the tun interface
			// if compression is used, check that ROHC has decompressed correctly
			if ( ( protocol_rec != 142 ) || ((protocol_rec == 142) && ( status == ROHC_STATUS_OK))) {

				LMLOG(LDBG_2, "\n");

				// write the demuxed packet to the network
				if ((write(tun_receive_fd, demuxed_packet, packet_length)) < 0) {
					LMLOG(LDBG_2, "lisp_input: write error: %s\n ", strerror(errno));
				}

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\tsent\tdemuxed\t%i\t%lu\n", GetTimeStamp(), packet_length, net2tun);	// the packet is good
					fflush(log_file);
				}
			}
		}
	}
}







