#ifndef SIMPLEMUX_H_
#define SIMPLEMUX_H_

#include "../liblisp/lisp_ip.h"
#include "../liblisp/lisp_address.h"
#include "sockets.h"
#include "packets.h"
#include "lbuf.h"

#define BUFSIZE 2304			// buffer for reading from tun interface, must be >= MTU of the network
#define MUX_STACK_OFFSET  100	// buffer offset for multiplexing
#define SIZE_PROTOCOL_FIELD 1	// 1: protocol field of one byte
								// 2: protocol field of two bytes

#define PROTOCOL_FIRST 0		// 1: protocol field goes before the length byte(s) (as in draft-saldana-tsvwg-simplemux-01)
								// 0: protocol field goes after the length byte(s)  (as in draft-saldana-tsvwg-simplemux-02 and subsequent versions)


#define MAXPKTS 100				// maximum number of packets to store
#define MAXTIMEOUT 100000000.0	// maximum value of the timeout (microseconds). (default 100 seconds)


#define IPv4_HEADER_SIZE 20
#define UDP_HEADER_SIZE  8
#define LISP_HEADER_SIZE 8


// REFERENCED STRUCTS

/*typedef struct packet_tuple {
    lisp_addr_t                     src_addr;
    lisp_addr_t                     dst_addr;
    uint16_t                        src_port;
    uint16_t                        dst_port;
    uint8_t                         protocol;
} packet_tuple_t;


typedef struct _lisp_addr_t {
    struct {
        union {
            ip_addr_t       ip;
            ip_prefix_t     ippref;
            lcaf_addr_t     lcaf;
        };
        lm_afi_t        lafi;
    };
}lisp_addr_t;


typedef struct {
    int      afi;
    union {
        struct in_addr      v4;
        struct in6_addr     v6;
    } addr;
} ip_addr_t;

typedef struct {
    ip_addr_t   prefix;
    uint8_t     plen;
} ip_prefix_t;


struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};
*/


typedef struct mux_tuple {
	ip_addr_t		src_addr;		// IP source address of packet to be sent
	ip_addr_t		dst_addr;		// IP destination address of packet to be sent
	ip_addr_t		src_net;		// IP source net address of packet to be sent
	int				src_mask;		// IP source address mask of packet to be sent
	ip_addr_t		dst_net;		// IP destination net address of packet to be sent
	int				dst_mask;		// IP destination address mask of packet to be sent
	lisp_addr_t		srloc;			// LISP source address of tunnel to be used
	lisp_addr_t		drloc;			// LISP destination address of tunnel to be used
	int				out_sock;		// LISP socket of tunnel to be used
} mux_tuple_t;


typedef struct config_simplemux {
	int ROHC_mode;							// it is 0 if ROHC is not used
											// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
											// it is 2 for ROHC Bidirectional Optimistic mode
											// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)

	int limit_numpackets_tun;				// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
											// limit of the number of packets for triggering a muxed packet 

	uint64_t timeout;						// timeout for triggering a muxed packet
											// (microseconds) if a packet arrives and the timeout has expired (time from the  
											// previous sending), the sending is triggered. default 100 seconds

	uint64_t period;						//Period for triggering a muxed packet 
	uint64_t time_last_sent_in_microsec;	// moment when the last multiplexed packet was sent

	int interface_mtu;						// the maximum transfer unit of the interface
	int user_mtu;							// the MTU specified by the user (it must be <= interface_mtu)

	int size_threshold;						// if the number of bytes stored is higher than this, a muxed packet is sent

	
	mux_tuple_t mux_tuple;					// Tuple to detect the simplemux configuration to be used

	// variables for storing the packets to multiplex
	unsigned char protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];	// protocol field of each packet
	uint16_t size_separators_to_multiplex[MAXPKTS];			// stores the size of the Simplemux separator. It does not include the "Protocol" field
	unsigned char separators_to_multiplex[MAXPKTS][3];		// stores the header ('protocol' not included) received from tun, before sending it to the network
	uint16_t size_packets_to_multiplex[MAXPKTS];			// stores the size of the received packet
	unsigned char packets_to_multiplex[MAXPKTS][BUFSIZE];	// stores the packets received from tun, before storing it or sending it to the network
	int num_pkts_stored_from_tun;							// number of packets received and not sent from tun (stored)
	int size_muxed_packet;									// acumulated size of the multiplexed packet
	int first_header_written;								// it indicates if the first header has been written or not

} data_simplemux_t;


void muxed_init();						// Initialize simplemux data

void muxed_timer_process_all();			// Process the timers of all "simplemux data structs"

int mux_tun_output_unicast (lbuf_t *b, packet_tuple_t *tuple, fwd_entry_t *fe);	// Multiplex the received packets from tun

int mux_packets(unsigned char *packet_in, uint32_t size_packet_in, data_simplemux_t *data_simplemux, unsigned char *out_muxed_packet, uint16_t *out_total_length); // Aggregation of packets (compress and multiplex)

//int lookup_mux_tuple (packet_tuple_t *tpl, fwd_entry_t *fe, data_simplemux_t *data_simplemux);	// Lookup mux_tuple from packet tuple and forward entry
data_simplemux_t * lookup_mux_tuple (packet_tuple_t *tpl, fwd_entry_t *fe); // Lookup mux_tuple from packet tuple and forward entry

int mux_output_unicast(lbuf_t *b, data_simplemux_t *data_simplemux);	// Send multiplexed packet encapsulated in LISP packet

void demux_packets (unsigned char *packet_in, uint32_t size_packet_in, int tun_receive_fd);  // Demuxtiplexer of packets (demultiplexer and (if necessary) decompression)


#endif /*SIMPELMUX_H_*/














			
