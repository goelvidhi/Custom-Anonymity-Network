/**
 * CS 558L Final Project
 *
 * router helper functions and data structures
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
//#include <openssl/des.h>

#include "packet.h"
#include "des.h"

#define ROUTE_QUERY_CYCLE				1		/* Router interface send route query packet every 300 packet it sniffs */
#define ROUTE_QUERY_WAIT_TIME_OUT		10		/* After the router sends out route query, if no response within 10 packets received,
											 	 * there is a timeout, the metric of that route is set to max */
#define ROUTE_QUERY_COUNT				5

#define ROUTING_TABLE_TIMEOUT			5*1000*1000
#define RIP_WAIT_TIMEOUT 				10*1000

typedef struct keybox {
	int dbIndex;
	unsigned char* key_val;
	DES_key_schedule key_sched;
}keybox_t;

typedef struct localIface {
	u_int16_t myaddr;
	pcap_t * handler;
}localIface_t;

typedef struct sniff {
	int tid;					// thread id
	u_int16_t rid;				// router id
	int iface_cnt;				// total number of interfaces in the router
	char dev_name[50];			// name of this particular interface
	char dev_list[5][50];		// store all device names
	pcap_t* handler_list[5];	// store handlers for all devices
	struct keybox* key_list;	// store all the keys
	struct localIface myIface;	// my own handler and my own addr
	FILE* logfile;				// file for my own log

	int rip;					// used only in dynamic routing, 1 means serve RIP purpose
	int rt_timeout;				// counter. exchange packet information every ROUTE_QUERY_CYCLE packets
	int rip_wait_timeout;		// counter. after sending routing info query, we count ROUTE_QUERY_WAIT_TIME_OUT packets
	int rt_updating;			// router in RT_updating states
	int alt_iface;
	int rip_valid;
	int rip_reply_cnt;
	u_char rip_reply[PACKET_BUF_SIZE];

	unsigned int total_packet;	// number of total packets coming to this interface
	u_int64_t total_bytes;
	unsigned int stat_pktnum;	// number of valid packets this interface has sniffed 
    u_int64_t stat_bytes;		// number of valid bytes processed through this interface
}sniff_t;

typedef struct scheduler_args {
	pthread_t* thread_list;
	int thread_cnt;
	u_int16_t rid;
	struct sniff* thread_args;
	pcap_t* handler_list[5];
} scheduler_args_t;

struct sockaddr getLocalMac(char *iface);
