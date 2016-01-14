#ifndef _ROUTING_H_
#define _ROUTING_H_

#include <stdint.h>
#include <net/ethernet.h>
#include "packet.h"
#include "packet_util.h"
//#include <netinet/in.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>


extern uint64_t routing_table[20];
//extern struct rt_entry routing_table_2[10];

typedef enum {
	// Routing options
	P_DO_NOTHING,			/* this interface sent the packet, do nothing */
	P_FORWARD,				/* Forward the packet to next hop */
	P_TIMEOUT,				/* Drop the packet and generate ICMP timeout reply */
	P_ERRCHK,				/* Checksum does not match the packet */
	P_APPRESPONSE,
	P_RIP_REPLY,
	P_RIP_RECV,
	P_NOT_YET_IMPLEMENTED	/* Used only for not-yet-implemented functions */
} r_op;

typedef enum {
	// Packet forward type
	P_LOCAL,
	P_REMOTE
} pf_t;

typedef struct rt_entry {
	int metrix;
	int iface_index; 
} rt_entry_t;

int rt_tbl_size;
extern struct rt_entry routing_table_2[10];

#define NUM_NODE				6
#define ROUTE_METRIX_MAX		99
#define PATH_QUERY_LENTH		64 + ETH_HLEN


void createRT(int);
void printRT(uint64_t *);

void createRT_2();
void printRT_2();
void printRT_atomic(FILE*, int);
int getIPfromIface(char*, char*);

/* takes in packet, return r_op; */
int routing_opt(u_char*, u_int16_t);
int routing_opt_2(u_char*, u_int16_t, u_int16_t);

/* takes in destination addr, return the iface index for the device*/
uint8_t rt_lookup(uint16_t);
int rt_lookup_dummy(uint16_t);
int rt_lookup_2(uint16_t);

/* takes in packet, modify it for forwarding */
void modify_packet(u_char* packet);


struct rt_entry* get_rt_entry(int);
/* return 1 for successful update, 0 for not updated */
int modify_rt_table(int, int, int, int);
void update_lossy_link(int);


/**
 * For dynamic routing
 */
int generate_path_query_packet(u_int16_t, u_int16_t, int, u_char*);
int generate_path_reply_packet(u_int16_t, u_int16_t, int, int, u_char*);
int parse_path_reply_packet(u_char*, int, int);


#endif
