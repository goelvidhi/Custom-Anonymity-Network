/**
 * CS 558L Final Project
 *
 * Packet related data structures and methods
 */

#ifndef _FINALPROJ_PACKET_H_
#define _FINALPROJ_PACKET_H_

#include <net/ethernet.h>

/*
 * Being slightly differet from the design, we made everything multiple of
 * 8 bytes, and added memory paddings for better memory line-up during 
 * encryption / decryption.
 *
 * Even with these modifications, our header is still much more efficient
 * than traditional OSI model for this project.
 */

/* Routing protocol header */
typedef struct rthdr {
	u_int16_t 		saddr;			/* source address */
	u_int16_t 		daddr;			/* destination address */
	u_int16_t		rid;			/* identify own router */
	u_int16_t		protocol;		/* route-on team defined protocol */
	u_int16_t		size;			/* packet length */
}__attribute__((packed)) rthdr_t;


/* reliable transfer protocol */
typedef struct rlhdr {
	u_int16_t		port;			/* application instance port */
	u_int16_t		dummy;
	u_int32_t		seq;			/* transfer sequence number */

	/* Memory paddings, for better parallelizations.
	 * note that even we add these paddings, we are still
	 * much efficient than the traditional OSI model.
	 **/
	u_int16_t		dummy2;
	u_int16_t		dummy3;
	u_int16_t		dummy4;
}__attribute__((packed)) rlhdr_t;

/* key exchange transfer protocol */
typedef struct kehdr {
	u_int16_t		size;			/* size of public key */
} kehdr_t;

#define ROUTE_ON_RELIABLE 		0								/* reliable protocol */
#define KEY_EXCHANGE            1								/* key exchange protocol */
#define PATH_QUERY				2
#define PATH_QUERY_REPLY		3

#define PACKET_BUF_SIZE			1600							/* packet buffer size */
#define MTU						1514							/* max transfer unit */
#define MAX_APP_PKT_LEN			MTU - sizeof(struct rthdr)		/* max data an application can send (including its header) */
#define MIN_APP_PKT_LEN			60 - sizeof(struct rthdr)		/* min data an application can send (including its header) */

#endif
