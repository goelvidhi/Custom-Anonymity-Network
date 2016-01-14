/**
 * CS 558L Final Project
 * 
 * Print packets
 */

#ifndef _PRINTP_H_
#define _PRINTP_H_

#include "packet.h"


/**
 * Prints out a packet CS 558L final project. Only supports ROUTE_ON_RELIABLE packet and KEY_EXCHANGE
 * 
 * @param logfile		(Input)		file handler where the log should be print to
 * @param packet 		(Input)		the entire packet
 * @param size 			(Input)		size of the entire packet
 */
void fprintp(FILE* logfile, u_char* packet, int size);

/**
 * Helper functions of fprintp
 */
void print_rthdr(FILE*, struct rthdr*);
void print_rl_packet(FILE*, u_char*, int);
void print_key_packet(FILE*, u_char*, int);
void print_path_query_packet(FILE*, u_char*, int);
void print_path_query_reply_packet(FILE*, u_char*, int);
void print_data(FILE*, u_char*, int);
void printKey(unsigned char *buf, int len);

#endif