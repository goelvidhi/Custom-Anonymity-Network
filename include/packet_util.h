/**
 * CS 558L Final Project
 *
 * Packet related data structures and methods
 */

#ifndef _PACKET_UTIL_H_
#define _PACKET_UTIL_H_

#include "packet.h"

#define TEST_SEQ_CNT 5
/**
 * @param packetOut 	(Output) 	key exchange packet that is ready to be transferred
 * @param payload		(Input)		key exchange packet content
 * @param key_size		(Input)		size of the key
 * @param size 			(Input)		size of the payload (excluding any header)
 * @param source		(Input)		source addr, defined in env.h
 * @param dest			(Input)		destination addr, defined in env.h
 * @return							size of the entire packet
 */
int generate_key_packet(u_char* packetOut, unsigned char* payload, int key_size, int size, u_int16_t source, u_int16_t dest);

/**
 * @param packetOut 	(Output) 	key exchange packet that is ready to be transferred
 * @param payload		(Input)		key exchange packet content
 * @param source		(Input)		source addr, defined in env.h
 * @param dest			(Input)		destination addr, defined in env.h
 * @param size 			(Input)		size of the file segment
 * @param port			(Input)		file transfer port number
 * @param seq			(Input)		file segment sequence number
 * @return							size of the entire packet
 */
int generate_file_packet(u_char* packetOut, unsigned char* payload, u_int16_t source, u_int16_t dest, int size, int port, int seq,u_int8_t last,int nacpacket);
int generate_fd_file_packet(u_char*, unsigned char*, u_int16_t, u_int16_t, int, int, int);
int generate_test_packet(u_char* packetOut, int size, int seq, int source, int dest);

/*
 * validates if we are supposed to take care of this packet
 *
 * @param packet 	(Input) the entire packet
 * @return 					ROUTE_ON_RELIABLE or KEY_EXCHANGE as defined in packet.h
 *							-1 for non-related packet
 */
int validate_packet(u_char* packet);

/*
 * Filter out packets coming from master network, and all local osi packet such as arp request
 */
int osi_filter(u_char* packet, u_int16_t myrid);

#endif
