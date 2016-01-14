/**
 * CS 558L Final Project
 *
 * Packet related data structures and methods
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "packet_util.h"
#include "env.h"

int generate_key_packet(u_char* packetOut, unsigned char* payload, int key_size, int size, u_int16_t source, u_int16_t dest) {
    if (size < MIN_APP_PKT_LEN || size > MAX_APP_PKT_LEN) {
        fprintf(stderr, "ERROR: size should between %lu and %lu, but the input is %d\n", MIN_APP_PKT_LEN, MAX_APP_PKT_LEN, size);
        return -1;
    }
    int hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct kehdr);
    int total_len = hdrlen + size;
    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
    memset(packetOut, 0xff, sizeof(u_char) * ETH_ALEN * 2);

    struct ethhdr* eth = (struct ethhdr*) packetOut;
    eth->h_proto = 0x0000;

    struct rthdr* rth = (struct rthdr*)(packetOut + sizeof(struct ethhdr));
    rth->saddr = source;
    rth->daddr = dest;
    rth->protocol = KEY_EXCHANGE;
    rth->size = htons((u_int16_t)total_len);

    struct kehdr* keh = (struct kehdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
    keh->size = (u_int16_t)key_size;
    memcpy(packetOut + hdrlen, payload, key_size);
    return total_len;
}

int generate_file_packet(u_char* packetOut, unsigned char* payload, u_int16_t source, u_int16_t dest, int size, int port, int seq, u_int8_t last,int nac_packet) {
	if (size < MIN_APP_PKT_LEN || size > MAX_APP_PKT_LEN) {
        fprintf(stderr, "ERROR: size should between %lu and %lu, but the input is %d\n", MIN_APP_PKT_LEN, MAX_APP_PKT_LEN, size);
        return -1;
    }

    int hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
    int total_len = hdrlen + size;

    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
    if (nac_packet==0){
   	 memset(packetOut, 0xff, sizeof(u_char) * ETH_ALEN * 2);
    }
    else{
   	 memset(packetOut, 0xaa, sizeof(u_char) * ETH_ALEN * 2);
    }
    struct ethhdr* eth = (struct ethhdr*) packetOut;
    eth->h_proto = 0x0000;

    struct rthdr* rth = (struct rthdr*)(packetOut + sizeof(struct ethhdr));
    rth->saddr = source;
    rth->daddr = dest;
    rth->protocol = ROUTE_ON_RELIABLE;
    rth->size = htons((u_int16_t)total_len);

    struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
    rlh->port = (u_int16_t)htons(port);
    rlh->seq = (u_int32_t)htons(seq);
    rlh->dummy = (u_int8_t)last;
    memcpy(packetOut + hdrlen, payload, size);
	//print_rl_packet(stdout, packetOut, total_len);
    return total_len;
}

int generate_fd_file_packet(u_char* packetOut, unsigned char* payload, u_int16_t source, u_int16_t dest, int size, int port, int seq) {
	if (size < MIN_APP_PKT_LEN || size > MAX_APP_PKT_LEN) {
        fprintf(stderr, "ERROR: size should between %lu and %lu, but the input is %d\n", MIN_APP_PKT_LEN, MAX_APP_PKT_LEN, size);
        return -1;
    }
    //fprintf(stdout, "source: %.4x; dest: %.4x; size: %d; port: %d; seq: %d\n", source, dest, size, port, seq);
	//u_char * py = payload;
	//int s =0;
	/*for(s=0;s<size;s++)
	{
		printf("%.4x ",*(py ++));
	}*/
    int hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
	//printf("RTH LEN %d, RLH Length %d, Header Length:%ld",sizeof(struct rthdr), sizeof(struct rlhdr), hdrlen);
    int total_len = hdrlen + size;

    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
    memset(packetOut, 0xff, sizeof(u_char) * ETH_ALEN * 2);

    struct ethhdr* eth = (struct ethhdr*) packetOut;
    eth->h_proto = 0x0000;

    struct rthdr* rth = (struct rthdr*)(packetOut + sizeof(struct ethhdr));
    rth->saddr = source;
    rth->daddr = dest;
    rth->protocol = ROUTE_ON_RELIABLE;
    rth->size = htons((u_int16_t)total_len);

    struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
    rlh->port = (u_int16_t)htons(port);
    rlh->seq = (u_int32_t)htons(seq);

    memcpy(packetOut + hdrlen, payload, size);
	//print_rl_packet(stdout, packetOut, total_len);
    return total_len;
}

int generate_test_packet(u_char* packetOut, int size, int seq, int source, int dest) {
	int hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
	int i;
	u_char content[PACKET_BUF_SIZE];
	for (i = 0; i < size - hdrlen; i++) {
		content[i] = (u_char) (rand() & 0x000000ff);
	}
	u_int16_t saddr, daddr;
	switch(source) {
		case 1:
			saddr = NODE1_RTR1;
			break;
		case 2:
			saddr = NODE2_RTR1;
			break;
		default:
			return -1;
	}
	switch(dest) {
		case 1:
			daddr = NODE1_RTR1;
			break;
		case 2:
			daddr = NODE2_RTR1;
			break;
		default:
			return -1;
	}
	int ret = generate_file_packet(packetOut, content, saddr, daddr, size - hdrlen, 1, seq,0,0);
	return ret;
}

int validate_packet(u_char* packet) {
    int i = 2;
    for (; i < 12; i++) {
        if (packet[i] != 0xff && packet[i] != 0xaa) {
            return -1;
        }
    }
    struct rthdr* rth = (struct rthdr*)(packet + ETH_HLEN);
    if (rth->protocol != ROUTE_ON_RELIABLE && rth->protocol != PATH_QUERY && rth->protocol != PATH_QUERY_REPLY) {
        return -1;
    }
    return rth->protocol;
}

int osi_filter(u_char* packet, u_int16_t myrid) {
    u_int16_t* pkt = (u_int16_t*) packet;
    if (pkt[0] == myrid) {
        return -1;
    }
    int i = 6;
    for (; i < 12; i++) {
        if (packet[i] != 0xff && packet[i] != 0xaa) {
            return -1;
        }
    }
    return 0;
}






