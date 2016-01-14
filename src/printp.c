/**
 * CS 558L Final Project
 *
 * Print packets
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "packet.h"
#include "routing.h"
#include "packet_util.h"
#include "printp.h"

void fprintp(FILE* logfile, u_char* packet, int size) {
	fprintf(logfile, "============================== packet received, size = %d ==============================\n", size);
	struct rthdr* rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
	switch(rth->protocol) {
		case ROUTE_ON_RELIABLE:
			print_rl_packet(logfile, packet, size);
			break;
		case KEY_EXCHANGE:
			print_key_packet(logfile, packet, size);
			break;
		case PATH_QUERY:
			print_path_query_packet(logfile, packet, size);
			break;
		case PATH_QUERY_REPLY:
			print_path_query_reply_packet(logfile, packet, size);
			break;
		default:
			fprintf(logfile, "this is a non route-on defined packet\n");
			print_data(logfile, packet, size);
			break;
	}
	fprintf(logfile, "============================== end of packet ==============================\n\n\n\n\n\n");
}

void print_rthdr(FILE* logfile, struct rthdr* hdr) {
	fprintf(logfile, "Routing Header:\n");
	fprintf(logfile, "\t|-source:             %04x\n", hdr->saddr);
	fprintf(logfile, "\t|-destination:        %04x\n", hdr->daddr);
	fprintf(logfile, "\t|-rid:                %04x\n", hdr->rid);
	fprintf(logfile, "\t|-protocol:           %d\n", (unsigned int)(hdr->protocol));
	fprintf(logfile, "\t|-size:               %d\n", (unsigned int)ntohs((hdr->size)));
	fprintf(logfile, "\n");
}

void print_rl_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
	print_rthdr(logfile, rth);
	struct rlhdr* rlh = (struct rlhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
	fprintf(logfile, "Reliable Protocol Header:\n");
	fprintf(logfile, "\t|-port:              %d\n", (unsigned int)ntohs((rlh->port)));
	fprintf(logfile, "\t|-dummy:             %02x\n", rlh->dummy);
	fprintf(logfile, "\t|-sequence number:   %d\n", (unsigned int)ntohs((rlh->seq)));
	fprintf(logfile, "\n");
	print_data(logfile, packet, size);
}

void print_key_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
	print_rthdr(logfile, rth);
	struct kehdr* khdr = (struct kehdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
	fprintf(logfile, "Key Exchange Header:\n");
	fprintf(logfile, "\t|-key size:          %d\n", (unsigned int)ntohs(khdr->size));
	fprintf(logfile, "\n");
	print_data(logfile, packet, size);
}

void print_path_query_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
	print_rthdr(logfile, rth);

	print_data(logfile, packet, size);
}

void print_path_query_reply_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
	print_rthdr(logfile, rth);
	struct rlhdr* rlh = (struct rlhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
	fprintf(logfile, "Reliable Protocol Header:\n");
	fprintf(logfile, "\t|-port:              %d\n", (unsigned int)ntohs((rlh->port)));
	fprintf(logfile, "\t|-dummy:             %d\n", ntohs(rlh->dummy));
	fprintf(logfile, "\t|-sequence number:   %d\n", (unsigned int)ntohs((rlh->seq)));
	fprintf(logfile, "\n");
	fprintf(logfile, "Routing Table Information:\n");
	int i;
	struct rt_entry* rt = (struct rt_entry*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr));
	for (i = 1; i <= NUM_NODE; i++) {
		fprintf(logfile, "\tNode %d: metrix %d, iface %d\n", i, rt->metrix, rt->iface_index);
		rt++;
	}
	print_data(logfile, packet, size);
}

void print_data(FILE* logfile, u_char* data, int size) {
	fprintf(logfile, "Data:\n");
	int i, j;
	for(i=0 ; i < size ; i++) {
		//if one line of hex printing is complete...
    	if( i!=0 && i%16==0) {
      		fprintf(logfile , "         ");
      		for(j=i-16 ; j<i ; j++) {
        		if(data[j]>=32 && data[j]<=128) {
          			fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
          		} else {
          			fprintf(logfile , "."); //otherwise print a dot
          		}
      		}
      		fprintf(logfile , "\n");
    	}

    	if(i%16==0) {
    		fprintf(logfile , "   ");
   		}

		fprintf(logfile , " %02X",(unsigned int)data[i]);

    	//print the last spaces
    	if( i==size-1) {
	    	for(j=0;j<15-i%16;j++) {
	        	fprintf(logfile , "   "); //extra spaces
	    	}

	    	fprintf(logfile , "         ");

	    	for(j=i-i%16 ; j<=i ; j++) {
		        if(data[j]>=32 && data[j]<=128) {
		        	fprintf(logfile , "%c",(unsigned char)data[j]);
		        } else {
		        	fprintf(logfile , ".");
		        }
	    	}
	    	fprintf(logfile ,  "\n" );
    	}
	}
}


void printKey(unsigned char *buf, int len) {
	int i;
    for(i = 0; i < len; i++)
    {
		printf("%02x", buf[i]);
    }
    printf("\n");
}
