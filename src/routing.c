#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <unistd.h>

#include <pthread.h>

#include "env.h"
#include "packet_util.h"
#include "routing.h"
#include "packet.h"


 uint64_t routing_table[20];
 struct rt_entry routing_table_2[10];
 pthread_mutex_t m_dynamic = PTHREAD_MUTEX_INITIALIZER;		/* Used for modify routing table stage */


void createRT(int extra)
{
    //Iface :"01", Metric : "00",Gateway : "0000", Mask : "fff0",destination network:  "0010"
    routing_table[0] = 0x00000000fff00010;
    rt_tbl_size++;
    routing_table[1] = 0x01000000fff00020;
    rt_tbl_size++;
    routing_table[2] = 0x02000000fff00030;
    rt_tbl_size++;
    if (extra == 1) {
    	routing_table[3] = 0x03000000fff00040;
    	rt_tbl_size++;
    }
    printf("Routing table created\n");
}


void printRT(uint64_t * rt_table)
{
    int i;
    for(i = 0; i < rt_tbl_size; i++){
         uint16_t dest = rt_table[i] & 0xffff;
         uint16_t mask = (rt_table[i] >> 16) & 0xffff;
         uint16_t gateway = (rt_table[i] >> 32) & 0xffff;
         uint8_t metric = (rt_table[i] >> 48) & 0xff;
         uint8_t iface = (rt_table[i] >> 56) & 0xff;
        printf("Dest: %02X Mask: %02X Gateway: %02X Metric: %02X Iface: %02X\n", dest, mask, gateway, metric, iface);
    }

}

void createRT_2() {
	#if DYNAMIC == 0
		#if RTR1 == 1
			// node 1
			routing_table_2[1].metrix = 1;
			routing_table_2[1].iface_index = 2;

			// node 2
			routing_table_2[2].metrix = 1;
			routing_table_2[2].iface_index = 1;

			// node 3
			routing_table_2[3].metrix = 2;
			routing_table_2[3].iface_index = 3;

			// node 4
			routing_table_2[4].metrix = 2;
			routing_table_2[4].iface_index = 3;

			// node 5
			routing_table_2[5].metrix = 2;
			routing_table_2[5].iface_index = 0;

			// node 6
			routing_table_2[6].metrix = 2;
			routing_table_2[6].iface_index = 0;
			return;
		#elif RTR2 == 1
			// node 1
			routing_table_2[1].metrix = 2;
			routing_table_2[1].iface_index = 3;

			// node 2
			routing_table_2[2].metrix = 2;
			routing_table_2[2].iface_index = 3;

			// node 3
			routing_table_2[3].metrix = 1;
			routing_table_2[3].iface_index = 2;

			// node 4
			routing_table_2[4].metrix = 1;
			routing_table_2[4].iface_index = 1;

			// node 5
			routing_table_2[5].metrix = 2;
			routing_table_2[5].iface_index = 0;

			// node 6
			routing_table_2[6].metrix = 2;
			routing_table_2[6].iface_index = 0;
			return;

		#elif RTR3 == 1
			// node 1
			routing_table_2[1].metrix = 2;
			routing_table_2[1].iface_index = 3;

			// node 2
			routing_table_2[2].metrix = 2;
			routing_table_2[2].iface_index = 3;

			// node 3
			routing_table_2[3].metrix = 2;
			routing_table_2[3].iface_index = 0;

			// node 4
			routing_table_2[4].metrix = 2;
			routing_table_2[4].iface_index = 0;

			// node 5
			routing_table_2[5].metrix = 1;
			routing_table_2[5].iface_index = 1;

			// node 6
			routing_table_2[6].metrix = 1;
			routing_table_2[6].iface_index = 2;
			return;
		#endif
	#else
		#if RTR1 == 1
			// node 1
			routing_table_2[1].metrix = 1;
			routing_table_2[1].iface_index = 2;

			// node 2
			routing_table_2[2].metrix = 1;
			routing_table_2[2].iface_index = 1;

			// node 3
			routing_table_2[3].metrix = ROUTE_METRIX_MAX;
			routing_table_2[3].iface_index = 0;

			// node 4
			routing_table_2[4].metrix = ROUTE_METRIX_MAX;
			routing_table_2[4].iface_index = 0;

			// node 5
			routing_table_2[5].metrix = ROUTE_METRIX_MAX;
			routing_table_2[5].iface_index = 3;

			// node 6
			routing_table_2[6].metrix = ROUTE_METRIX_MAX;
			routing_table_2[6].iface_index = 3;
			return;
		#elif RTR2 == 1
			// node 1
			routing_table_2[1].metrix = ROUTE_METRIX_MAX;
			routing_table_2[1].iface_index = 0;

			// node 2
			routing_table_2[2].metrix = ROUTE_METRIX_MAX;
			routing_table_2[2].iface_index = 0;

			// node 3
			routing_table_2[3].metrix = 1;
			routing_table_2[3].iface_index = 2;

			// node 4
			routing_table_2[4].metrix = 1;
			routing_table_2[4].iface_index = 1;

			// node 5
			routing_table_2[5].metrix = ROUTE_METRIX_MAX;
			routing_table_2[5].iface_index = 3;

			// node 6
			routing_table_2[6].metrix = ROUTE_METRIX_MAX;
			routing_table_2[6].iface_index = 3;
			return;

		#elif RTR3 == 1
			// node 1
			routing_table_2[1].metrix = ROUTE_METRIX_MAX;
			routing_table_2[1].iface_index = 0;

			// node 2
			routing_table_2[2].metrix = ROUTE_METRIX_MAX;
			routing_table_2[2].iface_index = 0;

			// node 3
			routing_table_2[3].metrix = ROUTE_METRIX_MAX;
			routing_table_2[3].iface_index = 3;

			// node 4
			routing_table_2[4].metrix = ROUTE_METRIX_MAX;
			routing_table_2[4].iface_index = 3;

			// node 5
			routing_table_2[5].metrix = 1;
			routing_table_2[5].iface_index = 1;

			// node 6
			routing_table_2[6].metrix = 1;
			routing_table_2[6].iface_index = 2;
			return;
		#endif
	#endif
	return;
}
void printRT_2() {
	int i = 1;
	printf("Routing Table:\n");
	for (; i <= NUM_NODE; i++) {
		printf("\tNode %d: iface_index = %d, metrix = %d\n", i, routing_table_2[i].iface_index, routing_table_2[i].metrix);
	}
	printf("\n");
}

void printRT_atomic(FILE* logfile, int tid) {
	if (tid != 99){
		fprintf(logfile, "thread %d: Routing table info:\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n",
			tid,
			1, routing_table_2[1].iface_index, routing_table_2[1].metrix,
			2, routing_table_2[2].iface_index, routing_table_2[2].metrix,
			3, routing_table_2[3].iface_index, routing_table_2[3].metrix,
			4, routing_table_2[4].iface_index, routing_table_2[4].metrix,
			5, routing_table_2[5].iface_index, routing_table_2[5].metrix,
			6, routing_table_2[6].iface_index, routing_table_2[6].metrix);
	} else {
		fprintf(logfile, "SCHEDULER: Routing table info:\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n\tNode %d: iface_index = %d, metrix = %d\n",
			1, routing_table_2[1].iface_index, routing_table_2[1].metrix,
			2, routing_table_2[2].iface_index, routing_table_2[2].metrix,
			3, routing_table_2[3].iface_index, routing_table_2[3].metrix,
			4, routing_table_2[4].iface_index, routing_table_2[4].metrix,
			5, routing_table_2[5].iface_index, routing_table_2[5].metrix,
			6, routing_table_2[6].iface_index, routing_table_2[6].metrix);
	}
}

int getIPfromIface(char* iface, char* ipstr) {
  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* Get IP address attached to iface */
  strcpy(ifr.ifr_name, iface);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);

  strcpy(ipstr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  return 0;
}


int routing_opt(u_char* packet, u_int16_t myaddr) {
	struct rthdr* rth = (struct rthdr*)(packet + ETH_HLEN);
	if (rth->daddr == myaddr) {
		return P_APPRESPONSE;
	}
	if ((rth->daddr & 0x00f0) == (myaddr & 0x00f0)) {
		return P_DO_NOTHING;
	}
	return P_FORWARD;
}

int routing_opt_2(u_char* packet, u_int16_t myaddr, u_int16_t myrid) {
	#if PERFORMANCE == 1
		struct rthdr* rth = (struct rthdr*)(packet + ETH_HLEN);
		if (rth->rid == myrid) {
			return P_DO_NOTHING;
		}
		if (rth->protocol == PATH_QUERY) {
			return P_RIP_REPLY;
		}
		if (rth->daddr == myaddr) {
			if (rth->protocol == PATH_QUERY_REPLY) {
				return P_RIP_RECV;
			}
			return P_APPRESPONSE;
		}
		return P_FORWARD;
	#endif
	return -1;
}


uint8_t rt_lookup(uint16_t dest) {

	//uint16_t dest = 0x0011;

	int min_metric = 1000, i;
	uint8_t rt_index;
    int match_found = 0;
	for(i = 0; i < rt_tbl_size; i++){
         uint16_t rt_dest = routing_table[i] & 0xffff;
         uint16_t rt_mask = (routing_table[i] >> 16) & 0xffff;
         uint16_t rt_gateway = (routing_table[i] >> 32) & 0xffff;
         uint8_t rt_metric = (routing_table[i] >> 48) & 0xff;
         uint8_t rt_iface = (routing_table[i] >> 56) & 0xff;
		 if ((dest & rt_mask) == (rt_dest & rt_mask)) {
			// Matches
			match_found = 1;
			if(rt_gateway == 0x0000) {
				// Local network
				//*rt_entry = routing_table[i];
				return rt_iface;
			} else {
				// remote network
				if(rt_metric < min_metric) {
					min_metric = rt_metric;
					//rtp = p;
					//*rt_entry = routing_table[i];
					rt_index = rt_iface;
				}
			}
		}
	}

	if (!match_found) {
		return -1;
	}
	return rt_index;
}
int rt_lookup_dummy(uint16_t dest) {
	#if FUNCTION == 1
		if (dest == NODE1_RTR1) {
			return 2;
		} else if (dest == NODE2_RTR1) {
			return 0;
		} else if (dest == NODE3_RTR1) {
			return 1;
		}
		return -1;
	#endif
	return -1;
}
int rt_lookup_2(uint16_t dest) {
	int node = (int)(dest >> 4);
	if (node > 0 && node <= NUM_NODE){
		return routing_table_2[node].iface_index;
	}
	
	return -1;
}
/* takes in packet, modify it for forwarding */
void modify_packet(u_char* packet) {

}





/*********************************************************************************************************************************/

/**
 * For dynamic routing
 */

struct rt_entry* get_rt_entry(int index) {
	/* TODO: Currently not thread safe. */
	if ( index >= 1 && index <= NUM_NODE) {
		return &(routing_table_2[index]);
	}
	return NULL;
}

/* return 1 for successful update, 0 for not updated, -1 for invalid input 
 * use force=1 when the router is setting unreachable nodes, in other words
 * the path inquery did not get a reply
 */
int modify_rt_table(int index, int metrix, int interface, int force) {
	if (index < 1 && index > NUM_NODE) {
		return -1;
	}
	if (force == 1) {
		pthread_mutex_lock(&m_dynamic);
			routing_table_2[index].metrix = metrix;
			routing_table_2[index].iface_index = interface;
		pthread_mutex_unlock(&m_dynamic);
		return 1;
	}
	pthread_mutex_lock(&m_dynamic);
		struct rt_entry* rt = get_rt_entry(index);
		if (metrix < rt->metrix) {
			rt->iface_index = interface;
			rt->metrix = metrix;
			pthread_mutex_unlock(&m_dynamic);
			return 1;
		}
	pthread_mutex_unlock(&m_dynamic);
	return 0;
}

void update_lossy_link(int interface) {
	/* TODO: implement it! */
	return;
}

int generate_path_query_packet(u_int16_t saddr, u_int16_t daddr, int rid, u_char* packet_out) {
	memset(packet_out, 0, PACKET_BUF_SIZE);
	int i = 0;
	int size = PATH_QUERY_LENTH;
	for (; i < 12; i++) {
		packet_out[i] = 0xff;
	}
	struct ethhdr* eth = (struct ethhdr*) packet_out;
    eth->h_proto = 0x0000;

    struct rthdr* rth = (struct rthdr*)(packet_out + ETH_HLEN);
    rth->saddr = saddr;
    rth->daddr = daddr;
    rth->protocol = PATH_QUERY;
    rth->rid = (u_int16_t)rid;
    rth->size = htons(size);

    for (i = ETH_HLEN + sizeof(struct rthdr); i < size; i++) {
    	packet_out[i] = (u_char)i;
    }
    return size;
}

/**
 * Lock the entire routing table and send the routing table content.
 * note normal routing does not need to lock the entire routing table and thus might not get
 * the most updated information
 */
int generate_path_reply_packet(u_int16_t saddr, u_int16_t daddr, int rid, int seq, u_char* packet_out) {
	memset(packet_out, 0, PACKET_BUF_SIZE);
	int i = 0;
	int size = ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr) + sizeof(struct rt_entry) * NUM_NODE;

	for (; i < 12; i++) {
		packet_out[i] = 0xff;
	}
	struct ethhdr* eth = (struct ethhdr*) packet_out;
    eth->h_proto = 0x0000;

    struct rthdr* rth = (struct rthdr*)(packet_out + ETH_HLEN);
    rth->saddr = saddr;
    rth->daddr = daddr;
    rth->protocol = PATH_QUERY_REPLY;
    rth->rid = (u_int16_t)rid;
    rth->size = htons(size);

    struct rlhdr* rlh = (struct rlhdr*)(packet_out + ETH_HLEN + sizeof(struct rthdr));
    rlh->seq = (u_int32_t)htons(seq);
    rlh->dummy = (u_int16_t)htons(NUM_NODE);

    struct rt_entry* rtp = (struct rt_entry*)(packet_out + ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr));

    pthread_mutex_lock(&m_dynamic);
    	for (i = 1; i <= NUM_NODE; i++) {
    		struct rt_entry* rt = get_rt_entry(i);
    		memcpy(rtp, rt, sizeof(struct rt_entry));
    		rtp++;
    	}
    pthread_mutex_unlock(&m_dynamic);

    return size;
}
int parse_path_reply_packet(u_char* packet_in, int iface, int metrix_add) {
	int i, ret;
	struct rt_entry* rtp = (struct rt_entry*)(packet_in + ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr));
	
	for (i = 1; i <= NUM_NODE; i++) {
		ret = modify_rt_table(i, rtp->metrix + 1 + metrix_add, iface, 0);
		if(ret == -1){
			return -1;
		}
		rtp++;
	}
	return 0;
}


