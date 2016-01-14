#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()

#include <pthread.h>
#include <omp.h>

#include "des.h"
#include "env.h"
#include "router_util.h"
#include "libkeystore.h"
#include "packet.h"
#include "packet_util.h"
#include "routing.h"
#include "printp.h"

DES_key_schedule sched_list[5];
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void sniffer(void*);
void dynamic_routing(u_char *, const struct pcap_pkthdr *, const u_char *);
void scheduler(void*);

int main (int argc, char** argv) {
	printf("\n\n\nROUTER STARTS\nInitializing...\n");

	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device

	char err[128];						// Holds the error
	char devices[5][20];				// For holding all available devices
	struct keybox key_list[5];			// For all the keys
	memset(key_list, 0, sizeof(struct keybox));

	int count = 0;
	int i = 0;
	int ret = 0;						// Return val


	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	/* Record devices starting with only "eth", and filter out those connecting with control network */
	printf("Filtering valid devices ... ");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		if (device_ptr->name != NULL && !strncmp(device_ptr->name, "eth", 3)){
			char ipaddr[20];
			if ((ret = getIPfromIface(device_ptr->name, ipaddr)) != 0) {
				fprintf(stderr, "ERROR getting IP from Iface for device %s\n", device_ptr->name);
			}
			if (strncmp(ipaddr, "192", 3) != 0) {
				strcpy(devices[count], device_ptr->name);
				count++;
			}
		}
	}
	printf("DONE\n");

	printf("\tHere is a list of ethernet devices we try to listen:\n");
	struct sniff* sniff_args = (struct sniff*)malloc( sizeof(struct sniff) * count );

	for (i = 0; i < count; i++) {
		sniff_args[i].tid = i;
		sniff_args[i].iface_cnt = count;
		sniff_args[i].total_packet = 0;
		sniff_args[i].total_bytes = 0;
		sniff_args[i].stat_bytes = 0;
        sniff_args[i].stat_pktnum = 0;
        sniff_args[i].rt_timeout = 0;
        sniff_args[i].rip_wait_timeout = 0;
        sniff_args[i].rt_updating = 0;
        memset(sniff_args[i].rip_reply, 0, PACKET_BUF_SIZE);
        sniff_args[i].rip_valid = 0;
        sniff_args[i].rip_reply_cnt = 0;

		strcpy(sniff_args[i].dev_name, devices[i]);
		int j;
		for (j = 0; j < count; j++) {
			strcpy((sniff_args[i].dev_list)[j], devices[j]);
		}

		/* Address and keys
		 * for demo purpose we assume the router knows the key already*/
        #if FUNCTION == 1
        	// Full Duplex Test (4 nodes)
        	if (i == 0) {
	        	sniff_args[i].myIface.myaddr = RTR1_NODE2;
		        if ((ret = initDes((unsigned char*)NODE2_RTR1_KEY, &(sched_list[i])) ) < 0) {
	        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
	        	}
	        } else if (i == 1) {
	        	sniff_args[i].myIface.myaddr = RTR1_NODE3;
		        if ((ret = initDes((unsigned char*)NODE3_RTR1_KEY, &(sched_list[i])) ) < 0) {
	        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
	        	}
	        } else if (i == 2) {
	        	sniff_args[i].myIface.myaddr = RTR1_NODE1;
		        if ((ret = initDes((unsigned char*)NODE1_RTR1_KEY, &(sched_list[i])) ) < 0) {
	        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
	        	}
		    } else {
	        	fprintf(stderr, "currently running full-duplex mdoe, only 3 nodes accepted\n");
	        	exit(1);
	        }

        #elif PERFORMANCE == 1
	        // Performance Test (9 nodes)
	        switch (i) {
	        	case 0:
	        		#if RTR1 == 1
	        			sniff_args[i].rid = RTR1_ID;
	        			sniff_args[i].myIface.myaddr = RTR1_RTR3;
	        			#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 1;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR1_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR2 == 1
			        	sniff_args[i].rid = RTR2_ID;
			        	sniff_args[i].myIface.myaddr = RTR2_RTR3;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 1;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR2_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR3 == 1
			        	sniff_args[i].rid = RTR3_ID;
			        	sniff_args[i].myIface.myaddr = RTR3_RTR2;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 3;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR2_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#else
	        		# error "Please set ONE of the following in Config.mk: RTR1=1, RTR2=1, RTR3=1"
	        		#endif
	        		break;
	        	case 1:
	        		#if RTR1 == 1
	        			sniff_args[i].rid = RTR1_ID;
	        			sniff_args[i].myIface.myaddr = RTR1_NODE2;
	        			#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE2_RTR1_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR2 == 1
			        	sniff_args[i].rid = RTR2_ID;
			        	sniff_args[i].myIface.myaddr = RTR2_NODE4;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE4_RTR2_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR3 == 1
			        	sniff_args[i].rid = RTR3_ID;
			        	sniff_args[i].myIface.myaddr = RTR3_NODE5;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE5_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#else
	        		# error "Please set ONE of the following in Config.mk: RTR1=1, RTR2=1, RTR3=1"
	        		#endif
	        		break;
	        	case 2:
	        		#if RTR1 == 1
	        			sniff_args[i].rid = RTR1_ID;
	        			sniff_args[i].myIface.myaddr = RTR1_NODE1;
	        			#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE1_RTR1_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR2 == 1
			        	sniff_args[i].rid = RTR2_ID;
			        	sniff_args[i].myIface.myaddr = RTR2_NODE3;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        				sniff_args[i].alt_iface = 3;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE3_RTR2_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler fRTR2_RTR3or interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR3 == 1
			        	sniff_args[i].rid = RTR3_ID;
			        	sniff_args[i].myIface.myaddr = RTR3_NODE6;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 0;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)NODE6_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#else
	        		# error "Please set ONE of the following in Config.mk: RTR1=1, RTR2=1, RTR3=1"
	        		#endif
	        		break;
	        	case 3:
	        		#if RTR1 == 1
	        			sniff_args[i].rid = RTR1_ID;
	        			sniff_args[i].myIface.myaddr = RTR1_RTR2;
	        			#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR1_RTR2_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR2 == 1
			        	sniff_args[i].rid = RTR2_ID;
			        	sniff_args[i].myIface.myaddr = RTR2_RTR1;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 2;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR1_RTR2_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#elif RTR3 == 1
			        	sniff_args[i].rid = RTR3_ID;
			        	sniff_args[i].myIface.myaddr = RTR3_RTR1;
			        	#if DYNAMIC == 1
	        				sniff_args[i].rip = 1;
	        				sniff_args[i].alt_iface = 0;
	        			#endif
				        if ((ret = initDes((unsigned char*)RTR1_RTR3_KEY, &(sched_list[i])) ) < 0) {
			        		fprintf(stderr, "Initialize scheduler for interface %d Failed with %d\n", i, ret);
			        	}
	        		#else
	        		# error "Please set ONE of the following in Config.mk: RTR1=1, RTR2=1, RTR3=1"
	        		#endif
	        		break;
	        	default:
	        		fprintf(stderr, "For performance test, the router should have 4 interfaces ONLY\n");
	        		exit(1);
	        }
        #else
        #	error "please set either FUNCTION=1 OR PERFORMANCE=1 in Config.mk"
        #endif   
	}

	for(i = 0; i < count; i++) {
		printf("\t\t- Dev %d, name: %s; assigned address: %04x; scheduler: ", 
			sniff_args[i].tid, 
			sniff_args[i].dev_name, 
			sniff_args[i].myIface.myaddr);
		printKey(&(sched_list[i]), 8);
		printf("\n");
	}

	#if PERFORMANCE == 1
		printf("Creating Routing Table ... ");
		createRT_2();
		printf("DONE\n");
		printRT_2();
	#endif

	printf("Creating Sniffer...\n");
	pthread_t* threads = (pthread_t*)malloc( sizeof(pthread_t) * count );



	for (i = 0; i < count; i++) {
		if (pthread_create(&(threads[i]), NULL, (void*(*)(void *))sniffer, (void *)(&sniff_args[i]) )) {
        	fprintf(stderr, "ERROR creating thread %d\n", i);
    	}
	}

	#if DYNAMIC == 1
		struct scheduler_args sched_data;
		sched_data.thread_list = threads;
		sched_data.thread_cnt = count;
		sched_data.thread_args = sniff_args;
		#if RTR1 == 1
			sched_data.rid = RTR1_ID;
		#elif RTR2 == 1
			sched_data.rid = RTR2_ID;
		#elif RTR3 == 1
			sched_data.rid = RTR3_ID;
		#else
		# error "Please set ONE of the following in Config.mk: RTR1=1, RTR2=1, RTR3=1"
		#endif
		pthread_t sched;
		if (pthread_create(&sched, NULL, (void*(*)(void *))scheduler, (void *)(&sched_data) )) {
        	fprintf(stderr, "ERROR creating scheduler thread\n");
    	}
	#endif

	for (i = 0; i < count; i++) {
		if (pthread_join(threads[i], NULL)){
        	fprintf(stderr, "ERROR joining thread %d\n", i);
    	}
	}

	#if DYNAMIC == 1
		if (pthread_join(sched, NULL)){
        	fprintf(stderr, "ERROR joining scheduler thread\n");
    	}
	#endif


	printf( "ROUTER TERMINATED SUCCESSFULLY\n");

	return 0;
}

void sniffer(void* param) {
	struct sniff* data = (struct sniff*)param;
	char err[128];
	pcap_t *pcap_handle = NULL;
	pcap_t *pcap_private = NULL;
	int i;
	data->logfile = stdout;
/* Create the thread's log file if not log to stdout */
/*	
	char filename[20];
	sprintf(filename, "iface_%04x.log", (data->myIface).myaddr);
	if ( (data->logfile = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}
*/
	printf("thread %d: Initializing...\n\t- Iface: %s\n\t- Addr: %04x\n\t- RIP: %d\n", 
		data->tid, 
		data->dev_name, 
		(data->myIface).myaddr,
		data->rip);

	if ( (pcap_handle = pcap_open_live(data->dev_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "thread %d: Error opening device %s, with error message %s\n", data->tid, data->dev_name, err);
		exit(1);
	}
    (data->myIface).handler = pcap_handle;
    for (i = 0; i < data->iface_cnt; i++) {
    	if (i != data->tid) {
    		if ( (pcap_private = pcap_open_live((data->dev_list)[i], BUFSIZ, 1, 100, err)) == NULL ) {
				fprintf(stderr, "thread %d: Error opening device %s, with error message %s\n", data->tid, (data->dev_list)[i], err);
				exit(1);
			}
			(data->handler_list)[i] = pcap_private;
			fprintf(data->logfile, "thread %d: added private handle for iface %s\n", data->tid, (data->dev_list)[i]);
    	}
    }

    #if DYNAMIC == 1
    	printf("thread %d: ===================================> START. Enable Dynamic Routing Mode\n", data->tid);
		pcap_loop(pcap_handle , -1 , dynamic_routing , (u_char*)data );
	#else
		printf("thread %d: ===================================> START. Normal Routing Mode\n", data->tid);
		pcap_loop(pcap_handle , -1 , process_packet , (u_char*)data );	// -1 means an infinite loop
	#endif

//	fclose(data->logfile);
	pcap_close(pcap_handle);
}

void dynamic_routing(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sniff* data = (struct sniff*)args;
	int size = (int) header->len;
	int ret = 0;

	data->total_packet++;
	data->total_bytes += size;

	if ((ret = osi_filter((u_char*)packet, data->rid)) != 0) {
//		fprintf(data->logfile, "thread %d: received OSI packet, filtered out.\n", data->tid);
		return;
	}
	unsigned char packetGen[PACKET_BUF_SIZE];

	int offset = ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr);
	int psize = size - offset;
	DES_key_schedule sched = sched_list[data->tid];
	if (size < 128)	{
		// RIP packet
		decrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)(packet + ETH_HLEN), &sched, size - ETH_HLEN);
	} else {
		// File Packet
		decrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)packet + ETH_HLEN, &(sched), sizeof(struct rthdr) + sizeof(struct rlhdr));
		#pragma omp parallel num_threads(4) shared(packet, sched, size)
		{
			#pragma omp sections nowait
			{
				#pragma omp section
				{
					decrypt((const unsigned char*)packet + offset, (unsigned char*)packet + offset, &(sched), psize/4);
				}
				#pragma omp section 
				{
	                decrypt((const unsigned char*)packet + offset + psize/4, (unsigned char*)packet + offset + psize/4, &(sched), psize/4);
	            }
				#pragma omp section
	            {
	                decrypt((const unsigned char*)packet + offset + psize/2, (unsigned char*)packet + offset + psize/2, &(sched), psize/4);
	            }
	            #pragma omp section 
	            {
	                decrypt((const unsigned char*)packet + offset + psize/4*3, (unsigned char*)packet + offset + psize/4*3, &(sched), psize/4);
	            }
			}
		}
	}

	if ((ret = validate_packet((u_char*)(packet))) < 0) {
//		fprintf(data->logfile, "thread %d: ERROR invalid packet\n", data->tid);
		return;
	}

	/* Classify Packet */
	ret = routing_opt_2((u_char*)packet, (data->myIface).myaddr, data->rid);

	struct rthdr* rth = (struct rthdr*)(packet + ETH_HLEN);
	switch(ret) {
		case P_FORWARD:
			data->stat_pktnum++;
			data->stat_bytes += size;
			
			int index = -1;
			rth->rid = data->rid;

			index = rt_lookup_2(rth->daddr);

			if (index == -1) {
				fprintf(stderr, "thread %d: ERROR: destination error. Error destination: %u\n", data->tid, rth->daddr);
				return;
			}
			//encrypt((const unsigned char*)(packet + ETH_HLEN), (unsigned char*)(packet + ETH_HLEN), &(sched_list[index]), size - ETH_HLEN);
			sched = sched_list[index];
			encrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)packet + ETH_HLEN, &(sched), sizeof(struct rthdr) + sizeof(struct rlhdr));
			#pragma omp parallel num_threads(4) shared(packet, sched, size)
			{
				#pragma omp sections nowait
				{
					#pragma omp section
					{
						encrypt((const unsigned char*)packet + offset, (unsigned char*)packet + offset, &(sched), psize/4);
					}
					#pragma omp section 
					{
		                encrypt((const unsigned char*)packet + offset + psize/4, (unsigned char*)packet + offset + psize/4, &(sched), psize/4);
		            }
					#pragma omp section
		            {
		                encrypt((const unsigned char*)packet + offset + psize/2, (unsigned char*)packet + offset + psize/2, &(sched), psize/4);
		            }
		            #pragma omp section 
		            {
		                encrypt((const unsigned char*)packet + offset + psize/4*3, (unsigned char*)packet + offset + psize/4*3, &(sched), psize/4);
		            }
				}
			}
			u_int16_t* ptr = (u_int16_t*)packet;
			ptr[0] = data->rid;
			if ((ret = pcap_inject((data->handler_list)[index], packet, size)) < 0){
				fprintf(stderr, "thread %d: fail to inject packet to iface[%d]\n", data->tid, index);
				exit(1);
			}
/*			fprintf(data->logfile, "thread %d: received a P_FORWARD packet of size %d, inject to iface[%d]; %d packets (%lld bytes) of total %d packets (%lldbytes) processed\n", 
				data->tid, size, 
				index, 
				data->stat_pktnum, 
				data->stat_bytes,
				data->total_packet,
				data->total_bytes);
				*/
			break;
		case P_RIP_RECV:
			memcpy(data->rip_reply, packet, size);
			data->rip_reply_cnt++;
			data->rip_valid = 1;
			return;
		case P_RIP_REPLY:
			if ((ret = generate_path_reply_packet(data->myIface.myaddr, rth->saddr, data->rid, 0, packetGen)) < 0) {
				fprintf(stderr, "thread %d: fail to generate RIP reply packet\n", data->tid);
			}
			ptr = (u_int16_t*)packetGen;
			ptr[0] = data->rid;
			encrypt((const unsigned char*)(packetGen + ETH_HLEN), (unsigned char*)(packetGen + ETH_HLEN), &(sched_list[data->tid]), ret - ETH_HLEN);
			if ((ret = pcap_inject(data->myIface.handler, packetGen, ret)) < 0){
				fprintf(stderr, "thread %d: fail to inject packet to node %04x\n", data->tid, rth->saddr);
				exit(1);
			}
//			fprintf(data->logfile, "thread %d: received a P_RIP_REPLY packet, sent my routing table to node %04x\n", data->tid, rth->saddr);
			break;
		case P_APPRESPONSE:
//			fprintf(data->logfile, "thread %d: router does not deal with P_APPRESPONSE packets for now\n", data->tid);
			return;
		case P_DO_NOTHING:
//			fprintf(data->logfile, "thread %d: received a P_DO_NOTHING packet\n", data->tid);
			return;
		default:
//			fprintf(stderr, "thread %d: ERROR no routing option available\n", data->tid);
			return;
	}

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sniff* data = (struct sniff*)args;
	int size = (int) header->len;
	int ret = 0;

	data->total_packet++;
	data->total_bytes += size;

	if ((ret = osi_filter((u_char*)packet, data->rid)) != 0) {
//		fprintf(data->logfile, "thread %d: received OSI packet, filtered out.\n", data->tid);
		return;
	}

//	fprintp(data->logfile, (u_char*)packet, size);
    //decrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)packet + ETH_HLEN, &(sched_list[data->tid]), size - ETH_HLEN);
//  fprintp(data->logfile, (u_char*)packet, size);
	int offset = ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr);
	int psize = size - offset;
	DES_key_schedule sched = sched_list[data->tid];
	//fprintf(data->logfile, "thread %d: psize = %d\n",data->tid, psize);
	decrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)packet + ETH_HLEN, &(sched), sizeof(struct rthdr) + sizeof(struct rlhdr));
	#pragma omp parallel num_threads(4) shared(packet, sched, size)
	{
		#pragma omp sections nowait
		{
			#pragma omp section
			{
				decrypt((const unsigned char*)packet + offset, (unsigned char*)packet + offset, &(sched), psize/4);
			}
			#pragma omp section 
			{
                decrypt((const unsigned char*)packet + offset + psize/4, (unsigned char*)packet + offset + psize/4, &(sched), psize/4);
            }
			#pragma omp section
            {
                decrypt((const unsigned char*)packet + offset + psize/2, (unsigned char*)packet + offset + psize/2, &(sched), psize/4);
            }
            #pragma omp section 
            {
                decrypt((const unsigned char*)packet + offset + psize/4*3, (unsigned char*)packet + offset + psize/4*3, &(sched), psize/4);
            }
		}
	}

	if ((ret = validate_packet((u_char*)(packet))) != ROUTE_ON_RELIABLE) {
		fprintf(data->logfile, "thread %d: ERROR invalid packet\n", data->tid);
		return;
	}
	#if FUNCTION == 1
		ret = routing_opt((u_char*)packet, (data->myIface).myaddr);
	#elif PERFORMANCE == 1
		ret = routing_opt_2((u_char*)packet, (data->myIface).myaddr, data->rid);
	#else
	# error "please set ONE of the following: FUNCTION=1 or PERFORMANCE=1 in Config.mk"
	#endif

	if (ret == P_DO_NOTHING) {
//		fprintf(data->logfile, "thread %d: received a P_DO_NOTHING packet, discard it\n", data->tid);
		return;
	} else if (ret == P_APPRESPONSE) {
//		fprintf(data->logfile, "thread %d: router does not deal with P_APPRESPONSE packets for now\n", data->tid);
		return;
	}

	data->stat_pktnum++;
	data->stat_bytes += size;

	struct rthdr* rth = (struct rthdr*)(packet + ETH_HLEN);
	
	int index = -1;
	#if FUNCTION == 1
		index = (int)rt_lookup_dummy(rth->daddr);
	#elif PERFORMANCE == 1
		rth->rid = data->rid;
		index = rt_lookup_2(rth->daddr);
	#else
	# error "please set ONE of the following: FUNCTION=1 or PERFORMANCE=1 in Config.mk"
	#endif

	if (index == -1) {
		fprintf(stderr, "thread %d: ERROR: destination error. Error destination: %u\n", data->tid, rth->daddr);
		return;
	}

//	encrypt((const unsigned char*)(packet + ETH_HLEN), (unsigned char*)(packet + ETH_HLEN), &(sched_list[index]), size - ETH_HLEN);
//	fprintp(data->logfile, (u_char*)packet, size);
/*	fprintf(data->logfile, "thread %d: received a P_FORWARD packet of size %d, inject to iface[%d]; %d packets (%lld bytes) of total %d packets (%lldbytes) processed\n", 
		data->tid, size, 
		index, 
		data->stat_pktnum, 
		data->stat_bytes,
		data->total_packet,
		data->total_bytes);
*/
	sched = sched_list[index];
	encrypt((const unsigned char*)(packet + ETH_HLEN), (u_char*)packet + ETH_HLEN, &(sched), sizeof(struct rthdr) + sizeof(struct rlhdr));
	#pragma omp parallel num_threads(4) shared(packet, sched, size)
	{
		#pragma omp sections nowait
		{
			#pragma omp section
			{
				encrypt((const unsigned char*)packet + offset, (unsigned char*)packet + offset, &(sched), psize/4);
			}
			#pragma omp section 
			{
                encrypt((const unsigned char*)packet + offset + psize/4, (unsigned char*)packet + offset + psize/4, &(sched), psize/4);
            }
			#pragma omp section
            {
                encrypt((const unsigned char*)packet + offset + psize/2, (unsigned char*)packet + offset + psize/2, &(sched), psize/4);
            }
            #pragma omp section 
            {
                encrypt((const unsigned char*)packet + offset + psize/4*3, (unsigned char*)packet + offset + psize/4*3, &(sched), psize/4);
            }
		}
	}
	u_int16_t* ptr = (u_int16_t*)packet;
	ptr[0] = data->rid;
	if ((ret = pcap_inject((data->handler_list)[index], packet, size)) < 0){
		fprintf(stderr, "thread %d: fail to inject packet to iface[%d]\n", data->tid, index);
		exit(1);
	}

}




void scheduler(void* args) {
	struct scheduler_args* data = (struct scheduler_args*) args;
	struct sniff* thread_data = data->thread_args;
	int i;
	pcap_t *pcap_private = NULL;
	char err[128];
	for (i = 0; i < data->thread_cnt; i++) {
		if (thread_data[i].rip == 1) {
			if ( (pcap_private = pcap_open_live(thread_data[i].dev_name, BUFSIZ, 1, 100, err)) == NULL ) {
				fprintf(stderr, "SCHEDULER: Error opening device %s, with error message %s\n", thread_data[i].dev_name, err);
				exit(1);
			}
			(data->handler_list)[i] = pcap_private;
			fprintf(stdout, "SCHEDULER: added private handler for thread %d\n", i);
		}
	}

	fprintf(stdout, "SCHEDULER: ===================================> START.\n\tThread Count: %d\n\tRouting Table Timeout: %dus\n\tRIP Wait Timeout: %dus\n", data->thread_cnt, ROUTING_TABLE_TIMEOUT, RIP_WAIT_TIMEOUT);
	
	int ret = 0;
	unsigned char packetGen[PACKET_BUF_SIZE];
	
	while(1){

		usleep(ROUTING_TABLE_TIMEOUT);

		for (i = 0; i < data->thread_cnt; i++) {
			if (thread_data[i].rip == 1) {
				fprintf(stdout, "SCHEDULER: signaling thread %d to send routing info query\n", i);

				u_int16_t myaddr = thread_data[i].myIface.myaddr;
				if ((ret = generate_path_query_packet(myaddr, 0xffff ,(int)thread_data[i].rid, packetGen)) < 0) {
					fprintf(stderr, "SCHEDULER: ERROR generating path query packet.\n");
					return;
				}
				//fprintp(stdout, packetGen, ret);
				int j;
				encrypt((const unsigned char*)(packetGen + ETH_HLEN), (unsigned char*)(packetGen + ETH_HLEN), &(sched_list[i]), ret - ETH_HLEN);
				u_int16_t* ptr = (u_int16_t*)packetGen;
				ptr[0] = data->rid;
				for (j = 0; j < ROUTE_QUERY_COUNT; j++) {
					if ((ret = pcap_inject((data->handler_list)[i], packetGen, ret)) < 0){
						fprintf(stderr, "SCHEDULER: fail to inject packet to %04x\n", thread_data[i].myIface.myaddr);
						exit(1);
					}
				}
				thread_data[i].rt_updating = 1;
				fprintf(stdout, "SCHEDULER: finished sending path query for thread %d\n", i);
			}
		}

		usleep(RIP_WAIT_TIMEOUT);
		createRT_2();

		for (i = 0; i < data->thread_cnt; i++) {
			if (thread_data[i].rip == 1) {
				fprintf(stdout, "SCHEDULER: signaling thread %d to update routing table ... this thread received %d of %d replies\n", i, thread_data[i].rip_reply_cnt, ROUTE_QUERY_COUNT);
				if (thread_data[i].rip_valid == 1) {
					if ((ret = parse_path_reply_packet(thread_data[i].rip_reply, thread_data[i].tid, ROUTE_QUERY_COUNT - thread_data[i].rip_reply_cnt)) < 0) {
						fprintf(stderr, "SCHEDULER: ERROR parse path reply packet\n");
					}
				} else {
					update_lossy_link(thread_data[i].tid);
				}
				thread_data[i].rip_valid = 0;
				thread_data[i].rip_reply_cnt = 0;
				memset(thread_data[i].rip_reply, 0, PACKET_BUF_SIZE);
			}
		}
		printRT_atomic(stdout, 99);
	}
}

