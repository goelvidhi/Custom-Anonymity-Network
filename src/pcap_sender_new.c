#include <pthread.h>
#include <omp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h> //hostent
#include <time.h>
#include <sys/poll.h>
#include <linux/if_ether.h>
#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "libkeystore.h"
#include "env.h"
#define PAYLOAD_SIZE 1024
#define RETRANSMISSION 1
#define BUF_SIZ 1024

char *device_name = NULL;

int full_header_length=ETH_HLEN+ sizeof(struct rthdr) + sizeof(struct rlhdr);
long numberOfPackets;
int bitSeqNo;
int nackNo;
u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut_e[PACKET_BUF_SIZE];


u_char payload_e[PAYLOAD_SIZE];
struct timespec start, stop;
double duration;
int * seq_array;
char * bitSeq;
char * buffer;
DES_key_schedule schedule1;
DES_key_schedule schedule2;

struct sockaddr_ll socket_address;


long printSeqArray()
{
	long i=0;
	long counter=0;
	for(i=0;i<numberOfPackets;i++)
	{
		if(seq_array[i] == 1)
			counter ++;
	}
	//printf("Total Packets to resend : %ld\n",counter);
	return counter;
}

void *receiver(){
	printf("In Receive Packet First New  %s\n",device_name);
	int s; /*socketdescriptor*/
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device_name, 4);
	char* buffer = (char*)malloc(1024+full_header_length); /*Buffer for ethernet frame*/
	int length = 0; /*length of the received frame*/
	char str[9];
	u_char * seqNo=NULL;
	long array_counter=0;
	int kk=0;
	int value=0;
	int seq=0;
	int ret;
	int size=0;
	int c=0;
	int countS=0;
	u_char * data;
	long yy=0;
	u_int8_t dummy = 0;
    	while(1){

	memset(buffer,0,1024+full_header_length);
    	length = recvfrom(s, buffer, 1024+full_header_length, 0, NULL, NULL);
	//Logic for Decryption with buffer
 	decrypt((const u_char *)buffer+ETH_HLEN, buffer+ETH_HLEN, &schedule2, sizeof(struct rlhdr)+sizeof(struct rthdr));
	#pragma omp parallel num_threads(4) shared(buffer, schedule2)
        {
               	#pragma omp sections nowait
                {
         		    #pragma omp section
                            {
                              		decrypt((const unsigned char*)buffer + full_header_length, (unsigned char*)buffer + full_header_length , &(schedule2), 256);
                            }
                            #pragma omp section
                            {
                                	decrypt((const unsigned char*)buffer + full_header_length + 256, (unsigned char*)buffer + full_header_length + 256, &(schedule2), 256);
                            }
                            #pragma omp section
                            {
                                	decrypt((const unsigned char*)buffer + full_header_length + 512, (unsigned char*)buffer + full_header_length + 512 , &(schedule2), 256);
                            }
                            #pragma omp section
                            {
                                	decrypt((const unsigned char*)buffer + full_header_length + 768, (unsigned char*)buffer + full_header_length + 768 , &(schedule2), 256);
                            }
		}
	}


	if ((ret = validate_packet((u_char*)(buffer))) == ROUTE_ON_RELIABLE) {
			//fprintp(stdout,buffer,1024+full_header_length);
        		struct rlhdr* rlh = (struct rlhdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct rthdr));
			dummy = (int) rlh->dummy;
			data = buffer + sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof (struct rlhdr);
			struct rthdr* hdr=(struct rthdr*)(buffer + sizeof(struct ethhdr));
			int source;
			source=(int) hdr->saddr;
			if (source==NODE1_RTR1){
				continue;
			}
			int *ptr=(int *)(buffer+full_header_length);
			int seq_count=256;
			int jkl;
			for(jkl=0;jkl<seq_count;jkl++){
				int index=ptr[jkl];
				seq_array[index]=1;
                        	//printf("%d\n",ptr[j]);
                	}
		}
	}


	close(s);
}


void *sender(){
	while(1){
	long temp_counter;
	temp_counter=printSeqArray();
	u_char head_e[full_header_length];
	printf("Sending Missing Packets %ld\n",temp_counter);
	char character;
	u_int8_t count=0;
	long counter=0;
	int seqno = -1;
	int ii=0;
	long seq=0;
	int tx_len = 0;
       	unsigned char sendbuf[BUF_SIZ];
	long t=0;
	int i=0;
	int s; /*socketdescriptor*/
	FILE *fr;
	fr = fopen ("/tmp/test.txt", "rb");
	fseek(fr, 0, SEEK_END);
	long fsize = ftell(fr);
	fseek(fr, 0, SEEK_SET);
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, device_name, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFINDEX, &if_idx) < 0)
   			perror("SIOCGIFINDEX");
	struct sockaddr_ll socket_address;
	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = if_idx.ifr_ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;		
	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x15;		
	socket_address.sll_addr[2]  = 0x17;
	socket_address.sll_addr[3]  = 0x57;
	socket_address.sll_addr[4]  = 0xc7;
	socket_address.sll_addr[5]  = 0x6f;
	/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/
	    	for(t=0;t< numberOfPackets; t++) {
			if (t%65535 ==0 && t>=65535){
				count++;
				seqno=-1;
			}
			seqno++;
    			memset(sendbuf, 0, BUF_SIZ);
			memset(packetOut,0,1024+full_header_length);
			tx_len=0;
			tx_len=1024;
        		int pktlen;
        		int y=0;
			seq=(count*65535)+seqno;
        		if (seq_array[seq] == 0){
        			continue;
        		}
        		else
        		{
	        		seq_array[seq] = 0;
        		}
			fseek(fr,((int)seq*1024),SEEK_SET);
			fread(sendbuf,PAYLOAD_SIZE,1,fr);
        		memset(payload_e,0,PAYLOAD_SIZE);
        		memset(head_e,0,full_header_length);

       			pktlen = generate_file_packet(packetOut, sendbuf,NODE1_RTR1,NODE3_RTR2, tx_len, 15, seqno,count,0);

	       		encrypt((const u_char *)packetOut+ETH_HLEN, packetOut+ETH_HLEN, &schedule2, sizeof(struct rlhdr)+sizeof(struct rthdr));
		      	#pragma omp parallel num_threads(4) shared(packetOut, schedule2)
        		{
                		#pragma omp sections nowait
                		{
         		               	#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length, (unsigned char*)packetOut + full_header_length , &(schedule2), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 256, (unsigned char*)packetOut + full_header_length + 256, &(schedule2), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 512, (unsigned char*)packetOut + full_header_length + 512 , &(schedule2), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 768, (unsigned char*)packetOut + full_header_length + 768 , &(schedule2), 256);
                        		}
				}
			}

       			int header_size = full_header_length;
        		if (sendto(s, packetOut, pktlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    			printf("Send failed\n");
	    		volatile int sleep_counter=2500;
	    		while(sleep_counter>=0)
	    			sleep_counter--;

		}
   fclose(fr);
close(s);

	}

}

int main (int argc, char** argv) {
	u_char head_e[full_header_length];
	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	
	int sockfd;
	int ii=0;
	int tx_len = 0;
    	unsigned char sendbuf[BUF_SIZ];
   	long t=0;
	long counter = 0;
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;
	char err[128];						// Holds the error
	char devices[10][64];				// For holding all available
	u_int8_t count = 0;
	int ret;
	int n = 0;
	struct rlhdr * rlh;
	srand(time(NULL));
	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");
	printf("Here are the available devices:\n");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		printf("%d. %s\t-\t%s\n", count, device_ptr->name, device_ptr->description);
		if (device_ptr->name != NULL) {
			strcpy(devices[count], device_ptr->name);
		}
		count++;
	}
	printf("Which device do you want to sniff? Enter the number:\n");
	scanf("%d", &n);
	device_name = devices[n];
	printf("Trying to open device %s to send ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}

	printf( "DONE\n");
	unsigned char key1[8];
    	strcpy(key1,"node1");
    	initDes(key1,&schedule1);
    	printKey(&schedule1,8);
	unsigned char key2[8];
    	strcpy(key2,"node1");
	initDes(key2,&schedule2);
	printKey(&schedule2,8);



	int y;
	FILE *fr;
   	fr = fopen ("/tmp/test.txt", "rb");
	fseek(fr, 0, SEEK_END);
	long fsize = ftell(fr);
	fseek(fr, 0, SEEK_SET);
	if (fsize%PAYLOAD_SIZE!=0) 
			numberOfPackets = (fsize/PAYLOAD_SIZE) + 1;
		else 
			numberOfPackets = (fsize/PAYLOAD_SIZE);

	printf("Number Of Packets:%ld\n",numberOfPackets);
	//Allocate arrays for sequence number

	seq_array = (int *)calloc(numberOfPackets,sizeof(int));
	long yy=0;
	for (yy=0;yy<numberOfPackets;yy++)
	{
		seq_array[yy]=1;
	}

	fclose(fr);
    	printf("Done");
    	long sum=0;
	long p=0;


	pthread_t sender_thread,recv_thread;
        if(pthread_create(&sender_thread,NULL,&sender,NULL)!=0){
                printf("Error in Creating thread1\n");
                return -1;
        }

        if(pthread_create(&recv_thread,NULL,&receiver,NULL)!=0){
                printf("Error in Creating thread2\n");
                return -1;
        }
        //pthread_join(sender_thread,NULL);
        pthread_join(recv_thread,NULL);


	printf("Sent Everything\n");
	return 0;
}

