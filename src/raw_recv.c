#include <sys/poll.h> 
#include <pcap.h> 
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
#include <math.h> 
#include <pthread.h>
#include <omp.h>
#define BUF_SIZ 1024 
#define ETH_FRAME_LEN 1500 
#include "packet_util.h" 
#include "printp.h" 
#include "des.h" 
#include "libkeystore.h"
#include "env.h"

int source;
int destination;
int *packetR;

int sender_counter;
int recv_counter;
int full_header_length=0;
DES_key_schedule schedule_header;
DES_key_schedule schedule_payload;
char header_key[8];
char payload_key[8];
FILE *file_to_write;
int count_packet;
#define PAYLOAD_SIZE 1024
//global variables

//filesize - command line
size_t filesize;
long packets_num;
unsigned int last_packet_size;
unsigned char * bits;
int bitSequenceSize= 0;
int nackPacketNums;
u_char packetOut[PACKET_BUF_SIZE];
char *device_name;
int completed=0;
int timeout=10000;




void calculateTotalPackets(){
	printf("Calculating Total Packets\n");
	if((filesize % PAYLOAD_SIZE) != 0){
    	packets_num = filesize/PAYLOAD_SIZE + 1;
        last_packet_size = filesize%PAYLOAD_SIZE;
    }
    else{
        packets_num = filesize/PAYLOAD_SIZE;
        last_packet_size = PAYLOAD_SIZE;
    }
}









void append(char* s, char c)
{
       int len = strlen(s);
       s[len] = c;
       s[len+1] = '\0';
}


float time_to_sleep(long array_sum){
	float time_to_sleep_value=((0.9 * array_sum * 43)/512000);
	return time_to_sleep_value;
}


void *sender(){
	int sleep_value;
	usleep(43000000);
	while(1){
		long array_count=0;
		long array_sum=0;
		for(array_count=0;array_count<packets_num;array_count++)
			array_sum=array_sum+packetR[array_count];
		sleep_value=(int)time_to_sleep(packets_num-array_sum);
		sleep_value++;
		printf("Approx time to sleep %d\n",sleep_value);
		printf("Need %ld packets \n",packets_num-array_sum);
		if(array_sum==packets_num){
			printf("Got Everything from Gaut\n.");
			printf("Writing to the file\n");
			fflush(file_to_write);
			fclose(file_to_write);
			completed=1;
			exit(1);
		}
		sendNackPackets(destination,source);
		usleep(sleep_value*1000000);
	}
}

void sendNackPackets(int source_nak, int destination_nak) {
	printf("In Sending NACK Packets\n");
	long i=0;
	int start;
	int end;
	int j;
	unsigned char payload[1024];
	int s; /*socketdescriptor*/
	u_char payload_e[PAYLOAD_SIZE];
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
	int send_packet;
	//Add
	char bufferForInt[10];
	char newPayload[1024];
	int ctr=0;
	int flag=0;
	memset (payload,0, 1024);
	int lastZero;
	int number_of_seq=0;

	for (i=0; i< packets_num; i++){
		if(packetR[i]==0){
			lastZero=i;
			number_of_seq++;
		}
	}
	printf("The Last Zero is %d\n",lastZero);
	printf("Sennding to Gaut:%d\n",number_of_seq);
	int *ptr=(int *)payload;
        int packet_counter=0;
        int seq_count=256;
	for (i=0; i< packets_num; i++){
                if(packetR[i]==0){
                        ptr[packet_counter]=i;
                        packet_counter++;

                }
                if (seq_count==packet_counter){
                        packet_counter=0;
			generate_file_packet(packetOut, payload, (u_int16_t)source_nak, (u_int16_t)destination_nak, 1024+full_header_length, 450, i,1,1);
			//Insert Logic for encryption
	        	encrypt(packetOut+ETH_HLEN, packetOut+ETH_HLEN, &schedule_payload, sizeof(struct rlhdr)+sizeof(struct rthdr));
		      	#pragma omp parallel num_threads(4) shared(packetOut, schedule_payload)
        		{
                		#pragma omp sections nowait
                		{
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length, (unsigned char*)packetOut + full_header_length, &(schedule_payload), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 256, (unsigned char*)packetOut + full_header_length + 256, &(schedule_payload), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 512, (unsigned char*)packetOut + full_header_length + 512 , &(schedule_payload), 256);
                        		}
                        		#pragma omp section
                        		{
                                		encrypt((const unsigned char*)packetOut + full_header_length + 768, (unsigned char*)packetOut + full_header_length + 768 , &(schedule_payload), 256);
                        		}
				}
			}


         		if (sendto(s, packetOut, 1024+full_header_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                        	printf("Send failed\n");
                        memset(payload,0,1024);
                        ptr=(int *)payload;

                }
	}
        if(packet_counter!=0){
                int balance=seq_count-packet_counter;
                for(j=balance;j<seq_count;j++)
                        ptr[j]=ptr[packet_counter-1];

        }

	generate_file_packet(packetOut, payload, (u_int16_t)source_nak, (u_int16_t)destination_nak, 1024+full_header_length, 450, i,1,1);
	//Insert Logic for encryption
        encrypt(packetOut+ETH_HLEN, packetOut+ETH_HLEN, &schedule_payload, sizeof(struct rlhdr)+sizeof(struct rthdr));
	#pragma omp parallel num_threads(4) shared(packetOut, schedule_payload)
        {
                #pragma omp sections nowait
                {
                       	#pragma omp section
                       	{
                               	encrypt((const unsigned char*)packetOut + full_header_length, (unsigned char*)packetOut + full_header_length, &(schedule_payload), 256);
                       	}
                       	#pragma omp section
                       	{
                               	encrypt((const unsigned char*)packetOut + full_header_length + 256, (unsigned char*)packetOut + full_header_length + 256, &(schedule_payload), 256);
                       	}
                       	#pragma omp section
                       	{
                               	encrypt((const unsigned char*)packetOut + full_header_length + 512, (unsigned char*)packetOut + full_header_length + 512 , &(schedule_payload), 256);
                       	}
                       	#pragma omp section
                       	{
                               	encrypt((const unsigned char*)packetOut + full_header_length + 768, (unsigned char*)packetOut + full_header_length + 768 , &(schedule_payload), 256);
                       	}
		}
	}



        if (sendto(s, packetOut, 1024+full_header_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
           printf("Send failed\n");
	close(s);
}

void process_packet(const u_char *packet,int length_packet) {
	        //int size = (int) header->len;
		long seq_num=0;
        	int size=0;
		int hsize=full_header_length;
        	int psize=size-hsize;
       	 	int seq = -1;
        	int i;
        	int ret;        

        	decrypt(packet+ETH_HLEN, packet+ETH_HLEN, &schedule_payload, sizeof(struct rlhdr)+sizeof(struct rthdr));
	      	#pragma omp parallel num_threads(4) shared(packet, schedule_payload)
        	{
                	#pragma omp sections nowait
                	{
                        	#pragma omp section
                        	{
                                	decrypt((const unsigned char*)packet + full_header_length, (unsigned char*)packet + full_header_length, &(schedule_payload), 256);
                        	}
                        	#pragma omp section
                        	{
                                	decrypt((const unsigned char*)packet + full_header_length + 256, (unsigned char*)packet + full_header_length + 256, &(schedule_payload), 256);
                        	}
                        	#pragma omp section
                        	{
                                	decrypt((const unsigned char*)packet + full_header_length + 512, (unsigned char*)packet + full_header_length + 512 , &(schedule_payload), 256);
                        	}
                        	#pragma omp section
                        	{
                                	decrypt((const unsigned char*)packet + full_header_length + 768, (unsigned char*)packet + full_header_length + 768 , &(schedule_payload), 256);
                        	}
			}
		}

		if ((ret = validate_packet((u_char*)(packet))) == ROUTE_ON_RELIABLE) {
			recv_counter++;
			timeout=1000;
		       	struct rthdr* hdr = (struct rthdr*) (packet + sizeof(struct ethhdr));
			source=(int)hdr->saddr;
			destination=(int)hdr->daddr;
		    	size= (int)ntohs((hdr->size));
	    		struct rlhdr* rlh = (struct rlhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
			u_int8_t dummy=(u_int8_t) rlh->dummy;
			int i_i=0;
	  		seq_num= (unsigned int)ntohs((rlh->seq))+(int)dummy*65535;
		if (source==NODE3_RTR2){
			return;
		}
		if (packetR[seq_num]==0){
			packetR[seq_num]=1;
			long position;
			position=dummy*(65535)+((int)seq_num*1024);	
			fseek(file_to_write,((int)seq_num*1024),SEEK_SET);
			fwrite(packet+full_header_length,1,1024,file_to_write);
			count_packet++;
		}
	}
}



void *receiver()
{
		int s; /*socketdescriptor*/
		printf("Recieving.. \n");
		s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device_name, 4);
		int length;
		u_char* buffer = (u_char*)malloc(1024+full_header_length); /*Buffer for ethernet frame*/
		while(1)
		{
				length = recvfrom(s, buffer, 1024+full_header_length, 0, NULL, NULL);
				process_packet(buffer,length);
	   			memset(buffer,0,1024+full_header_length);
		}
}

int main(int argc, char *argv[])
{

	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	int sockfd;
	int ii=0;
	int tx_len = 0;
   	unsigned char sendbuf[BUF_SIZ];
   	int t=0;
	int counter = 0;
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;
	char err[128];						// Holds the error
	device_name = NULL;
	char devices[10][64];				// For holding all available
	int count = 0;
	int ret = 0;
	int n = 0;
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



	count_packet=0;
	file_to_write=fopen("/tmp/test3.txt","wb");
	int size_of_file=0;
        strcpy(header_key, "node1");
        strcpy(payload_key, "node1");
	initDes(header_key, &schedule_header);
        initDes(payload_key, &schedule_payload);

  	printKey(&schedule_payload, 8);
  	printKey(&schedule_header, 8);

	filesize=524288000;
	calculateTotalPackets();

        packetR=(int *) calloc(packets_num,sizeof(int));


	memset(packetR,0,packets_num);
	int i=0;
	for(i=0;i<packets_num;i++){
		packetR[i]=0;
	}

        full_header_length=ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr);
	pthread_t sender_thread,recv_thread;
	if(pthread_create(&sender_thread,NULL,&sender,NULL)!=0){
		printf("Error in Creating thread1\n");
		return -1;
	}
	if(pthread_create(&recv_thread,NULL,&receiver,NULL)!=0){
		printf("Error in Creating thread2\n");
		return -1;
	}
	pthread_join(sender_thread,NULL);
	pthread_join(recv_thread,NULL);
	return 0;
}





