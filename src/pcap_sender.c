#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>

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

#include "env.h"
#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "libkeystore.h"

/*int generate_random_packet(u_char* packetOut, int size) {
	memset(packetOut, 0, sizeof(u_char) * 1600);
	sprintf((char*)packetOut, "here is a random packet with size %d*", size);
	int len = strlen((const char*)packetOut);
	int i;
	for (i = len; i < size; i++) {
		packetOut[i] = (u_char) (rand() & 0x000000ff);
	}
	return size;
}
*/


u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut_e[PACKET_BUF_SIZE];
u_char head_e[30];
struct timespec start, stop;
double duration;

DES_key_schedule schedule1;
DES_key_schedule schedule2;

void send_test_packet(pcap_t* handle, int testno, int packetsize, int source, int dest) {
	printf("==========> Test %d: generating packets of %d bytes...\n", testno, packetsize);
	int pktlen = generate_test_packet(packetOut, packetsize, testno, source, dest);
	print_rl_packet(stdout, packetOut, pktlen);
	encrypt((const u_char *)packetOut, packetOut_e, &schedule1, pktlen);
	int ret = 0;
	//print_data(stdout, packetOut, pktlen);
	/*printf("generating packets of 8 bytes...\n");
	generate_random_packet(packetOut, 8);*/

	if ((ret = pcap_inject(handle, packetOut_e, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
		usleep(50);
	//sleep(1);
}

void send_file_packet(pcap_t* handle, unsigned char* payload, u_int16_t source, u_int16_t dest, int packetsize, int port, int seq)
{
	u_char payload_e[packetsize];
	memset(payload_e,0,packetsize);
	
	//encrypt payload
	encrypt((const u_char *)payload, payload_e, &schedule2, packetsize);
	
	int pktlen = generate_file_packet(packetOut, payload_e, (u_int16_t)source, (u_int16_t)dest, packetsize, port, seq);
	//print packet
	fprintp(stdout,packetOut,pktlen);
	memset(head_e,0,30);
	//encrypt header
	int header_size = 30;
	encrypt((const u_char *)(packetOut+ETH_HLEN), head_e, &schedule1, sizeof(struct rthdr));
	
	memcpy(packetOut+ETH_HLEN, head_e, sizeof(struct rthdr) );
	fprintp(stdout,packetOut,pktlen);
	int ret = 0;
	if ((ret = pcap_inject(handle, packetOut, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}

	printf( "DONE\n");
	usleep(50);
	//exit(1);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;
	printf("Received HELLO\n");
	print_data(stdout, (u_char*)packet, size);
}
void receive_ack(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;
	struct rthdr* rth = (struct rthdr*) (packet + ETH_HLEN);
	if (rth->protocol == ROUTE_ON_RELIABLE) {
		if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) { perror( "clock gettime" );}
		duration = (stop.tv_sec - start.tv_sec)+ (double)(stop.tv_nsec - start.tv_nsec)/1e9;
		fprintf(stdout, "Execution time: %f sec, throughput: %fpps, %fbps\n", duration, TEST_SEQ_CNT/duration, TEST_SEQ_CNT*256*8/duration);
		exit(1);
	}
}
int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
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
	printf( "DONE\n");

	//pcap_loop(handle_sniffed , 5 , process_packet , NULL);
    //initialize keys
	unsigned char key1[4];
    //key = get_key(5);
    //key1[0] = 0x32; key1[1] = 0x12; key1[2]= 0x2f; key1[3] = 0xe3;
    key1[0] = 0x33; key1[1] = 0x13; key1[2]= 0x3f; key1[3] = 0xe4;
    //printKey(key1, 4);
    initDes(key1,&schedule1);
	
	unsigned char key2[4];
    //key = get_key(5);
    key2[0] = 0x33; key2[1] = 0x13; key2[2]= 0x3f; key2[3] = 0xe4;
    //printKey(key2, 4);
	initDes(key2,&schedule2);
	
	int BUF_SIZ= 1024;
	FILE *fr;
    fr = fopen ("/tmp/test.txt", "rb");
	fseek(fr, 0, SEEK_END);
	long fsize = ftell(fr);
	fseek(fr, 0, SEEK_SET);
	int numberOfPackets;
	if ((int)fsize%1024 !=0) 
			numberOfPackets = (int)(fsize/1024) + 1;
		else 
			numberOfPackets =(int)(fsize/1024);
    int ii=0;
    int tx_len = 0;
    unsigned char sendbuf[BUF_SIZ];

   	int t=0;
	int counter = 0;
    for(t=0;t< numberOfPackets; t++) {
    	memset(sendbuf, 0, BUF_SIZ);
	    tx_len=0;
        unsigned char ch;
        for (ii = 0; ii < 1024; ii++) {
        	ch=fgetc(fr);
        	counter++;
        	if(((int)fsize < counter))
        		break;
        	else{
                    sendbuf[tx_len++] = ch;
                }
        }
        fprintf(stdout, "source: %.4x; dest: %.4x; len: %d; seq: %d;\n", NODE1_RTR1, NODE2_RTR1, tx_len, t);
        send_file_packet(handle_sniffed, sendbuf, NODE1_RTR1, NODE2_RTR1, tx_len, 5, t);
    }
    fclose(fr);

	/*
	int i;
	if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) { perror( "clock gettime" );}
	for (i = 0; i < TEST_SEQ_CNT; i++) {
		send_test_packet(handle_sniffed, i, 1024, source, dest);
	}
	printf("Waiting for ACK...\n");
	pcap_loop(handle_sniffed, -1, receive_ack, NULL);/

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);*/

	return 0;
}
