#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h> //hostent

#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "libkeystore.h"

int checkArray[TEST_SEQ_CNT];
u_char packetOut[PACKET_BUF_SIZE];
int source;
int dest;
char header_key[4];
char payload_key[4];
pcap_t *handle_sniffed = NULL;

DES_key_schedule schedule_header;
DES_key_schedule schedule_payload;
FILE *file_to_write;


/*int generate_random_packet(u_char* packetOut, int size) {
	memset(packetOut, 0, sizeof(u_char) * 1600);
	sprintf((char*)packetOut, "here is a random packet with size %d*", size);
	int len = strlen((const char*)packetOut);
	int i;
	for (i = len; i < size; i++) {
		packetOut[i] = (u_char) (rand() & 0x000000ff);
	}
	return size;
}*/

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	int size = (int) header->len;
	int hsize=30;
	int psize=size-hsize;

	int seq = -1;
	int i;
	int ret;	
	u_char packet_d[size];
	u_char head_d[hsize];
	u_char data_d[psize];
	//print_rl_packet(stdout, packet, size);




	decrypt(packet+ETH_HLEN, packet+ETH_HLEN, &schedule_header, sizeof(struct rthdr));


	u_char *data;
	data=packet+hsize;

	//decrypt(data, data_d, &schedule_payload, psize);
	decrypt(packet+hsize, packet+hsize, &schedule_payload, psize);

	//memcpy(packet_d,head_d,hsize);
	//memcpy(packet_d+hsize,data_d,psize);

    if ((ret = validate_packet((u_char*)(packet))) != ROUTE_ON_RELIABLE) {
		fprintf(stdout, "ERROR invalid packet\n");
		return;
	}

	struct rlhdr* rlh = (struct rthdr*)(packet + sizeof(struct ethhdr)+sizeof(struct rthdr));
    u_char * buf = packet+hsize;
    int position = 1024 * rlh->seq;
    fseek(file_to_write,position,SEEK_SET);
    int k=0;
    for(k=0;k<psize;k++){
            putc(*buf,file_to_write);
            buf++;
    }
    
    //logic to exit
    //if (psize < 1024)
    //        return;
	fprintp(stdout,packet,size);
	//print_rl_packet(stdout, packet, size);

}



int main (int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: sudo ./pcap_receiver source destination\n");
		exit(1);
	}
	source = atoi(argv[1]);
	dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available
	int count = 0;
	int ret = 0;
	int n = 0;

	srand(time(NULL));
    file_to_write=fopen("/tmp/test3.txt","wb"); 
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

    //key = get_key(5);
	header_key[0] = 0x33; header_key[1] = 0x13; header_key[2]= 0x3f; header_key[3] = 0xe4;
    	payload_key[0] = 0x33; payload_key[1] = 0x13; payload_key[2]= 0x3f; payload_key[3] = 0xe4;
	initDes(header_key, &schedule_header);
	initDes(payload_key, &schedule_payload);

    //printKey(header_key, 4);

	pcap_loop(handle_sniffed , -1 , process_packet , NULL);	// -1 means an infinite loop

	fflush(file_to_write);
	fclose(file_to_write);

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}
