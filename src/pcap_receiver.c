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
pcap_t *handle_sniffed = NULL;

DES_key_schedule schedule;

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
	int seq = -1;
	int i;
	int ret;
	u_char packet_d[PACKET_BUF_SIZE];

	decrypt(packet, packet_d, &schedule, size);
	print_rl_packet(stdout, packet_d, size);
	struct rthdr* rth = (struct rthdr*) (packet_d + ETH_HLEN);
	if (rth->protocol == ROUTE_ON_RELIABLE) {
		struct rlhdr* rlh = (struct rlhdr*)(packet_d + ETH_HLEN + sizeof(struct rthdr));
		seq = ntohs(rlh->seq);
		fprintf(stdout, "Received sequence %d\n", seq);
		checkArray[seq] = 1;
		for (i = 0; i < TEST_SEQ_CNT; i++) {
			if (checkArray[i] != 1) {
				return;
			}
		}
		printf("ALL test segments received.\n");
		int pktlen = generate_test_packet(packetOut, 128, 9999, source, dest);
		if ((ret = pcap_inject(handle_sniffed, packetOut, pktlen)) < 0){
			fprintf(stderr, "Fail to inject packet\n");
			// exit(1);
		}
		exit(1);
	}
	else{
        printf("Packet checksum failed \n");
	}
	//print_data(stdout, (u_char*)packet, size);
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

	char key[4];
    //key = get_key(5);
    key[0] = 0x32; key[1] = 0x12; key[2]= 0x2f; key[3] = 0xe3;
    printKey(key, 4);
    initDes(key, &schedule);

	pcap_loop(handle_sniffed , -1 , process_packet , NULL);	// -1 means an infinite loop

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}
