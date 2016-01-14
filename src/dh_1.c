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
#include <netinet/in.h>
#include <netdb.h> //hostent
#include <time.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "env.h"
#include "libkeystore.h"
#include "routing.h"
#include "router_util.h"


pcap_t *handle_sniffed = NULL;
char *device_name = NULL;

u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut_e[PACKET_BUF_SIZE];
struct timespec start, stop;
DH * dhparam;
int pk_send_size;
int pk_rcv_size;
unsigned char pk_send[1024];
unsigned char pk_rcv[1024];
unsigned char* sym_key;


int source;
int dest;
double duration;


void send_pubkey(pcap_t* handle, int packetsize) {
    //printf("Packet size %d, payload size %d \n", packetsize, pk_send_size);
    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	int pktlen = generate_key_packet(packetOut, pk_send, pk_send_size, packetsize, 0x0011, 0x0021);
	//fprintp(stdout, packetOut, pktlen);

	int ret = 0;
	if ((ret = pcap_inject(handle, packetOut, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	//printf( "PUBLIC KEY SENT\n");

	//sleep(1);
}
void receive_pubkey(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;

	//print_data(stdout, (u_char*)packet, size);
	//fprintp(stdout, packet, size);
	struct rthdr *rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
    u_char *packetIn = (u_char *) packet;
	int hdrlen;
    if(rth->saddr == 0x0011)
        return;

    int protocol = rth->protocol;
    if(protocol == KEY_EXCHANGE){
        //printf("Received Key\n");
        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct kehdr);
        struct kehdr* keh = (struct kehdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
        pk_rcv_size = keh->size;
        printf("Received Public Key of size %d\n", pk_rcv_size);


        bzero(pk_rcv, 1024);
        memcpy(pk_rcv, packetIn + hdrlen, pk_rcv_size);
        printKey(pk_rcv, pk_rcv_size);
        printf("\n");
        struct BIGNUM* r_pub_key = BN_new();
        r_pub_key = BN_bin2bn(pk_rcv , pk_rcv_size, NULL);
        //printf("Use size %d \n", 4 * DH_size(dhparam));
        sym_key = (unsigned char* )malloc(DH_size(dhparam));
        //printf("Allocated size %d ", sizeof(sym_key));

        DH_compute_key(sym_key, (const struct BIGNUM*)r_pub_key, dhparam);
        printf("SYMMETRIC KEY (%d bytes)\n", sizeof(sym_key));
        printKey(sym_key, sizeof(sym_key));
		//put_key(source, (char *)sym_key);
		writeKey(device_name, sym_key);
		exit(1);
//		char key[20];
//        memset(key, 0, 20);
//        readKey(key);
//        printKey(key, sizeof(sym_key));
    }
}

void keyExchange(){
    dhparam = DH_new();
    if(dhparam == NULL){
        printf("Unable to allocate DH \n");
    }

    FILE * f = fopen("dh1024.pem" , "r");
    if (f == NULL)
        printf("Cannot Open file to read \n");

    dhparam = PEM_read_DHparams(f, NULL, NULL, NULL);
	//Generate Public and Private Keys

	DH_generate_key(dhparam);
    //Send my public key
    bzero(pk_send, 1024);
    pk_send_size = BN_num_bytes(dhparam->pub_key);
    BN_bn2bin(dhparam->pub_key, pk_send);
    //printf("Send Size %d \n", pk_send_size);
    //printKey(pk_send, pk_send_size);
    //char c[20];
    //fprintf(stdout, "Please enter Y/y to send my public key \n");
    //scanf("%s", &c);
    send_pubkey(handle_sniffed, 256);


    // TODO: receive Public key of node at other end
    pcap_loop(handle_sniffed, 5, receive_pubkey , NULL);

}

int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./dh_1 source destination\n");
		exit(1);
	}
	source = atoi(argv[1]);
	dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device


	char err[128];						// Holds the error

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
    //memset(end_of_mac, 0, 2);
    //getLocalMac(device_name, end_of_mac);
    //getLocalMac(device_name);
    //printf("End of MAC is %02x:%02x \n", end_of_mac[0], end_of_mac[1]);

    keyExchange();
	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}




