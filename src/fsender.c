#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "fsender.h"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

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

int fp;
char * data;
size_t filesize;

int no_of_packets;

u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut1[PACKET_BUF_SIZE];

u_char packetOut_e[PACKET_BUF_SIZE];

struct timespec start, stop;
double duration;

DES_key_schedule schedule_h;
//DES_key_schedule schedule_p;

pcap_t *handle_sniffed = NULL;

void send_test_packet(pcap_t* handle, int testno, int packetsize, int source, int dest) {
	printf("==========> Test %d: generating packets of %d bytes...\n", testno, packetsize);
	int pktlen = generate_test_packet(packetOut, packetsize, testno, source, dest);
	print_rl_packet(stdout, packetOut, pktlen);
	//encrypt((const u_char *)packetOut, packetOut_e, &schedule1, pktlen);
	int ret = 0;
	if ((ret = pcap_inject(handle, packetOut_e, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	usleep(50);
	//sleep(1);
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}

void send_file_packet(unsigned char* payload, int payloadsize, u_int16_t source, u_int16_t dest, int port, int seq)
{

	int pktlen = generate_fd_file_packet(packetOut, payload, (u_int16_t)source, (u_int16_t)dest, payloadsize, port, seq);
    //printf("RAW PACKET \n");
    //fprintp(stdout, packetOut, pktlen);
    memcpy(packetOut_e, packetOut, pktlen);   // create a copy

	encrypt((const u_char *)(packetOut + ETH_HLEN), packetOut_e + ETH_HLEN, &schedule_h, sizeof(struct rthdr) + sizeof(struct rlhdr) + payloadsize);
	//printf("E-PACKET \n");
	//fprintp(stdout,packetOut_e,pktlen);
	int ret = 0;
	if ((ret = pcap_inject(handle_sniffed, packetOut_e, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;
	printf("Received HELLO\n");
	print_data(stdout, (u_char*)packet, size);
}
void receive_ack(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	//int size = (int) header->len;
	struct rthdr* rth = (struct rthdr*) (packet + ETH_HLEN);
	if (rth->protocol == ROUTE_ON_RELIABLE) {
		if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) { perror( "clock gettime" );}
		duration = (stop.tv_sec - start.tv_sec)+ (double)(stop.tv_nsec - start.tv_nsec)/1e9;
		fprintf(stdout, "Execution time: %f sec, throughput: %fpps, %fbps\n", duration, TEST_SEQ_CNT/duration, TEST_SEQ_CNT*256*8/duration);
		exit(1);
	}
}

void mapfile(char *filename){
    pthread_mutex_lock(&lock);
    if ((fp = open (filename, O_RDONLY)) < 0){
        fprintf(stderr,"can't open %s for reading", filename);
        pthread_mutex_unlock(&lock);
        exit(0);
    }
    filesize = lseek(fp, 0, SEEK_END);
    printf("Filesize is %zu\n",filesize);
    data = mmap((caddr_t)0, filesize, PROT_READ, MAP_SHARED, fp, 0);
    if (data == (caddr_t)(-1)) {
        fprintf(stdout, "MMAP ERROR");
        exit(0);
    }
}

int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./fsender filepath source dest1 dest2\n");
		exit(1);
	}
	int src, dest1, dest2;
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	//pcap_t *handle_sniffed = NULL;

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


    //	unsigned char key_p[4];
//    key_p[0] = 0x33; key_p[1] = 0x13; key_p[2]= 0x3f; key_p[3] = 0xe4;
//	initDes(key_p, &schedule_p);

    u_char payload[PAYLOAD_SIZE];
    char node_name[8];
    int payload_size;
    long offset = 0;
    mapfile(argv[1]);

    switch(atoi(argv[2])){
    case 1:
        src = NODE1_RTR1;
        strcpy(node_name, "node1");
//        key_h[0] = 0x99; key_h[1] = 0xa1; key_h[2]= 0x10; key_h[3] = 0x7b;
//        key_h[4] = 0xeb; key_h[5] = 0x17; key_h[6]= 0x6a; key_h[7] = 0x2a;
        break;
    case 2:
        src = NODE2_RTR1;
        strcpy(node_name, "node2");
//        key_h[0] = 0x13; key_h[1] = 0x33; key_h[2]= 0xe4; key_h[3] = 0x3f;
//        key_h[4] = 0x13; key_h[5] = 0x33; key_h[6]= 0xe4; key_h[7] = 0x3f;
        break;
    case 3:
        src = NODE3_RTR1;
        strcpy(node_name, "node3");
//        key_h[0] = 0xe4; key_h[1] = 0x3f; key_h[2]= 0x13; key_h[3] = 0x33;
//        key_h[4] = 0xe4; key_h[5] = 0x3f; key_h[6]= 0x13; key_h[7] = 0x33;
        break;
    default:
        break;
    }

    switch(atoi(argv[3])){
    case 1:
        dest1 = NODE1_RTR1;
        break;
    case 2:
        dest1 = NODE2_RTR1;
        break;
    case 3:
        dest1 = NODE3_RTR1;
        break;
    default:
        break;
    }

    switch(atoi(argv[4])){
    case 1:
        dest2 = NODE1_RTR1;
        break;
    case 2:
        dest2 = NODE2_RTR1;
        break;
    case 3:
        dest2 = NODE3_RTR1;
        break;
    default:
        break;
    }

    //printKey(key_h, 8);
    if((ret = initDes(node_name, &schedule_h)) < 0){
        printf("Failed with %d \n", ret);
        }

    //printKey(&schedule_h, 8);
//    fp_read = fopen(argv[1], "r");
//    if(fp_read == NULL){
//        fprintf(stderr, "File open failed");
//        exit(1);
//    }
//    fseek(fp_read, 0L, SEEK_END);
//    filesize = ftell(fp_read);
    if((filesize % PAYLOAD_SIZE) != 0)
        no_of_packets = (filesize/PAYLOAD_SIZE) + 1;
    else
        no_of_packets = (filesize/PAYLOAD_SIZE);

    //initialize keys

    int seqNum = 0; int i;

    char str[20];
    fprintf(stdout, "Please enter Y/y to start \n");
    scanf("%s", &str);

    if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) { perror( "clock gettime" );}
    printTime();
    printf("Sending ... \n");
    for(i = 0; i < 1; i++){
        seqNum = 0;
        offset = 0;
        while (seqNum < no_of_packets) {
            //printf("Seq : %d\n", seqNum);
            //fseek(fp_read, offset, SEEK_SET);
            if((seqNum == (no_of_packets-1)) && ((filesize % PAYLOAD_SIZE) != 0))
                payload_size = filesize % PAYLOAD_SIZE;
            else
                payload_size = PAYLOAD_SIZE;
            memcpy(payload, data + offset, payload_size);
            //fread(payload, 1, payload_size, fp_read);
            offset = offset + payload_size;
            // send to 1 destination
            send_file_packet(payload, payload_size, src, dest1, 11, seqNum);
            usleep(200);
            // send to 2nd destination
            send_file_packet(payload, payload_size, src, dest2, 12, seqNum);
            usleep(100);
            seqNum++;
        }
    }
    printf("\n");
    //pthread_join(resend_thread, NULL);
    pcap_close(handle_sniffed);
    //pcap_close(handle_sniffed_nack);
    munmap(data, filesize);
    close(fp);
    printf( "ALL DONE\n");
    return 1;
}
