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
#include <netinet/in.h>
#include "freceiver.h"

FILE* fp_write1;
FILE* fp_write2;
size_t filesize;
int packets_num;
unsigned int last_packet_size;
int total1 = 0, total2 = 0;
//int checkArray[TEST_SEQ_CNT];
u_char packetOut[PACKET_BUF_SIZE];

pcap_t *handle_sniffed = NULL;

DES_key_schedule schedule_h;
//DES_key_schedule schedule_p;

int my_addr;
int *track_packets1, *track_packets2;
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
void init(){
    packets_num = 0;
    if((filesize % PAYLOAD_SIZE) != 0){
        packets_num = filesize/PAYLOAD_SIZE + 1;
        last_packet_size = filesize%PAYLOAD_SIZE;
    }
    else{
        packets_num = filesize/PAYLOAD_SIZE;
        last_packet_size = PAYLOAD_SIZE;
    }
    //printf("packet num: %d \n", packets_num);
    track_packets1 = (int *)calloc(packets_num, sizeof (int));
    track_packets2 = (int *)calloc(packets_num, sizeof (int));
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int size = (int) header->len;
    u_char *packetIn = (u_char *) packet;
    //printf("REC E-PACKET \n");
    //fprintp(stdout, packetIn, size);
    int i;
	for(i=0 ; i < 2 * ETH_ALEN ; i++){
        if(packetIn[i] != 0xFF){
            printf("NOT TEAM1 PACKET\n");
            return;
        }
	}
    decrypt(packetIn + ETH_HLEN, packetIn + ETH_HLEN, &schedule_h,  size - ETH_HLEN);
    //printf("REC D-PACKET \n");
    //fprintp(stdout, packetIn, size);

	struct rthdr *rth = (struct rthdr*) (packetIn + sizeof(struct ethhdr));

	//char err[128];
	//print_rl_packet(stdout, packet, size);
	int hdrlen, payload_size;
	if(rth->saddr == my_addr){
        //fprintf(stdout, "Wrong addr \n");
        return;
	}


    hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
    //printf("hdrlen : %d \n", hdrlen);
    struct rlhdr* rlh = (struct rlhdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
    int port = ntohs(rlh->port);
    int seq = ntohs(rlh->seq);
    //printf("Port : %d Seq : %d\n", port, seq);

    if(port == 11){
        if (updateTrackPacketsArray(track_packets1, seq)){
        track_packets1[seq] = 1;
        payload_size = size - hdrlen;
        write_re_to_file1(packetIn + hdrlen, payload_size, seq);
    }
    }
    else if(port == 12){
        if (updateTrackPacketsArray(track_packets2, seq)){
        track_packets2[seq] = 1;
        payload_size = size - hdrlen;
        write_re_to_file2(packetIn + hdrlen, payload_size, seq);
    }
    }
    else{
        printf("Incorrect Port \n");
    }

}

void write_re_to_file1(u_char * payload, int payload_size, int seqNum){

    fseek( fp_write1, seqNum * PAYLOAD_SIZE, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write1);
    fflush(fp_write1);
    total1++;
    if(total1 == 2000)
        fprintf(stdout, "Received 2000 packets at port 11\n");
    if(total1 == 5000)
        fprintf(stdout, "Received 5000 packets at port 11\n");
    if(total1 == 7000)
        fprintf(stdout, "Received 7000 packets at port 11 \n");
    //fprintf(stdout, "total : %d\n", total);
    if(total1 == packets_num){
        //fprintf(stdout, "File successfully written \n");
        fprintf(stdout, "FILE 1 WRITING DONE \n");
        printTime();
        fclose(fp_write1);
        //exit(1);
    }
}

void write_re_to_file2(u_char * payload, int payload_size, int seqNum){

    fseek( fp_write2, seqNum * PAYLOAD_SIZE, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write2);
    fflush(fp_write2);
    total2++;
    if(total2 == 2000)
        fprintf(stdout, "Received 2000 packets at port 12\n");
    if(total2 == 5000)
        fprintf(stdout, "Received 5000 packets at port 12\n");
    if(total2 == 7000)
        fprintf(stdout, "Received 7000 packets at port 12 \n");

    //fprintf(stdout, "total : %d\n", total);
    if(total2 == packets_num){
        //fprintf(stdout, "File successfully written \n");
        fprintf(stdout, "FILE 2 WRITING DONE\n");
        printTime();
        fclose(fp_write2);
        //exit(1);
    }
}

int updateTrackPacketsArray(int *track_packets, int seq_num){
    if(seq_num>= 0 && seq_num < packets_num)
    {
        if(track_packets[seq_num] == 0){
            track_packets[seq_num] = 1;
            return 1;
        }
        else return 0;

    }
    return 0;
}


int main (int argc, char** argv) {
    char node_name[8];
    //char key_p[4];
	if (argc < 5) {
         fprintf(stderr,"%s", USAGE);
         exit(1);
    }
    switch(atoi(argv[1])){
        case 1:
            my_addr = NODE1_RTR1;
            strcpy(node_name, "node1");
            //key_h[0] = 0x33; key_h[1] = 0x13; key_h[2]= 0x3f; key_h[3] = 0xe4;
            break;
        case 2:
            my_addr = NODE2_RTR1;
            strcpy(node_name, "node2");
            //key_h[0] = 0x13; key_h[1] = 0x33; key_h[2]= 0xe4; key_h[3] = 0x3f;
            break;

        case 3:
            my_addr = NODE3_RTR1;
            strcpy(node_name, "node3");
            //key_h[0] = 0xe4; key_h[1] = 0x3f; key_h[2]= 0x13; key_h[3] = 0x33;
            break;
        default:
            break;
    }
    filesize = atoi(argv[4]);

    fp_write1 = fopen(argv[2] , "w+");
    fp_write2 = fopen(argv[3] , "w+");

    if(fp_write1 == NULL || fp_write2 == NULL){
        fprintf(stdout, "File open failed");
        exit(1);
    }

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

	init();

    //key = get_key(5);
	if((ret = initDes(node_name, &schedule_h)) < 0){
        printf("Failed with %d \n", ret);
        }
	//initDes(key_p, &schedule_p);

    //printKey(&schedule_h, 8);

	pcap_loop(handle_sniffed , -1 , process_packet , NULL);	// -1 means an infinite loop

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}
