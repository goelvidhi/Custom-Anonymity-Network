/**
 * CS 558L Final Project
 *
 * Key Store
 */

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "des.h"
#include "libkeystore.h"

int get_key(int node, unsigned char * buf) {
/*	//open tcp socket to server
	int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    portno = 5001;
	//open socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        fprintf(stderr, "ERROR opening socket\n");
	//Fill Up server Struct
    server = gethostbyname("rtr1.FinalProjectTest.USC558L.isi.deterlab.net");
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr,server->h_length);
    serv_addr.sin_port = htons(portno);
	//connect to server
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        fprintf(stderr, "ERROR connecting\n");
	//write the node value to socket
	n = write(sockfd,node,sizeof(node));
    if (n < 0) 
         fprintf(stderr, "ERROR writing to socket\n");
	//receive key
	n = read(sockfd,buf,KEY_SIZE);
	if (n != KEY_SIZE){
		return -1;
	}
	else
		return 0;*/
		return 0;
}

void put_key(int node,unsigned char *key) {
	/*unsigned char buf[KEY_SIZE+sizeof(node)+1];
	//open tcp socket to server
	int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    portno = 5001;
	//open socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        fprintf(stderr, "ERROR opening socket\n");
	//Fill Up server Struct
    server = gethostbyname("rtr1.FinalProjectTest.USC558L.isi.deterlab.net");
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr,server->h_length);
    serv_addr.sin_port = htons(portno);
	//connect to server
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        fprintf(stderr, "ERROR connecting\n");
	//create Structure for Server
	u_char* buff = buf;
	memcpy(buff,(const u_char*)node,strlen((const u_char*)node));
	memcpy(buff+strlen((const u_char*)node),",",1);
	memcpy(buff+strlen((const u_char*)node)+1,key,KEY_SIZE);
	//Write to socket
	n = write(sockfd,node,sizeof(node));
    if (n != (KEY_SIZE+sizeof(node)+1)) 
         fprintf(stderr, "ERROR writing to socket\n");  */
}
/*



int main()
{
	u_char key1[4];
	
	key1[0] = 0x32; key1[1] = 0x12; key1[2]= 0x2f; key1[3] = 0xe3;
	
	printf("Putting Key");
	put_key(1,key1);
	printf("Getting Key");
	int i;
	u_char * buf = (unsigned char*)calloc(KEY_SIZE,sizeof(unsigned char));
	i=get_key(1,buf);
	printKey(key1, 4);
	printf("Result from Get Key :%d",i);
	return 0;
}
*/
