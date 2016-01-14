/**
 * CS 558L
 *
 * SENDER for reliable transfer
 */
#ifndef FSENDER_H
#define FSENDER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include "env.h"
#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "libkeystore.h"
#define RETRANSMISSIONS 5
//Function declaration
void init();

void send_test_packet(pcap_t*, int, int, int, int);
void send_file_packet(unsigned char*, int, u_int16_t, u_int16_t, int, int);

#endif
