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
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "env.h"
#include "libkeystore.h"
#define USAGE "Usage: ./freceiver mynode [filename1] [filename2] [filesize]"
//methods
void init();

void write_re_to_file1(u_char *, int, int);
void write_re_to_file2(u_char *, int, int);

int updateTrackPacketsArray();


