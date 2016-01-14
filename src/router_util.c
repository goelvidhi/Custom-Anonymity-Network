/**
 * CS 558L Final Project
 *
 * router helper functions
 */

#include "router_util.h"

struct sockaddr getLocalMac(char *iface){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, iface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        return s.ifr_hwaddr;
  	}
  	struct sockaddr dummy;
  	return dummy;
}