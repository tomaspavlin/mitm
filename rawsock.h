/*
 * This file is an system independent interface for
 * operations with raw sockets
 */

#ifndef RAWSOCK_H_
#define RAWSOCK_H_


#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include "lib/packet.h"


/* partability to OSX */
#ifndef AF_PACKET
  #define AF_PACKET PF_NDRV
#endif
/* partability to OSX */
#ifndef ETH_P_ARP
  #define ETH_P_ARP 0x0806
#endif

typedef struct rawsock_
{
	int s; // socket
	struct sockaddr_ll sockaddr; // interface addr
} rawsock_t;


void gethwaddr(uint8_t * hwaddr, const char * ifname);
rawsock_t rawsocket_arp(const char * ifname);
rawsock_t rawsocket_ip(const char * ifname);
void rawsend(rawsock_t rs, const void * p, size_t p_size);
ssize_t rawrecv(rawsock_t rs, void * buf, size_t bufsize);
void rawclose(rawsock_t rs);

#endif