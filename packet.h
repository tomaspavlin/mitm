#ifndef PACKET_H_
#define PACKET_H_

#include <netpacket/packet.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>


#define SOCKADDR_SIZE sizeof(struct sockaddr_ll)

struct eth_packet {
	uint8_t dest[6];
	uint8_t source[6];
	uint16_t type;
};

struct sockaddr_ll getsockaddr(char * ifname, uint8_t * hwaddr); // return sockaddr structure. ifname is interface name, hwaddr is mac address

void gethwaddr(uint8_t * hwaddr, char * ifname); // get hardware address of interface ifname and save it to hwaddr
#endif
