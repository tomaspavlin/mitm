#ifndef PACKET_H_
#define PACKET_H_

#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#include "utils.h"

#define SOCKADDR_SIZE sizeof(struct sockaddr_ll)

typedef enum  {PD_1TO2, PD_2TO1, PD_OTHER} pkt_dir_t; // who is sending the packet

struct eth_packet
{
	uint8_t dest[ETH_ALEN];
	uint8_t source[ETH_ALEN];
	uint16_t type;
};

struct ip_packet
{
	struct ether_header eth_h;
	struct iphdr ip_h;
} __attribute__((__packed__));

struct sockaddr_ll getsockaddr(char * ifname);
void gethwaddr(uint8_t * hwaddr, char * ifname);
void printpktinfo(struct ip_packet * p, size_t p_size);
int logpacket(struct ip_packet * p, size_t p_size);
void printbuf(const uint8_t * buf, size_t numbytes);
#endif
