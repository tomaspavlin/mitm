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

typedef enum {PBF_HEX, PBF_CHAR} pb_format_t;

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

#include "packet_tcp.h"

struct sockaddr_ll getsockaddr(char * ifname);
void gethwaddr(uint8_t * hwaddr, char * ifname);
void dprintpkt_s(int fd, const struct ip_packet * p, size_t p_size);
void dprintpkt_l(int fd, const struct ip_packet * p, size_t p_size);
void dprintbuf_f(int fd, const uint8_t * buf, size_t numbytes, pb_format_t format);
void dprintbuf(int fd, const uint8_t * buf, size_t numbytes);
void printbuf(const uint8_t * buf, size_t numbytes);
int injectpkt(struct ip_packet * p, size_t numbytes, char ** subs, size_t subs_c);

#endif
