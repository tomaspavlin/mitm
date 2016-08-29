#include <netpacket/packet.h>
#include "packet.h"

/*
 * returns sockaddr_ll structure made
 * with interface name ifname
 */
struct sockaddr_ll
getsockaddr(char * ifname)
{
	struct sockaddr_ll ret;
	memset(&ret, 0, sizeof(ret));
	ret.sll_ifindex = if_nametoindex(ifname);
  	ret.sll_family = AF_PACKET;

  	ret.sll_halen = htons(ETH_ALEN);

  	return ret;
}

/* get local hardware address of interface ifname
 * and save it to hwaddr buffer
 */
void
gethwaddr(uint8_t * hwaddr, char * ifname)
{
	int s;
	struct ifreq buf;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	strcpy(buf.ifr_name, ifname);
	ioctl(s, SIOCGIFHWADDR, &buf);
	close(s);

	memcpy(hwaddr, buf.ifr_hwaddr.sa_data, ETH_ALEN);
}

/* prints info about ip packet into stdout */
void
printpktinfo(struct ip_packet * p, size_t p_size)
{

	char ipa_s[IPA_STR_LEN];
	char ipa_d[IPA_STR_LEN];
	char hwa_s[HWA_STR_LEN];
	char hwa_d[HWA_STR_LEN];


	uint8_t a[4];

	memcpy(a,&p->eth_h.ether_shost,ETH_ALEN);
	hwa_tostr(hwa_s,a);

	memcpy(a,&p->eth_h.ether_dhost,ETH_ALEN);
	hwa_tostr(hwa_d,a);

	memcpy(a,&p->ip_h.saddr,4);
	ipa_tostr(ipa_s,a);

	memcpy(a,&p->ip_h.daddr,4);
	ipa_tostr(ipa_d,a);

	printf("IP packet: %s > %s, %s > %s",hwa_s, hwa_d, ipa_s, ipa_d);

	printf(" Proto:%hhx)", p->ip_h.protocol);

	printf("\n");
}

/* log packet into file */
int
logpacket(struct ip_packet * p, size_t p_size)
{
	//printpktinfo(p, p_size);
}

/* prints buffer in hexadecimal form */
void
printbuf(const uint8_t * buf, size_t numbytes)
{
	int i = 0;
    for(; i < numbytes; i++){
    	printf("%.2x ", buf[i]);
    	if(i%16 == 15)
    		printf("\n");
    }
    printf("\n\n");
}