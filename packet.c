#include <netpacket/packet.h>
#include "packet.h"

struct sockaddr_ll
getsockaddr(char * ifname, uint8_t * hwaddr)
{
	struct sockaddr_ll ret;
	memset(&ret, 0, sizeof(ret));
	ret.sll_ifindex = if_nametoindex(ifname);
  	ret.sll_family = AF_PACKET;
  	//memcpy(ret.sll_addr, hwaddr, 6);
  	ret.sll_halen = htons(6);

  	return ret;
}

void
gethwaddr(uint8_t * hwaddr, char * ifname)
{
	int s;
	struct ifreq buf;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	strcpy(buf.ifr_name, ifname);
	ioctl(s, SIOCGIFHWADDR, &buf);
	close(s);

	memcpy(hwaddr, buf.ifr_hwaddr.sa_data, 6);
}