#include "rawsock.h"


/* 
 * get local hardware address of interface ifname
 * and save it to hwaddr buffer
 */
void
gethwaddr(uint8_t * hwaddr, const char * ifname)
{

	// BRUTAL HACK
	//#ifndef __APPLE__
	int s;
	struct ifreq buf;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	strcpy(buf.ifr_name, ifname);


	if(ioctl(s, SIOCGIFHWADDR, &buf) < 0){
		perror("ioctl");
		exit(1);
	}


	close(s);

	memcpy(hwaddr, buf.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	//#endif
}

/*
 * returns sockaddr_ll structure made
 * with interface name ifname
 */
struct sockaddr_ll
_getsockaddr(const char * ifname)
{
	//TODO
	struct sockaddr_ll ret;
	memset(&ret, 0, sizeof(ret));
	ret.sll_ifindex = if_nametoindex(ifname);
  	ret.sll_family = AF_PACKET;

  	ret.sll_halen = htons(ETHER_ADDR_LEN);

  	return ret;
}


/* create rawsock_t from s */
rawsock_t
_rsfroms(int s, const char * if_name)
{
  /* Set interface to prom mode */
  struct ifreq opts;
  strncpy(opts.ifr_name, if_name, IFNAMSIZ-1);
  ioctl(s, SIOCGIFFLAGS, &opts);
  opts.ifr_flags |= IFF_PROMISC;
  ioctl(s, SIOCSIFFLAGS, &opts);

  /* Bind to interface */
  if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1)  {
    perror("SO_BINDTODEVICE");
    exit(1);
  }

  /* Socket can be reused */
  int so;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &so, sizeof so) == -1) {
    perror("SO_REUSEADDR");
    exit(1);
  }

  /* Set sockaddr */
  rawsock_t ret;
  ret.s = s;
  ret.sockaddr = _getsockaddr(if_name);
  return ret;
}

/*
 * create new raw socket for sending of 
 * arp packets. If error, print it end exit
 * the program
 */
rawsock_t
rawsocket_arp(const char * ifname)
{
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (s < 0){
		perror("raw socket for arp");
		exit(1);
	}

	return _rsfroms(s, ifname);
}

/*
 * create new raw socket for sending and recv of 
 * ip packets. If error, print it end exit
 * the program
 */
rawsock_t
rawsocket_ip(const char * ifname)
{
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (s < 0){
		perror("raw socket for ip");
		exit(1);
	}
	
	return _rsfroms(s, ifname);
}

void
rawsend(rawsock_t rs, const void * p, size_t p_size)
{
	if(sendto(rs.s, p, p_size, 0, (struct sockaddr *) &rs.sockaddr, sizeof(struct sockaddr_ll)) < 0){
		perror("rawsendto");
		exit(1);
	}
}

ssize_t
rawrecv(rawsock_t rs, void * buf, size_t bufsize)
{
	return recv(rs.s, buf, bufsize, 0);
}

void
rawclose(rawsock_t rs)
{
	if(close(rs.s) < 0){
		perror("rawclose");
		exit(1);
	}
}