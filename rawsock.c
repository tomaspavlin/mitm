#include "rawsock.h"


/* ################################  Linux  ############################# */
#ifdef __linux__

/* 
 * get local hardware address (MAC) of interface ifname
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

	/*struct ifaddrs * ifa, ifa0;

	// get the right ifaddr
	getifaddrs(&ifa);
	ifa0 = ifa;

	while(ifa){
		if(strcmp(ifa->ifa_name, ifname) == 0){
			break;
		}
		ifa = ifa->ifa_next;
	}

	// if if found
	if(ifa){
		struct sockaddr * sa = ifa->ifa_addr;
		//memcpy(hwaddr, ifa->, ETHER_ADDR_LEN);
		..
	}else{ // if not found
		memset(hwaddr, 0, ETHER_ADDR_LEN);
	}


	freeifaddrs(&ifa0);*/
	//macaddr(hwaddr, ifname);

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
 * ip packets. If error occur, print it end exit
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

/*
 * sends packet p of size p_size with raw socket rs,
 * if error occur, print it and exit program
 */
void
rawsend(rawsock_t rs, const void * p, size_t p_size)
{
	if(sendto(rs.s, p, p_size, 0, (struct sockaddr *) &rs.sockaddr, sizeof(struct sockaddr_ll)) < 0){
		perror("rawsendto");
		exit(1);
	}
}

/*
 * rect packet to buffer buf of size bufsize with raw socket rs,
 * if error occure, print it and exit program
 */
ssize_t
rawrecv(rawsock_t rs, void * buf, size_t bufsize)
{
	return recv(rs.s, buf, bufsize, 0);
}

/*
 * closes raw socket rs,
 * if error occur, print it and exit program
 */
void
rawclose(rawsock_t rs)
{
	if(close(rs.s) < 0){
		perror("rawclose");
		exit(1);
	}
}

/* ################################  BSD  ############################# */
#elif defined(BSD)


#include <net/if_dl.h>
#include <net/bpf.h>

/* 
 * get local hardware address (MAC) of interface ifname
 * and save it to hwaddr buffer
 */
void
gethwaddr(uint8_t * hwaddr, const char * ifname)
{
	struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
            	
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
                
                memcpy(hwaddr, ptr, ETHER_ADDR_LEN);
                break;
            }
        }
        freeifaddrs(ifap);

    } else {
    	memset(hwaddr, 0, ETHER_ADDR_LEN);
    }
}

/*
 * create new raw socket for sending of 
 * arp packets. If error, print it end exit
 * the program
 */
rawsock_t
rawsocket_arp(const char * ifname)
{

	int fd =  open("/dev/bpf", O_RDWR);//|O_APPEND|O_CREAT)

	if(fd < 0){
		perror("/dev/bpf open");
		exit(1);
	}

	struct ifreq ifr;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);

	if(ioctl(fd, BIOCSETIF, &ifr) < 0){
		perror("BIOCSETIF");
		exit(1);
	}

    /* Set header complete mode */
    //if(ioctl(fd, BIOCSHDRCMPLT, &enable) < 0)
    //    return -1;

    /* Monitor packets sent from our interface */
    //if(ioctl(fd, BIOCSSEESENT, &enable) < 0)
    //    err(EXIT_FAILURE, "BIOCSEESENT");

    /* Return immediately when a packet received */
    //if(ioctl(fd, BIOCIMMEDIATE, &enable) < 0)
    //    err(EXIT_FAILURE, "BIOCIMMEDIATE");


}

/*
 * create new raw socket for sending and recv of 
 * ip packets. If error occur, print it end exit
 * the program
 */
rawsock_t
rawsocket_ip(const char * ifname)
{
	rawsock_t ret = 0;
	return ret;
}

/*
 * sends packet p of size p_size with raw socket rs,
 * if error occur, print it and exit program
 */
void
rawsend(rawsock_t rs, const void * p, size_t p_size)
{
	if(write(rs, p, p_size) < 0){
		perror("rawsend");
		exit(1);
	}
}

/*
 * rect packet to buffer buf of size bufsize with raw socket rs,
 * if error occure, print it and exit program
 */
ssize_t
rawrecv(rawsock_t rs, void * buf, size_t bufsize)
{
	return 0;
}

/*
 * closes raw socket rs,
 * if error occur, print it and exit program
 */
void
rawclose(rawsock_t rs)
{

}



#else
#error Only Linux and BSD systems are supported
#endif