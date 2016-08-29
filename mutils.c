#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>


#include "packet.h"
#include "utils.h"

/* text representation of addresses */
char * if_name;
char * ipa1_str;
char * hwa1_str;
char * ipa2_str;
char * hwa2_str;

/* addresses binary representation */
uint8_t ipa1[4];
uint8_t hwa1[ETH_ALEN];
uint8_t ipa2[4];
uint8_t hwa2[ETH_ALEN];
uint8_t hwa_host[ETH_ALEN];

/* address for sendto */
struct sockaddr_ll sa;

void
showusage(int argc, char ** argv)
{
  printf("Usage: %s <interface> <target1-ip> \
    <target1-mac> <target2-ip> <target2-mac> ", argv[0]);

  exit(1);
}

/*
 * this method show usage if there is no sufficient
 * number of args and exit the program. If there is
 * sufficient number of args, save them into proper
 * global variables and convert is to binary repre-
 * sentation.
 */
void
process_args(int argc, char ** argv)
{
  if (argc < 6)
    showusage(argc, argv);

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

  // get local interface mac address
  gethwaddr(hwa_host, if_name);

  // get sockaddr
  sa = getsockaddr(if_name);

}
