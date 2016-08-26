#ifndef UTILS_H_
#define UTILS_H_

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

bool parse_hwa(uint8_t * buf, char * addr); // parse hardware adress
bool parse_ipa(uint8_t * buf, char * addr); // parse ip adress
void hwa_tostr(char * buf, uint8_t * addr); // save string representation of hw addr to buf
void ipa_tostr(char * buf, uint8_t * addr); // save string representation of ip addr to buf
int p(char * msg); // print msg to standard output

#endif
