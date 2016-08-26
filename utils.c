#include "utils.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool
parse_hwa(uint8_t * buf, char * str)
{
	int n = sscanf(str, "%x:%x:%x:%x:%x:%x",
					(unsigned int *) &buf[0],
					(unsigned int *) &buf[1],
					(unsigned int *) &buf[2],
					(unsigned int *) &buf[3],
					(unsigned int *) &buf[4],
					(unsigned int *) &buf[5]);

	return n == 6;
}

bool
parse_ipa(uint8_t * buf, char * str)
{
	int n = sscanf(str, "%d.%d.%d.%d",
					(unsigned int *) &buf[0],
					(unsigned int *) &buf[1],
					(unsigned int *) &buf[2],
					(unsigned int *) &buf[3]);

	return n == 4;
}

void hwa_tostr(char * buf, uint8_t * addr)
{
	snprintf(buf, 18, "%x:%x:%x:%x:%x:%x",
					addr[0], addr[1], addr[2],
					addr[3], addr[4], addr[5]);
}

void ipa_tostr(char * buf, uint8_t * addr)
{
	snprintf(buf, 16, "%d:%d:%d:%d",
					addr[0], addr[1], addr[2], addr[3]);
}

int
p(char * msg)
{
	write(1, msg, strlen(msg));
	write(1, "\n", strlen("\n"));
}