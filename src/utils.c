/*
  Copyright (c) 2012-2018 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
  ipdecap [http://loicpefferkorn.net/ipdecap]

  This file is part of ipdecap.

  Ipdecap is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Ipdecap is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ipdecap.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "utils.h"
#include <sys/types.h>
#include <net/ethernet.h>  // for ETHER_ADDR_LEN
#include <stdarg.h>        // for va_list
#include <stdio.h>         // for printf, NULL, vfprintf, stdout
#include <stdlib.h>        // for free
#include <string.h>        // for strlen

void *str2dec(const char *in, int maxsize) {

  int i, len;
  unsigned char c;
  unsigned char *out = NULL;

  MALLOC(out, maxsize, unsigned char);

  len = strlen(in);
  if (len > maxsize*2) {
    printf("str too long\n");
    free(out);
    return NULL;
  }
  for(i=0;i<len;i++) {
    c = in[i];

    if ((c >= '0') && (c <= '9'))
      c -= '0';
    else if ((c >= 'A') && (c <= 'F'))
      c = c-'A'+10;
    else if ((c >= 'a') && (c <= 'f'))
      c = c-'a'+10;
    else {
      printf("non hex digit: %c\n", c);
      free(out);
      return NULL;
    }

    if (i % 2 == 0)
      out[i/2] = (c<<4);
    else
      out[i/2] = out[i/2] | c;
  }
  return out;
}

/*
 * Friendly printed MAC address
 *
 */
void print_mac(const unsigned char *mac_ptr) {

  int i;
  for(i=0;i<ETHER_ADDR_LEN;i++)
    i != ETHER_ADDR_LEN ? printf("%02x:",  *(mac_ptr+i)) : printf("%02x",  *(mac_ptr+i));
  printf("\n");
}

void dumpmem(char *prefix, const unsigned char *ptr, int size, int space) {

  int i;
  printf("%s:: ", prefix);
  for(i=0;i<size;i++)
    space == 0
      ? printf("%02x", *(ptr+i))
      : printf("%02x ", *(ptr+i));
  printf("\n");
}

void verbose(const char *format, ...) {

  if (global_args.verbose == true) {
    va_list argp;
    va_start (argp, format);
    vfprintf(stdout, format, argp);
    va_end(argp);
  }
}
