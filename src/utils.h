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

#include <stdbool.h>
#include <stdio.h>   // for stderr, fprintf, NULL
#include <stdlib.h>  // for EXIT_FAILURE, exit, malloc
#pragma once

void *str2dec(const char *in, int maxsize);

typedef struct pcap_pkthdr pcap_hdr;
void dumpmem(char *prefix, const unsigned char *ptr, int size, int space);
void print_mac(const unsigned char *mac_ptr);
void verbose(const char *format, ...);


/* Command line parameters */
typedef struct global_args_t {
  char *input_file;       // --input option
  char *output_file;      // --output option
  char *esp_config_file;  // --config option
  char *bpf_filter;       // --filter option
  bool verbose;           // --verbose option
  bool list_algo;         // --list option
} global_args_t;

extern global_args_t global_args;

#define member_size(type, member) sizeof(((type *)0)->member)

#ifdef DEBUG
  #define DEBUG_FLAG 1
#else
  #define DEBUG_FLAG 0
#endif

#define debug_print(fmt, ...) \
            do { if (DEBUG_FLAG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define MALLOC(ptr, count, type) {                      \
  if ( (ptr = malloc(count * sizeof(type))) == NULL) {  \
    error("Cannot malloc");                             \
  }                                                     \
}

#if DEBUG_FLAG
  #define error(...)  {                                     \
    fprintf(stderr, "error: %s(%d) ", __FILE__, __LINE__);  \
    fprintf(stderr, __VA_ARGS__);                           \
    exit(EXIT_FAILURE);                                     \
  }
#else
  #define error(...)  {           \
    fprintf(stderr, "error: ");   \
    fprintf(stderr, __VA_ARGS__); \
    exit(EXIT_FAILURE);           \
  }
#endif
