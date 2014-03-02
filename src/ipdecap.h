/*
  Copyright (c) 2012-2014 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
  ipdecap [http://www.loicp.eu/ipdecap]

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

#ifdef DEBUG
  #define DEBUG_FLAG 1
#else
  #define DEBUG_FLAG 0
#endif

#define debug_print(fmt, ...) \
            do { if (DEBUG_FLAG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define MAXIMUM_SNAPLEN   65535
#define GRE_HEADERLEN     4
#define CONF_BUFFER_SIZE  1024

#define member_size(type, member) sizeof(((type *)0)->member)

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

#define MALLOC(ptr, count, type) {                      \
  if ( (ptr = malloc(count * sizeof(type))) == NULL) {  \
    error("Cannot malloc");                             \
  }                                                     \
}

typedef struct pcap_pkthdr pcap_hdr;

typedef struct sockaddr_storage sa_sto;

typedef union address {
  struct sockaddr sa;
  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  struct sockaddr_storage sa_sto;
} address_t;

void print_version(void);
void print_algorithms(void);
void verbose(const char *format, ...);
void copy_n_shift(u_char *ptr, u_char *dst, u_int len);
void *str2dec(const char *in, int maxsize);
int add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi);
void dumpmem(char *prefix, const unsigned char *ptr, int size, int space);
void dump_flows(void);
void usage(void);
void print_mac(const unsigned char *mac_ptr);
void flows_cleanup(void);
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi);
int parse_esp_conf(char *filename);
struct crypt_method_t * find_crypt_method(char *crypt_name);
struct auth_method_t * find_auth_method(char *auth_name);
void handle_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload);
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_ipip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_gre_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_esp_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);

struct llflow_t *flow_head = NULL;
void parse_options(int argc, char **argv);
