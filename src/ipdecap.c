/*
  Copyright (c) 2012-2013 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>
#include <inttypes.h>

#include "config.h"
#include "ipdecap.h"
#include "gre.h"
#include "esp.h"

// Command line parameters
static const char *args_str = "vi:o:c:f:Vl";

struct global_args_t {
  char *input_file;       // --input option
  char *output_file;      // --output option
  char *esp_config_file;  // --config option
  char *bpf_filter;       // --filter option
  bool verbose;           // --verbose option
  bool list_algo;         // --list option
} global_args;

static const struct option args_long[] = {
  { "input",      required_argument,  NULL, 'i'},
  { "output",     required_argument,  NULL, 'o'},
  { "esp_config", required_argument,  NULL, 'c'},
  { "filter",     required_argument,  NULL, 'f'},
  { "list",       no_argument,        NULL, 'l'},
  { "verbose",    no_argument,        NULL, 'v'},
  { "version",    no_argument,        NULL, 'V'},
  { NULL,         0,                  NULL, 0}

};

// Global variables
pcap_dumper_t *pcap_dumper;
int ignore_esp;

void usage(void) {
  printf("Ipdecap %s, decapsulate ESP, GRE, IPIP packets - Loic Pefferkorn\n", PACKAGE_VERSION);
  printf(
  "Usage\n"
  "    ipdecap [-v] [-l] [-V] -i input.cap -o output.cap [-c esp.conf] [-f <bpf filter>] \n"
  "Options:\n"
  "  -c, --conf     configuration file for ESP parameters (IP addresses, algorithms, ... (see man ipdecap)\n"
  "  -h, --help     this help message\n"
  "  -i, --input    pcap file to process\n"
  "  -o, --output   pcap file with decapsulated data\n"
  "  -f, --filter   only process packets matching the bpf filter\n"
  "  -l, --list     list availables ESP encryption and authentication algorithms\n"
  "  -V, --version  print version\n"
  "  -v, --verbose  verbose\n"
  "\n");
}

void print_version() {
  printf("Ipdecap %s\n", PACKAGE_VERSION);
}

void verbose(const char *format, ...) {

  if (global_args.verbose == true) {
    va_list argp;
    va_start (argp, format);
    vfprintf(stdout, format, argp);
    va_end(argp);
  }
}
/*
 * Parse commande line arguments
 *
 */
void parse_options(int argc, char **argv) {

  int opt = 0;
  int opt_index = 0;

  // Init parameters to default values
  global_args.esp_config_file = NULL;
  global_args.input_file = NULL;
  global_args.output_file = NULL;
  global_args.bpf_filter = NULL;
  global_args.verbose = false;
  global_args.list_algo = false;

  opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  while(opt != -1) {
    switch(opt) {
      case 'i':
        global_args.input_file = optarg;
        break;
      case 'o':
        global_args.output_file = optarg;
        break;
      case 'c':
        global_args.esp_config_file = optarg;
        break;
      case 'f':
        global_args.bpf_filter = optarg;
        break;
      case 'l':
        global_args.list_algo = true;
        break;
      case 'v':
        global_args.verbose = true;
        break;
      case 'V':
        print_version();
        exit(EXIT_SUCCESS);
      case 'h':
      case '?':
        usage();
        exit(EXIT_FAILURE);
        break;
      case 0:
        if (strcmp("verbose", args_long[opt_index].name) == 0) {
          global_args.verbose = true;
        }
        break;

      default:
        break;
    }
    opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  }
}

void print_algorithms() {

  printf("Supported ESP algorithms:\n"
    "\n"
    "\tEncryption:\n"
    "\n"
    "\t\tdes-cbc                            (rfc2405)\n"
    "\t\t3des-cbc                           (rfc2451)\n"
    "\t\taes128-cbc aes192-cbc aes256-cbc   (rfc3602)\n"
    "\t\taes128-ctr                         (rfc3686)\n"
    "\t\tnull_enc                           (rfc2410)\n"
    "\n"
    "\tAuthentication (not yet checked):\n"
    "\n"
    "\t\thmac_md5-96                        (rfc2403)\n"
    "\t\thmac_sha1-96                       (rfc2404)\n"
    "\t\taes_xcbc_mac-96                    (rfc3566)\n"
    "\t\tnull_auth                          (rfc2410)\n"
    "\t\tany96 any128 any160 any192 any256 any384 any512\n"
    "\n"
  );

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

// Cleanup allocated flow during configuration file parsing (makes valgrind happy)
void flows_cleanup() {

  llflow_t *f, *tmp;
  f = flow_head;

  while (f != NULL) {
    tmp = f;
    f = f->next;
    free(tmp->crypt_name);
    free(tmp->auth_name);
    free(tmp->key);

    free(tmp);
  }
}

/*
 * Add to the linked list flow_head this ESP flow, read from configuration file by parse_esp_conf
 *
 */
int add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi) {

  unsigned char *dec_key = NULL;
  unsigned char *dec_spi = NULL;
  llflow_t *flow = NULL;
  llflow_t *ptr = NULL;
  crypt_method_t *cm = NULL;
  auth_method_t *am = NULL;
  char *endptr = NULL;  // for strtol

  MALLOC(flow, 1, llflow_t);

  flow->next = NULL;

  debug_print("\tadd_flow() src:%s dst:%s crypt:%s auth:%s spi:%s\n",
    ip_src, ip_dst, crypt_name, auth_name, spi);

  if ((cm = find_crypt_method(crypt_name)) == NULL)
    err(1, "Cannot find encryption method: %s, please check supported algorithms\n", crypt_name);
  else
    flow->crypt_method = cm;

  if ((am = find_auth_method(auth_name)) == NULL)
    err(1, "Cannot find authentification method: %s, please check supported algorithms\n", auth_name);
  else
    flow->auth_method = am;

  // If non NULL encryption, check key
  if (cm->openssl_cipher != NULL)  {

    // Check for hex format header
    if (key[0] != '0' || (key[1] != 'x' && key[1] != 'X' ) ) {
      error("Only hex keys are supported and must begin with 0x\n");
    }
    else
      key += 2; // shift over 0x

    // Check key length
    if (strlen(key) > EVP_MAX_KEY_LENGTH) {
      error("Key is too long : %lu > %i\n",
        strlen(key),
        EVP_MAX_KEY_LENGTH
        );
    }

    // Convert key to decimal format
    if ((dec_key = str2dec(key, EVP_MAX_KEY_LENGTH)) == NULL)
      err(1, "str2dec() key err\n");

  } else {
    dec_key = NULL;
  }

  if (spi[0] != '0' || (spi[1] != 'x' && spi[1] != 'X' ) ) {
    error("Only hex SPIs are supported and must begin with 0x\n");
  }
  else
    spi += 2; // shift over 0x

  if ((dec_spi = str2dec(spi, ESP_SPI_LEN)) == NULL)
    err(1, "str2dec() spi err\n");

  if (inet_pton(AF_INET, ip_src, &(flow->addr_src)) != 1
    || inet_pton(AF_INET, ip_dst, &(flow->addr_dst)) != 1) {
    error("Cannot convert ip");
  }

  errno = 0;
  flow->spi = strtol(spi, &endptr, 16);

  // Check for conversion errors
  if (errno == ERANGE) {
    error("Cannot convert spi (strtol: %s)", strerror(errno));
  }

  if (endptr == spi) {
      error("Cannot convert spi (strtol: %s)", strerror(errno));
  }

  flow->crypt_name = strdup(crypt_name);
  flow->auth_name = strdup(auth_name);
  flow->key = dec_key;

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  flow->ctx = ctx;

  // Adding to linked list
  if (flow_head == NULL) {
    flow_head = flow;
    flow_head->next = NULL;
  } else {
    ptr = flow_head;
    while(ptr->next != NULL)
      ptr = ptr->next;
    ptr->next = flow;
  }

  free(dec_spi);
  return 0;
}

/*
 * Parse the ipdecap ESP configuration file
 *
 */
int parse_esp_conf(char *filename) {

  const char delimiters[] = " \t";
  char buffer[CONF_BUFFER_SIZE];
  char *copy = NULL;
  char *src = NULL;
  char *dst = NULL;
  char *crypt = NULL;
  char *auth = NULL;
  char *spi = NULL;
  char *key = NULL;
  int line = 0;
  FILE *conf;

  conf = fopen(filename, "r");
  if (conf == NULL )
    return -1;

  while (fgets(buffer, CONF_BUFFER_SIZE, conf) != NULL) {

    line++;
    copy = strdup(buffer);

    // Empty line
    if (strlen(copy) == 1)
     continue;

    // Commented line
    if (copy[0] == '#')
      continue;

    // Remove new line character
    copy[strcspn(copy, "\n")] = '\0';

    if ((src = strtok(copy, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    if ((dst = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    if ((crypt = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    if ((auth = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    if ((key = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    if ((spi = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);

    debug_print("parse_esp_conf() src:%s dst:%s crypt:%s auth:%s key:%s spi:%s\n",
      src, dst, crypt, auth, key, spi);

    add_flow(src, dst, crypt, auth, key, spi);
    free(copy);
  }

  fclose(conf);
  return 0;
}

/*
 * Find the corresponding crypt_method_t from its name
 *
 */
struct crypt_method_t * find_crypt_method(char *crypt_name) {

  int rc;
  struct crypt_method_t *cm = NULL;

  cm = crypt_method_list;

  while(cm != NULL) {
    rc = strcmp(crypt_name, cm->name);
    if (rc == 0) {
      return cm;
    }
    cm = cm->next;
  }
  return NULL;
}

/*
 * Find the corresponding auth_method_t from its name
 *
 */
struct auth_method_t * find_auth_method(char *auth_name) {

  int rc;
  struct auth_method_t *am = NULL;

  am = auth_method_list;

  while(am != NULL) {
    rc = strcmp(auth_name, am->name);
    if (rc == 0) {
      return am;
    }
    am = am->next;
  }
  return NULL;
}

/*
 * Try to find an ESP configuration to decrypt the flow between ip_src and ip_dst
 *
 */
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi) {

  const char *rc;
  struct llflow_t *f = NULL;
  char src_txt[INET_ADDRSTRLEN];
  char dst_txt[INET_ADDRSTRLEN];

  debug_print("find_flow() need:: ip_src:%s ip_dst:%s spi:%02x\n", ip_src, ip_dst, spi);

  f = flow_head;

  while(f != NULL) {

    rc = inet_ntop(AF_INET, &(f->addr_src), src_txt, INET_ADDRSTRLEN);
    if (rc == NULL)
      error("inet_ntop() err");

    inet_ntop(AF_INET, &(f->addr_dst), dst_txt, INET_ADDRSTRLEN);
    if (rc == NULL)
      error("inet_ntop() err");

    if (strcmp(ip_src, src_txt) == 0) {
      if (strcmp(ip_dst, dst_txt) == 0) {
        if (f->spi == ntohl(spi)) {
          debug_print("find_flow() found match:: src:%s dst:%s spi:%x\n", src_txt, dst_txt, ntohl(f->spi));
          return f;
        }
      }
    }
    f = f->next;
  }
  return NULL;
}

/*
 * Print known ESP flows, read from the ESP confguration file
 *
 */
void dump_flows() {

  char src[INET_ADDRSTRLEN];
  char dst[INET_ADDRSTRLEN];
  struct llflow_t *e = NULL;

  e = flow_head;

  while(e != NULL) {
    if (inet_ntop(AF_INET, &(e->addr_src), src, INET_ADDRSTRLEN) == NULL
      || inet_ntop(AF_INET, &(e->addr_dst), dst, INET_ADDRSTRLEN) == NULL) {
      free(e);
      error("Cannot convert ip");
    }

    printf("dump_flows: src:%s dst:%s crypt:%s auth:%s spi:%lx\n",
      src, dst, e->crypt_name, e->auth_name, (long unsigned int) e->spi);

      dumpmem("key", e->key, EVP_CIPHER_CTX_key_length(&e->ctx), 0);
      printf("\n");

    e = e->next;
  }
}

/*
 * Remove IEEE 802.1Q header (virtual lan)
 *
 */
void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload) {

  u_char *payload_dst = NULL;
  u_char *payload_src = NULL;

  // Pointer used to shift through source packet bytes
  payload_src = (u_char *) in_payload;
  payload_dst = out_payload;

  // Copy ethernet src and dst
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);

  // Skip ieee 802.1q bytes
  payload_src += VLAN_TAG_LEN;
  memcpy(payload_dst, payload_src, in_payload_len
                                  - 2*sizeof(struct ether_addr)
                                  - VLAN_TAG_LEN);

  // Should I check for minimum frame size, even if most drivers don't supply FCS (4 bytes) ?
  out_pkthdr->len = in_payload_len - VLAN_TAG_LEN;
  out_pkthdr->caplen = in_payload_len - VLAN_TAG_LEN;
}

/*
 * Simply copy non-IP packet
 *
 */
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  // Copy full packet
  memcpy(new_packet_payload, payload, payload_len);
  new_packet_hdr->len = payload_len;
}

/* Decapsulate an IPIP packet
 *
 */
void process_ipip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct iphdr *ip_hdr = NULL;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);

  // Read encapsulating IP header to find offset to encapsulted IP packet
  ip_hdr = (const struct iphdr *) payload_src;

  debug_print("\tIPIP: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ihl *4), ntohs(ip_hdr->tot_len), ip_hdr->protocol);

  // Shift to encapsulated IP header, read total length
  payload_src += ip_hdr->ihl *4;
  ip_hdr = (const struct iphdr *) payload_src;

  debug_print("\tIPIP: inner IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ihl *4), ntohs(ip_hdr->tot_len), ip_hdr->protocol);

  memcpy(payload_dst, payload_src, ntohs(ip_hdr->tot_len));
  packet_size += ntohs(ip_hdr->tot_len);

  new_packet_hdr->len = packet_size;
}

/* Decapsulate an IPv6 packet
 *
 */
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct iphdr *ip_hdr = NULL;
  uint16_t ethertype;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy src and dst ether addr
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);

  // Set ethernet type to IPv6
  ethertype = htons(ETHERTYPE_IPV6);
  memcpy(payload_dst, &ethertype, member_size(struct ether_header, ether_type));
  payload_src += member_size(struct ether_header, ether_type);
  payload_dst += member_size(struct ether_header, ether_type);

  // Read encapsulating IPv4 header to find header lenght and offset to encapsulated IPv6 packet
  ip_hdr = (const struct iphdr *) payload_src;

  packet_size = payload_len - (ip_hdr->ihl *4);

  debug_print("\tIPv6: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ihl *4), ntohs(ip_hdr->tot_len), ip_hdr->protocol);

  // Shift to encapsulated IPv6 packet, then copy
  payload_src += ip_hdr->ihl *4;

  memcpy(payload_dst, payload_src, packet_size);
  new_packet_hdr->len = packet_size;
}

/*
 * Decapsulate a GRE packet
 *
 */
void process_gre_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  //TODO: check si version == 0 1 non supporté car pptp)
  int packet_size = 0;
  u_int16_t flags;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct iphdr *ip_hdr = NULL;
  const struct grehdr *gre_hdr = NULL;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);

  // Read encapsulating IP header to find offset to GRE header
  ip_hdr = (const struct iphdr *) payload_src;
  payload_src += (ip_hdr->ihl *4);

  debug_print("\tGRE: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
    (ip_hdr->ihl *4), ntohs(ip_hdr->tot_len), ip_hdr->protocol);

  packet_size += ntohs(ip_hdr->tot_len) - ip_hdr->ihl*4;

  // Read GRE header to find offset to encapsulated IP packet
  gre_hdr = (const struct grehdr *) payload_src;
  debug_print("\tGRE - GRE header: flags:%u protocol:%u\n", gre_hdr->flags, gre_hdr->next_protocol);

  packet_size -= sizeof(struct grehdr);
  payload_src += sizeof(struct grehdr);
  flags = ntohs(gre_hdr->flags);

  if (flags & GRE_CHECKSUM || flags & GRE_ROUTING) {
    payload_src += 4; // Both checksum and offset fields are present
    packet_size -= 4;
  }

  if (flags & GRE_KEY) {
    payload_src += 4;
    packet_size -= 4;
  }

  if (flags & GRE_SEQ) {
    payload_src += 4;
    packet_size -= 4;
  }

  memcpy(payload_dst, payload_src, packet_size);
  new_packet_hdr->len = packet_size;

}

/*
 * Decapsulate an ESP packet:
 * -try to find an ESP configuration entry (ip, spi, algorithms)
 * -decrypt packet with the configuration found
 *
 */
void process_esp_packet(u_char const *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct iphdr *ip_hdr = NULL;
  esp_packet_t esp_packet;
  char ip_src[INET_ADDRSTRLEN+1];
  char ip_dst[INET_ADDRSTRLEN+1];
  llflow_t *flow = NULL;
  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher = NULL;
  int packet_size, rc, len, remaining;
  int ivlen;

  // TODO: memset sur new_packet_payload
  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);

  // Read encapsulating IP header to find offset to ESP header
  ip_hdr = (const struct iphdr *) payload_src;
  payload_src += (ip_hdr->ihl *4);

  // Read ESP fields
  memcpy(&esp_packet.spi, payload_src, member_size(esp_packet_t, spi));
  payload_src += member_size(esp_packet_t, spi);
  memcpy(&esp_packet.seq, payload_src, member_size(esp_packet_t, seq));
  payload_src += member_size(esp_packet_t, seq);

  // Extract dst/src IP
  inet_ntop(AF_INET, &(ip_hdr->saddr), ip_src, INET_ADDRSTRLEN);
  if (ip_src == NULL)
    error("Cannot convert source ip address for ESP packet\n");

  inet_ntop(AF_INET, &(ip_hdr->daddr), ip_dst, INET_ADDRSTRLEN);
  if (ip_dst == NULL)
    error("Cannot convert destination ip address for ESP packet\n");

  // Find encryption configuration used
  flow = find_flow(ip_src, ip_dst, esp_packet.spi);

  if (flow == NULL) {
    verbose("No suitable flow configuration found for src:%s dst:%s spi: %lx copying raw packet\n",
      ip_src, ip_dst, esp_packet.spi);
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
      return;

  } else {
    debug_print("Found flow configuration src:%s dst:%s crypt:%s auth:%s spi: %lx\n",
      ip_src, ip_dst, flow->crypt_name, flow->auth_name, (long unsigned) flow->spi);
  }

  // Differences between (null) encryption algorithms and others algorithms start here
  if (flow->crypt_method->openssl_cipher == NULL) {

    remaining = ntohs(ip_hdr->tot_len)
    - ip_hdr->ihl*4
    - member_size(esp_packet_t, spi)
    - member_size(esp_packet_t, seq);

    // If non null authentication, discard authentication data
    if (flow->auth_method->openssl_auth == NULL) {
      remaining -= flow->auth_method->len;
    }

    u_char *pad_len = ((u_char *)payload_src + remaining -2);

    remaining = remaining
      - member_size(esp_packet_t, pad_len)
      - member_size(esp_packet_t, next_header)
      - *pad_len;

    packet_size += remaining;

    memcpy(payload_dst, payload_src, remaining);
    new_packet_hdr->len = packet_size;

  } else {

    if ((cipher = EVP_get_cipherbyname(flow->crypt_method->openssl_cipher)) == NULL)
      error("EVP_get_cipherbyname() err");

    EVP_CIPHER_CTX_init(&ctx);

    // Copy initialization vector
    ivlen = EVP_CIPHER_iv_length(cipher);
    memset(&esp_packet.iv, 0, EVP_MAX_IV_LENGTH);
    memcpy(&esp_packet.iv, payload_src, ivlen);
    payload_src += ivlen;

    rc = EVP_DecryptInit_ex(&ctx, cipher,NULL, flow->key, esp_packet.iv);
    if (rc != 1) {
      error("Error during the initialization of crypto system. Please report this bug with your .pcap file");
    }

    // ESP payload length to decrypt
    remaining =  ntohs(ip_hdr->tot_len)
    - ip_hdr->ihl*4
    - member_size(esp_packet_t, spi)
    - member_size(esp_packet_t, seq)
    - ivlen;

    // If non null authentication, discard authentication data
    if (flow->auth_method->openssl_auth == NULL) {
      remaining -= flow->auth_method->len;
    }

    // Do the decryption work
    rc = EVP_DecryptUpdate(&ctx, payload_dst, &len, payload_src, remaining);
    packet_size += len;

    if (rc != 1) {
      verbose("Warning: cannot decrypt packet with EVP_DecryptUpdate(). Corrupted ? Cipher is %s, copying raw packet...\n",
        flow->crypt_method->openssl_cipher);
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
        return;
    }

    EVP_DecryptFinal_ex(&ctx, payload_dst+len, &len);
    packet_size += len;

    // http://www.mail-archive.com/openssl-users@openssl.org/msg23434.html
    packet_size +=EVP_CIPHER_CTX_block_size(&ctx);

    u_char *pad_len = (new_packet_payload + packet_size -2);

    // Detect obviously badly decrypted packet
    if (*pad_len >=  EVP_CIPHER_CTX_block_size(&ctx)) {
      verbose("Warning: invalid pad_len field, wrong encryption key ? copying raw packet...\n");
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
      return;
    }

    // Remove next protocol, pad len fields and padding
    packet_size = packet_size
      - member_size(esp_packet_t, pad_len)
      - member_size(esp_packet_t, next_header)
      - *pad_len;

    new_packet_hdr->len = packet_size;

    EVP_CIPHER_CTX_cleanup(&ctx);

    } /*  flow->crypt_method->openssl_cipher == NULL */

}


/*
 * For each packet, identify its encapsulation protocol and give it to the corresponding process_xx_packet function
 *
 */
void handle_packets(u_char *bpf_filter, const struct pcap_pkthdr *pkthdr, const u_char *bytes) {

  static int packet_num = 0;
  const struct ether_header *eth_hdr = NULL;
  const struct iphdr *ip_hdr = NULL;
  struct bpf_program *bpf = NULL;
  struct pcap_pkthdr *in_pkthdr = NULL;
  struct pcap_pkthdr *out_pkthdr = NULL;
  u_char *in_payload = NULL;
  u_char *out_payload = NULL;

  verbose("Processing packet %i\n", packet_num);

  // Check if packet match bpf filter, if given
  if (bpf_filter != NULL) {
    bpf = (struct bpf_program *) bpf_filter;
    if (pcap_offline_filter(bpf, pkthdr, bytes)  == 0) {
      verbose("Packet %i does not match bpf filter\n", packet_num);
      goto exit;
    }
  }

  MALLOC(out_pkthdr, 1, struct pcap_pkthdr);
  MALLOC(out_payload, 65535, u_char);
  memset(out_pkthdr, 0, sizeof(struct pcap_pkthdr));
  memset(out_payload, 0, 65535);

  // Pointer used to shift through source packet bytes
  // updated when vlan header is removed
  // TODO: don't modify source packet

  in_pkthdr = (struct pcap_pkthdr *) pkthdr;
  in_payload = (u_char *) bytes;

  // Copy source pcap metadata
  out_pkthdr->ts.tv_sec = in_pkthdr->ts.tv_sec;
  out_pkthdr->ts.tv_usec = in_pkthdr->ts.tv_usec;
  out_pkthdr->caplen = in_pkthdr->caplen;

  eth_hdr = (const struct ether_header *) in_payload;

  // If IEEE 802.1Q header, remove it before further processing
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
      debug_print("%s\n", "\tIEEE 801.1Q header\n");
      remove_ieee8021q_header(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);

      // Update source packet with the new one without 802.1q header
      memcpy(in_payload, out_payload, out_pkthdr->caplen);
      in_pkthdr->caplen = out_pkthdr->caplen;
      in_pkthdr->len = out_pkthdr->len;

      // Re-read new ethernet type
      eth_hdr = (const struct ether_header *) in_payload;
  }
  // ethertype = *(pkt_in_ptr + 12) << 8 | *(pkt_in_ptr+13);

  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {

    // Non IP packet ? Just copy
    process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);

  } else {

    // Find encapsulation type
    ip_hdr = (const struct iphdr *) (in_payload + sizeof(struct ether_header));

    //debug_print("\tIP hlen:%i iplen:%02x protocol:%02x payload_len:%i\n",
      //(ip_hdr->ihl *4), ntohs(ip_hdr->tot_len), ip_hdr->protocol, payload_len);

    switch (ip_hdr->protocol) {

      case IPPROTO_IPIP:
        debug_print("%s\n", "\tIPPROTO_IPIP");
        process_ipip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_IPV6:
        debug_print("%s\n", "\tIPPROTO_IPV6");
        process_ipv6_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_GRE:
        debug_print("%s\n", "\tIPPROTO_GRE\n");
        process_gre_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_ESP:
        debug_print("%s\n", "\tIPPROTO_ESP\n");

        if (ignore_esp == 1) {
          verbose("Ignoring ESP packet %i\n", packet_num);
          free(out_pkthdr);
          free(out_payload);
          return;
        }

        process_esp_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      default:
        // Copy not encapsulated/unknown encpsulation protocol packets, like non_ip packets
        process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        verbose("Copying packet %i: not encapsulated/unknown encapsulation protocol\n", packet_num);

    }
  } // if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)

  free(out_pkthdr);
  free(out_payload);

  exit: // Avoid several 'return' in middle of code
    packet_num++;
}


int main(int argc, char **argv) {

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_reader = NULL;
  pcap_dumper = NULL;
  pcap_t *p = NULL;
  struct bpf_program *bpf = NULL;
  ignore_esp = 0;
  int rc;

  parse_options(argc, argv);

  if (global_args.list_algo == true) {
    print_algorithms();
    exit(0);
  }

  verbose("Input file :\t%s\nOutput file:\t%s\nConfig file:\t%s\nBpf filter:\t%s\n",
    global_args.input_file,
    global_args.output_file,
    global_args.esp_config_file,
    global_args.bpf_filter);

  if (global_args.input_file == NULL || global_args.output_file == NULL) {
    usage();
    error("Input and outfile file parameters are mandatory\n");
  }

  pcap_reader = pcap_open_offline(global_args.input_file, errbuf);

  if (pcap_reader == NULL)
    error("Cannot open input file %s: %s", global_args.input_file, errbuf);

  debug_print("snaplen:%i\n", pcap_snapshot(pcap_reader));

  p = pcap_open_dead(DLT_EN10MB, MAXIMUM_SNAPLEN);

  // try to compile bpf filter for input packets
  if (global_args.bpf_filter != NULL) {
    MALLOC(bpf, 1, struct bpf_program);
    verbose("Using bpf filter:%s\n", global_args.bpf_filter);
    if (pcap_compile(p, bpf, global_args.bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
      error("pcap_compile() %s\n", pcap_geterr(p));
    }
  }
  pcap_dumper = pcap_dump_open(p, global_args.output_file);

  if (pcap_dumper == NULL)
    error("Cannot open output file %s : %s\n", global_args.output_file, errbuf);

  // Try to read ESP configuration file
  if (global_args.esp_config_file != NULL) {
    rc = parse_esp_conf(global_args.esp_config_file);
    switch(rc) {
      case -1:
        warnx("ESP config file: cannot open %s - ignoring ESP packets\n",
          global_args.esp_config_file);
        ignore_esp = 1;
        break;
      case -2:
        warnx("ESP config file: %s is not parsable (missing column ?) - ignoring ESP packets\n",
          global_args.esp_config_file);
        ignore_esp = 1;
        break;
      case 0: // Processing of ESP configuraton file is OK
        break;
    }
  }

  #ifdef DEBUG
    dump_flows();
  #endif

  OpenSSL_add_all_algorithms();

  // Dispatch to handle_packet function each packet read from the pcap file
  pcap_dispatch(pcap_reader, 0, handle_packets, (u_char *) bpf);

  pcap_close(pcap_reader);
  pcap_close(p);
  pcap_dump_close(pcap_dumper);

  EVP_cleanup();

  flows_cleanup();

  return 0;
}
