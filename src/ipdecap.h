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

#define MAXIMUM_SNAPLEN   65535
#define GRE_HEADERLEN     4

extern struct auth_method_t *auth_method_list;

void print_version(void);
void copy_n_shift(u_char *ptr, u_char *dst, u_int len);
void usage(void);
void handle_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload);
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
int process_ipip_packet(const u_char *payload, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_gre_packet(const u_char *payload, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);

void parse_options(int argc, char **argv);
