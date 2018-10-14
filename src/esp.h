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

#include <stdint.h>
#include <sys/socket.h>    // for struct sockaddr
#include <netinet/in.h>    // for struct sockaddr_in
#include <openssl/evp.h>
#include "utils.h"
#pragma once

/* I used previously OpenSSL EVP_MAX_KEY_LENGTH,
 * but it has changed between OpenSSL 1.0.1 and 1.1.0 versions.
 */
#define MY_MAX_KEY_LENGTH  64

#define CONF_BUFFER_SIZE  1024


int parse_esp_conf(char *filename);
void process_esp_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
int esp_add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi);
void esp_dump_flows(void);
void esp_flows_cleanup(void);
void print_algorithms(void);
struct llflow_t * esp_find_flow(char *ip_src, char *ip_dst, u_int32_t spi);
struct crypt_method_t * esp_find_crypt_method(char *crypt_name);
struct auth_method_t * esp_find_auth_method(char *auth_name);

typedef struct sockaddr_storage sa_sto;

typedef union address {
  struct sockaddr sa;
  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  struct sockaddr_storage sa_sto;
} address_t;

#define ESP_SPI_LEN       8

typedef struct esp_packet_t {
  u_int32_t spi;
  u_int32_t seq;
  u_char iv[EVP_MAX_IV_LENGTH];
  u_int8_t pad_len;
  u_int8_t next_header;
} __attribute__ ((__packed__)) esp_packet_t;

// ESP encryption methods
typedef struct crypt_method_t {
  char *name;             // Name used in ESP configuration file
  char *openssl_cipher;   // OpenSSL internal name
  struct crypt_method_t *next;
} crypt_method_t;

// ESP authentication methods
typedef struct auth_method_t {
  char *name;             // Name used in ESP configuration file
  char *openssl_auth;     // OpenSSL internal name,  not yet used (no verification made)
  int len;                // Digest bytes length
  struct auth_method_t *next;
} auth_method_t;

// Roughly a line of the ESP configuration file, plus internals pointers
typedef struct llflow_t {
  address_t addr_src;
  address_t addr_dst;
  EVP_CIPHER_CTX *ctx;
  unsigned char *key;
  u_int32_t spi;
  char *crypt_name;
  char *auth_name;
  crypt_method_t *crypt_method;
  auth_method_t *auth_method;
  struct llflow_t *next;
} llflow_t;

