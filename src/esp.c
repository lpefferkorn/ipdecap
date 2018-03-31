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

#include <arpa/inet.h>     // for inet_ntop, inet_pton
#include <err.h>           // for err
#include <errno.h>         // for __errno_location, errno, ERANGE
#include <net/ethernet.h>  // for ether_header
#include <netinet/ip.h>    // for ip
#include <stdio.h>         // for printf, fclose, fgets, fopen, FILE
#include <stdlib.h>        // for NULL, free, strtol
#include <string.h>        // for strtok, memcpy, strcmp, strdup, strlen
#include <pcap/vlan.h>
#include <pcap/pcap.h>
#include "utils.h"         // for error, member_size, global_args_t, verbose
#include "esp.h"
#include "ipdecap.h"       // for process_nonip_packet

extern global_args_t global_args;

struct llflow_t *flow_head = NULL;
/* rfc 4835:
        Requirement    Encryption Algorithm (notes)
        -----------    --------------------------
        MUST           NULL [RFC2410] (1)
        MUST           AES-CBC with 128-bit keys [RFC3602]
        MUST-          TripleDES-CBC [RFC2451]
        SHOULD         AES-CTR [RFC3686]
        SHOULD NOT     DES-CBC [RFC2405] (2)


        Requirement    Authentication Algorithm (notes)
        -----------    -----------------------------
        MUST           HMAC-SHA1-96 [RFC2404] (3)
        SHOULD+        AES-XCBC-MAC-96 [RFC3566]
        MAY            NULL (1)
        MAY            HMAC-MD5-96 [RFC2403] (4)
*/

/* Authentication algorithms */

auth_method_t any512            = { .name = "any512",          .openssl_auth = NULL, .len = 512/8, .next = NULL };
auth_method_t any384            = { .name = "any384",          .openssl_auth = NULL, .len = 384/8, .next = &any512 };
auth_method_t any256            = { .name = "any256",          .openssl_auth = NULL, .len = 256/8, .next = &any384 };
auth_method_t any192            = { .name = "any192",          .openssl_auth = NULL, .len = 192/8, .next = &any256 };
auth_method_t any160            = { .name = "any160",          .openssl_auth = NULL, .len = 160/8, .next = &any192 };
auth_method_t any128            = { .name = "any128",          .openssl_auth = NULL, .len =  96/8, .next = &any160 };
auth_method_t any96             = { .name = "any96",           .openssl_auth = NULL, .len =  96/8, .next = &any128 };
auth_method_t aes_xcbc_mac_96   = { .name = "aes_xcbc_mac-96", .openssl_auth = NULL, .len =  96/8, .next = &any96 };
auth_method_t hmac_md5_96       = { .name = "hmac_md5-96",     .openssl_auth = NULL, .len =  96/8, .next = &aes_xcbc_mac_96 };
auth_method_t hmac_sha_1_96     = { .name = "hmac_sha1-96",    .openssl_auth = NULL, .len =  96/8, .next = &hmac_md5_96 };
auth_method_t null_auth         = { .name = "null_auth",       .openssl_auth = NULL, .len =   8/8, .next = &hmac_sha_1_96 };

// Linked list, point to first element
auth_method_t *auth_method_list = &null_auth;

/* Encryption algorithms */

crypt_method_t null_enc       = { .name = "null_enc",   .openssl_cipher = NULL,           .next = NULL};
crypt_method_t aes_256_cbc    = { .name = "aes256-cbc", .openssl_cipher = "aes-256-cbc",  .next = &null_enc};
crypt_method_t aes_192_cbc    = { .name = "aes192-cbc", .openssl_cipher = "aes-192-cbc",  .next = &aes_256_cbc};
crypt_method_t aes_128_cbc    = { .name = "aes128-cbc", .openssl_cipher = "aes-128-cbc",  .next = &aes_192_cbc};
crypt_method_t aes_128_ctr    = { .name = "aes128-ctr", .openssl_cipher = "aes-128-ctr",  .next = &aes_128_cbc};
crypt_method_t tripledes_cbc  = { .name = "3des-cbc",   .openssl_cipher = "des-ede3-cbc", .next = &aes_128_ctr};
crypt_method_t des_cbc        = { .name = "des-cbc",    .openssl_cipher = "des-cbc",      .next = &tripledes_cbc};


// Linked list, point to first element
crypt_method_t *crypt_method_list = &des_cbc;

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
    err(1, "%s: Cannot find encryption method: %s, please check supported algorithms\n",
        global_args.esp_config_file, crypt_name);
  else
    flow->crypt_method = cm;

  if ((am = find_auth_method(auth_name)) == NULL)
    err(1, "%s: Cannot find authentification method: %s, please check supported algorithms\n",
        global_args.esp_config_file, auth_name);
  else
    flow->auth_method = am;

  // If non NULL encryption, check key
  if (cm->openssl_cipher != NULL)  {

    // Check for hex format header
    if (key[0] != '0' || (key[1] != 'x' && key[1] != 'X' ) ) {
      error("%s: Only hex keys are supported and must begin with 0x\n", global_args.esp_config_file);
    }
    else
      key += 2; // shift over 0x

    // Check key length
    if (strlen(key) > MY_MAX_KEY_LENGTH) {
      error("%s: Key is too long : %lu > %i -  %s\n",
        global_args.esp_config_file,
        strlen(key),
        MY_MAX_KEY_LENGTH,
        key
        );
    }

    // Convert key to decimal format
    if ((dec_key = str2dec(key, MY_MAX_KEY_LENGTH)) == NULL)
      err(1, "Cannot convert key to decimal format: %s\n", key);

  } else {
    dec_key = NULL;
  }

  if (spi[0] != '0' || (spi[1] != 'x' && spi[1] != 'X' ) ) {
    error("%s: Only hex SPIs are supported and must begin with 0x\n", global_args.esp_config_file);
  }
  else
    spi += 2; // shift over 0x

  if ((dec_spi = str2dec(spi, ESP_SPI_LEN)) == NULL)
    err(1, "%s: Cannot convert spi to decimal format\n", global_args.esp_config_file);

  if (inet_pton(AF_INET, ip_src, &(flow->addr_src)) != 1
    || inet_pton(AF_INET, ip_dst, &(flow->addr_dst)) != 1) {
    error("%s: Cannot convert ip address\n", global_args.esp_config_file);
  }

  errno = 0;
  flow->spi = strtol(spi, &endptr, 16);

  // Check for conversion errors
  if (errno == ERANGE) {
    error("%s: Cannot convert spi (strtol: %s)\n",
        global_args.esp_config_file,
        strerror(errno));
  }

  if (endptr == spi) {
      error("%s: Cannot convert spi (strtol: %s)\n",
          global_args.esp_config_file,
          strerror(errno));
  }

  flow->crypt_name = strdup(crypt_name);
  flow->auth_name = strdup(auth_name);
  flow->key = dec_key;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
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
 * Try to find an ESP configuration to decrypt the flow between ip_src and ip_dst
 *
 */
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi) {

  struct llflow_t *f = NULL;
  char src_txt[INET_ADDRSTRLEN];
  char dst_txt[INET_ADDRSTRLEN];

  debug_print("find_flow() need:: ip_src:%s ip_dst:%s spi:%02x\n", ip_src, ip_dst, spi);

  f = flow_head;

  while(f != NULL) {

    if (inet_ntop(AF_INET, &(f->addr_src),
                  src_txt, INET_ADDRSTRLEN) == NULL)
      error("Cannot convert source IP adddress - inet_ntop() err");

    if (inet_ntop(AF_INET, &(f->addr_dst),
                  dst_txt, INET_ADDRSTRLEN) == NULL)
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

      dumpmem("key", e->key, EVP_CIPHER_CTX_key_length(e->ctx), 0);
      printf("\n");

    e = e->next;
  }
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
 * Decapsulate an ESP packet:
 * -try to find an ESP configuration entry (ip, spi, algorithms)
 * -decrypt packet with the configuration found
 *
 */
void process_esp_packet(u_char const *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  esp_packet_t esp_packet;
  char ip_src[INET_ADDRSTRLEN+1];
  char ip_dst[INET_ADDRSTRLEN+1];
  llflow_t *flow = NULL;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
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
  ip_hdr = (const struct ip *) payload_src;
  payload_src += (ip_hdr->ip_hl *4);

  // Read ESP fields
  memcpy(&esp_packet.spi, payload_src, member_size(esp_packet_t, spi));
  payload_src += member_size(esp_packet_t, spi);
  memcpy(&esp_packet.seq, payload_src, member_size(esp_packet_t, seq));
  payload_src += member_size(esp_packet_t, seq);

  // Extract dst/src IP
  if (inet_ntop(AF_INET, &(ip_hdr->ip_src),
                ip_src, INET_ADDRSTRLEN) == NULL)
    error("Cannot convert source ip address for ESP packet\n");

  if (inet_ntop(AF_INET, &(ip_hdr->ip_dst),
                ip_dst, INET_ADDRSTRLEN) == NULL)
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

    remaining = ntohs(ip_hdr->ip_len)
    - ip_hdr->ip_hl*4
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
      error("Cannot find cipher %s - EVP_get_cipherbyname() err", flow->crypt_method->openssl_cipher);

    EVP_CIPHER_CTX_init(ctx);

    // Copy initialization vector
    ivlen = EVP_CIPHER_iv_length(cipher);
    memset(&esp_packet.iv, 0, EVP_MAX_IV_LENGTH);
    memcpy(&esp_packet.iv, payload_src, ivlen);
    payload_src += ivlen;

    rc = EVP_DecryptInit_ex(ctx, cipher,NULL, flow->key, esp_packet.iv);
    if (rc != 1) {
      error("Error during the initialization of crypto system. Please report this bug with your .pcap file");
    }

    // ESP payload length to decrypt
    remaining =  ntohs(ip_hdr->ip_len)
    - ip_hdr->ip_hl*4
    - member_size(esp_packet_t, spi)
    - member_size(esp_packet_t, seq)
    - ivlen;

    // If non null authentication, discard authentication data
    if (flow->auth_method->openssl_auth == NULL) {
      remaining -= flow->auth_method->len;
    }

    // Do the decryption work
    rc = EVP_DecryptUpdate(ctx, payload_dst, &len, payload_src, remaining);
    packet_size += len;

    if (rc != 1) {
      verbose("Warning: cannot decrypt packet with EVP_DecryptUpdate(). Corrupted ? Cipher is %s, copying raw packet...\n",
        flow->crypt_method->openssl_cipher);
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
        return;
    }

    EVP_DecryptFinal_ex(ctx, payload_dst+len, &len);
    packet_size += len;

    // http://www.mail-archive.com/openssl-users@openssl.org/msg23434.html
    packet_size +=EVP_CIPHER_CTX_block_size(ctx);

    u_char *pad_len = (new_packet_payload + packet_size -2);

    // Detect obviously badly decrypted packet
    if (*pad_len >=  EVP_CIPHER_CTX_block_size(ctx)) {
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

    EVP_CIPHER_CTX_cleanup(ctx);

    } /*  flow->crypt_method->openssl_cipher == NULL */

}
