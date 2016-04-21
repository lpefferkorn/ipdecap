/*
  Copyright (c) 2012-2016 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
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
  EVP_CIPHER_CTX ctx;
  unsigned char *key;
  u_int32_t spi;
  char *crypt_name;
  char *auth_name;
  crypt_method_t *crypt_method;
  auth_method_t *auth_method;
  struct llflow_t *next;
} llflow_t;

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
