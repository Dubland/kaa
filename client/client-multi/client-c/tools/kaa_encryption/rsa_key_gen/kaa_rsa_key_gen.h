/*
 *  Copyright 2014-2016 CyberVision, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

/* Filename where public/private keys are stored */
#define KAA_KEYS_STORAGE "kaa_keys_gen.h"

/* RSA Endpoint definitions */
#define KAA_RSA_KEY_LENGTH 2048
#define KAA_RSA_EXPONENT   65537

#define KAA_RSA_PUBLIC_KEY_LENGTH_MAX  294
#define KAA_RSA_PRIVATE_KEY_LENGTH_MAX 1200

#define SHA1_LENGTH 20

/* File structure */
#define GUARD_IFNDEF                    "#ifndef KAA_RSA_KEYS_H_\n"
#define GUARD_DEF                       "#define KAA_RSA_KEYS_H_\n\n\n"
#define PUBLIC_KEY_LEN                  "#define KAA_RSA_PUBLIC_KEY_LENGTH  %zu\n"
#define PRIVATE_KEY_LEN                 "#define KAA_RSA_PRIVATE_KEY_LENGTH %zu\n\n\n"
#define KAA_SHA1_PUB_LEN                "#define KAA_SHA1_PUB_LEN %zu\n"
#define KAA_SHA1_PUB_BASE64_LEN         "#define KAA_SHA1_PUB_BASE64_LEN %zu\n\n\n"
#define KEY_STARTS                      "{ "
#define KEY_SEPARATOR                   ", "
#define KEY_ENDS                        " };\n\n"
#define KAA_RSA_PUBLIC_KEY              "uint8_t KAA_RSA_PUBLIC_KEY[] = "
#define KAA_RSA_PRIVATE_KEY             "uint8_t KAA_RSA_PRIVATE_KEY[] = "
#define KAA_SHA1_PUB                    "uint8_t KAA_SHA1_PUB[] = "
#define KAA_SHA1_PUB_BASE64             "uint8_t KAA_SHA1_PUB_BASE64[] = "
#define GUARD_ENDIF                     "#endif /* KAA_RSA_KEYS_H */\n"

/*
 * Structure which contains Endpoint keys.
 *
 * public_key is a pointer to RSA public key.
 * private_key is a pointer to RSA private key.
 *
 * note: the main purpose of the structure is
 * caching calculated keys.
 */
typedef struct {
    uint8_t public_key[KAA_RSA_PUBLIC_KEY_LENGTH_MAX];
    uint8_t private_key[KAA_RSA_PRIVATE_KEY_LENGTH_MAX];
    size_t  public_key_length;
    size_t  private_key_length;
} endpoint_keys_t;

int rsa_genkey(mbedtls_pk_context *pk);

/* Use this function to extract RSA keys from mbedtls_pk_context.
 * private_key_length and public_key_length should poing to the
 * value which is the size of the private and public keys respectively.
 * They will be initialized with actual length of the keys.
 */
int kaa_write_keys(mbedtls_pk_context *pk, uint8_t *public_key,
                          size_t *public_key_length, uint8_t *private_key,
                          size_t *private_key_length);

int rsa_keys_create(mbedtls_pk_context *pk, uint8_t *public_key,
                           size_t *public_key_length, uint8_t *private_key,
                           size_t *private_key_length);

int rsa_genkey(mbedtls_pk_context *pk);

void store_key(FILE *fd, const char *prefix, size_t prefix_size,
                      uint8_t *key, size_t length);

int sha1_store(FILE *fd, uint8_t *sha1, size_t sha1_len, uint8_t *sha1_base64, size_t sha1_base64_len);

int sha1_from_public_key(uint8_t *key, size_t length, uint8_t *sha1);

int sha1_to_base64(uint8_t *key, size_t length, uint8_t *base64, size_t base64_len, size_t *output_len);

int kaa_keys_store(uint8_t *public_key, size_t public_key_length,
                          uint8_t *private_key, size_t private_key_length);
