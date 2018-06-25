/*

 The MIT License (MIT)

 Copyright (c) 2018 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include "cipherseed.h"

#include "chacha.h"
#include "poly1305.h"
#include "sha2.h"

#ifndef HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const void *b1, const void *b2, size_t n) {
    const unsigned char *p1 = b1, *p2 = b2;
    int ret = 0;

    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}

#endif /* TIMINGSAFE_BCMP */

#ifndef HAVE_MEMSET_S
void memory_cleanse(void *p, size_t n) {
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset(p, 0, n);
#endif
#endif
}

#else /* no memset_s available */
void memory_cleanse(void *p, size_t n) { (void)memset_s(p, n, 0, n); }
#endif

void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen,
                        const uint8_t salt_in[PBKDF2_SALTLEN], uint8_t *key,
                        int keylen) {
    uint32_t i, j, k;
    uint8_t f[PBKDF2_HMACLEN], g[PBKDF2_HMACLEN];
    uint32_t blocks = keylen / PBKDF2_HMACLEN;

    uint8_t salt[PBKDF2_SALTLEN + 4 + sizeof(PBKDF2_SALTPREFIX)];
    memset(salt, 0, sizeof(salt));
    memcpy(salt, PBKDF2_SALTPREFIX, sizeof(PBKDF2_SALTPREFIX));
    memcpy(salt+sizeof(PBKDF2_SALTPREFIX), salt_in, PBKDF2_SALTLEN);

    if (keylen & (PBKDF2_HMACLEN - 1)) {
        blocks++;
    }
    for (i = 1; i <= blocks; i++) {
        salt[PBKDF2_SALTLEN] = (i >> 24) & 0xFF;
        salt[PBKDF2_SALTLEN + 1] = (i >> 16) & 0xFF;
        salt[PBKDF2_SALTLEN + 2] = (i >> 8) & 0xFF;
        salt[PBKDF2_SALTLEN + 3] = i & 0xFF;
        hmac_sha512(pass, passlen, salt, PBKDF2_SALTLEN + 4, g);
        memcpy(f, g, PBKDF2_HMACLEN);
        for (j = 1; j < PBKDF2_ROUNDS; j++) {
            hmac_sha512(pass, passlen, g, PBKDF2_HMACLEN, g);
            for (k = 0; k < PBKDF2_HMACLEN; k++) {
                f[k] ^= g[k];
            }
        }
        if (i == blocks && (keylen & (PBKDF2_HMACLEN - 1))) {
            memcpy(key + PBKDF2_HMACLEN * (i - 1), f,
                   keylen & (PBKDF2_HMACLEN - 1));
        } else {
            memcpy(key + PBKDF2_HMACLEN * (i - 1), f, PBKDF2_HMACLEN);
        }
    }
    memset(f, 0, sizeof(f));
    memset(g, 0, sizeof(g));
}

static const uint8_t version_byte = 0x00;
static const uint8_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0}; /* NB little-endian */
static const uint64_t nonce_polykey = 0;
static const uint64_t nonce_seedcipher = 1;
static const unsigned int saltlen = 5;
static const unsigned int tag_truncation_length = 4; // 32bit tag
static const unsigned int enc_header_length = 3; // 1 usage type + 2 byte bday

int encrypt_seed(const uint8_t key256[32], const uint8_t key256_sec[32],
                 const uint8_t *seed, unsigned int seedlen,
                 const uint8_t *salt_5bytes, const uint16_t bday,
                 const uint8_t type, uint8_t *dest_out, int is_encrypt) {
    struct chacha_ctx ctx_prim, ctx_sec;
    int r = -1;

    uint8_t expected_tag[POLY1305_TAGLEN] = {};
    uint8_t prim_tag_container[POLY1305_TAGLEN] = {};
    uint8_t poly_key_prim[POLY1305_KEYLEN] = {0},
            poly_key_sec[POLY1305_KEYLEN] = {0};

    memset(poly_key_prim, 0, POLY1305_TAGLEN);
    memset(poly_key_sec, 0, POLY1305_TAGLEN);

    /* setup the primary key */
    chacha_ivsetup(&ctx_prim, (uint8_t *)&nonce_polykey, NULL);
    chacha_keysetup(&ctx_prim, key256, 256);

    /* run once to generate primary poly1305 key */
    chacha_encrypt_bytes(&ctx_prim, poly_key_prim, poly_key_prim,
                         POLY1305_KEYLEN);

    /* setup the secondary key if we encrypt */
    chacha_ivsetup(&ctx_sec, (uint8_t *)&nonce_polykey, NULL);
    chacha_keysetup(&ctx_sec, key256_sec, 256);

    /* run once to generate secondary poly1305 key */
    chacha_encrypt_bytes(&ctx_sec, poly_key_sec, poly_key_sec, POLY1305_KEYLEN);

    /* set nonce / IV for seed ciphering */
    chacha_ivsetup(&ctx_prim, (uint8_t *)&nonce_seedcipher, one);

    /* set the plaintext version-byte & salt */
    memcpy(dest_out, &version_byte, 1);
    memcpy(dest_out+1, salt_5bytes, saltlen);

    /* encrypt the usage type (1 byte)*/
    chacha_encrypt_bytes(&ctx_prim, (uint8_t *)&type,
                         (uint8_t *)dest_out + 1 + saltlen, 1);

    /* encrypt the birthday (2 bytes) */
    chacha_encrypt_bytes(&ctx_prim, (uint8_t *)&bday,
                         (uint8_t *)dest_out + 1 + saltlen + 1, 2);

    /* encrypt the seed */
    chacha_encrypt_bytes(&ctx_prim, seed, (uint8_t *)dest_out + 1 + saltlen + enc_header_length,
                         seedlen);

    /* poly1305 auth of encrypted seed + salt */
    poly1305_auth(prim_tag_container, dest_out,
                  1 + saltlen + enc_header_length + seedlen, poly_key_prim);
    /* append 1st truncated tag (32bit) to the dest buffer */
    memcpy(dest_out + 1 + saltlen + enc_header_length + seedlen, prim_tag_container,
           tag_truncation_length);
    memory_cleanse(prim_tag_container, sizeof(poly_key_sec));

    /* perform and append the second poly1305 auth tag */
    poly1305_auth(prim_tag_container, dest_out,
                  1 + saltlen + enc_header_length + seedlen, poly_key_sec);

    /* append 2nd truncated tag (32bit) to the dest buffer */
    memcpy(dest_out + 1 + saltlen + enc_header_length + seedlen +
               tag_truncation_length,
           prim_tag_container, tag_truncation_length);

    r = 0;
out:
    memory_cleanse(expected_tag, sizeof(expected_tag));
    memory_cleanse(poly_key_prim, sizeof(poly_key_prim));
    memory_cleanse(poly_key_sec, sizeof(poly_key_sec));
    memory_cleanse(prim_tag_container, sizeof(poly_key_sec));
    return r;
}

int decrypt_seed(const uint8_t key256[32], const uint8_t *payload,
                 unsigned int payload_len, uint16_t *bday_out,
                 uint8_t *usage_type_out, uint8_t *seed_out) {
    struct chacha_ctx ctx_prim;
    int r = -1;
    uint8_t poly_key_prim[POLY1305_KEYLEN] = {0};
    memset(poly_key_prim, 0, POLY1305_TAGLEN);

    if (payload_len < 1 || payload == NULL || payload[0] != version_byte) {
        /* invalid payload or version */
        return r;
    }
    const unsigned int seedlen =
        payload_len - saltlen - enc_header_length - 2 * tag_truncation_length;
    uint8_t expected_tag[POLY1305_TAGLEN] = {};

    /* setup the primary key */
    chacha_ivsetup(&ctx_prim, (uint8_t *)&nonce_polykey, NULL);
    chacha_keysetup(&ctx_prim, key256, 256);

    /* run once to generate primary poly1305 key */
    chacha_encrypt_bytes(&ctx_prim, poly_key_prim, poly_key_prim,
                         POLY1305_KEYLEN);

    const uint8_t *tag_prim = payload + 1 + saltlen + enc_header_length + seedlen;
    const uint8_t *tag_sec =
        payload + 1 + saltlen + tag_truncation_length + seedlen;
    poly1305_auth(expected_tag, payload, 1 + saltlen + enc_header_length + seedlen,
                  poly_key_prim);
    if (timingsafe_bcmp(expected_tag, tag_prim, tag_truncation_length) != 0 &&
        timingsafe_bcmp(expected_tag, tag_sec, tag_truncation_length) != 0) {
        r = -1;
        goto out;
    }

    /* set nonce / IV for seed decryption */
    chacha_ivsetup(&ctx_prim, (uint8_t *)&nonce_seedcipher, one);

    /* decrypt the version byte */
    chacha_encrypt_bytes(&ctx_prim, payload + 1 + saltlen, (uint8_t *)usage_type_out,
                         1);

    /* decrypt the birthday */
    chacha_encrypt_bytes(&ctx_prim, payload + 1 + saltlen + 1, (uint8_t *)bday_out,
                         2);

    /* decrypt the seed */
    chacha_encrypt_bytes(&ctx_prim, payload + 1 + saltlen + enc_header_length, seed_out,
                         seedlen);
    r = 0;
out:
    memory_cleanse(expected_tag, sizeof(expected_tag));
    memory_cleanse(poly_key_prim, sizeof(poly_key_prim));
    return r;
}
