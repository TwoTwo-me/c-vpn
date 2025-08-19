#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>

/* Real crypto interface using libsodium primitives & custom BLAKE2s/HMAC to mimic python-vpn logic.
 * NOTE: This still mirrors the insecure aspects intentionally. */

#define WG_KEY_LEN 32
#define WG_TAG_LEN 16

struct crypto_keys {
    uint8_t private_key[WG_KEY_LEN];
    uint8_t public_key[WG_KEY_LEN];
};

/* Derive private key = BLAKE2s(password) (32 bytes) then clamp like X25519 scalar. */
int derive_private_key(struct crypto_keys *ck, const char *password, size_t pass_len);
/* X25519 shared (libsodium wrapper) */
int x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[32]);

/* BLAKE2s (unkeyed) 32 bytes */
int blake2s_hash(const uint8_t *in, size_t inlen, uint8_t out[32]);
/* HMAC(BLAKE2s) -> 32 bytes */
int hmac_blake2s(const uint8_t *key, size_t keylen, const uint8_t *in, size_t inlen, uint8_t out[32]);
/* Short MAC like python (blake2s(key=K, data) truncated 16) */
int blake2s_key_mac16(const uint8_t *key, size_t keylen, const uint8_t *in, size_t inlen, uint8_t out[16]);

/* AEAD ChaCha20-Poly1305 with nonce = 4 zero + little-endian 8-byte counter. */
int aead_chacha20poly1305_encrypt(const uint8_t key[32], uint64_t counter,
                                  const uint8_t *pt, size_t pt_len,
                                  const uint8_t *ad, size_t ad_len,
                                  uint8_t *out, size_t *out_len);
int aead_chacha20poly1305_decrypt(const uint8_t key[32], uint64_t counter,
                                  const uint8_t *ct, size_t ct_len,
                                  const uint8_t *ad, size_t ad_len,
                                  uint8_t *out, size_t *out_len);

/* HKDF-like helper used by python code: chaining_key, input_key_material -> new chaining_key, output */
int hkdf_blake2s_3(const uint8_t *ck, const uint8_t *ikm, size_t ikm_len,
                   uint8_t out_ck[32], uint8_t out1[32], uint8_t out2[32]);


#endif
