/* Placeholder ChaCha20-Poly1305 (NOT SECURE) for structural progress. */
#ifndef PVPN_CHACHA20POLY1305_H
#define PVPN_CHACHA20POLY1305_H
#include <stddef.h>
#include <stdint.h>

int aead_chacha20poly1305_encrypt(const uint8_t *key,const uint8_t nonce[12],
                                  const uint8_t *ad,size_t adlen,
                                  const uint8_t *pt,size_t ptlen,
                                  uint8_t *ct,uint8_t tag[16]);

int aead_chacha20poly1305_decrypt(const uint8_t *key,const uint8_t nonce[12],
                                  const uint8_t *ad,size_t adlen,
                                  const uint8_t *ct,size_t ctlen,const uint8_t tag[16],
                                  uint8_t *pt);

#endif
