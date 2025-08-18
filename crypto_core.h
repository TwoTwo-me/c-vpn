#ifndef PVPN_CRYPTO_CORE_H
#define PVPN_CRYPTO_CORE_H
#include <stddef.h>
#include <stdint.h>
int prf_hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *data,size_t dlen,uint8_t out[32]);
size_t prfplus_hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *seed,size_t seedlen,uint8_t *out,size_t outlen);
#endif
