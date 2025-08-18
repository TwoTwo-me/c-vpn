#ifndef PVPN_HMAC_H
#define PVPN_HMAC_H
#include <stddef.h>
#include <stdint.h>
void hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *data,size_t dlen,uint8_t out[32]);
#endif
