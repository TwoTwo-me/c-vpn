#ifndef PVPN_ESP_H
#define PVPN_ESP_H
#include <stdint.h>
#include <stddef.h>
int esp_encrypt(uint32_t spi,uint32_t seq,const uint8_t key[16],const uint8_t iv[16],const uint8_t *plain,size_t plen,uint8_t *out,size_t *outlen,const uint8_t *auth_key,size_t auth_len);
int esp_decrypt(const uint8_t *pkt,size_t pkt_len,const uint8_t *key,const uint8_t *auth_key,size_t auth_len,uint8_t *out,size_t *outlen);
#endif
