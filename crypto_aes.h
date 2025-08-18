#ifndef PVPN_AES_H
#define PVPN_AES_H
#include <stddef.h>
#include <stdint.h>
void aes_128_cbc_encrypt(const uint8_t *key,const uint8_t *iv,const uint8_t *in,uint8_t *out,size_t len);
void aes_128_cbc_decrypt(const uint8_t *key,const uint8_t *iv,const uint8_t *in,uint8_t *out,size_t len);
#endif
