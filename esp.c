#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "crypto_aes.h"
#include "crypto_hmac.h"
/* 최소 ESP (AES-CBC + HMAC-SHA256) 구현 - 데모용 */

int esp_encrypt(uint32_t spi,uint32_t seq,const uint8_t key[16],const uint8_t iv[16],const uint8_t *plain,size_t plen,uint8_t *out,size_t *outlen,const uint8_t *auth_key,size_t auth_len){
    size_t padlen = 16 - ((plen+2) % 16);
    size_t total = 16 + 16 + plen + padlen + 2 + 32; // IV + enc + ICV(32)
    if(*outlen < 8 + total) return 0;
    uint8_t *p = out;
    write_be32(p, spi); write_be32(p+4, seq); p+=8;
    memcpy(p, iv, 16); p+=16;
    uint8_t *enc = p;
    memcpy(enc, plain, plen); memset(enc+plen,0,padlen); enc[plen+padlen]=padlen; enc[plen+padlen+1]=4; // next header dummy 4
    size_t enc_len = plen+padlen+2;
    aes_128_cbc_encrypt(key, iv, enc, enc, enc_len);
    p += enc_len;
    uint8_t mac[32];
    hmac_sha256(auth_key, auth_len, out, p-out, mac);
    memcpy(p, mac, 32); p+=32;
    *outlen = p-out; return 1;
}

int esp_decrypt(const uint8_t *pkt,size_t pkt_len,const uint8_t *key,const uint8_t *auth_key,size_t auth_len,uint8_t *out,size_t *outlen){
    if(pkt_len < 8+16+2+32) return 0; // header + iv + min pad+nh + icv
    const uint8_t *spi_seq = pkt; // 8 bytes
    const uint8_t *iv = pkt+8;
    size_t enc_len = pkt_len - 8 - 16 - 32; // encrypted payload + pad + nh
    const uint8_t *enc = pkt + 8 + 16;
    const uint8_t *icv = pkt + pkt_len - 32;
    // ICV 확인
    uint8_t calc[32];
    hmac_sha256(auth_key, auth_len, pkt, pkt_len-32, calc);
    if(memcmp(calc, icv, 32)!=0) return 0;
    // 복호화
    if(enc_len % 16 != 0) return 0;
    if(*outlen < enc_len) return 0;
    aes_128_cbc_decrypt(key, iv, enc, out, enc_len);
    if(enc_len < 2) return 0;
    uint8_t padlen = out[enc_len-2];
    if(padlen + 2 > enc_len) return 0;
    size_t plain_len = enc_len - padlen - 2;
    *outlen = plain_len;
    return 1;
}
