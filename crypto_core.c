#include "crypto_core.h"
 #include <string.h>
#include <stdlib.h>
#include "crypto_hmac.h"
#include "util.h"

int prf_hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *data,size_t dlen,uint8_t out[32]){
    hmac_sha256(key,klen,data,dlen,out); return 1; }

size_t prfplus_hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *seed,size_t seedlen,uint8_t *out,size_t outlen){
    uint8_t t[32]; size_t produced=0; uint8_t iter=1; size_t tlen=0;
    while(produced<outlen){
        // T(n) = HMAC(K, T(n-1) | seed | iter)
        uint8_t buf[32 + 256 + 1]; // seedlen 제한 가정(<=256)
        CHECK(seedlen <= 256, "seed too large");
        size_t off = 0;
        if(tlen){ memcpy(buf+off,t,tlen); off+=tlen; }
        memcpy(buf+off, seed, seedlen); off+=seedlen; buf[off++]=iter;
        hmac_sha256(key,klen,buf,off,t);
        tlen=32;
        size_t cpy = (outlen-produced < tlen)? outlen-produced : tlen;
        memcpy(out+produced, t, cpy); produced += cpy; iter++; if(iter==0) break; }
    return produced; }
