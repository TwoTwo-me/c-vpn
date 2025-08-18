#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
/* 매우 간단한 SHA256 + HMAC 구현 (참고용; 최적화/안전성 미확보) */

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t idx; } sha256_ctx;

static uint32_t ROR(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
static uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x & y) ^ (~x & z);} 
static uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x & y) ^ (x & z) ^ (y & z);} 
static uint32_t S0(uint32_t x){return ROR(x,2)^ROR(x,13)^ROR(x,22);} 
static uint32_t S1(uint32_t x){return ROR(x,6)^ROR(x,11)^ROR(x,25);} 
static uint32_t s0(uint32_t x){return ROR(x,7)^ROR(x,18)^(x>>3);} 
static uint32_t s1(uint32_t x){return ROR(x,17)^ROR(x,19)^(x>>10);} 

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static void sha256_init(sha256_ctx *c){
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len=0; c->idx=0;
}

static void sha256_compress(sha256_ctx *c,const uint8_t block[64]){
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=read_be32(block+i*4);
    for(int i=16;i<64;i++) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    uint32_t a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4],g=c->h[5],h=c->h[6],i=c->h[7];
    for(int t=0;t<64;t++){
        uint32_t T1=i+S1(f)+Ch(f,g,h)+K[t]+w[t];
        uint32_t T2=S0(a)+Maj(a,b,d);
        i=h; h=g; g=f; f=e+T1; e=d; d=b; b=a; a=T1+T2; 
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e; c->h[4]+=f; c->h[5]+=g; c->h[6]+=h; c->h[7]+=i; 
}

static void sha256_update(sha256_ctx *c,const uint8_t *data,size_t len){
    c->len += len*8;
    while(len--){
        c->buf[c->idx++]=*data++;
        if(c->idx==64){ sha256_compress(c,c->buf); c->idx=0; }
    }
}
static void sha256_final(sha256_ctx *c,uint8_t out[32]){
    c->buf[c->idx++]=0x80;
    if(c->idx>56){ while(c->idx<64) c->buf[c->idx++]=0; sha256_compress(c,c->buf); c->idx=0; }
    while(c->idx<56) c->buf[c->idx++]=0;
    for(int i=7;i>=0;i--) c->buf[c->idx++]=(uint8_t)(c->len>>(i*8));
    sha256_compress(c,c->buf);
    for(int i=0;i<8;i++){ write_be32(out+i*4, c->h[i]); }
}

void hmac_sha256(const uint8_t *key,size_t klen,const uint8_t *data,size_t dlen,uint8_t out[32]){
    uint8_t k_ipad[64]={0}, k_opad[64]={0};
    uint8_t kh[32];
    if(klen>64){ sha256_ctx t; sha256_init(&t); sha256_update(&t,key,klen); sha256_final(&t,kh); key=kh; klen=32; }
    memcpy(k_ipad,key,klen); memcpy(k_opad,key,klen);
    for(int i=0;i<64;i++){ k_ipad[i]^=0x36; k_opad[i]^=0x5c; }
    sha256_ctx c; sha256_init(&c); sha256_update(&c,k_ipad,64); sha256_update(&c,data,dlen); sha256_final(&c,out);
    sha256_init(&c); sha256_update(&c,k_opad,64); sha256_update(&c,out,32); sha256_final(&c,out);
}
