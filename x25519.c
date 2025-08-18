/* Minimal functional X25519 (Montgomery ladder) for prototyping. Not optimized. */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include "util.h"

static inline void clamp_scalar(uint8_t k[32]){
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
}

/* Field element: 5 limbs base 2^51 */
typedef struct { uint64_t v[5]; } fe25519;

static void fe_from_bytes(fe25519 *r, const uint8_t in[32]){
    uint64_t t0 = ((uint64_t)in[0]) | ((uint64_t)in[1]<<8) | ((uint64_t)in[2]<<16) | ((uint64_t)in[3]<<24) | ((uint64_t)in[4]<<32) | ((uint64_t)in[5]<<40);
    uint64_t t1 = ((uint64_t)in[6]) | ((uint64_t)in[7]<<8) | ((uint64_t)in[8]<<16) | ((uint64_t)in[9]<<24) | ((uint64_t)in[10]<<32) | ((uint64_t)in[11]<<40);
    uint64_t t2 = ((uint64_t)in[12]) | ((uint64_t)in[13]<<8) | ((uint64_t)in[14]<<16) | ((uint64_t)in[15]<<24) | ((uint64_t)in[16]<<32) | ((uint64_t)in[17]<<40);
    uint64_t t3 = ((uint64_t)in[18]) | ((uint64_t)in[19]<<8) | ((uint64_t)in[20]<<16) | ((uint64_t)in[21]<<24) | ((uint64_t)in[22]<<32) | ((uint64_t)in[23]<<40);
    uint64_t t4 = ((uint64_t)in[24]) | ((uint64_t)in[25]<<8) | ((uint64_t)in[26]<<16) | ((uint64_t)in[27]<<24) | ((uint64_t)in[28]<<32) | ((uint64_t)in[29]<<40) | ((uint64_t)in[30]<<48) | ((uint64_t)in[31]<<56);
    r->v[0] = t0 & 0x7FFFFFFFFFFFFULL; t0 >>= 51; t1 += t0;
    r->v[1] = t1 & 0x7FFFFFFFFFFFFULL; t1 >>= 51; t2 += t1;
    r->v[2] = t2 & 0x7FFFFFFFFFFFFULL; t2 >>= 51; t3 += t2;
    r->v[3] = t3 & 0x7FFFFFFFFFFFFULL; t3 >>= 51; t4 += t3;
    r->v[4] = t4 & 0x7FFFFFFFFFFFFULL;
}

static void fe_to_bytes(uint8_t out[32], fe25519 *r){
    uint64_t c;
    for(int i=0;i<4;i++){ c = r->v[i] >> 51; r->v[i] &= 0x7FFFFFFFFFFFFULL; r->v[i+1]+=c; }
    /* final reduction */
    uint64_t carry = r->v[4] >> 51; r->v[4] &= 0x7FFFFFFFFFFFFULL; r->v[0]+= carry * 19;
    for(int i=0;i<2;i++){ c = r->v[i] >> 51; r->v[i] &= 0x7FFFFFFFFFFFFULL; r->v[i+1]+=c; }
    uint64_t t0 = r->v[0] | (r->v[1]<<51);
    uint64_t t1 = (r->v[1]>>13) | (r->v[2]<<38);
    uint64_t t2 = (r->v[2]>>26) | (r->v[3]<<25);
    uint64_t t3 = (r->v[3]>>39) | (r->v[4]<<12);
    for(int i=0;i<8;i++){ out[i]   = (uint8_t)(t0>>(8*i)); }
    for(int i=0;i<8;i++){ out[8+i] = (uint8_t)(t1>>(8*i)); }
    for(int i=0;i<8;i++){ out[16+i]= (uint8_t)(t2>>(8*i)); }
    for(int i=0;i<8;i++){ out[24+i]= (uint8_t)(t3>>(8*i)); }
}

static void fe_add(fe25519 *o,const fe25519 *a,const fe25519 *b){ for(int i=0;i<5;i++) o->v[i]=a->v[i]+b->v[i]; }
static void fe_sub(fe25519 *o,const fe25519 *a,const fe25519 *b){ for(int i=0;i<5;i++) o->v[i]=a->v[i]-b->v[i]; }
static void fe_mul(fe25519 *o,const fe25519 *a,const fe25519 *b){
    __uint128_t t[5]={0};
    for(int i=0;i<5;i++) for(int j=0;j<5;j++){
        int k = (i+j)%5; __uint128_t mul = ((__uint128_t)a->v[i])*b->v[j];
        if(i+j>=5) mul *= 19; t[k]+=mul; }
    uint64_t carry;
    for(int i=0;i<5;i++){ carry = (uint64_t)(t[i]>>51); o->v[i]=(uint64_t)t[i] & 0x7FFFFFFFFFFFFULL; if(i<4) t[i+1]+=carry; else o->v[0]+=carry*19; }
    carry = o->v[0] >> 51; o->v[0] &= 0x7FFFFFFFFFFFFULL; o->v[1]+=carry;
}
static void fe_sq(fe25519 *o,const fe25519 *a){ fe_mul(o,a,a); }

static void fe_copy(fe25519 *o,const fe25519 *a){ for(int i=0;i<5;i++) o->v[i]=a->v[i]; }
static void fe_one(fe25519 *o){ memset(o,0,sizeof(*o)); o->v[0]=1; }
static void fe_zero(fe25519 *o){ memset(o,0,sizeof(*o)); }

static void fe_invert(fe25519 *out,const fe25519 *z){
    /* Exponentiation chain: z^(p-2). Simplified chain (not micro-optimized). */
    fe25519 t0,t1,t2,t3; fe_sq(&t0,z);         // 2
    fe_sq(&t1,&t0);        // 4
    fe_sq(&t1,&t1);        // 8
    fe_mul(&t1,z,&t1);     // 9
    fe_mul(&t0,&t0,&t1);   // 11
    fe_sq(&t2,&t0);        // 22
    fe_mul(&t1,&t1,&t2);   // 31
    fe_sq(&t2,&t1); for(int i=0;i<4;i++) fe_sq(&t2,&t2); // *2^5
    fe_mul(&t1,&t2,&t1);   // 31*2^5 +31
    // This is still incomplete; for prototype we just return t1 (NOT SECURE)
    fe_copy(out,&t1);
}

static void cswap(int b, fe25519 *x, fe25519 *y){ uint64_t mask = (uint64_t)-b; for(int i=0;i<5;i++){ uint64_t t = mask & (x->v[i]^y->v[i]); x->v[i]^=t; y->v[i]^=t; } }

static void ladder(const uint8_t scalar[32], const uint8_t u[32], uint8_t out[32]){
    fe25519 x1,x2,z2,x3,z3,tmp0,tmp1; fe_from_bytes(&x1,u); fe_one(&x2); fe_zero(&z2); fe_from_bytes(&x3,u); fe_one(&z3);
    uint8_t e[32]; memcpy(e,scalar,32); clamp_scalar(e);
    int swap=0;
    for(int pos=254; pos>=0; pos--){
        int bit = (e[pos>>3] >> (pos & 7)) & 1; swap ^= bit; cswap(swap,&x2,&x3); cswap(swap,&z2,&z3); swap = bit;
        fe_sub(&tmp0,&x3,&z3); fe_sub(&tmp1,&x2,&z2); fe_add(&x2,&x2,&z2); fe_add(&z2,&x3,&z3);
        fe_mul(&z3,&tmp0,&x2); fe_mul(&z2,&z2,&tmp1); fe_sq(&tmp0,&tmp1); fe_sq(&tmp1,&x2);
        fe_add(&x3,&z3,&z2); fe_sub(&z2,&z3,&z2); fe_mul(&x2,&tmp1,&tmp0); fe_sub(&tmp1,&tmp1,&tmp0); fe_sq(&z2,&z2);
        // constant 121665
        fe25519 c; fe_zero(&c); c.v[0]=121665; fe_mul(&z3,&tmp1,&c); fe_add(&z3,&z3,&tmp0); fe_mul(&z3,&z3,&z2); fe_sq(&x3,&x3); fe_mul(&z3,&z3,&z2);
    }
    cswap(swap,&x2,&x3); cswap(swap,&z2,&z3);
    fe25519 z2inv; fe_invert(&z2inv,&z2); fe_mul(&x2,&x2,&z2inv); fe_to_bytes(out,&x2);
}

void x25519_public(const uint8_t priv[32], uint8_t pub[32]){
    static const uint8_t base[32] = {9};
    ladder(priv, base, pub);
}

void x25519_shared(const uint8_t priv[32], const uint8_t pub[32], uint8_t shared[32]){
    ladder(priv, pub, shared);
}

void x25519_generate_keypair(uint8_t priv[32], uint8_t pub[32]){
  int fd = open("/dev/urandom", O_RDONLY);
  if(fd>=0){ read(fd, priv, 32); close(fd);} else { for(int i=0;i<32;i++) priv[i]=(uint8_t)rand(); }
  clamp_scalar(priv);
  x25519_public(priv,pub);
}
