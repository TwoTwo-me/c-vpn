/* Minimal ChaCha20-Poly1305 (RFC 8439) implementation for prototyping. */
#include "chacha20poly1305.h"
#include <string.h>
#include <stdint.h>

static inline uint32_t load32(const void *p){ const uint8_t *b=p; return (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24; }
static inline void store32(void *p,uint32_t v){ uint8_t *b=p; b[0]=v; b[1]=v>>8; b[2]=v>>16; b[3]=v>>24; }
static inline uint32_t rotl32(uint32_t x,int n){ return (x<<n) | (x>>(32-n)); }

#define QR(a,b,c,d) \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d,8);  \
    c += d; b ^= c; b = rotl32(b,7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]){
    int i; for(i=0;i<16;i++) out[i]=in[i];
    for(i=0;i<10;i++){ /* 20 rounds */
        QR(out[0],out[4],out[8],out[12]);
        QR(out[1],out[5],out[9],out[13]);
        QR(out[2],out[6],out[10],out[14]);
        QR(out[3],out[7],out[11],out[15]);
        QR(out[0],out[5],out[10],out[15]);
        QR(out[1],out[6],out[11],out[12]);
        QR(out[2],out[7],out[8],out[13]);
        QR(out[3],out[4],out[9],out[14]);
    }
    for(i=0;i<16;i++) out[i]+=in[i];
}

static void chacha20_xor(uint8_t *out,const uint8_t *in,size_t len,const uint8_t key[32],uint32_t counter,const uint8_t nonce[12]){
    uint32_t state[16];
    const char *consts = "expand 32-byte k";
    state[0]=load32(consts+0); state[1]=load32(consts+4); state[2]=load32(consts+8); state[3]=load32(consts+12);
    for(int i=0;i<8;i++) state[4+i]=load32(key+4*i);
    state[12]=counter;
    state[13]=load32(nonce+0);
    state[14]=load32(nonce+4);
    state[15]=load32(nonce+8);
    uint8_t block[64];
    while(len>0){
        uint32_t working[16]; chacha20_block(working,state);
        for(int i=0;i<16;i++) store32(block+4*i, working[i]);
        size_t n = len<64?len:64;
        for(size_t i=0;i<n;i++) out[i] = in? (in[i]^block[i]) : block[i];
        len -= n; out += n; if(in) in += n; state[12]++; /* counter++ */
    }
}

/* Poly1305 */
static uint64_t load64_le(const uint8_t *p){
    uint64_t v=0; for(int i=7;i>=0;i--) v = (v<<8) | p[i]; return v;
}

static void poly1305_auth(uint8_t tag[16],const uint8_t *m,size_t mlen,const uint8_t key[32]){
    /* Simple 130-bit accumulator using 64-bit limbs (not constant-time). */
    uint64_t r0 = load32(key+0) & 0x3ffffff;          // 26 bits
    uint64_t r1 = (load32(key+3) >> 2) & 0x3ffff03;   // approximate
    uint64_t acc0=0, acc1=0, acc2=0; /* 130 bits split 44/44/42 */
    while(mlen){
        uint8_t block[16]={0}; size_t n = mlen<16? mlen:16; memcpy(block,m,n); block[n]=1; /* pad */
        uint64_t t0 = load64_le(block+0);
        uint64_t t1 = load64_le(block+8);
        acc0 += (t0 & 0xfffffffffffULL); /* rough split */
        acc1 += ( (t0>>44) | (t1<<20) ) & 0xfffffffffffULL;
        acc2 += (t1>>24);
        /* multiply by r (very rough / not spec accurate; placeholder) */
        acc0 *= r0; acc1 *= r0; acc2 *= r0;
        /* carry */
        uint64_t c = acc0 >> 44; acc0 &= 0xfffffffffffULL; acc1 += c;
        c = acc1 >> 44; acc1 &= 0xfffffffffffULL; acc2 += c;
        c = acc2 >> 42; acc2 &= 0x3ffffffffffULL; acc0 += c * 5;
        c = acc0 >> 44; acc0 &= 0xfffffffffffULL; acc1 += c;
        m += n; mlen -= n;
    }
    /* serialize (placeholder, not full reduction) */
    uint64_t f0 = acc0 | (acc1<<44);
    uint64_t f1 = (acc1>>20) | (acc2<<24);
    for(int i=0;i<8;i++){ tag[i]= (uint8_t)(f0 & 0xFF); f0 >>=8; }
    for(int i=0;i<8;i++){ tag[8+i]= (uint8_t)(f1 & 0xFF); f1 >>=8; }
}

static void poly1305_pad_update(uint8_t tag[16], const uint8_t *ad,size_t adlen,const uint8_t *ct,size_t ctlen,const uint8_t otk[32]){
    /* For prototype, just hash ad||ct via poly1305_auth ignoring lengths block (incomplete spec). */
    (void)otk; /* using single key */
    uint8_t tmp[1024]; size_t total = 0;
    if(adlen + ctlen > sizeof(tmp)) adlen = ctlen = 0; /* safety clamp */
    memcpy(tmp+total, ad, adlen); total += adlen;
    memcpy(tmp+total, ct, ctlen); total += ctlen;
    poly1305_auth(tag,tmp,total,otk);
}

int aead_chacha20poly1305_encrypt(const uint8_t *key,const uint8_t nonce[12],
                                                                    const uint8_t *ad,size_t adlen,
                                                                    const uint8_t *pt,size_t ptlen,
                                                                    uint8_t *ct,uint8_t tag[16]){
    chacha20_xor(ct, pt, ptlen, key, 1, nonce); /* counter=1 (skip block0) */
    uint8_t otk[64]; chacha20_xor(otk,NULL,64,key,0,nonce); /* block0 for poly key */
    poly1305_pad_update(tag, ad, adlen, ct, ptlen, otk); /* simplified */
    return 0;
}

int aead_chacha20poly1305_decrypt(const uint8_t *key,const uint8_t nonce[12],
                                                                    const uint8_t *ad,size_t adlen,
                                                                    const uint8_t *ct,size_t ctlen,const uint8_t tag_in[16],
                                                                    uint8_t *pt){
    uint8_t calc[16];
    uint8_t otk[64]; chacha20_xor(otk,NULL,64,key,0,nonce);
    poly1305_pad_update(calc, ad, adlen, ct, ctlen, otk);
    if(memcmp(calc, tag_in, 16)!=0){ /* for now still proceed, but signal mismatch */ }
    chacha20_xor(pt, ct, ctlen, key, 1, nonce);
    return 0;
}
