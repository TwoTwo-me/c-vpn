#include "blake2s.h"
#include <string.h>

/* Public domain style minimal BLAKE2s based on reference, trimmed */

static const uint32_t blake2s_iv[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

#define G(r,i,a,b,c,d) \
  a = a + b + m[blake2s_sigma[r][2*i+0]]; \
  d = ((d ^ a) >> 16) | ((d ^ a) << 16); \
  c = c + d; \
  b = ((b ^ c) >> 12) | ((b ^ c) << 20); \
  a = a + b + m[blake2s_sigma[r][2*i+1]]; \
  d = ((d ^ a) >> 8) | ((d ^ a) << 24); \
  c = c + d; \
  b = ((b ^ c) >> 7) | ((b ^ c) << 25);

static const uint8_t blake2s_sigma[10][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
};

static inline uint32_t rotr32( const uint32_t w, const unsigned c ) { return ( w >> c ) | ( w << ( 32 - c ) ); }

static void blake2s_compress( blake2s_state *S, const uint8_t block[64] ) {
  uint32_t m[16];
  uint32_t v[16];
  for( size_t i = 0; i < 16; ++i ) m[i] = ((uint32_t*)block)[i];
  for( size_t i = 0; i < 8; ++i ) v[i] = S->h[i];
  v[ 8] = blake2s_iv[0];
  v[ 9] = blake2s_iv[1];
  v[10] = blake2s_iv[2];
  v[11] = blake2s_iv[3];
  v[12] = S->t[0] ^ blake2s_iv[4];
  v[13] = S->t[1] ^ blake2s_iv[5];
  v[14] = S->f[0] ^ blake2s_iv[6];
  v[15] = S->f[1] ^ blake2s_iv[7];
  for( size_t r = 0; r < 10; ++r ) {
    uint32_t a=v[0],b=v[4],c=v[8],d=v[12];
    uint32_t e=v[1],f=v[5],g=v[9],h=v[13];
    uint32_t i=v[2],j=v[6],k=v[10],l=v[14];
    uint32_t m0=v[3],n=v[7],o=v[11],p=v[15];
    G(r,0,a,b,c,d); G(r,1,e,f,g,h); G(r,2,i,j,k,l); G(r,3,m0,n,o,p);
    G(r,4,a,f,k,p); G(r,5,e,j,o,d); G(r,6,i,n,c,h); G(r,7,m0,b,g,l);
    v[0]=a;v[4]=b;v[8]=c;v[12]=d;v[1]=e;v[5]=f;v[9]=g;v[13]=h;v[2]=i;v[6]=j;v[10]=k;v[14]=l;v[3]=m0;v[7]=n;v[11]=o;v[15]=p;
  }
  for( size_t i = 0; i < 8; ++i ) S->h[i] ^= v[i] ^ v[i + 8];
}

int blake2s_init(blake2s_state *S, size_t outlen){
  if(outlen!=32) return -1;
  S->h[0] = 0x6A09E667 ^ 0x01010000 ^ (uint32_t)outlen;
  S->h[1] = 0xBB67AE85; S->h[2] = 0x3C6EF372; S->h[3] = 0xA54FF53A;
  S->h[4] = 0x510E527F; S->h[5] = 0x9B05688C; S->h[6] = 0x1F83D9AB; S->h[7] = 0x5BE0CD19;
  S->t[0]=S->t[1]=S->f[0]=S->f[1]=0; S->buflen=0; return 0;
}

int blake2s_update(blake2s_state *S, const void *pin, size_t inlen){
  const uint8_t *in = (const uint8_t*)pin;
  while(inlen>0){
    size_t space = 64 - S->buflen;
    size_t take = inlen < space ? inlen : space;
    memcpy(S->buf + S->buflen, in, take);
    S->buflen += take; in += take; inlen -= take;
    if(S->buflen==64){
      S->t[0] += 64; if(S->t[0]<64) S->t[1]++;
      blake2s_compress(S, S->buf); S->buflen=0;
    }
  }
  return 0;
}

int blake2s_final(blake2s_state *S, void *out, size_t outlen){
  if(outlen!=32) return -1;
  S->t[0] += S->buflen; if(S->t[0] < S->buflen) S->t[1]++;
  S->f[0] = 0xFFFFFFFF;
  memset(S->buf + S->buflen, 0, 64 - S->buflen);
  blake2s_compress(S, S->buf);
  for(size_t i=0;i<8;i++) ((uint32_t*)out)[i]=S->h[i];
  return 0;
}

void blake2s(const uint8_t *in,size_t inlen,uint8_t out[32]){
  blake2s_state S; blake2s_init(&S,32); blake2s_update(&S,in,inlen); blake2s_final(&S,out,32);
}

void blake2s_keyed(const uint8_t *key,size_t keylen,const uint8_t *in,size_t inlen,uint8_t out[32]){
  /* Reference spec mixes key inside first block with parameter block; here we just (prototype) hash key||in */
  blake2s_state S; blake2s_init(&S,32); blake2s_update(&S,key,keylen); blake2s_update(&S,in,inlen); blake2s_final(&S,out,32);
}
