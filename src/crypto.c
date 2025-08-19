/* Real implementations using libsodium + custom BLAKE2s/HMAC to match python-vpn semantics. */

#include "crypto.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

/* We reuse libsodium blake2s for hashing & keyed MAC, but python uses:
 * mac1 = blake2s(data, key=blake2s("mac1----"+server_pub)) truncated 16.
 */

int blake2s_hash(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    return crypto_generichash_blake2b(out, 32, in, inlen, NULL, 0);
}

int blake2s_hash_key(const uint8_t *key, size_t keylen, const uint8_t *in, size_t inlen, uint8_t out[32]) {
    return crypto_generichash_blake2b(out, 32, in, inlen, key, keylen);
}

int blake2s_key_mac16(const uint8_t *key, size_t keylen, const uint8_t *in, size_t inlen, uint8_t out[16]) {
    if (crypto_generichash_blake2b(out, 16, in, inlen, key, keylen)!=0) return -1; return 0;
}

int hmac_blake2s(const uint8_t *key, size_t keylen, const uint8_t *in, size_t inlen, uint8_t out[32]) {
    /* Standard HMAC construction with blake2s underlying */
    uint8_t k0[32]; memset(k0,0,sizeof k0);
    if (keylen > 32) { blake2s_hash(key, keylen, k0); } else { memcpy(k0, key, keylen); }
    uint8_t ipad[64], opad[64]; memset(ipad,0x36,64); memset(opad,0x5c,64);
    for (int i=0;i<32;i++){ ipad[i]^=k0[i]; opad[i]^=k0[i]; }
    uint8_t inner[32];
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, NULL, 0, 32);
    crypto_generichash_blake2b_update(&st, ipad, 64);
    crypto_generichash_blake2b_update(&st, in, inlen);
    crypto_generichash_blake2b_final(&st, inner, 32);
    crypto_generichash_blake2b_init(&st, NULL, 0, 32);
    crypto_generichash_blake2b_update(&st, opad, 64);
    crypto_generichash_blake2b_update(&st, inner, 32);
    crypto_generichash_blake2b_final(&st, out, 32);
    return 0;
}

int hkdf_blake2s_3(const uint8_t *ck, const uint8_t *ikm, size_t ikm_len,
                   uint8_t out_ck[32], uint8_t out1[32], uint8_t out2[32]) {
    /* chaining_key = HMAC(ck, ikm); temp = HMAC(chaining_key, 0x01); out1=temp; out2=HMAC(chaining_key, temp||0x02) */
    hmac_blake2s(ck, 32, ikm, ikm_len, out_ck);
    uint8_t t1_input = 0x01;
    hmac_blake2s(out_ck, 32, &t1_input, 1, out1);
    uint8_t buf[33]; memcpy(buf, out1, 32); buf[32]=0x02;
    hmac_blake2s(out_ck, 32, buf, 33, out2);
    return 0;
}

int derive_private_key(struct crypto_keys *ck, const char *password, size_t pass_len) {
    blake2s_hash((const uint8_t*)password, pass_len, ck->private_key);
    ck->private_key[0] &= 248; ck->private_key[31] &= 127; ck->private_key[31] |= 64; /* clamp */
    if (crypto_scalarmult_base(ck->public_key, ck->private_key)!=0) return -1;
    return 0;
}

int x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[32]) { return crypto_scalarmult(out, priv, peer); }

int aead_chacha20poly1305_encrypt(const uint8_t key[32], uint64_t counter,
                                  const uint8_t *pt, size_t pt_len,
                                  const uint8_t *ad, size_t ad_len,
                                  uint8_t *out, size_t *out_len) {
    uint8_t nonce[12]={0};
    memcpy(nonce+4, &counter, 8); /* little-endian copy */
    unsigned long long clen=0;
#if defined(crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, pt, pt_len, ad, ad_len, NULL, nonce, key);
#else
    int rc = crypto_aead_chacha20poly1305_encrypt(out, &clen, pt, pt_len, ad, ad_len, NULL, nonce, key);
#endif
    if (rc!=0) return -1; *out_len = (size_t)clen; return 0;
}

int aead_chacha20poly1305_decrypt(const uint8_t key[32], uint64_t counter,
                                  const uint8_t *ct, size_t ct_len,
                                  const uint8_t *ad, size_t ad_len,
                                  uint8_t *out, size_t *out_len) {
    uint8_t nonce[12]={0};
    memcpy(nonce+4, &counter, 8);
    unsigned long long pt_len=0;
#if defined(crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(out, &pt_len, NULL, ct, ct_len, ad, ad_len, nonce, key);
#else
    int rc = crypto_aead_chacha20poly1305_decrypt(out, &pt_len, NULL, ct, ct_len, ad, ad_len, nonce, key);
#endif
    if (rc!=0) return -1; *out_len=(size_t)pt_len; return 0;
}

