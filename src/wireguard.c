#include "wireguard.h"
#include "util.h"
#include "ip_handler.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <sodium.h>

/* Message type constants */
#define WG_MSG_INITIATION 1
#define WG_MSG_RESPONSE   2
#define WG_MSG_DATA       4

struct __attribute__((packed)) wg_initiation {
    uint32_t type;
    uint32_t sender_index; /* peer */
    uint8_t  ephemeral[32];
    uint8_t  encrypted_static[48];
    uint8_t  encrypted_timestamp[28];
    uint8_t  mac1[16];
    uint8_t  mac2[16];
};

struct __attribute__((packed)) wg_response {
    uint32_t type;
    uint32_t sender_index; /* server */
    uint32_t receiver_index; /* peer */
    uint8_t  ephemeral[32];
    uint8_t  encrypted_empty[16];
    uint8_t  mac1[16];
    uint8_t  mac2[16];
};

struct __attribute__((packed)) wg_data_hdr {
    uint32_t type;
    uint32_t receiver; /* server local index */
    uint64_t counter;  /* nonce */
};

static const uint8_t protocol_name[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t identifier_name[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

void wg_init(struct wg_context *ctx, const char *password) {
    derive_private_key(&ctx->keys, password, strlen(password));
    memset(ctx->psk, 0, sizeof ctx->psk);
    /* mac1 key base = HASH("mac1----" + server_pub) */
    uint8_t tmp[7+32]; memcpy(tmp, "mac1----", 7); memcpy(tmp+7, ctx->keys.public_key, 32); /* note python used HASH("mac1----" + pub) as key to MAC */
    blake2s_hash(tmp, sizeof tmp, ctx->mac1_key);
    char b64[64];
    if (b64_encode(ctx->keys.public_key, 32, b64, sizeof b64) > 0) {
        printf("======== WIREGUARD SETTING ========\nPublicKey: %s\n===================================\n", b64);
    }
}

static size_t handle_initiation(struct wg_context *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max) {
    if (in_len != sizeof(struct wg_initiation)) return 0;
    const struct wg_initiation *msg = (const struct wg_initiation*)in;
    /* mac1 verify */
    uint8_t calc_mac1[16];
    blake2s_key_mac16(ctx->mac1_key, 32, in, 116, calc_mac1); /* first 116 bytes before macs */
    if (memcmp(calc_mac1, msg->mac1, 16)!=0) {
        return 0; /* drop */
    }
    /* mac2 must be zero */
    for (int i=0;i<16;i++) if (msg->mac2[i]!=0) return 0;

    /* Begin Noise IKpsk2 simplified derivation replicating python operations */
    uint8_t chaining_key[32]; blake2s_hash(protocol_name, sizeof(protocol_name)-1, chaining_key);
    uint8_t hash0[32];
    /* hash = HASH(HASH(HASH(protocol_name)+identifier)+server_pub + peer_ephemeral) */
    blake2s_hash(protocol_name, sizeof(protocol_name)-1, hash0);
    uint8_t t[32]; blake2s_hash(hash0, 32, t); /* H(H(...)) mimic nested */
    uint8_t concat1[32+sizeof(identifier_name)-1]; memcpy(concat1, t, 32); memcpy(concat1+32, identifier_name, sizeof(identifier_name)-1);
    blake2s_hash(concat1, sizeof concat1, hash0);
    uint8_t concat2[32+32]; memcpy(concat2, hash0,32); memcpy(concat2+32, ctx->keys.public_key,32);
    blake2s_hash(concat2, sizeof concat2, hash0);
    uint8_t concat3[32+32]; memcpy(concat3, hash0,32); memcpy(concat3+32, msg->ephemeral,32);
    blake2s_hash(concat3, sizeof concat3, hash0);

    /* ECDH(server_priv, peer_ephemeral) */
    uint8_t dh1[32]; x25519(dh1, ctx->keys.private_key, msg->ephemeral);
    uint8_t temp1_ck[32], temp1[32], temp2[32];
    hkdf_blake2s_3(chaining_key, dh1, 32, temp1_ck, temp1, temp2); /* approximate chain usage */
    memcpy(chaining_key, temp1_ck, 32);
    /* decrypt static peer key */
    uint8_t peer_static[32]; size_t dec_len=0;
    if (aead_chacha20poly1305_decrypt(temp2, 0, msg->encrypted_static, 48, hash0, 32, peer_static, &dec_len)!=0 || dec_len!=32) return 0;
    uint8_t hash1_input[32+48]; memcpy(hash1_input, hash0,32); memcpy(hash1_input+32, msg->encrypted_static,48);
    blake2s_hash(hash1_input, sizeof hash1_input, hash0);
    /* ECDH(server_priv, peer_static) */
    uint8_t dh2[32]; x25519(dh2, ctx->keys.private_key, peer_static);
    hkdf_blake2s_3(chaining_key, dh2, 32, temp1_ck, temp1, temp2); memcpy(chaining_key, temp1_ck, 32);
    /* decrypt timestamp */
    uint8_t timestamp[12];
    if (aead_chacha20poly1305_decrypt(temp2, 0, msg->encrypted_timestamp, 28, hash0, 32, timestamp, &dec_len)!=0 || dec_len!=12) return 0;
    uint8_t hash2_input[32+28]; memcpy(hash2_input, hash0,32); memcpy(hash2_input+32, msg->encrypted_timestamp,28);
    blake2s_hash(hash2_input, sizeof hash2_input, hash0);

    /* Generate server ephemeral */
    uint8_t server_eph_priv[32]; randombytes_buf(server_eph_priv, 32);
    server_eph_priv[0] &= 248; server_eph_priv[31] &= 127; server_eph_priv[31] |= 64;
    uint8_t server_eph_pub[32]; crypto_scalarmult_base(server_eph_pub, server_eph_priv);
    uint8_t hash3_input[32+32]; memcpy(hash3_input, hash0,32); memcpy(hash3_input+32, server_eph_pub,32);
    blake2s_hash(hash3_input, sizeof hash3_input, hash0);
    /* ECDH(server_eph_priv, peer_ephemeral) */
    uint8_t dh3[32]; x25519(dh3, server_eph_priv, msg->ephemeral);
    hkdf_blake2s_3(chaining_key, dh3, 32, temp1_ck, temp1, temp2); memcpy(chaining_key, temp1_ck,32);
    /* ECDH(server_eph_priv, peer_static) */
    uint8_t dh4[32]; x25519(dh4, server_eph_priv, peer_static);
    hkdf_blake2s_3(chaining_key, dh4, 32, temp1_ck, temp1, temp2); memcpy(chaining_key, temp1_ck,32);
    /* PSK mix */
    hkdf_blake2s_3(chaining_key, ctx->psk, 32, temp1_ck, temp1, temp2); memcpy(chaining_key, temp1_ck,32);
    /* Get final key for encrypted_nothing (temp2) */
    uint8_t nothing_key[32]; memcpy(nothing_key, temp2, 32);
    uint8_t temp2_input[32+1]; memcpy(temp2_input, temp2,32); temp2_input[32]=0x03; blake2s_hash(temp2_input,33, hash0); /* mimic +temp2 */

    uint8_t encrypted_nothing[16]; size_t enc_len=0;
    aead_chacha20poly1305_encrypt(nothing_key, 0, (const uint8_t*)"", 0, hash0, 32, encrypted_nothing, &enc_len); /* expect 16 tag */

    struct peer_state *peer = state_alloc(msg->sender_index);
    if (!peer) return 0;
    /* Derive final sending/receiving keys: use temp1_ck as chaining_key; then final HKDF */
    uint8_t final_ck[32], recv_key[32], send_key[32];
    hkdf_blake2s_3(chaining_key, (const uint8_t*)"", 0, final_ck, recv_key, send_key);
    memcpy(peer->recv_key, msg->sender_index?recv_key:recv_key, 32); /* order matches python: receiving_key first */
    memcpy(peer->send_key, send_key, 32);

    struct wg_response resp; memset(&resp,0,sizeof resp);
    resp.type = WG_MSG_RESPONSE;
    resp.sender_index = peer->local_index;
    resp.receiver_index = peer->peer_index;
    memcpy(resp.ephemeral, server_eph_pub,32);
    memcpy(resp.encrypted_empty, encrypted_nothing, 16);
    /* mac1 over response first 48? Python calculates MAC over entire header w/out macs (struct size-32) */
    blake2s_key_mac16(ctx->mac1_key, 32, (uint8_t*)&resp, sizeof(resp)-32, resp.mac1);
    memset(resp.mac2, 0,16);
    if (out_max < sizeof resp) return 0;
    memcpy(out, &resp, sizeof resp);
    return sizeof resp;
}

static size_t handle_data(struct wg_context *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max) {
    if (in_len < sizeof(struct wg_data_hdr)+16) return 0;
    const struct wg_data_hdr *hdr = (const struct wg_data_hdr*)in;
    struct peer_state *peer = state_get(hdr->receiver);
    if (!peer) return 0;
    const uint8_t *cipher = in + sizeof *hdr;
    size_t cipher_len = in_len - sizeof *hdr;
    uint8_t plain[1500]; size_t plain_len=0;
    if (aead_chacha20poly1305_decrypt(peer->recv_key, hdr->counter, cipher, cipher_len, NULL, 0, plain, &plain_len)!=0) return 0;
    ip_handle_ipv4(plain, plain_len);
    /* echo back same payload */
    struct wg_data_hdr ohdr; ohdr.type=WG_MSG_DATA; ohdr.receiver=peer->peer_index; ohdr.counter=peer->send_counter++;
    uint8_t cbuf[1600]; size_t clen=0;
    aead_chacha20poly1305_encrypt(peer->send_key, ohdr.counter, plain, plain_len, NULL, 0, cbuf, &clen);
    size_t total = sizeof ohdr + clen;
    if (out_max < total) return 0;
    memcpy(out, &ohdr, sizeof ohdr);
    memcpy(out+sizeof ohdr, cbuf, clen);
    return total;
}

size_t wg_process(struct wg_context *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max) {
    if (in_len < 4) return 0;
    uint32_t type = *(uint32_t*)in;
    switch(type) {
        case WG_MSG_INITIATION: return handle_initiation(ctx, in, in_len, out, out_max);
        case WG_MSG_DATA: return handle_data(ctx, in, in_len, out, out_max);
        default: return 0;
    }
}
