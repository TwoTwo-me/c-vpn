/* WireGuard minimal parser (incremental) */
#include "wg.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include "blake2s.h"
#include "x25519.h"

/* Development switch: set to 1 to drop handshake responses when MAC1 mismatch.
 * In production WireGuard MUST verify MAC1 (DoS mitigation).
 */
#ifndef WG_REQUIRE_MAC1
#define WG_REQUIRE_MAC1 0
#endif

/* 매우 단순한 WireGuard 서버 스텁: 수신 패킷 길이/출력만 수행.
 * 실제 WireGuard 핸드셰이크(메시지 타입 1/2/4), NoiseIK 해시체인, 키 파생, AEAD(ChaCha20-Poly1305) 전혀 미구현.
 * 포트 바인딩 후 블로킹 recvfrom 루프; SIGINT 시 종료.
 */

int wg_parse_handshake_initiation(const unsigned char *data,size_t len,wg_handshake_initiation *out){
    if(len < sizeof(wg_handshake_initiation_raw)) return 0;
    const wg_handshake_initiation_raw *raw = (const wg_handshake_initiation_raw*)data;
    if(raw->type != WG_MSG_TYPE_HANDSHAKE_INITIATION) return 0;
    out->sender_index = raw->sender_index; /* little-endian already in struct layout for host assumed LE; adjust if BE */
    memcpy(out->ephemeral, raw->ephemeral, WG_KEY_SIZE);
    out->static_enc    = raw->static_enc;
    out->timestamp_enc = raw->timestamp_enc;
    out->mac1          = raw->mac1;
    out->mac2          = raw->mac2;
    out->mac2_present = 0;
    for(int i=0;i<WG_MAC_SIZE;i++){ if(raw->mac2[i]!=0){ out->mac2_present=1; break; } }
    return 1;
}

static void dump_hex(const char *label,const uint8_t *p,size_t n,size_t limit){
    fprintf(stderr,"%s=", label);
    size_t m = n<limit? n:limit;
    for(size_t i=0;i<m;i++) fprintf(stderr,"%02x", p[i]);
    if(m<n) fprintf(stderr,"...");
}

static void b64_encode(const uint8_t *in,size_t inlen,char *out,size_t *outlen){
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = 4 * ((inlen + 2) / 3);
    if(*outlen < need + 1){ *outlen = 0; return; }
    size_t op=0; size_t i=0;
    while(i < inlen){
        uint32_t v = (uint32_t)in[i++] << 16;
        int have2 = 0, have3 = 0;
        if(i < inlen){ v |= (uint32_t)in[i++] << 8; have2=1; }
        if(i < inlen){ v |= in[i++]; have3=1; }
        out[op++] = tbl[(v>>18)&63];
        out[op++] = tbl[(v>>12)&63];
        out[op++] = have2 ? tbl[(v>>6)&63] : '=';
        out[op++] = have3 ? tbl[v&63] : '=';
    }
    out[op]=0; *outlen=op;
}

/* MAC1 = BLAKE2s(key=mac1_key, data=packet_without_mac1_mac2) truncated 16
 * 즉, 패킷 끝의 mac1(16)+mac2(16) 32바이트를 제외한 나머지. */
void wg_mac1(wg_context *ctx, const uint8_t *packet,size_t len,uint8_t out[16]){
     size_t trailer = 2*WG_MAC_SIZE; /* mac1 + mac2 */
     size_t data_len = (len>trailer)? (len - trailer) : len;
    if(data_len > len) data_len = len; /* safety */
    uint8_t full[32];
    blake2s_keyed(ctx->mac1_key, 32, packet, data_len, full);
    memcpy(out, full, 16);
}

void wg_begin_handshake(wg_context *ctx, const uint8_t client_ephemeral[32]){
    /* Placeholder: update chaining_key = BLAKE2s(chaining_key || client_ephemeral) */
    uint8_t buf[64];
    memcpy(buf, ctx->chaining_key, 32);
    memcpy(buf+32, client_ephemeral, 32);
    blake2s(buf, 64, ctx->chaining_key);
    /* Placeholder DH: XOR server eph_public with client ephemeral → mix_key */
    uint8_t dh[32];
    for(int i=0;i<32;i++) dh[i] = ctx->eph_public[i] ^ client_ephemeral[i];
    wg_mix_key(ctx, dh, 32);
}

void wg_context_init(wg_context *ctx){
    if(ctx->initialized) return;
    x25519_generate_keypair(ctx->static_private, ctx->static_public);
    /* mac1_key 파생 (라벨 + static_pub) */
    uint8_t label[] = { 'm','a','c','1','-','-','-','-' };
    blake2s_state S; blake2s_init(&S,32); blake2s_update(&S,label,sizeof(label)); blake2s_update(&S,ctx->static_public,WG_KEY_SIZE); blake2s_final(&S,ctx->mac1_key,32);
    /* choose server sender index (random) */
    ctx->server_sender_index = ((uint32_t)ctx->static_private[0]<<24) ^ ((uint32_t)ctx->static_private[1]<<16) ^ ((uint32_t)ctx->static_private[2]<<8) ^ ctx->static_private[3];
    /* Initialize Noise seeds */
    wg_noise_init(ctx);
    memset(ctx->temp_key,0,32);
    /* ephemeral placeholder (reuse static for now) */
    x25519_generate_keypair(ctx->eph_private, ctx->eph_public);
    ctx->initialized=1;
}

void wg_noise_init(wg_context *ctx){
    static const char proto[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    blake2s((const uint8_t*)proto, sizeof(proto)-1, ctx->chaining_key);
    memcpy(ctx->handshake_hash, ctx->chaining_key, 32);
}

void wg_mix_hash(wg_context *ctx,const uint8_t *data,size_t len){
    uint8_t buf[64]; if(len>32) len=32;
    memcpy(buf, ctx->handshake_hash, 32);
    memcpy(buf+32, data, len);
    blake2s(buf, 32+len, ctx->handshake_hash);
}

void wg_mix_key(wg_context *ctx,const uint8_t *ikm,size_t len){
    uint8_t buf[64]; if(len>32) len=32;
    memcpy(buf, ctx->chaining_key, 32);
    memcpy(buf+32, ikm, len);
    blake2s(buf, 32+len, ctx->chaining_key);
    blake2s(ctx->chaining_key,32,ctx->temp_key);
}

int wg_load_or_create_static_key(wg_context *ctx, const char *path){
    if(!path) return 0; /* not used */
    FILE *f = fopen(path,"rb");
    uint8_t priv[32];
    if(f){
        size_t r=fread(priv,1,32,f); fclose(f);
        if(r!=32){ fprintf(stderr,"[wg] key file size invalid (expected 32)\n"); return -1; }
        memcpy(ctx->static_private, priv, 32);
        x25519_public(ctx->static_private, ctx->static_public);
        fprintf(stderr,"[wg] loaded static key from %s\n", path);
        return 0;
    }
    /* create */
    x25519_generate_keypair(ctx->static_private, ctx->static_public);
    f = fopen(path,"wb"); if(!f){ perror("[wg] fopen create key"); return -1; }
    if(fwrite(ctx->static_private,1,32,f)!=32){ perror("[wg] write key"); fclose(f); return -1; }
    /* best-effort permission tighten */
#ifdef __unix__
    fchmod(fileno(f),0600);
#endif
    fclose(f);
    fprintf(stderr,"[wg] created new static key at %s\n", path);
    return 0;
}

int wg_run_stub(uint16_t port, int verbose, const char *key_path){
    wg_context ctx={0}; wg_context_init(&ctx); /* generates random first */
    if(key_path){
        if(wg_load_or_create_static_key(&ctx,key_path)==0){
            /* recompute mac1_key with loaded static_public */
            uint8_t label[] = { 'm','a','c','1','-','-','-','-' }; blake2s_state S; blake2s_init(&S,32); blake2s_update(&S,label,sizeof(label)); blake2s_update(&S,ctx.static_public,WG_KEY_SIZE); blake2s_final(&S,ctx.mac1_key,32);
        }
    }
    /* Print static public key always (hex + base64) so client config 가능 */
    {
        char b64[128]; size_t blen=sizeof(b64);
        b64_encode(ctx.static_public, WG_KEY_SIZE, b64, &blen);
        fprintf(stderr,"[wg] static public key (hex) : ");
        for(int i=0;i<WG_KEY_SIZE;i++) fprintf(stderr,"%02x", ctx.static_public[i]);
        fprintf(stderr,"\n[wg] static public key (b64) : %s\n", b64);
        if(verbose){
            char privb64[128]; size_t prlen=sizeof(privb64); b64_encode(ctx.static_private, WG_KEY_SIZE, privb64, &prlen);
            fprintf(stderr,"[wg] static private key (b64, keep secret) : %s\n", privb64);
        }
        if(key_path) fprintf(stderr,"[wg] private key file       : %s (raw 32-byte private)\n", key_path);
        else fprintf(stderr,"[wg] private key ephemeral (not saved)\n");
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd<0){ perror("socket"); return 1; }
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); close(fd); return 1; }
    fprintf(stderr,"[wg] listening on UDP :%u (stub)\n", port);
    unsigned char buf[2048];
    size_t pkt_count=0;
    time_t last_heartbeat = 0;
    while(1){
        struct sockaddr_in peer; socklen_t plen=sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,(struct sockaddr*)&peer,&plen);
        if(n<0){ if(errno==EINTR) break; perror("recvfrom"); break; }
        if(n==0) continue;
        uint32_t mtype = *(uint32_t*)buf; /* little-endian 환경 가정 */
        pkt_count++;
        /* Generic packet throttle: print every 50th unless verbose. */
        if(verbose || (pkt_count % 50 == 1)){
            fprintf(stderr,"[wg] packet %zd bytes from %s:%u type=%u (count=%zu)\n", n, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port), mtype, pkt_count);
        }
        if(mtype == WG_MSG_TYPE_HANDSHAKE_INITIATION){
            wg_handshake_initiation hs;
            if(wg_parse_handshake_initiation(buf,n,&hs)){
                /* Always print a one-line summary for every handshake initiation (even without -v)
                   so 사용자가 재전송 여부를 즉시 확인 가능 */
                int mac1_zero=1; for(int i=0;i<WG_MAC_SIZE;i++) if(hs.mac1[i]) { mac1_zero=0; break; }
                uint8_t calc_mac1[16];
                wg_mac1(&ctx, buf, (size_t)n, calc_mac1);
                int mac1_match = memcmp(calc_mac1, hs.mac1, 16)==0;
                size_t trailer = 2*WG_MAC_SIZE; size_t data_len = (size_t)n>trailer? (size_t)n - trailer : (size_t)n;
                fprintf(stderr,"[wg] HS1 sender=%u mac1_zero=%d mac1_match=%d mac2=%s data_len=%zu total=%zd\n",
                        hs.sender_index, mac1_zero, mac1_match, hs.mac2_present?"present":"none", data_len, n);
                if(verbose){
                    if(!mac1_match){
                        fprintf(stderr,"  mac1 debug covered-bytes (first 64 of %zu): ", data_len);
                        size_t lim = data_len<64?data_len:64; for(size_t ii=0; ii<lim; ++ii) fprintf(stderr,"%02x", buf[ii]); fprintf(stderr,"\n");
                    }
                    dump_hex("  ephem", hs.ephemeral, WG_KEY_SIZE, 16); fprintf(stderr,"\n");
                    dump_hex("  static_enc", hs.static_enc, WG_KEY_SIZE+16, 16); fprintf(stderr,"\n");
                    dump_hex("  timestamp_enc", hs.timestamp_enc, 12+16, 12); fprintf(stderr,"\n");
                    dump_hex("  mac1_recv", hs.mac1, WG_MAC_SIZE, WG_MAC_SIZE); fprintf(stderr,"\n");
                    dump_hex("  mac1_calc", calc_mac1, 16, 16); fprintf(stderr,"\n");
                    dump_hex("  server_static_pub", ctx.static_public, WG_KEY_SIZE, 16); fprintf(stderr,"\n");
                    dump_hex("  chain_key_pre", ctx.chaining_key, 32, 16); fprintf(stderr," (pre-mix shown before update?)\n");
                }
                if(mac1_match || !WG_REQUIRE_MAC1){
                    if(!mac1_match && !WG_REQUIRE_MAC1 && verbose){
                        fprintf(stderr,"[wg] WARNING: accepting handshake with MAC1 mismatch (dev mode)\n");
                    }
                    wg_begin_handshake(&ctx, hs.ephemeral);
                    if(verbose){ dump_hex("  chain_key_post", ctx.chaining_key, 32, 16); fprintf(stderr,"\n"); }
                    wg_send_handshake_response(&ctx, fd, &peer, &hs, verbose);
                } else {
                    if(verbose) fprintf(stderr,"[wg] dropped handshake (MAC1 mismatch)\n");
                }
            } else if(verbose){
                fprintf(stderr,"[wg] malformed handshake initiation\n");
            }
        }
        /* Heartbeat (idle indication) every ~5s even if no verbose, to show loop alive */
        time_t now = time(NULL);
        if(now - last_heartbeat >= 5){
            fprintf(stderr,"[wg] heartbeat alive (pkts=%zu)\n", pkt_count);
            last_heartbeat = now;
        }
    }
    close(fd);
    return 0;
}

int wg_send_handshake_response(wg_context *ctx,int fd,const struct sockaddr_in *peer,const wg_handshake_initiation *hs,int verbose){
    wg_handshake_response_raw resp;
    memset(&resp,0,sizeof(resp));
    resp.type = WG_MSG_TYPE_HANDSHAKE_RESPONSE;
    resp.sender_index = ctx->server_sender_index; /* little-endian assumption */
    resp.receiver_index = hs->sender_index; /* reflect client's sender index */
    /* ephemeral: placeholder copy of server static (should be fresh X25519 ephemeral) */
    memcpy(resp.ephemeral, ctx->static_public, WG_KEY_SIZE);
    /* empty_enc left zero + tag placeholder (not valid) */
    /* mac1: compute keyed blake2s over packet without mac2 */
    wg_mac1(ctx,(uint8_t*)&resp,sizeof(resp),resp.mac1);
    /* mac2 all zero */
    ssize_t sent = sendto(fd,&resp,sizeof(resp),0,(const struct sockaddr*)peer,sizeof(*peer));
    if(sent!=(ssize_t)sizeof(resp)){
        if(verbose) perror("sendto resp");
        return -1;
    }
    if(verbose) fprintf(stderr,"[wg] sent handshake response (dummy) to %s:%u\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
    return 0;
}
