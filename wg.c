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

/* MAC1 계산: 실제로는 BLAKE2s(key=mac1_key, data=packet_without_mac2) → 16바이트.
 * 현재는 key 파라미터 전달 대신, 단순 무키 버전 (임시). 추후 ctx 전달 구조로 변경 가능. */
void wg_mac1(const uint8_t *packet,size_t len,uint8_t out[16]){
    uint8_t full[32];
    blake2s(packet, len - WG_MAC_SIZE, full);
    memcpy(out, full, 16);
}

void wg_context_init(wg_context *ctx){
    if(ctx->initialized) return;
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd>=0){ read(fd, ctx->static_private, WG_KEY_SIZE); close(fd);} else { for(int i=0;i<WG_KEY_SIZE;i++) ctx->static_private[i]=(uint8_t)(rand()&0xFF); }
    memcpy(ctx->static_public, ctx->static_private, WG_KEY_SIZE); /* placeholder (no X25519) */
    /* mac1_key 파생 (라벨 + static_pub) */
    uint8_t label[] = { 'm','a','c','1','-','-','-','-' };
    blake2s_state S; blake2s_init(&S,32); blake2s_update(&S,label,sizeof(label)); blake2s_update(&S,ctx->static_public,WG_KEY_SIZE); blake2s_final(&S,ctx->mac1_key,32);
    ctx->initialized=1;
}

int wg_run_stub(uint16_t port, int verbose){
    wg_context ctx={0}; wg_context_init(&ctx);
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
                wg_mac1(buf, (size_t)n, calc_mac1);
                int mac1_match = memcmp(calc_mac1, hs.mac1, 16)==0;
                fprintf(stderr,"[wg] HS1 sender=%u mac1_zero=%d mac1_match(proto)=%d mac2=%s (count=%zu)\n",
                        hs.sender_index, mac1_zero, mac1_match, hs.mac2_present?"present":"none", pkt_count);
                if(verbose){
                    dump_hex("  ephem", hs.ephemeral, WG_KEY_SIZE, 16); fprintf(stderr,"\n");
                    dump_hex("  static_enc", hs.static_enc, WG_KEY_SIZE+16, 16); fprintf(stderr,"\n");
                    dump_hex("  timestamp_enc", hs.timestamp_enc, 12+16, 12); fprintf(stderr,"\n");
                    dump_hex("  mac1_recv", hs.mac1, WG_MAC_SIZE, WG_MAC_SIZE); fprintf(stderr,"\n");
                    dump_hex("  mac1_calc", calc_mac1, 16, 16); fprintf(stderr,"\n");
                    dump_hex("  server_static_pub", ctx.static_public, WG_KEY_SIZE, 16); fprintf(stderr,"\n");
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
