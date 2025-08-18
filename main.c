#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ikev2.h"
#include "esp.h"
#include "ipv4.h"
#include "util.h"
#include "wg.h"
#include <getopt.h>

int main(int argc, char **argv){
    int wg_port = 0; int verbose=0; const char *wg_key_path=NULL;
    /* 옵션: -wg <port> -wgkey <file> -v */
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-wg")==0 && i+1<argc){ wg_port = atoi(argv[++i]); }
        else if(strcmp(argv[i],"-wgkey")==0 && i+1<argc){ wg_key_path = argv[++i]; }
        else if(strcmp(argv[i],"-v")==0){ verbose++; }
    }
    printf("pvpn C 포팅 데모 (부분 기능)\n");
    // 데모: 가짜 IKEv2 헤더 파싱
    uint8_t demo[28]={0};
    demo[16]=46; // SK payload
    demo[17]=0x20; // version 2.0
    demo[18]=34; // IKE_SA_INIT
    demo[19]=0x08; // Initiator flag
    write_be32(demo+20, 1);
    write_be32(demo+24, 28);
    ikev2_header h; ikev2_parse_header(demo,sizeof(demo),&h); ikev2_dump_header(&h);

    // 데모: IPv4 패킷 생성
    uint8_t pkt[1500];
    uint8_t payload[]="HELLO";
    size_t pklen = ipv4_make(pkt,sizeof(pkt),17, htonl(0x0a000001), htonl(0x08080808), payload, sizeof(payload)-1);
    printf("IPv4 packet length=%zu checksum=0x%04x\n", pklen, (unsigned) (pkt[10]<<8|pkt[11]));

    // 데모: ESP 암호화 (패딩/무작위 IV 생략)
    uint8_t esp_out[2048]; size_t esp_len=sizeof(esp_out);
    uint8_t key[16]={0}; uint8_t iv[16]={0}; uint8_t auth_key[32]={0};
    if(esp_encrypt(0x11111111,1,key,iv,payload,sizeof(payload)-1,esp_out,&esp_len,auth_key,sizeof(auth_key))){
        printf("ESP encrypted len=%zu\n", esp_len);
    }
    if(wg_port){
        printf("WireGuard stub 시작: 포트 %d\n", wg_port);
        wg_run_stub((uint16_t)wg_port, verbose, wg_key_path);
    }
    printf("완료\n");
    return 0;
}
