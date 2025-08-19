#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include "wireguard.h"
#include "state.h"
#include <sodium.h>

static void usage(const char *p){
    fprintf(stderr, "Usage: %s -p <password> -l <listen_port>\n", p);
}

int main(int argc, char **argv){
    const char *password = "test";
    int port = 51820;
    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"-p") && i+1<argc) password = argv[++i];
        else if (!strcmp(argv[i],"-l") && i+1<argc) port = atoi(argv[++i]);
        else { usage(argv[0]); return 1; }
    }

#ifndef _WIN32
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock<0){perror("socket");return 1;}
    struct sockaddr_in addr; memset(&addr,0,sizeof addr);
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
    if (bind(sock,(struct sockaddr*)&addr,sizeof addr)<0){perror("bind");return 1;}
#else
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr; memset(&addr,0,sizeof addr);
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
    bind(sock,(struct sockaddr*)&addr,sizeof addr);
#endif

    if (sodium_init()<0){fprintf(stderr,"libsodium init failed\n");return 1;}
    state_init();
    struct wg_context ctx; wg_init(&ctx, password);
    printf("Listening UDP :%d (minimal stub)\n", port);

    uint8_t inbuf[2048]; uint8_t outbuf[2048];
    while (1){
        struct sockaddr_in caddr; socklen_t clen=sizeof caddr;
        ssize_t r = recvfrom(sock,(char*)inbuf,sizeof inbuf,0,(struct sockaddr*)&caddr,&clen);
        if (r<=0) continue;
        size_t olen = wg_process(&ctx, inbuf, (size_t)r, outbuf, sizeof outbuf);
        if (olen>0){
            sendto(sock,(char*)outbuf,olen,0,(struct sockaddr*)&caddr,clen);
        }
    }
    return 0;
}
