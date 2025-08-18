#include <stdint.h>
#include <string.h>
#include "util.h"

/* IPv4 header 생성 및 간단 파서 */

size_t ipv4_make(uint8_t *out,size_t outlen,uint8_t proto,uint32_t src,uint32_t dst,const uint8_t *payload,size_t plen){
    if(outlen < 20+plen) return 0;
    memset(out,0,20);
    out[0]=0x45; // version=4, IHL=5
    write_be16(out+2, (uint16_t)(20+plen));
    out[8]=64; // TTL
    out[9]=proto; // protocol
    memcpy(out+12,&src,4); memcpy(out+16,&dst,4);
    uint16_t csum = ipv4_checksum(out,20);
    write_be16(out+10, csum);
    memcpy(out+20,payload,plen);
    return 20+plen;
}
