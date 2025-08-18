#include "message.h"
#include <string.h>
#include <stdio.h>

int ikev2_iter_payloads(const uint8_t *data,size_t len, ikev2_payload_iter_cb cb, void *user){
    if(len < 28) return 0;
    uint8_t next = data[16];
    size_t offset = 28;
    while(next!=0 && offset+4 <= len){
        if(offset+4 > len) return 0;
        uint8_t np = data[offset];
        uint8_t flags = data[offset+1];
        uint16_t plen = (data[offset+2]<<8)|data[offset+3];
        if(plen < 4 || offset+plen > len) return 0;
        if(!cb(next, flags, data+offset+4, plen-4, user)) return 1;
        next = np; offset += plen;
    }
    return 1;
}
