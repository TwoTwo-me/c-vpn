#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "util.h"
/* IKEv2 Header 파싱 & 간단 덤프 (Payload 처리 Stub) */

/* IKEv2 Header (RFC 7296) */
/* 0..7  Initiator SPI
 * 8..15 Responder SPI
 * 16   Next Payload
 * 17   Version
 * 18   Exchange Type
 * 19   Flags
 * 20..23 Message ID
 * 24..27 Length
 */

typedef struct {
    uint8_t initiator_spi[8];
    uint8_t responder_spi[8];
    uint8_t next_payload;
    uint8_t version;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
} ikev2_header;

int ikev2_parse_header(const uint8_t *data,size_t len, ikev2_header *hdr){
    if(len<28) return 0;
    memcpy(hdr->initiator_spi,data,8);
    memcpy(hdr->responder_spi,data+8,8);
    hdr->next_payload = data[16];
    hdr->version = data[17];
    hdr->exchange_type = data[18];
    hdr->flags = data[19];
    hdr->message_id = read_be32(data+20);
    hdr->length = read_be32(data+24);
    return 1;
}

void ikev2_dump_header(const ikev2_header *h){
    printf("IKEv2: ver=%u exch=%u flags=0x%02X msgid=%u len=%u\n", h->version, h->exchange_type, h->flags, h->message_id, h->length);
}
