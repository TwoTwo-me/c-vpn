#ifndef PVPN_IKEV2_H
#define PVPN_IKEV2_H
#include <stddef.h>
#include <stdint.h>

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

int ikev2_parse_header(const uint8_t *data,size_t len, ikev2_header *hdr);
void ikev2_dump_header(const ikev2_header *h);

#endif
