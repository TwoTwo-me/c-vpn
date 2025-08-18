#ifndef PVPN_MESSAGE_H
#define PVPN_MESSAGE_H
#include <stdint.h>
#include <stddef.h>
#include "enums.h"

typedef int (*ikev2_payload_iter_cb)(uint8_t payload_type,uint8_t flags,const uint8_t *body,uint16_t body_len, void *user);
int ikev2_iter_payloads(const uint8_t *data,size_t len, ikev2_payload_iter_cb cb, void *user);

#endif
