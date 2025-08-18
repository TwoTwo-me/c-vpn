#ifndef PVPN_IPV4_H
#define PVPN_IPV4_H
#include <stdint.h>
#include <stddef.h>
size_t ipv4_make(uint8_t *out,size_t outlen,uint8_t proto,uint32_t src,uint32_t dst,const uint8_t *payload,size_t plen);
#endif
