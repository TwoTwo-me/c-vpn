#ifndef IP_HANDLER_H
#define IP_HANDLER_H
#include <stddef.h>
#include <stdint.h>

/* For parity we simply dump IPv4 packets length */
void ip_handle_ipv4(const uint8_t *pkt, size_t len);

#endif
