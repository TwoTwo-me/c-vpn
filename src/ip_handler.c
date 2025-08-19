#include "ip_handler.h"
#include <stdio.h>

void ip_handle_ipv4(const uint8_t *pkt, size_t len) {
    if (len < 20) return; /* minimal */
    printf("IPv4 packet len=%zu\n", len);
}
