#ifndef STATE_H
#define STATE_H
#include <stdint.h>
#include <stddef.h>

#define MAX_PEERS 64

struct peer_state {
    uint32_t local_index;    /* server sender index */
    uint32_t peer_index;     /* peer sender index */
    uint8_t  recv_key[32];
    uint8_t  send_key[32];
    uint64_t send_counter;   /* next outbound counter */
    int used;
};

void state_init(void);
struct peer_state *state_alloc(uint32_t peer_index);
struct peer_state *state_get(uint32_t local_index);

#endif
