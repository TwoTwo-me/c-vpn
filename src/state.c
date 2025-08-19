#include "state.h"
#include <string.h>

static struct peer_state peers[MAX_PEERS];
static uint32_t next_index = 0;

void state_init(void) {
    memset(peers, 0, sizeof(peers));
    next_index = 0;
}

struct peer_state *state_alloc(uint32_t peer_index) {
    for (int i=0;i<MAX_PEERS;i++) if (!peers[i].used) {
        peers[i].used=1;
        peers[i].local_index = next_index++;
        peers[i].peer_index = peer_index;
        peers[i].send_counter = 0;
        return &peers[i];
    }
    return NULL;
}

struct peer_state *state_get(uint32_t local_index) {
    for (int i=0;i<MAX_PEERS;i++) if (peers[i].used && peers[i].local_index==local_index) return &peers[i];
    return NULL;
}
