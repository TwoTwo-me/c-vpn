#ifndef WIREGUARD_H
#define WIREGUARD_H
#include <stdint.h>
#include <stddef.h>
#include "crypto.h"
#include "state.h"

struct wg_context {
    struct crypto_keys keys;      /* static server keys */
    uint8_t psk[32];              /* all zero */
    uint8_t mac1_key[32];         /* HASH("mac1----" + server_pub) */
};

void wg_init(struct wg_context *ctx, const char *password);
/* Process single UDP datagram; output (if any) is written into out buffer.
 * Returns length of response or 0 for none.
 */
size_t wg_process(struct wg_context *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max);

#endif
