/* Minimal BLAKE2s (subset) for WireGuard MAC1 & chaining key hash.
 * NOTE: Simplified, NOT constant-time; suitable only for prototyping.
 */
#ifndef PVPN_BLAKE2S_H
#define PVPN_BLAKE2S_H
#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_OUTBYTES 32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[64];
    size_t   buflen;
} blake2s_state;

int blake2s_init(blake2s_state *S, size_t outlen); /* only 32 supported */
int blake2s_update(blake2s_state *S, const void *pin, size_t inlen);
int blake2s_final(blake2s_state *S, void *out, size_t outlen);

/* Convenience: compute hash of single buffer */
void blake2s(const uint8_t *in,size_t inlen,uint8_t out[32]);

#endif
