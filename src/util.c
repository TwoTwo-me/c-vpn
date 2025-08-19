#include "util.h"
#include <stdio.h>
#include <string.h>

void hex_print(const char *label, const uint8_t *data, size_t len) {
    if (label) printf("%s (%zu): ", label, len);
    for (size_t i=0;i<len;i++) printf("%02x", data[i]);
    printf("\n");
}

/* Simple base64 (minimal, not optimized). */
static const char *B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    /* Correct padding implementation: output length = 4 * ceil(n/3) */
    size_t olen = ((in_len + 2)/3)*4;
    if (out_len < olen + 1) return -1;
    size_t i = 0, o = 0;
    while (i < in_len) {
        size_t rem = in_len - i; /* remaining bytes */
        uint32_t v = in[i] << 16;
        if (rem > 1) v |= in[i+1] << 8;
        if (rem > 2) v |= in[i+2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        if (rem > 1) out[o++] = B64[(v >> 6) & 63]; else out[o++] = '=';
        if (rem > 2) out[o++] = B64[v & 63]; else out[o++] = '=';
        i += rem >= 3 ? 3 : rem; /* advance by 1,2,3 */
    }
    out[o] = '\0';
    return (int)o;
}
