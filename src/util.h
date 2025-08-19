#ifndef UTIL_H
#define UTIL_H
#include <stdint.h>
#include <stddef.h>

void hex_print(const char *label, const uint8_t *data, size_t len);
int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len); /* returns length or -1 */

#endif
