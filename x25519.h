#ifndef PVPN_X25519_H
#define PVPN_X25519_H
#include <stdint.h>
void x25519_public(const uint8_t priv[32], uint8_t pub[32]);
void x25519_shared(const uint8_t priv[32], const uint8_t pub[32], uint8_t shared[32]);
void x25519_generate_keypair(uint8_t priv[32], uint8_t pub[32]);
#endif
