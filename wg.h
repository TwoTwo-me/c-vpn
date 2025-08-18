#ifndef PVPN_WG_H
#define PVPN_WG_H
#include <stdint.h>
#include <stddef.h>

/* WireGuard handshake message types */
#define WG_MSG_TYPE_HANDSHAKE_INITIATION 1
#define WG_MSG_TYPE_HANDSHAKE_RESPONSE   2
#define WG_MSG_TYPE_DATA                 4

/* Fixed sizes (WireGuard spec) */
#define WG_KEY_SIZE 32
#define WG_MAC_SIZE 16

typedef struct {
	uint32_t type;              /* 1 */
	uint32_t sender_index;      /* little-endian */
	uint8_t  ephemeral[WG_KEY_SIZE];
	uint8_t  static_enc[WG_KEY_SIZE + 16]; /* encrypted static pub + tag */
	uint8_t  timestamp_enc[12 + 16];       /* encrypted timestamp + tag */
	uint8_t  mac1[WG_MAC_SIZE];
	uint8_t  mac2[WG_MAC_SIZE]; /* optional (all zero if unused) */
} wg_handshake_initiation_raw;

/* Parsed view (no decryption yet) */
typedef struct {
	uint32_t sender_index;
	uint8_t  ephemeral[WG_KEY_SIZE];
	const uint8_t *static_enc;      /* pointer into packet */
	const uint8_t *timestamp_enc;   /* pointer into packet */
	const uint8_t *mac1;            /* pointer into packet */
	const uint8_t *mac2;            /* pointer into packet */
	int mac2_present;               /* heuristic: any non-zero byte */
} wg_handshake_initiation;

int wg_parse_handshake_initiation(const uint8_t *data,size_t len,wg_handshake_initiation *out);

typedef struct {
	uint8_t static_private[WG_KEY_SIZE];
	uint8_t static_public[WG_KEY_SIZE]; /* placeholder: currently copies private (X25519 미구현) */
	int initialized;
} wg_context;

void wg_context_init(wg_context *ctx);

int wg_run_stub(uint16_t port, int verbose);
#endif
