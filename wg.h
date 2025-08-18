#ifndef PVPN_WG_H
#define PVPN_WG_H
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include "x25519.h"

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
	uint8_t mac1_key[32]; /* BLAKE2s("mac1----"||static_pub) */
	int initialized;
	uint32_t server_sender_index; /* our chosen index */
	uint8_t chaining_key[32];
	uint8_t handshake_hash[32];
	uint8_t temp_key[32];
	uint8_t eph_private[32];
	uint8_t eph_public[32];
} wg_context;

void wg_context_init(wg_context *ctx);

int wg_run_stub(uint16_t port, int verbose, const char *key_path);
int wg_load_or_create_static_key(wg_context *ctx, const char *path);

/* MAC1 계산 (context 의 mac1_key 사용) */
void wg_mac1(wg_context *ctx, const uint8_t *packet,size_t len,uint8_t out[16]);
void wg_begin_handshake(wg_context *ctx, const uint8_t client_ephemeral[32]);
void wg_noise_init(wg_context *ctx);
void wg_mix_hash(wg_context *ctx,const uint8_t *data,size_t len);
void wg_mix_key(wg_context *ctx,const uint8_t *ikm,size_t len);

/* Handshake response raw layout (simplified) */
typedef struct {
	uint32_t type;            /* 2 */
	uint32_t sender_index;    /* server index */
	uint32_t receiver_index;  /* client's sender_index */
	uint8_t  ephemeral[WG_KEY_SIZE];
	uint8_t  empty_enc[16];   /* placeholder tag only */
	uint8_t  mac1[WG_MAC_SIZE];
	uint8_t  mac2[WG_MAC_SIZE];
} wg_handshake_response_raw;

int wg_send_handshake_response(wg_context *ctx,int fd,const struct sockaddr_in *peer,const wg_handshake_initiation *hs,int verbose);
#endif
