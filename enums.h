#ifndef PVPN_ENUMS_H
#define PVPN_ENUMS_H
#include <stdint.h>

typedef enum {
	EXCHANGE_IKE_SA_INIT=34,
	EXCHANGE_IKE_AUTH=35,
	EXCHANGE_CREATE_CHILD_SA=36,
	EXCHANGE_INFORMATIONAL=37,
	EXCHANGE_IKE_SESSION_RESUME=38
} ikev2_exchange_t;

typedef enum {
	PAYLOAD_NONE=0,
	PAYLOAD_SA=33,
	PAYLOAD_KE=34,
	PAYLOAD_IDi=35,
	PAYLOAD_IDr=36,
	PAYLOAD_CERT=37,
	PAYLOAD_CERTREQ=38,
	PAYLOAD_AUTH=39,
	PAYLOAD_NONCE=40,
	PAYLOAD_NOTIFY=41,
	PAYLOAD_DELETE=42,
	PAYLOAD_VENDOR=43,
	PAYLOAD_TSi=44,
	PAYLOAD_TSr=45,
	PAYLOAD_SK=46,
	PAYLOAD_CP=47,
	PAYLOAD_EAP=48
} ikev2_payload_type_t;

typedef enum {
	TRANSFORM_ENCR=1,
	TRANSFORM_PRF=2,
	TRANSFORM_INTEG=3,
	TRANSFORM_DH=4,
	TRANSFORM_ESN=5
} ikev2_transform_type_t;

typedef enum { PROTO_NONE=0, PROTO_IKE=1, PROTO_AH=2, PROTO_ESP=3 } ikev2_protocol_id_t;

typedef enum { ENCR_AES_CBC=12, ENCR_CHACHA20_POLY1305=28 } ikev2_encr_id_t; /* subset */
typedef enum { PRF_HMAC_SHA2_256=5 } ikev2_prf_id_t; /* subset */
typedef enum { INTEG_HMAC_SHA2_256_128=12 } ikev2_integ_id_t; /* subset */
typedef enum { DH_14=14, DH_19=19, DH_20=20, DH_21=21 } ikev2_dh_id_t; /* subset */

#endif
