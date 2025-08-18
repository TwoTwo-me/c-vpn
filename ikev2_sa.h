#ifndef PVPN_IKEV2_SA_H
#define PVPN_IKEV2_SA_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t transform_type; /* ikev2_transform_type_t */
    uint16_t transform_id;  /* e.g. ENCR_AES_CBC */
    uint16_t key_length;    /* optional, 0 if absent */
} ikev2_transform;

typedef struct {
    uint8_t proposal_num;
    uint8_t protocol_id; /* ikev2_protocol_id_t */
    uint8_t spi_size;
    uint8_t n_transforms; /* raw count in header */
    uint8_t *spi; /* length spi_size */
    ikev2_transform *transforms; /* dynamic list */
    size_t transform_count; /* number of parsed transforms */
} ikev2_proposal;

typedef struct {
    ikev2_proposal *proposals;
    size_t proposal_count;
} ikev2_sa;

int ikev2_parse_sa(const uint8_t *data,size_t len, ikev2_sa *sa);
void ikev2_free_sa(ikev2_sa *sa);

#endif
