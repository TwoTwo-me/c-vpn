#include "ikev2_sa.h"
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "enums.h"

static int parse_transform(const uint8_t *p,size_t len, size_t *consumed, ikev2_transform *out){
    if(len < 8) return 0; // header + maybe attrs
    uint8_t more = p[0];
    uint16_t tlen = (p[1]<<8)|p[2];
    if(tlen < 8 || tlen > len) return 0;
    out->transform_type = p[3];
    out->transform_id = (p[6]<<8)|p[7];
    out->key_length = 0;
    // attributes area
    size_t attr_off = 8;
    while(attr_off + 4 <= tlen){
        uint16_t attr = (p[attr_off]<<8)|p[attr_off+1];
        uint16_t val = (p[attr_off+2]<<8)|p[attr_off+3];
        attr_off += 4;
        if(attr == 0x800e){ // KEY_LENGTH (bit 15 set means TV format, id=14)
            out->key_length = val;
        }
    }
    *consumed = tlen;
    return 1;
}

int ikev2_parse_sa(const uint8_t *data,size_t len, ikev2_sa *sa){
    memset(sa,0,sizeof(*sa));
    size_t offset=0; size_t alloc_prop=0; ikev2_proposal *props=NULL;
    while(offset + 4 <= len){
        uint8_t more = data[offset];
        uint16_t plen = (data[offset+1]<<8)|data[offset+2];
        if(plen < 4 || offset+plen > len) goto fail;
        if(plen < 8) goto fail;
        const uint8_t *pp = data+offset+4; size_t remain = plen-4;
        if(remain < 4) goto fail;
        uint8_t pnum = pp[0];
        uint8_t proto = pp[1];
        uint8_t spi_size = pp[2];
        uint8_t tcount = pp[3];
        if(remain < 4 + spi_size) goto fail;
        size_t consumed = 4 + spi_size;
        ikev2_proposal prop; memset(&prop,0,sizeof(prop));
        prop.proposal_num = pnum; prop.protocol_id = proto; prop.spi_size = spi_size; prop.n_transforms = tcount;
        if(spi_size){
            prop.spi = (uint8_t*)malloc(spi_size);
            memcpy(prop.spi, pp+4, spi_size);
        }
        // parse transforms
        size_t tcap=0; ikev2_transform *tlist=NULL; size_t tparsed=0;
        while(consumed < remain){
            size_t tcons=0; ikev2_transform tr;
            if(!parse_transform(pp+consumed, remain-consumed, &tcons, &tr)) goto prop_fail;
            if(tparsed==tcap){ tcap = tcap? tcap*2:4; tlist = (ikev2_transform*)realloc(tlist, tcap*sizeof(*tlist)); }
            tlist[tparsed++] = tr;
            consumed += tcons;
            if(pp[consumed - tcons] == 0) break; // last transform
        }
        prop.transforms = tlist; prop.transform_count = tparsed;
        if(sa->proposal_count == alloc_prop){ alloc_prop = alloc_prop? alloc_prop*2:4; props = (ikev2_proposal*)realloc(props, alloc_prop*sizeof(*props)); }
        props[sa->proposal_count++] = prop;
        offset += plen;
        if(more==0) break; // last proposal
        continue;
prop_fail:
        free(prop.spi); free(tlist); goto fail;
    }
    sa->proposals = props; return 1;
fail:
    ikev2_free_sa(sa); free(props); return 0;
}

void ikev2_free_sa(ikev2_sa *sa){
    if(!sa) return; for(size_t i=0;i<sa->proposal_count;i++){ free(sa->proposals[i].spi); free(sa->proposals[i].transforms);} free(sa->proposals); sa->proposals=NULL; sa->proposal_count=0; }
