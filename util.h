#ifndef PVPN_UTIL_H
#define PVPN_UTIL_H
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define CHECK(cond,msg) do{ if(!(cond)){ fprintf(stderr,"[!] %s:%d %s\n", __FILE__, __LINE__, msg); exit(1);} }while(0)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

static inline uint16_t read_be16(const uint8_t *p){ return (uint16_t)p[0]<<8 | p[1]; }
static inline uint32_t read_be32(const uint8_t *p){ return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static inline void write_be16(uint8_t *p, uint16_t v){ p[0]=v>>8; p[1]=v; }
static inline void write_be32(uint8_t *p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

uint16_t ipv4_checksum(const uint8_t *data, size_t len);

#endif
