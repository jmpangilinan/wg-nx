#ifndef BLAKE2S_NEON_H
#define BLAKE2S_NEON_H

#include <stdint.h>
#include <stddef.h>

int blake2s_neon_available(void);

void blake2s_compress_neon(uint32_t h[8], const uint8_t block[64], uint32_t t0, uint32_t t1, uint32_t f0, uint32_t f1);

#endif
