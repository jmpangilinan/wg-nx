#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_HASH_SIZE 32
#define BLAKE2S_KEY_SIZE 32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[BLAKE2S_BLOCK_SIZE];
    size_t buflen;
    size_t outlen;
} blake2s_state;

void blake2s_init(blake2s_state *S, size_t outlen);
void blake2s_init_key(blake2s_state *S, size_t outlen, const void *key, size_t keylen);
void blake2s_update(blake2s_state *S, const void *in, size_t inlen);
void blake2s_final(blake2s_state *S, void *out);

void blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

#endif
