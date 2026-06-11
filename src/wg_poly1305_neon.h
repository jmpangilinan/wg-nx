#ifndef WG_POLY1305_NEON_H
#define WG_POLY1305_NEON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t r[5];
    uint32_t s[4];
    uint32_t acc[5];
    uint8_t buf[16];
    size_t buf_len;
} wg_poly1305_ctx;

void wg_poly1305_init(wg_poly1305_ctx *ctx, const uint8_t key[32]);
void wg_poly1305_update(wg_poly1305_ctx *ctx, const uint8_t *data, size_t len);
void wg_poly1305_final(wg_poly1305_ctx *ctx, uint8_t tag[16]);

void wg_poly1305(uint8_t tag[16], const uint8_t *data, size_t len, const uint8_t key[32]);

#ifdef __cplusplus
}
#endif

#endif
