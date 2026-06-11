#include "wg_poly1305_neon.h"
#include <string.h>

#if defined(__aarch64__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define HAS_NEON 1
#else
#define HAS_NEON 0
#endif

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void wg_poly1305_init(wg_poly1305_ctx *ctx, const uint8_t key[32]) {
    uint8_t r[16];
    memcpy(r, key, 16);
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[12] &= 0xfc;

    uint32_t t0 = load32_le(r + 0);
    uint32_t t1 = load32_le(r + 4);
    uint32_t t2 = load32_le(r + 8);
    uint32_t t3 = load32_le(r + 12);

    ctx->r[0] = t0 & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    ctx->r[4] = (t3 >> 8);

    ctx->s[0] = load32_le(key + 16);
    ctx->s[1] = load32_le(key + 20);
    ctx->s[2] = load32_le(key + 24);
    ctx->s[3] = load32_le(key + 28);

    ctx->acc[0] = 0;
    ctx->acc[1] = 0;
    ctx->acc[2] = 0;
    ctx->acc[3] = 0;
    ctx->acc[4] = 0;

    ctx->buf_len = 0;
}

#if HAS_NEON

static void poly1305_block_neon(wg_poly1305_ctx *ctx, const uint8_t *data, uint32_t hibit) {
    uint32_t t0 = load32_le(data + 0);
    uint32_t t1 = load32_le(data + 4);
    uint32_t t2 = load32_le(data + 8);
    uint32_t t3 = load32_le(data + 12);

    uint64_t a0 = (uint64_t)ctx->acc[0] + (t0 & 0x3ffffff);
    uint64_t a1 = (uint64_t)ctx->acc[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
    uint64_t a2 = (uint64_t)ctx->acc[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    uint64_t a3 = (uint64_t)ctx->acc[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    uint64_t a4 = (uint64_t)ctx->acc[4] + ((t3 >> 8) | (hibit << 24));

    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];

    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    uint32x2_t va0 = vdup_n_u32((uint32_t)a0);
    uint32x2_t va1 = vdup_n_u32((uint32_t)a1);
    uint32x2_t va2 = vdup_n_u32((uint32_t)a2);
    uint32x2_t va3 = vdup_n_u32((uint32_t)a3);
    uint32x2_t va4 = vdup_n_u32((uint32_t)a4);

    uint32x2_t vr0 = vdup_n_u32(r0);
    uint32x2_t vr1 = vdup_n_u32(r1);
    uint32x2_t vr2 = vdup_n_u32(r2);
    uint32x2_t vr3 = vdup_n_u32(r3);
    uint32x2_t vr4 = vdup_n_u32(r4);

    uint32x2_t vs1 = vdup_n_u32(s1);
    uint32x2_t vs2 = vdup_n_u32(s2);
    uint32x2_t vs3 = vdup_n_u32(s3);
    uint32x2_t vs4 = vdup_n_u32(s4);

    uint64x2_t d0 = vmull_u32(va0, vr0);
    d0 = vmlal_u32(d0, va1, vs4);
    d0 = vmlal_u32(d0, va2, vs3);
    d0 = vmlal_u32(d0, va3, vs2);
    d0 = vmlal_u32(d0, va4, vs1);

    uint64x2_t d1 = vmull_u32(va0, vr1);
    d1 = vmlal_u32(d1, va1, vr0);
    d1 = vmlal_u32(d1, va2, vs4);
    d1 = vmlal_u32(d1, va3, vs3);
    d1 = vmlal_u32(d1, va4, vs2);

    uint64x2_t d2 = vmull_u32(va0, vr2);
    d2 = vmlal_u32(d2, va1, vr1);
    d2 = vmlal_u32(d2, va2, vr0);
    d2 = vmlal_u32(d2, va3, vs4);
    d2 = vmlal_u32(d2, va4, vs3);

    uint64x2_t d3 = vmull_u32(va0, vr3);
    d3 = vmlal_u32(d3, va1, vr2);
    d3 = vmlal_u32(d3, va2, vr1);
    d3 = vmlal_u32(d3, va3, vr0);
    d3 = vmlal_u32(d3, va4, vs4);

    uint64x2_t d4 = vmull_u32(va0, vr4);
    d4 = vmlal_u32(d4, va1, vr3);
    d4 = vmlal_u32(d4, va2, vr2);
    d4 = vmlal_u32(d4, va3, vr1);
    d4 = vmlal_u32(d4, va4, vr0);

    uint64_t h0 = vgetq_lane_u64(d0, 0);
    uint64_t h1 = vgetq_lane_u64(d1, 0);
    uint64_t h2 = vgetq_lane_u64(d2, 0);
    uint64_t h3 = vgetq_lane_u64(d3, 0);
    uint64_t h4 = vgetq_lane_u64(d4, 0);

    uint64_t c;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    ctx->acc[0] = (uint32_t)h0;
    ctx->acc[1] = (uint32_t)h1;
    ctx->acc[2] = (uint32_t)h2;
    ctx->acc[3] = (uint32_t)h3;
    ctx->acc[4] = (uint32_t)h4;
}

#else

static void poly1305_block_scalar(wg_poly1305_ctx *ctx, const uint8_t *data, uint32_t hibit) {
    uint32_t t0 = load32_le(data + 0);
    uint32_t t1 = load32_le(data + 4);
    uint32_t t2 = load32_le(data + 8);
    uint32_t t3 = load32_le(data + 12);

    uint64_t a0 = (uint64_t)ctx->acc[0] + (t0 & 0x3ffffff);
    uint64_t a1 = (uint64_t)ctx->acc[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
    uint64_t a2 = (uint64_t)ctx->acc[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    uint64_t a3 = (uint64_t)ctx->acc[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    uint64_t a4 = (uint64_t)ctx->acc[4] + ((t3 >> 8) | (hibit << 24));

    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];

    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    uint64_t h0 = (uint64_t)a0*r0 + (uint64_t)a1*s4 + (uint64_t)a2*s3 + (uint64_t)a3*s2 + (uint64_t)a4*s1;
    uint64_t h1 = (uint64_t)a0*r1 + (uint64_t)a1*r0 + (uint64_t)a2*s4 + (uint64_t)a3*s3 + (uint64_t)a4*s2;
    uint64_t h2 = (uint64_t)a0*r2 + (uint64_t)a1*r1 + (uint64_t)a2*r0 + (uint64_t)a3*s4 + (uint64_t)a4*s3;
    uint64_t h3 = (uint64_t)a0*r3 + (uint64_t)a1*r2 + (uint64_t)a2*r1 + (uint64_t)a3*r0 + (uint64_t)a4*s4;
    uint64_t h4 = (uint64_t)a0*r4 + (uint64_t)a1*r3 + (uint64_t)a2*r2 + (uint64_t)a3*r1 + (uint64_t)a4*r0;

    uint64_t c;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    ctx->acc[0] = (uint32_t)h0;
    ctx->acc[1] = (uint32_t)h1;
    ctx->acc[2] = (uint32_t)h2;
    ctx->acc[3] = (uint32_t)h3;
    ctx->acc[4] = (uint32_t)h4;
}

#endif

static inline void poly1305_block(wg_poly1305_ctx *ctx, const uint8_t *data, uint32_t hibit) {
#if HAS_NEON
    poly1305_block_neon(ctx, data, hibit);
#else
    poly1305_block_scalar(ctx, data, hibit);
#endif
}

void wg_poly1305_update(wg_poly1305_ctx *ctx, const uint8_t *data, size_t len) {
    if (ctx->buf_len > 0) {
        size_t want = 16 - ctx->buf_len;
        if (len < want) {
            memcpy(ctx->buf + ctx->buf_len, data, len);
            ctx->buf_len += len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_len, data, want);
        poly1305_block(ctx, ctx->buf, 1);
        data += want;
        len -= want;
        ctx->buf_len = 0;
    }

    while (len >= 16) {
        poly1305_block(ctx, data, 1);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void wg_poly1305_final(wg_poly1305_ctx *ctx, uint8_t tag[16]) {
    if (ctx->buf_len > 0) {
        ctx->buf[ctx->buf_len] = 1;
        memset(ctx->buf + ctx->buf_len + 1, 0, 16 - ctx->buf_len - 1);
        poly1305_block(ctx, ctx->buf, 0);
    }

    uint32_t h0 = ctx->acc[0];
    uint32_t h1 = ctx->acc[1];
    uint32_t h2 = ctx->acc[2];
    uint32_t h3 = ctx->acc[3];
    uint32_t h4 = ctx->acc[4];

    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f0 = ((uint64_t)h0 | ((uint64_t)h1 << 26)) + (uint64_t)ctx->s[0];
    uint64_t f1 = ((uint64_t)h2 << 20) + (uint64_t)ctx->s[1];
    uint64_t f2 = ((uint64_t)h3 << 14) + (uint64_t)ctx->s[2];
    uint64_t f3 = ((uint64_t)h4 << 8) + (uint64_t)ctx->s[3];

    f1 += f0 >> 32; f0 &= 0xffffffff;
    f2 += f1 >> 32; f1 &= 0xffffffff;
    f3 += f2 >> 32; f2 &= 0xffffffff;

    store32_le(tag + 0, (uint32_t)f0);
    store32_le(tag + 4, (uint32_t)f1);
    store32_le(tag + 8, (uint32_t)f2);
    store32_le(tag + 12, (uint32_t)f3);

    memset(ctx, 0, sizeof(*ctx));
}

void wg_poly1305(uint8_t tag[16], const uint8_t *data, size_t len, const uint8_t key[32]) {
    wg_poly1305_ctx ctx;
    wg_poly1305_init(&ctx, key);
    wg_poly1305_update(&ctx, data, len);
    wg_poly1305_final(&ctx, tag);
}
