#include "blake2s_neon.h"

#if defined(__aarch64__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define HAS_NEON 1
#else
#define HAS_NEON 0
#endif

#include <string.h>

static const uint32_t blake2s_iv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};

#if HAS_NEON

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint32x4_t rotr32_7(uint32x4_t x) {
    return vorrq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 25));
}

static inline uint32x4_t rotr32_8(uint32x4_t x) {
    return vorrq_u32(vshrq_n_u32(x, 8), vshlq_n_u32(x, 24));
}

static inline uint32x4_t rotr32_12(uint32x4_t x) {
    return vorrq_u32(vshrq_n_u32(x, 12), vshlq_n_u32(x, 20));
}

#define ROTR16(x) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))

static inline void g_neon(uint32x4_t *a, uint32x4_t *b, uint32x4_t *c, uint32x4_t *d,
                          uint32x4_t mx, uint32x4_t my) {
    *a = vaddq_u32(vaddq_u32(*a, *b), mx);
    *d = ROTR16(veorq_u32(*d, *a));
    *c = vaddq_u32(*c, *d);
    *b = rotr32_12(veorq_u32(*b, *c));
    *a = vaddq_u32(vaddq_u32(*a, *b), my);
    *d = rotr32_8(veorq_u32(*d, *a));
    *c = vaddq_u32(*c, *d);
    *b = rotr32_7(veorq_u32(*b, *c));
}

static inline uint32x4_t gather4(const uint32_t *m, int i0, int i1, int i2, int i3) {
    uint32_t tmp[4] = {m[i0], m[i1], m[i2], m[i3]};
    return vld1q_u32(tmp);
}

void blake2s_compress_neon(uint32_t h[8], const uint8_t block[64],
                           uint32_t t0, uint32_t t1, uint32_t f0, uint32_t f1) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = load32_le(block + i * 4);

    uint32x4_t row0 = vld1q_u32(&h[0]);
    uint32x4_t row1 = vld1q_u32(&h[4]);
    uint32x4_t row2 = vld1q_u32(blake2s_iv);
    uint32x4_t row3 = vsetq_lane_u32(t0 ^ blake2s_iv[4], vld1q_u32(&blake2s_iv[4]), 0);
    row3 = vsetq_lane_u32(t1 ^ blake2s_iv[5], row3, 1);
    row3 = vsetq_lane_u32(f0 ^ blake2s_iv[6], row3, 2);
    row3 = vsetq_lane_u32(f1 ^ blake2s_iv[7], row3, 3);

    uint32x4_t orig0 = row0;
    uint32x4_t orig1 = row1;

    for (int r = 0; r < 10; r++) {
        const uint8_t *s = blake2s_sigma[r];

        uint32x4_t mx = gather4(m, s[0], s[2], s[4], s[6]);
        uint32x4_t my = gather4(m, s[1], s[3], s[5], s[7]);
        g_neon(&row0, &row1, &row2, &row3, mx, my);

        row1 = vextq_u32(row1, row1, 1);
        row2 = vextq_u32(row2, row2, 2);
        row3 = vextq_u32(row3, row3, 3);

        mx = gather4(m, s[8], s[10], s[12], s[14]);
        my = gather4(m, s[9], s[11], s[13], s[15]);
        g_neon(&row0, &row1, &row2, &row3, mx, my);

        row1 = vextq_u32(row1, row1, 3);
        row2 = vextq_u32(row2, row2, 2);
        row3 = vextq_u32(row3, row3, 1);
    }

    row0 = veorq_u32(row0, row2);
    row1 = veorq_u32(row1, row3);
    row0 = veorq_u32(row0, orig0);
    row1 = veorq_u32(row1, orig1);

    vst1q_u32(&h[0], row0);
    vst1q_u32(&h[4], row1);
}

int blake2s_neon_available(void) {
    return 1;
}

#else

void blake2s_compress_neon(uint32_t h[8], const uint8_t block[64],
                           uint32_t t0, uint32_t t1, uint32_t f0, uint32_t f1) {
    (void)h; (void)block; (void)t0; (void)t1; (void)f0; (void)f1;
}

int blake2s_neon_available(void) {
    return 0;
}

#endif
