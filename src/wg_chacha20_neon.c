#include "wg_chacha20_neon.h"
#include "wg_poly1305_neon.h"
#include "monocypher.h"

#if defined(__aarch64__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define HAS_NEON 1
#else
#define HAS_NEON 0
#endif

#include <string.h>

#define CHACHA20_CONSTANTS_0 0x61707865
#define CHACHA20_CONSTANTS_1 0x3320646e
#define CHACHA20_CONSTANTS_2 0x79622d32
#define CHACHA20_CONSTANTS_3 0x6b206574

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

#if HAS_NEON

static inline uint32x4_t rotl_neon(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_n_u32(x, n), vshrq_n_u32(x, 32 - n));
}

#define ROTL16(x) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))

static inline void quarterround_neon(uint32x4_t *a, uint32x4_t *b,
                                     uint32x4_t *c, uint32x4_t *d) {
    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = ROTL16(*d);

    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = rotl_neon(*b, 12);

    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = rotl_neon(*d, 8);

    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = rotl_neon(*b, 7);
}

static void chacha20_block_neon_internal(uint32_t out[16], const uint32_t in[16]) {
    uint32x4_t row0 = vld1q_u32(&in[0]);
    uint32x4_t row1 = vld1q_u32(&in[4]);
    uint32x4_t row2 = vld1q_u32(&in[8]);
    uint32x4_t row3 = vld1q_u32(&in[12]);

    uint32x4_t orig0 = row0;
    uint32x4_t orig1 = row1;
    uint32x4_t orig2 = row2;
    uint32x4_t orig3 = row3;

    for (int i = 0; i < 10; i++) {
        quarterround_neon(&row0, &row1, &row2, &row3);

        row1 = vextq_u32(row1, row1, 1);
        row2 = vextq_u32(row2, row2, 2);
        row3 = vextq_u32(row3, row3, 3);

        quarterround_neon(&row0, &row1, &row2, &row3);

        row1 = vextq_u32(row1, row1, 3);
        row2 = vextq_u32(row2, row2, 2);
        row3 = vextq_u32(row3, row3, 1);
    }

    row0 = vaddq_u32(row0, orig0);
    row1 = vaddq_u32(row1, orig1);
    row2 = vaddq_u32(row2, orig2);
    row3 = vaddq_u32(row3, orig3);

    vst1q_u32(&out[0], row0);
    vst1q_u32(&out[4], row1);
    vst1q_u32(&out[8], row2);
    vst1q_u32(&out[12], row3);
}

void wg_chacha20_block_neon(uint8_t out[64], const uint8_t key[32],
                            const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16];
    uint32_t block[16];

    state[0] = CHACHA20_CONSTANTS_0;
    state[1] = CHACHA20_CONSTANTS_1;
    state[2] = CHACHA20_CONSTANTS_2;
    state[3] = CHACHA20_CONSTANTS_3;
    state[4] = load32_le(key + 0);
    state[5] = load32_le(key + 4);
    state[6] = load32_le(key + 8);
    state[7] = load32_le(key + 12);
    state[8] = load32_le(key + 16);
    state[9] = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);
    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    chacha20_block_neon_internal(block, state);

    for (int i = 0; i < 16; i++) {
        store32_le(out + i * 4, block[i]);
    }
}

void wg_chacha20_neon(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter) {
    uint32_t state[16];
    uint32_t block[16];
    uint8_t keystream[64];

    state[0] = CHACHA20_CONSTANTS_0;
    state[1] = CHACHA20_CONSTANTS_1;
    state[2] = CHACHA20_CONSTANTS_2;
    state[3] = CHACHA20_CONSTANTS_3;
    state[4] = load32_le(key + 0);
    state[5] = load32_le(key + 4);
    state[6] = load32_le(key + 8);
    state[7] = load32_le(key + 12);
    state[8] = load32_le(key + 16);
    state[9] = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    while (len >= 64) {
        state[12] = counter++;
        chacha20_block_neon_internal(block, state);

        uint32x4_t *out32 = (uint32x4_t *)out;
        uint32x4_t *in32 = (uint32x4_t *)in;
        uint32x4_t *blk32 = (uint32x4_t *)block;

        vst1q_u32((uint32_t *)out32, veorq_u32(vld1q_u32((uint32_t *)in32), vld1q_u32((uint32_t *)blk32)));
        vst1q_u32((uint32_t *)(out32 + 1), veorq_u32(vld1q_u32((uint32_t *)(in32 + 1)), vld1q_u32((uint32_t *)(blk32 + 1))));
        vst1q_u32((uint32_t *)(out32 + 2), veorq_u32(vld1q_u32((uint32_t *)(in32 + 2)), vld1q_u32((uint32_t *)(blk32 + 2))));
        vst1q_u32((uint32_t *)(out32 + 3), veorq_u32(vld1q_u32((uint32_t *)(in32 + 3)), vld1q_u32((uint32_t *)(blk32 + 3))));

        out += 64;
        in += 64;
        len -= 64;
    }

    if (len > 0) {
        state[12] = counter;
        chacha20_block_neon_internal(block, state);

        for (int i = 0; i < 16; i++) {
            store32_le(keystream + i * 4, block[i]);
        }

        for (size_t i = 0; i < len; i++) {
            out[i] = in[i] ^ keystream[i];
        }
    }
}

int wg_chacha20_neon_available(void) {
	return 1;
}

static void build_nonce(uint8_t nonce[12], uint64_t counter) {
    nonce[0] = 0;
    nonce[1] = 0;
    nonce[2] = 0;
    nonce[3] = 0;
    nonce[4] = (uint8_t)(counter);
    nonce[5] = (uint8_t)(counter >> 8);
    nonce[6] = (uint8_t)(counter >> 16);
    nonce[7] = (uint8_t)(counter >> 24);
    nonce[8] = (uint8_t)(counter >> 32);
    nonce[9] = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);
}

static void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

int wg_aead_neon_encrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *plaintext, size_t plaintext_len,
                         const void *ad, size_t ad_len) {
    uint8_t nonce[12];
    uint8_t poly_key[64];
    uint8_t pad[16] = {0};
    uint8_t sizes[16];

    build_nonce(nonce, counter);

    wg_chacha20_block_neon(poly_key, key, nonce, 0);

    wg_chacha20_neon(out, plaintext, plaintext_len, key, nonce, 1);

    size_t ad_pad = (16 - (ad_len % 16)) % 16;
    size_t ct_pad = (16 - (plaintext_len % 16)) % 16;

    store64_le(sizes, ad_len);
    store64_le(sizes + 8, plaintext_len);

    wg_poly1305_ctx poly_ctx;
    wg_poly1305_init(&poly_ctx, poly_key);
    if (ad_len > 0) {
        wg_poly1305_update(&poly_ctx, ad, ad_len);
        if (ad_pad > 0) wg_poly1305_update(&poly_ctx, pad, ad_pad);
    }
    wg_poly1305_update(&poly_ctx, out, plaintext_len);
    if (ct_pad > 0) wg_poly1305_update(&poly_ctx, pad, ct_pad);
    wg_poly1305_update(&poly_ctx, sizes, 16);
    wg_poly1305_final(&poly_ctx, out + plaintext_len);

    crypto_wipe(poly_key, sizeof(poly_key));

    return 0;
}

int wg_aead_neon_decrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *ciphertext, size_t ciphertext_len,
                         const void *ad, size_t ad_len) {
    if (ciphertext_len < 16)
        return -1;

    size_t plaintext_len = ciphertext_len - 16;
    const uint8_t *mac = (const uint8_t *)ciphertext + plaintext_len;

    uint8_t nonce[12];
    uint8_t poly_key[64];
    uint8_t pad[16] = {0};
    uint8_t sizes[16];
    uint8_t computed_mac[16];

    build_nonce(nonce, counter);

    wg_chacha20_block_neon(poly_key, key, nonce, 0);

    size_t ad_pad = (16 - (ad_len % 16)) % 16;
    size_t ct_pad = (16 - (plaintext_len % 16)) % 16;

    store64_le(sizes, ad_len);
    store64_le(sizes + 8, plaintext_len);

    wg_poly1305_ctx poly_ctx;
    wg_poly1305_init(&poly_ctx, poly_key);
    if (ad_len > 0) {
        wg_poly1305_update(&poly_ctx, ad, ad_len);
        if (ad_pad > 0) wg_poly1305_update(&poly_ctx, pad, ad_pad);
    }
    wg_poly1305_update(&poly_ctx, ciphertext, plaintext_len);
    if (ct_pad > 0) wg_poly1305_update(&poly_ctx, pad, ct_pad);
    wg_poly1305_update(&poly_ctx, sizes, 16);
    wg_poly1305_final(&poly_ctx, computed_mac);

    int result = crypto_verify16(computed_mac, mac);

    if (result == 0) {
        wg_chacha20_neon(out, ciphertext, plaintext_len, key, nonce, 1);
    }

    crypto_wipe(poly_key, sizeof(poly_key));
    crypto_wipe(computed_mac, sizeof(computed_mac));

    return result;
}

#else

void wg_chacha20_block_neon(uint8_t out[64], const uint8_t key[32],
                            const uint8_t nonce[12], uint32_t counter) {
    (void)out; (void)key; (void)nonce; (void)counter;
}

void wg_chacha20_neon(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter) {
    (void)out; (void)in; (void)len; (void)key; (void)nonce; (void)counter;
}

int wg_chacha20_neon_available(void) {
    return 0;
}

int wg_aead_neon_encrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *plaintext, size_t plaintext_len,
                         const void *ad, size_t ad_len) {
    (void)out; (void)key; (void)counter;
    (void)plaintext; (void)plaintext_len;
    (void)ad; (void)ad_len;
    return -1;
}

int wg_aead_neon_decrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *ciphertext, size_t ciphertext_len,
                         const void *ad, size_t ad_len) {
    (void)out; (void)key; (void)counter;
    (void)ciphertext; (void)ciphertext_len;
    (void)ad; (void)ad_len;
    return -1;
}

#endif
