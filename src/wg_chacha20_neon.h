#ifndef WG_CHACHA20_NEON_H
#define WG_CHACHA20_NEON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void wg_chacha20_neon(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter);

void wg_chacha20_block_neon(uint8_t out[64], const uint8_t key[32],
                            const uint8_t nonce[12], uint32_t counter);

int wg_chacha20_neon_available(void);

int wg_aead_neon_encrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *plaintext, size_t plaintext_len,
                         const void *ad, size_t ad_len);

int wg_aead_neon_decrypt(uint8_t *out, const uint8_t key[32], uint64_t counter,
                         const void *ciphertext, size_t ciphertext_len,
                         const void *ad, size_t ad_len);

#ifdef __cplusplus
}
#endif

#endif
