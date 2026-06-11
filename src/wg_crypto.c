#include "wg_internal.h"
#include "wg_chacha20_neon.h"
#include "blake2s.h"
#include <string.h>
#include <time.h>

void wg_hash(uint8_t out[WG_HASH_LEN], const void* data, size_t len) {
    blake2s(out, WG_HASH_LEN, data, len, NULL, 0);
}

void wg_hash2(uint8_t out[WG_HASH_LEN], const void* a, size_t a_len, const void* b, size_t b_len) {
    blake2s_state state;
    blake2s_init(&state, WG_HASH_LEN);
    blake2s_update(&state, a, a_len);
    blake2s_update(&state, b, b_len);
    blake2s_final(&state, out);
}

void wg_mac(uint8_t out[WG_MAC_LEN], const uint8_t* key, size_t key_len, const void* data, size_t len) {
    blake2s(out, WG_MAC_LEN, data, len, key, key_len);
}

void wg_hmac(uint8_t* out, size_t out_len, const uint8_t* key, size_t key_len, const void* data, size_t data_len) {
    uint8_t ipad[BLAKE2S_BLOCK_SIZE];
    uint8_t opad[BLAKE2S_BLOCK_SIZE];
    uint8_t inner[WG_HASH_LEN];

    memset(ipad, 0x36, BLAKE2S_BLOCK_SIZE);
    memset(opad, 0x5c, BLAKE2S_BLOCK_SIZE);

    for (size_t i = 0; i < key_len && i < BLAKE2S_BLOCK_SIZE; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    blake2s_state state;
    blake2s_init(&state, WG_HASH_LEN);
    blake2s_update(&state, ipad, BLAKE2S_BLOCK_SIZE);
    blake2s_update(&state, data, data_len);
    blake2s_final(&state, inner);

    blake2s_init(&state, out_len);
    blake2s_update(&state, opad, BLAKE2S_BLOCK_SIZE);
    blake2s_update(&state, inner, WG_HASH_LEN);
    blake2s_final(&state, out);

    crypto_wipe(ipad, sizeof(ipad));
    crypto_wipe(opad, sizeof(opad));
    crypto_wipe(inner, sizeof(inner));
}

void wg_kdf1(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len) {
    uint8_t temp[WG_HASH_LEN];
    uint8_t one = 0x01;

    wg_hmac(temp, WG_HASH_LEN, key, WG_HASH_LEN, input, input_len);
    wg_hmac(out, WG_HASH_LEN, temp, WG_HASH_LEN, &one, 1);

    crypto_wipe(temp, sizeof(temp));
}

void wg_kdf2(uint8_t out1[WG_HASH_LEN], uint8_t out2[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len) {
    uint8_t temp[WG_HASH_LEN];
    uint8_t t1[WG_HASH_LEN + 1];
    uint8_t one = 0x01;
    uint8_t two = 0x02;

    wg_hmac(temp, WG_HASH_LEN, key, WG_HASH_LEN, input, input_len);
    wg_hmac(out1, WG_HASH_LEN, temp, WG_HASH_LEN, &one, 1);

    memcpy(t1, out1, WG_HASH_LEN);
    t1[WG_HASH_LEN] = two;
    wg_hmac(out2, WG_HASH_LEN, temp, WG_HASH_LEN, t1, WG_HASH_LEN + 1);

    crypto_wipe(temp, sizeof(temp));
    crypto_wipe(t1, sizeof(t1));
}

void wg_kdf3(uint8_t out1[WG_HASH_LEN], uint8_t out2[WG_HASH_LEN], uint8_t out3[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len) {
    uint8_t temp[WG_HASH_LEN];
    uint8_t t1[WG_HASH_LEN + 1];
    uint8_t t2[WG_HASH_LEN + 1];
    uint8_t one = 0x01;
    uint8_t two = 0x02;
    uint8_t three = 0x03;

    wg_hmac(temp, WG_HASH_LEN, key, WG_HASH_LEN, input, input_len);
    wg_hmac(out1, WG_HASH_LEN, temp, WG_HASH_LEN, &one, 1);

    memcpy(t1, out1, WG_HASH_LEN);
    t1[WG_HASH_LEN] = two;
    wg_hmac(out2, WG_HASH_LEN, temp, WG_HASH_LEN, t1, WG_HASH_LEN + 1);

    memcpy(t2, out2, WG_HASH_LEN);
    t2[WG_HASH_LEN] = three;
    wg_hmac(out3, WG_HASH_LEN, temp, WG_HASH_LEN, t2, WG_HASH_LEN + 1);

    crypto_wipe(temp, sizeof(temp));
    crypto_wipe(t1, sizeof(t1));
    crypto_wipe(t2, sizeof(t2));
}

void wg_mix_hash(WgHandshakeState* state, const void* data, size_t len) {
    wg_hash2(state->hash, state->hash, WG_HASH_LEN, data, len);
}

void wg_mix_key(WgHandshakeState* state, const void* input, size_t len) {
    wg_kdf2(state->chaining_key, state->chaining_key, state->chaining_key, input, len);
}

int wg_aead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter, const void* plaintext, size_t plaintext_len, const void* ad, size_t ad_len) {
    if (wg_chacha20_neon_available()) {
        return wg_aead_neon_encrypt(out, key, counter, plaintext, plaintext_len, ad, ad_len);
    }

    uint8_t nonce[12] = {0};
    nonce[4] = (uint8_t)(counter);
    nonce[5] = (uint8_t)(counter >> 8);
    nonce[6] = (uint8_t)(counter >> 16);
    nonce[7] = (uint8_t)(counter >> 24);
    nonce[8] = (uint8_t)(counter >> 32);
    nonce[9] = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);

    uint8_t mac[16];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, out, mac, ad, ad_len, plaintext, plaintext_len);
    memcpy(out + plaintext_len, mac, 16);

    crypto_wipe(&ctx, sizeof(ctx));
    return 0;
}

int wg_aead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter, const void* ciphertext, size_t ciphertext_len, const void* ad, size_t ad_len) {
    if (ciphertext_len < WG_AEAD_TAG_LEN)
        return -1;

    if (wg_chacha20_neon_available()) {
        return wg_aead_neon_decrypt(out, key, counter, ciphertext, ciphertext_len, ad, ad_len);
    }

    uint8_t nonce[12] = {0};
    nonce[4] = (uint8_t)(counter);
    nonce[5] = (uint8_t)(counter >> 8);
    nonce[6] = (uint8_t)(counter >> 16);
    nonce[7] = (uint8_t)(counter >> 24);
    nonce[8] = (uint8_t)(counter >> 32);
    nonce[9] = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);

    size_t plaintext_len = ciphertext_len - WG_AEAD_TAG_LEN;
    const uint8_t* mac = (const uint8_t*)ciphertext + plaintext_len;

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    int result = crypto_aead_read(&ctx, out, mac, ad, ad_len, ciphertext, plaintext_len);

    crypto_wipe(&ctx, sizeof(ctx));
    return result;
}

void wg_timestamp(uint8_t out[WG_TIMESTAMP_LEN]) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    uint64_t secs = (uint64_t)ts.tv_sec + 0x400000000000000aULL;
    uint32_t nsecs = (uint32_t)ts.tv_nsec;

    out[0] = (uint8_t)(secs >> 56);
    out[1] = (uint8_t)(secs >> 48);
    out[2] = (uint8_t)(secs >> 40);
    out[3] = (uint8_t)(secs >> 32);
    out[4] = (uint8_t)(secs >> 24);
    out[5] = (uint8_t)(secs >> 16);
    out[6] = (uint8_t)(secs >> 8);
    out[7] = (uint8_t)(secs);
    out[8] = (uint8_t)(nsecs >> 24);
    out[9] = (uint8_t)(nsecs >> 16);
    out[10] = (uint8_t)(nsecs >> 8);
    out[11] = (uint8_t)(nsecs);
}
