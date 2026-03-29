#include "wg_internal.h"
#include "blake2s.h"
#include <switch.h>
#include <string.h>

static void wg_handshake_init_state(WgHandshakeState* state, const uint8_t peer_public[WG_KEY_LEN]) {
    wg_hash(state->chaining_key, WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));
    wg_hash2(state->hash, state->chaining_key, WG_HASH_LEN, WG_IDENTIFIER, strlen(WG_IDENTIFIER));
    wg_mix_hash(state, peer_public, WG_KEY_LEN);
}

static void wg_compute_mac1(uint8_t mac1[WG_MAC_LEN], const uint8_t peer_public[WG_KEY_LEN], const void* msg, size_t msg_len) {
    uint8_t mac1_key[WG_HASH_LEN];
    wg_hash2(mac1_key, WG_LABEL_MAC1, strlen(WG_LABEL_MAC1), peer_public, WG_KEY_LEN);
    wg_mac(mac1, mac1_key, WG_HASH_LEN, msg, msg_len);
    crypto_wipe(mac1_key, sizeof(mac1_key));
}

int wg_xaead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[WG_COOKIE_NONCE_LEN],
                     const void* ciphertext, size_t ciphertext_len,
                     const void* ad, size_t ad_len) {
    if (ciphertext_len < WG_AEAD_TAG_LEN)
        return -1;

    size_t plaintext_len = ciphertext_len - WG_AEAD_TAG_LEN;
    const uint8_t* mac = (const uint8_t*)ciphertext + plaintext_len;

    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);
    int result = crypto_aead_read(&ctx, out, mac, ad, ad_len, ciphertext, plaintext_len);
    crypto_wipe(&ctx, sizeof(ctx));
    return result;
}

int wg_process_cookie_reply(WgTunnel* tun, const WgCookieReply* msg) {
    if (msg->type != WG_MSG_COOKIE_REPLY)
        return WG_ERR_HANDSHAKE;

    if (msg->receiver_index != tun->session.local_index)
        return WG_ERR_HANDSHAKE;

    uint8_t cookie_key[WG_HASH_LEN];
    wg_hash2(cookie_key, WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE),
             tun->peer_public, WG_KEY_LEN);

    int result = wg_xaead_decrypt(
        tun->cookie, cookie_key, msg->nonce,
        msg->encrypted_cookie, sizeof(msg->encrypted_cookie),
        tun->last_mac1, WG_MAC_LEN);

    crypto_wipe(cookie_key, sizeof(cookie_key));

    if (result != 0) {
        wg_log("cookie_reply: decrypt failed");
        return WG_ERR_DECRYPT;
    }

    tun->has_cookie = true;
    tun->cookie_timestamp = wg_time_now();
    wg_log("cookie_reply: stored cookie");
    return WG_OK;
}

int wg_handshake_init(WgTunnel* tun, WgHandshakeInit* msg, WgHandshakeState* state) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];

    wg_handshake_init_state(state, tun->peer_public);

    randomGet(state->ephemeral_private, WG_KEY_LEN);
    state->ephemeral_private[0] &= 248;
    state->ephemeral_private[31] &= 127;
    state->ephemeral_private[31] |= 64;

    crypto_x25519_public_key(msg->ephemeral, state->ephemeral_private);

    msg->type = WG_MSG_HANDSHAKE_INIT;
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->sender_index = wg_random_index();
    tun->session.old_local_index = tun->session.local_index;
    __atomic_store_n(&tun->session.local_index, msg->sender_index, __ATOMIC_RELEASE);
    __atomic_store_n(&tun->session.rekey_in_progress, true, __ATOMIC_RELEASE);

    wg_mix_hash(state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state->chaining_key, state->chaining_key, msg->ephemeral, WG_KEY_LEN);

    crypto_x25519(dh_result, state->ephemeral_private, tun->peer_public);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);
    wg_aead_encrypt(msg->encrypted_static, key, 0, tun->static_public, WG_KEY_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_static, sizeof(msg->encrypted_static));

    crypto_x25519(dh_result, tun->static_private, tun->peer_public);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);

    wg_timestamp(timestamp);
    wg_aead_encrypt(msg->encrypted_timestamp, key, 0, timestamp, WG_TIMESTAMP_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp));

    wg_compute_mac1(msg->mac1, tun->peer_public, msg, sizeof(WgHandshakeInit) - 2 * WG_MAC_LEN);

    memcpy(tun->last_mac1, msg->mac1, WG_MAC_LEN);

    uint64_t cookie_age_ns = wg_time_now() - tun->cookie_timestamp;
    if (tun->has_cookie && cookie_age_ns < (uint64_t)WG_COOKIE_SECRET_MAX_AGE * 1000000000ULL) {
        wg_mac(msg->mac2, tun->cookie, WG_COOKIE_LEN, msg, sizeof(WgHandshakeInit) - WG_MAC_LEN);
    } else {
        if (tun->has_cookie && cookie_age_ns >= (uint64_t)WG_COOKIE_SECRET_MAX_AGE * 1000000000ULL) {
            tun->has_cookie = false;
            crypto_wipe(tun->cookie, WG_COOKIE_LEN);
        }
        memset(msg->mac2, 0, WG_MAC_LEN);
    }

    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(timestamp, sizeof(timestamp));

    return WG_OK;
}

int wg_handshake_response(WgTunnel* tun, const WgHandshakeResponse* msg, WgHandshakeState* state) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t psk_temp[WG_HASH_LEN];
    uint8_t decrypted[WG_AEAD_TAG_LEN];

    if (msg->type != WG_MSG_HANDSHAKE_RESPONSE)
        return WG_ERR_HANDSHAKE;

    if (msg->receiver_index != tun->session.local_index)
        return WG_ERR_HANDSHAKE;

    tun->session.remote_index = msg->sender_index;

    wg_mix_hash(state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state->chaining_key, state->chaining_key, msg->ephemeral, WG_KEY_LEN);

    crypto_x25519(dh_result, state->ephemeral_private, msg->ephemeral);
    wg_kdf1(state->chaining_key, state->chaining_key, dh_result, WG_KEY_LEN);

    crypto_x25519(dh_result, tun->static_private, msg->ephemeral);
    wg_kdf1(state->chaining_key, state->chaining_key, dh_result, WG_KEY_LEN);

    if (tun->has_psk) {
        wg_kdf3(state->chaining_key, psk_temp, key, state->chaining_key, tun->preshared_key, WG_KEY_LEN);
        wg_mix_hash(state, psk_temp, WG_HASH_LEN);
    } else {
        uint8_t zero_psk[WG_KEY_LEN] = {0};
        wg_kdf3(state->chaining_key, psk_temp, key, state->chaining_key, zero_psk, WG_KEY_LEN);
        wg_mix_hash(state, psk_temp, WG_HASH_LEN);
    }

    int dec_result = wg_aead_decrypt(decrypted, key, 0, msg->encrypted_nothing, sizeof(msg->encrypted_nothing), state->hash, WG_HASH_LEN);
    wg_log("handshake_response: decrypt=%d", dec_result);
    if (dec_result != 0) {
        crypto_wipe(dh_result, sizeof(dh_result));
        crypto_wipe(key, sizeof(key));
        crypto_wipe(psk_temp, sizeof(psk_temp));
        return WG_ERR_DECRYPT;
    }

    wg_mix_hash(state, msg->encrypted_nothing, sizeof(msg->encrypted_nothing));

    if (tun->session.valid) {
        crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
        tun->prev_session = tun->session;
        tun->prev_session.local_index = tun->session.old_local_index;
    }

    wg_kdf2(tun->session.sending_key, tun->session.receiving_key, state->chaining_key, NULL, 0);
    tun->session.sending_counter = 0;
    tun->session.receiving_counter = 0;
    tun->session.last_handshake = wg_time_now();
    tun->session.valid = true;
    crypto_wipe(&tun->session.replay, sizeof(tun->session.replay));

    __atomic_store_n(&tun->session.rekey_in_progress, false, __ATOMIC_RELEASE);

    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(psk_temp, sizeof(psk_temp));
    crypto_wipe(state, sizeof(*state));

    return WG_OK;
}
