#include "wg_internal.h"
#include "blake2s.h"
#include <switch.h>
#include <string.h>
#include <stdio.h>

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

// Multi-peer version: initiates handshake to a specific peer
int wg_handshake_init_peer(WgTunnel* tun, WgPeer* peer, WgHandshakeInit* msg, WgHandshakeState* state) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];

    wg_handshake_init_state(state, peer->public_key);

    randomGet(state->ephemeral_private, WG_KEY_LEN);
    state->ephemeral_private[0] &= 248;
    state->ephemeral_private[31] &= 127;
    state->ephemeral_private[31] |= 64;

    crypto_x25519_public_key(msg->ephemeral, state->ephemeral_private);

    msg->type = WG_MSG_HANDSHAKE_INIT;
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->sender_index = wg_random_index();
    peer->session.old_local_index = peer->session.local_index;
    peer->session.local_index = msg->sender_index;

    wg_mix_hash(state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state->chaining_key, state->chaining_key, msg->ephemeral, WG_KEY_LEN);

    crypto_x25519(dh_result, state->ephemeral_private, peer->public_key);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);
    wg_aead_encrypt(msg->encrypted_static, key, 0, tun->static_public, WG_KEY_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_static, sizeof(msg->encrypted_static));

    crypto_x25519(dh_result, tun->static_private, peer->public_key);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);

    wg_timestamp(timestamp);
    wg_aead_encrypt(msg->encrypted_timestamp, key, 0, timestamp, WG_TIMESTAMP_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp));

    wg_compute_mac1(msg->mac1, peer->public_key, msg, sizeof(WgHandshakeInit) - 2 * WG_MAC_LEN);
    memcpy(peer->last_mac1, msg->mac1, WG_MAC_LEN);

    uint64_t cookie_age_ns = wg_time_now() - tun->cookie_timestamp;
    if (tun->has_cookie && cookie_age_ns < (uint64_t)WG_COOKIE_SECRET_MAX_AGE * 1000000000ULL) {
        wg_mac(msg->mac2, tun->cookie, WG_COOKIE_LEN, msg, sizeof(WgHandshakeInit) - WG_MAC_LEN);
    } else {
        memset(msg->mac2, 0, WG_MAC_LEN);
    }

    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(timestamp, sizeof(timestamp));

    return WG_OK;
}

// ─── Passive (responder) handshake ────────────────────────────
// Processes an incoming HANDSHAKE_INIT from a peer and sends a RESPONSE.
// This handles the case where both peers initiate simultaneously.
int wg_handshake_init_process(WgTunnel* tun, const WgHandshakeInit* msg) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t decrypted_static[WG_KEY_LEN];
    uint8_t decrypted_timestamp[WG_TIMESTAMP_LEN];
    WgHandshakeState state;
    WgHandshakeResponse response;

    if (msg->type != WG_MSG_HANDSHAKE_INIT) {
        fprintf(stderr, "[WG] init_process: wrong type %d (expected 1)\n", msg->type);
        return WG_ERR_HANDSHAKE;
    }

    fprintf(stderr, "[WG] init_process: processing incoming INIT (sender_idx=0x%08x)\n", msg->sender_index);

    // Verify MAC1
    uint8_t expected_mac1[WG_MAC_LEN];
    wg_compute_mac1(expected_mac1, tun->static_public, msg, sizeof(WgHandshakeInit) - 2 * WG_MAC_LEN);
    int mac1_ok = 1;
    for (int i = 0; i < WG_MAC_LEN; i++) {
        if (expected_mac1[i] != msg->mac1[i]) { mac1_ok = 0; break; }
    }
    if (!mac1_ok) {
        fprintf(stderr, "[WG] init_process: MAC1 mismatch\n");
        // Send cookie reply if we have cookie support
        // For now, just reject
        return WG_ERR_HANDSHAKE;
    }
    fprintf(stderr, "[WG] init_process: MAC1 OK\n");

    // Save MAC1 for cookie replies
    memcpy(tun->last_mac1, msg->mac1, WG_MAC_LEN);

    // Initialize state with OUR static public key (responder's static)
    wg_handshake_init_state(&state, tun->static_public);

    // ── Process token e: mix ephemeral ──
    wg_mix_hash(&state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state.chaining_key, state.chaining_key, msg->ephemeral, WG_KEY_LEN);

    // ── Process token es + s: DH + KDF2 (matches initiator's single KDF2 at es) ──
    crypto_x25519(dh_result, tun->static_private, msg->ephemeral);
    wg_kdf2(state.chaining_key, key, state.chaining_key, dh_result, WG_KEY_LEN);
    // Now chaining_key matches initiator's after es step; key is for static decrypt
    int dec_static = wg_aead_decrypt(decrypted_static, key, 0,
                                      msg->encrypted_static, sizeof(msg->encrypted_static),
                                      state.hash, WG_HASH_LEN);
    if (dec_static != 0) {
        fprintf(stderr, "[WG] init_process: static decrypt failed\n");
        crypto_wipe(dh_result, sizeof(dh_result));
        crypto_wipe(key, sizeof(key));
        crypto_wipe(&state, sizeof(state));
        return WG_ERR_DECRYPT;
    }
    fprintf(stderr, "[WG] init_process: static decrypted OK\n");
    wg_mix_hash(&state, msg->encrypted_static, sizeof(msg->encrypted_static));

    // ── Process token ss: DH(our_static_priv, peer_static_pub) ──
    crypto_x25519(dh_result, tun->static_private, decrypted_static);
    wg_kdf2(state.chaining_key, key, state.chaining_key, dh_result, WG_KEY_LEN);

    // Decrypt timestamp
    int dec_ts = wg_aead_decrypt(decrypted_timestamp, key, 0,
                                  msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp),
                                  state.hash, WG_HASH_LEN);
    if (dec_ts != 0) {
        fprintf(stderr, "[WG] init_process: timestamp decrypt failed\n");
        crypto_wipe(dh_result, sizeof(dh_result));
        crypto_wipe(key, sizeof(key));
        crypto_wipe(decrypted_static, sizeof(decrypted_static));
        crypto_wipe(&state, sizeof(state));
        return WG_ERR_DECRYPT;
    }
    fprintf(stderr, "[WG] init_process: timestamp decrypted OK\n");
    wg_mix_hash(&state, msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp));

    crypto_wipe(decrypted_timestamp, sizeof(decrypted_timestamp));

    // ── Find or create peer entry ──
    WgPeer* peer = wg_find_peer_by_public_key(tun, decrypted_static);
    if (!peer) {
        // Unknown peer — accept anyway (or could add to table)
        fprintf(stderr, "[WG] init_process: unknown peer, accepting passively\n");
        // Use legacy single-peer storage for backward compat
        memcpy(tun->peer_public, decrypted_static, WG_KEY_LEN);
    } else {
        fprintf(stderr, "[WG] init_process: found peer in table\n");
    }

    // ── Build RESPONSE message ──
    memset(&response, 0, sizeof(response));
    response.type = WG_MSG_HANDSHAKE_RESPONSE;
    response.sender_index = wg_random_index();
    response.receiver_index = msg->sender_index;

    // Generate ephemeral for response
    uint8_t resp_eph_priv[WG_KEY_LEN];
    randomGet(resp_eph_priv, WG_KEY_LEN);
    resp_eph_priv[0] &= 248;
    resp_eph_priv[31] &= 127;
    resp_eph_priv[31] |= 64;
    crypto_x25519_public_key(response.ephemeral, resp_eph_priv);

    // ── Response token e: mix our ephemeral ──
    wg_mix_hash(&state, response.ephemeral, WG_KEY_LEN);
    wg_kdf1(state.chaining_key, state.chaining_key, response.ephemeral, WG_KEY_LEN);

    // ── Response token ee: DH(our_response_eph, peer_init_eph) ──
    crypto_x25519(dh_result, resp_eph_priv, msg->ephemeral);
    wg_kdf1(state.chaining_key, state.chaining_key, dh_result, WG_KEY_LEN);

    // ── Response token se: DH(our_response_eph, peer_static) ──
    crypto_x25519(dh_result, resp_eph_priv, decrypted_static);
    wg_kdf1(state.chaining_key, state.chaining_key, dh_result, WG_KEY_LEN);

    // ── PSK mix ──
    uint8_t psk_temp[WG_HASH_LEN];
    if (tun->has_psk) {
        wg_kdf3(state.chaining_key, psk_temp, key, state.chaining_key, tun->preshared_key, WG_KEY_LEN);
        wg_mix_hash(&state, psk_temp, WG_HASH_LEN);
    } else {
        uint8_t zero_psk[WG_KEY_LEN] = {0};
        wg_kdf3(state.chaining_key, psk_temp, key, state.chaining_key, zero_psk, WG_KEY_LEN);
        wg_mix_hash(&state, psk_temp, WG_HASH_LEN);
    }

    // ── Encrypt empty payload ──
    uint8_t nothing[WG_AEAD_TAG_LEN] = {0};
    wg_aead_encrypt(response.encrypted_nothing, key, 0, nothing, 0, state.hash, WG_HASH_LEN);
    wg_mix_hash(&state, response.encrypted_nothing, sizeof(response.encrypted_nothing));

    // ── Compute MACs ──
    wg_compute_mac1(response.mac1, decrypted_static, &response, sizeof(WgHandshakeResponse) - 2 * WG_MAC_LEN);
    memcpy(tun->last_mac1, response.mac1, WG_MAC_LEN);
    memset(response.mac2, 0, WG_MAC_LEN);

    // ── Derive session keys ──
    // IMPORTANT: responder SWAPS the KDF2 outputs!
    // Initiator: (sending_key, receiving_key) = KDF2(ck, NULL)
    // Responder: (receiving_key, sending_key) = KDF2(ck, NULL)
    WgSession* target_sess;
    if (peer) {
        target_sess = &peer->session;
        if (peer->session.valid) {
            crypto_wipe(&peer->prev_session, sizeof(peer->prev_session));
            peer->prev_session = peer->session;
            peer->prev_session.local_index = peer->session.local_index;
        }
    } else {
        target_sess = &tun->session;
        if (tun->session.valid) {
            crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
            tun->prev_session = tun->session;
            tun->prev_session.local_index = tun->session.local_index;
        }
    }

    wg_kdf2(target_sess->receiving_key, target_sess->sending_key, state.chaining_key, NULL, 0);
    target_sess->sending_counter = 0;
    target_sess->receiving_counter = 0;
    target_sess->local_index = response.sender_index;
    target_sess->remote_index = msg->sender_index;
    target_sess->last_handshake = wg_time_now();
    target_sess->valid = true;
    __atomic_store_n(&target_sess->rekey_in_progress, false, __ATOMIC_RELEASE);
    crypto_wipe(&target_sess->replay, sizeof(target_sess->replay));

    if (peer) {
        peer->connected = true;
        memcpy(peer->last_mac1, response.mac1, WG_MAC_LEN);
    }

    // ── Send the response via relay (use peer hash if available) ──
    fprintf(stderr, "[WG] init_process: sending RESPONSE (our_idx=0x%08x peer_idx=0x%08x)\n",
            response.sender_index, response.receiver_index);
    if (peer) {
        wg_socket_send_to(tun, peer->relay_hash, &response, sizeof(response));
    } else {
        wg_socket_send(tun, &response, sizeof(response));
    }

    // Cleanup
    crypto_wipe(resp_eph_priv, sizeof(resp_eph_priv));
    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(psk_temp, sizeof(psk_temp));
    crypto_wipe(decrypted_static, sizeof(decrypted_static));
    crypto_wipe(&state, sizeof(state));

    fprintf(stderr, "[WG] init_process: session established (passive)\n");
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

int wg_handshake_init_process_response(WgTunnel* tun, WgPeer* peer, const WgHandshakeResponse* msg) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t psk_temp[WG_HASH_LEN];
    uint8_t decrypted[WG_AEAD_TAG_LEN];
    
    WgHandshakeState* state = &peer->pending_hs;
    
    if (msg->type != WG_MSG_HANDSHAKE_RESPONSE)
        return WG_ERR_HANDSHAKE;
    if (msg->receiver_index != peer->session.local_index)
        return WG_ERR_HANDSHAKE;
    
    peer->session.remote_index = msg->sender_index;
    
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
    
    if (wg_aead_decrypt(decrypted, key, 0, msg->encrypted_nothing,
                         sizeof(msg->encrypted_nothing), state->hash, WG_HASH_LEN) != 0)
        return WG_ERR_DECRYPT;
    
    wg_mix_hash(state, msg->encrypted_nothing, sizeof(msg->encrypted_nothing));
    
    wg_kdf2(peer->session.sending_key, peer->session.receiving_key, state->chaining_key, NULL, 0);
    peer->session.sending_counter = 0;
    peer->session.receiving_counter = 0;
    peer->session.last_handshake = wg_time_now();
    peer->session.valid = true;
    crypto_wipe(&peer->session.replay, sizeof(peer->session.replay));
    
    peer->hs_pending = false;
    crypto_wipe(state, sizeof(*state));
    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(psk_temp, sizeof(psk_temp));
    
    return WG_OK;
}
