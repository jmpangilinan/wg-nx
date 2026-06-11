#include "wg_internal.h"

// WG_DEBUG_LOG: set to 1 for hot-path logging
#define WG_DEBUG_LOG 0
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>

#define WG_MAX_PACKET_SIZE 2048

_Static_assert(WG_MAX_PACKET_SIZE <= WG_RECV_SLOT_CAP, "slot capacity too small");

int wg_recv_pool_init(WgRecvPool* pool) {
    if (!pool) return -1;
    fprintf(stderr, "[WG] recv_pool: allocating %zu bytes...\n", WG_RECV_POOL_SIZE * sizeof(WgRecvSlot));
    pool->slots = calloc(WG_RECV_POOL_SIZE, sizeof(WgRecvSlot));
    if (!pool->slots) { fprintf(stderr, "[WG] recv_pool: calloc failed\n"); return -1; }
    fprintf(stderr, "[WG] recv_pool: calloc OK, mutex init...\n");
    if (wg_mutex_init(&pool->free_mutex, false) != 0) {
        fprintf(stderr, "[WG] recv_pool: mutex failed\n");
        free(pool->slots);
        pool->slots = NULL;
        return -1;
    }
    fprintf(stderr, "[WG] recv_pool_init OK\n");
    pool->free_head = NULL;
    for (size_t i = 0; i < WG_RECV_POOL_SIZE; i++) {
        pool->slots[i].next = pool->free_head;
        pool->free_head = &pool->slots[i];
    }
    pool->initialized = true;
    return 0;
}

void wg_recv_pool_destroy(WgRecvPool* pool) {
    if (!pool || !pool->initialized) return;
    wg_mutex_fini(&pool->free_mutex);
    free(pool->slots);
    pool->slots = NULL;
    pool->free_head = NULL;
    pool->initialized = false;
}

WgRecvSlot* wg_recv_pool_acquire(WgRecvPool* pool) {
    if (!pool || !pool->initialized) return NULL;
    wg_mutex_lock(&pool->free_mutex);
    WgRecvSlot* slot = pool->free_head;
    if (slot) pool->free_head = slot->next;
    wg_mutex_unlock(&pool->free_mutex);
    if (slot) slot->next = NULL;
    return slot;
}

void wg_recv_pool_release(WgRecvPool* pool, WgRecvSlot* slot) {
    if (!pool || !pool->initialized || !slot) return;
    wg_mutex_lock(&pool->free_mutex);
    slot->next = pool->free_head;
    pool->free_head = slot;
    wg_mutex_unlock(&pool->free_mutex);
}

void wg_recv_slot_release(WgTunnel* tun, WgRecvSlot* slot) {
    if (!tun) return;
    wg_recv_pool_release(&tun->recv_pool, slot);
}

#define WG_KEEPALIVE_DEFAULT 25
#define WG_REKEY_CHECK_INTERVAL_MS 10000

static int wg_jitter_ms(void) {
    return (int)(wg_random_index() % 334);
}

static void (*wg_log_func)(const char* msg) = NULL;
bool wg_log_enabled = false;

void wg_set_log_callback(void (*func)(const char* msg)) {
    wg_log_func = func;
    __atomic_store_n(&wg_log_enabled, func != NULL, __ATOMIC_RELEASE);
}

void wg_log_impl(const char* fmt, ...) {
    void (*cb)(const char*) = wg_log_func;
    if (!cb)
        return;
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    cb(buf);
}

uint32_t wg_random_index(void);
int wg_resolve_endpoint(WgTunnel* tun, const char* host, uint16_t port);

WgTunnel* wg_init(const WgConfig* config) {
    if (!config)
        return NULL;

    WgTunnel* tun = calloc(1, sizeof(WgTunnel));
    if (!tun)
        return NULL;

    memcpy(tun->static_private, config->private_key, WG_KEY_LEN);
    crypto_x25519_public_key(tun->static_public, tun->static_private);
    memcpy(tun->peer_public, config->peer_public_key, WG_KEY_LEN);
    tun->tunnel_ip = config->tunnel_ip;
    tun->keepalive_interval = config->keepalive_interval;
    fprintf(stderr, "[WG] wg_init after key setup\n");

    if (config->has_preshared_key) {
        memcpy(tun->preshared_key, config->preshared_key, WG_KEY_LEN);
        tun->has_psk = true;
    }

    fprintf(stderr, "[WG] wg_init resolving endpoint...\n");
    if (wg_resolve_endpoint(tun, config->endpoint_host, config->endpoint_port) != WG_OK) {
        fprintf(stderr, "[WG] resolve failed\n");
        free(tun);
        return NULL;
    }
    fprintf(stderr, "[WG] wg_init endpoint resolved OK\n");

    tun->socket_fd = -1;
    tun->session.valid = false;
    tun->running = false;
    tun->recv_cb = NULL;
    tun->recv_cb_user = NULL;
    fprintf(stderr, "[WG] wg_init about to mutex_init...\n");

    if (wg_mutex_init(&tun->send_mutex, false) != 0) {
        fprintf(stderr, "[WG] mutex_init failed\n");
        free(tun);
        return NULL;
    }
    fprintf(stderr, "[WG] mutex_init OK\n");
    fprintf(stderr, "[WG] about to stop_cond_init...\n");

    if (wg_stop_cond_init(&tun->stop_cond) != 0) {
        fprintf(stderr, "[WG] stop_cond_init failed\n");
        wg_mutex_fini(&tun->send_mutex);
        free(tun);
        return NULL;
    }
    fprintf(stderr, "[WG] stop_cond_init OK\n");
    fprintf(stderr, "[WG] about to recv_pool_init...\n");

    if (wg_recv_pool_init(&tun->recv_pool) != 0) {
        fprintf(stderr, "[WG] recv_pool_init failed\n");
        wg_stop_cond_fini(&tun->stop_cond);
        wg_mutex_fini(&tun->send_mutex);
        free(tun);
        return NULL;
    }

    fprintf(stderr, "[WG] wg_init returning successfully\n");
    tun->canary_begin = WG_CANARY_MAGIC;
    tun->canary_end   = WG_CANARY_MAGIC;
    return tun;
}

// ─── Multi-peer management ───────────────────────────────────

WgPeer* wg_add_peer(WgTunnel* tun, const uint8_t public_key[WG_KEY_LEN],
                    const uint8_t relay_hash[WG_RELAY_HASH_LEN], uint32_t ip_raw) {
    if (!tun || tun->peer_count >= WG_MAX_PEERS) return NULL;
    
    WgPeer* peer = &tun->peers[tun->peer_count];
    memset(peer, 0, sizeof(WgPeer));
    memcpy(peer->public_key, public_key, WG_KEY_LEN);
    memcpy(peer->relay_hash, relay_hash, WG_RELAY_HASH_LEN);
    peer->ip_raw = ip_raw;
    peer->tunnel_ip.s_addr = ip_raw;
    peer->configured = true;
    peer->connected = false;
    tun->peer_count++;
    return peer;
}

WgPeer* wg_find_peer_by_ip(WgTunnel* tun, uint32_t ip_raw) {
    if (!tun) return NULL;
    for (int i = 0; i < tun->peer_count; i++) {
        if (tun->peers[i].configured && tun->peers[i].ip_raw == ip_raw)
            return &tun->peers[i];
    }
    return NULL;
}

WgPeer* wg_find_peer_by_local_index(WgTunnel* tun, uint32_t local_index) {
    if (!tun) return NULL;
    for (int i = 0; i < tun->peer_count; i++) {
        WgPeer* p = &tun->peers[i];
        if (p->configured && p->session.valid && p->session.local_index == local_index)
            return p;
        if (p->configured && p->prev_session.valid && p->prev_session.local_index == local_index)
            return p;
    }
    return NULL;
}

WgPeer* wg_find_peer_by_public_key(WgTunnel* tun, const uint8_t public_key[WG_KEY_LEN]) {
    if (!tun) return NULL;
    for (int i = 0; i < tun->peer_count; i++) {
        if (tun->peers[i].configured && memcmp(tun->peers[i].public_key, public_key, WG_KEY_LEN) == 0)
            return &tun->peers[i];
    }
    return NULL;
}

// ─── Send to specific peer ───────────────────────────────────

int wg_send_to_peer(WgTunnel* tun, WgPeer* peer, const void* data, size_t len) {
    if (!tun || !peer || !peer->connected || !peer->session.valid)
        return WG_ERR_NOT_CONNECTED;

    size_t packet_size = sizeof(WgTransport) + len + WG_AEAD_TAG_LEN;
    if (packet_size > WG_MAX_PACKET_SIZE)
        return WG_ERR_BUFFER_TOO_SMALL;

    wg_mutex_lock(&tun->send_mutex);

    uint8_t* packet = tun->send_buffer;
    WgTransport* transport = (WgTransport*)packet;
    transport->type = WG_MSG_TRANSPORT;
    memset(transport->reserved, 0, sizeof(transport->reserved));
    transport->receiver_index = peer->session.remote_index;
    transport->counter = peer->session.sending_counter++;

    wg_aead_encrypt(transport->encrypted_data, peer->session.sending_key, transport->counter,
                    data, len, NULL, 0);

    int sent = wg_socket_send_to(tun, peer->relay_hash, packet, packet_size);
    if (sent >= 0)
        peer->last_sent = wg_time_now();

    wg_mutex_unlock(&tun->send_mutex);

    if (sent < 0)
        return WG_ERR_SOCKET;
    return (int)len;
}

void wg_send_keepalive_to_peer(WgTunnel* tun, WgPeer* peer) {
    uint8_t keepalive[sizeof(WgTransport) + WG_AEAD_TAG_LEN];
    WgTransport* pkt = (WgTransport*)keepalive;
    pkt->type = WG_MSG_TRANSPORT;
    memset(pkt->reserved, 0, sizeof(pkt->reserved));
    pkt->receiver_index = peer->session.remote_index;
    pkt->counter = peer->session.sending_counter++;
    wg_aead_encrypt(pkt->encrypted_data, peer->session.sending_key, pkt->counter, NULL, 0, NULL, 0);
    wg_socket_send_to(tun, peer->relay_hash, keepalive, sizeof(keepalive));
    peer->last_sent = wg_time_now();
}

void wg_set_recv_callback(WgTunnel* tun, WgRecvCallback cb, void* user) {
    if (!tun)
        return;
    tun->recv_cb = cb;
    tun->recv_cb_user = user;
}

static void wg_send_keepalive(WgTunnel* tun) {
    uint8_t keepalive[sizeof(WgTransport) + WG_AEAD_TAG_LEN];
    WgTransport* pkt = (WgTransport*)keepalive;
    pkt->type = WG_MSG_TRANSPORT;
    memset(pkt->reserved, 0, sizeof(pkt->reserved));
    pkt->receiver_index = tun->session.remote_index;
    pkt->counter = tun->session.sending_counter++;
    wg_aead_encrypt(pkt->encrypted_data, tun->session.sending_key, pkt->counter, NULL, 0, NULL, 0);
    wg_socket_send(tun, keepalive, sizeof(keepalive));
    tun->last_sent = wg_time_now();
}

int wg_connect(WgTunnel* tun) {
    if (!tun)
        return WG_ERR_INVALID_CONFIG;
    fprintf(stderr, "[WG] wg_connect entered\n");

    wg_log("connect: opening socket");
    fprintf(stderr, "[WG] wg_connect calling socket_open...\n");
    if (tun->socket_fd < 0) {
        int err = wg_socket_open(tun);
        if (err != WG_OK) {
            wg_log("socket_open failed: %d", err);
            fprintf(stderr, "[WG] socket_open failed: %d\n", err);
            return err;
        }
    }
    wg_log("socket_fd=%d", tun->socket_fd);
    fprintf(stderr, "[WG] socket fd=%d, starting handshake...\n", tun->socket_fd);

    WgHandshakeInit init_msg;
    WgHandshakeState state;
    uint8_t recv_buf[256];

    int err = WG_ERR_TIMEOUT;
    for (int attempt = 0; attempt < WG_MAX_TIMER_HANDSHAKES; attempt++) {
        wg_log("connect: attempt %d", attempt + 1);
        fprintf(stderr, "[WG] handshake attempt %d\n", attempt + 1);

        err = wg_handshake_init(tun, &init_msg, &state);
        if (err != WG_OK) {
            wg_log("handshake_init failed: %d", err);
            break;
        }
        wg_log("connect: idx=0x%08x", init_msg.sender_index);

        int sent = wg_socket_send(tun, &init_msg, sizeof(init_msg));
        if (sent < 0) {
            err = WG_ERR_SOCKET;
            break;
        }

        tun->pending_cookie = false;

        int64_t remaining_ms = (int64_t)WG_REKEY_TIMEOUT * 1000 + wg_jitter_ms();
        int received = WG_ERR_TIMEOUT;
        while (remaining_ms > 0) {
            received = wg_socket_recv(tun, recv_buf, sizeof(recv_buf), 10);
            remaining_ms -= 10;
            if (received >= 0)
                break;
            if (received != WG_ERR_TIMEOUT)
                break;
            if (tun->pending_cookie) {
                wg_log("connect: cookie received, retransmitting");
                break;
            }
        }

        if (tun->pending_cookie) {
            tun->pending_cookie = false;
            err = WG_ERR_TIMEOUT;
            continue;
        }

        if (received < 0) {
            wg_log("connect: no response (attempt %d)", attempt + 1);
            err = WG_ERR_TIMEOUT;
            crypto_wipe(&state, sizeof(state));
            crypto_wipe(&init_msg, sizeof(init_msg));
            continue;
        }

        uint8_t msg_type = recv_buf[0];
        fprintf(stderr, "[WG] connect: recv %d bytes type=%d (expect RESP=%d size=%zu)\n",
                received, msg_type, WG_MSG_HANDSHAKE_RESPONSE, sizeof(WgHandshakeResponse));

        // Handle incoming HANDSHAKE_INIT (passive/responder role)
        // This happens when the peer initiates its own handshake simultaneously
        if (msg_type == WG_MSG_HANDSHAKE_INIT && (size_t)received >= sizeof(WgHandshakeInit)) {
            fprintf(stderr, "[WG] connect: received peer INIT, processing passively...\n");
            int passive_err = wg_handshake_init_process(tun, (const WgHandshakeInit*)recv_buf);
            if (passive_err == WG_OK) {
                // Session established via passive handshake!
                // The session is already valid; no keepalive needed here
                // (our own INIT may still get a response later, but we're good)
                fprintf(stderr, "[WG] connect: passive handshake SUCCESS, session valid\n");
                crypto_wipe(&state, sizeof(state));
                crypto_wipe(&init_msg, sizeof(init_msg));
                err = WG_OK;
                break;
            }
            fprintf(stderr, "[WG] connect: passive handshake failed (%d), continuing\n", passive_err);
            // Continue waiting — our own INIT may still get a response
            continue;
        }

        if ((size_t)received < sizeof(WgHandshakeResponse)) {
            fprintf(stderr, "[WG] connect: too small for response (%d < %zu)\n", received, sizeof(WgHandshakeResponse));
            err = WG_ERR_HANDSHAKE;
            crypto_wipe(&state, sizeof(state));
            continue;
        }

        WgHandshakeResponse* response = (WgHandshakeResponse*)recv_buf;
        err = wg_handshake_response(tun, response, &state);
        if (err == WG_OK)
            break;

        wg_log("connect: response failed (%d), retrying", err);
        fprintf(stderr, "[WG] connect: response failed (err=%d), retrying\n", err);
        crypto_wipe(&state, sizeof(state));
        crypto_wipe(&init_msg, sizeof(init_msg));
    }

    crypto_wipe(&state, sizeof(state));
    crypto_wipe(&init_msg, sizeof(init_msg));

    if (err != WG_OK) {
        tun->session.rekey_in_progress = false;
        return err;
    }

    wg_send_keepalive(tun);

    return WG_OK;
}

int wg_rekey(WgTunnel* tun) {
    WgHandshakeInit init_msg;
    WgHandshakeState state;

    uint32_t saved_local_index = tun->session.local_index;
    tun->pending_response_len = 0;

    wg_log("rekey: starting (old_idx=%08x)", tun->session.local_index);

    int err = WG_ERR_TIMEOUT;
    for (int attempt = 0; attempt < WG_MAX_TIMER_HANDSHAKES; attempt++) {
        tun->pending_response_len = 0;
        tun->pending_cookie = false;

        err = wg_handshake_init(tun, &init_msg, &state);
        if (err != WG_OK) {
            wg_log("rekey: init failed: %d", err);
            break;
        }
        wg_log("rekey: attempt %d new_idx=%08x", attempt + 1, tun->session.local_index);

        wg_mutex_lock(&tun->send_mutex);
        int sent = wg_socket_send(tun, &init_msg, sizeof(init_msg));
        wg_mutex_unlock(&tun->send_mutex);

        if (sent < 0) {
            err = WG_ERR_SOCKET;
            break;
        }

        int64_t remaining_ms = (int64_t)WG_REKEY_TIMEOUT * 1000 + wg_jitter_ms();
        while (remaining_ms > 0) {
            if (tun->pending_response_len > 0 || tun->pending_cookie)
                break;
            wg_sleep_ms(10);
            remaining_ms -= 10;
        }

        if (tun->pending_cookie) {
            wg_log("rekey: cookie received, retransmitting with mac2");
            tun->pending_cookie = false;
            crypto_wipe(&state, sizeof(state));
            crypto_wipe(&init_msg, sizeof(init_msg));
            continue;
        }

        if (tun->pending_response_len == 0) {
            wg_log("rekey: timeout attempt %d", attempt + 1);
            err = WG_ERR_TIMEOUT;
            crypto_wipe(&state, sizeof(state));
            crypto_wipe(&init_msg, sizeof(init_msg));
            continue;
        }

        if ((size_t)tun->pending_response_len < sizeof(WgHandshakeResponse)) {
            err = WG_ERR_HANDSHAKE;
            crypto_wipe(&state, sizeof(state));
            crypto_wipe(&init_msg, sizeof(init_msg));
            continue;
        }

        WgHandshakeResponse* response = (WgHandshakeResponse*)tun->pending_response;
        err = wg_handshake_response(tun, response, &state);
        if (err == WG_OK) {
            wg_log("rekey: success");
            break;
        }
        wg_log("rekey: response failed (%d) attempt %d", err, attempt + 1);
        crypto_wipe(&state, sizeof(state));
        crypto_wipe(&init_msg, sizeof(init_msg));
    }

    crypto_wipe(&state, sizeof(state));
    crypto_wipe(&init_msg, sizeof(init_msg));

    if (err != WG_OK) {
        tun->session.local_index = saved_local_index;
        tun->session.rekey_in_progress = false;
        return err;
    }

    wg_mutex_lock(&tun->send_mutex);
    wg_send_keepalive(tun);
    wg_mutex_unlock(&tun->send_mutex);

    return WG_OK;
}

static bool wg_session_expired(WgTunnel* tun) {
    if (!tun->session.valid)
        return false;
    uint64_t elapsed = wg_time_now() - tun->session.last_handshake;
    return elapsed >= (uint64_t)WG_REJECT_AFTER_TIME * 1000000000ULL ||
           tun->session.sending_counter >= WG_REJECT_AFTER_MESSAGES;
}

static bool wg_needs_rekey(WgTunnel* tun) {
    if (!tun->session.valid)
        return false;

    if (tun->session.rekey_in_progress)
        return false;

    uint64_t now = wg_time_now();
    uint64_t elapsed = now - tun->session.last_handshake;

    if (elapsed >= (uint64_t)WG_REKEY_AFTER_TIME * 1000000000ULL)
        return true;

    if (tun->session.sending_counter >= WG_REKEY_AFTER_MESSAGES)
        return true;

    return false;
}

static void* recv_thread_func(void* arg) {
    WgTunnel* tun = (WgTunnel*)arg;
    wg_thread_set_affinity(WG_THREAD_NAME_RECV);
    uint64_t total_recv = 0;
    uint64_t last_log = 0;
    static uint8_t fallback_packet[WG_MAX_PACKET_SIZE];

    wg_log("recv thread started");

    while (!wg_stop_cond_check(&tun->stop_cond)) {
        WgRecvSlot* slot = wg_recv_pool_acquire(&tun->recv_pool);
        uint8_t* packet = slot ? slot->data : fallback_packet;

        int received = wg_socket_recv(tun, packet, WG_MAX_PACKET_SIZE, 100);

        if (received < 0) {
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            if (received == WG_ERR_TIMEOUT) {
                uint64_t now = wg_time_now();
                if (now - last_log > 5000000000ULL) {
                    wg_log("recv: total=%llu idx=%08x", (unsigned long long)total_recv, tun->session.local_index);
                    last_log = now;
                }
                continue;
            }
            wg_log("recv error: %d", received);
            continue;
        }

        total_recv++;

        if ((size_t)received < sizeof(WgTransport) + WG_AEAD_TAG_LEN) {
            wg_log("recv: pkt too small (%d)", received);
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        WgTransport* transport = (WgTransport*)packet;
        wg_log("recv: type=%d size=%d rekey=%d", transport->type, received, tun->session.rekey_in_progress);
#if WG_DEBUG_LOG
        fprintf(stderr, "[WG] recv: pkt type=%d size=%d\n", transport->type, received);
#endif

        if (transport->type != WG_MSG_TRANSPORT) {
            if (transport->type == WG_MSG_HANDSHAKE_RESPONSE) {
                const WgHandshakeResponse *resp = (const WgHandshakeResponse*)packet;
                if (tun->session.rekey_in_progress) {
                    // Main tunnel rekey
                    wg_log("recv: handshake_response rekey=%d", tun->session.rekey_in_progress);
                    if ((size_t)received <= sizeof(tun->pending_response)) {
                        memcpy(tun->pending_response, packet, received);
                        tun->pending_response_len = received;
                    }
                } else {
                    // Per-peer active handshake: find which peer sent the INIT
                    fprintf(stderr, "[WG] recv: HANDSHAKE_RESPONSE (receiver_idx=0x%08x)\n", resp->receiver_index);
                    for (int pi = 0; pi < tun->peer_count; pi++) {
                        WgPeer *peer = &tun->peers[pi];
                        if (peer->connected && !peer->session.valid &&
                            peer->session.local_index == resp->receiver_index) {
                            // Complete the handshake for this peer
                            int perr = wg_handshake_init_process_response(tun, peer, resp);
                            fprintf(stderr, "[WG] recv: per-peer handshake for peer[%d]: %s\n",
                                    pi, perr == WG_OK ? "OK" : "FAILED");
                            break;
                        }
                    }
                }
            } else if (transport->type == WG_MSG_COOKIE_REPLY) {
                if ((size_t)received >= sizeof(WgCookieReply)) {
                    wg_process_cookie_reply(tun, (const WgCookieReply*)packet);
                    tun->pending_cookie = true;
                }
            } else if (transport->type == WG_MSG_HANDSHAKE_INIT) {
                fprintf(stderr, "[WG] recv: HANDSHAKE_INIT received (%d bytes)\n", received);
                if ((size_t)received >= sizeof(WgHandshakeInit)) {
                    int passive_err = wg_handshake_init_process(tun, (const WgHandshakeInit*)packet);
                    if (passive_err == WG_OK) {
                        fprintf(stderr, "[WG] recv: passive handshake from peer OK\n");
                        // Send keepalive to newly connected peer
                        for (int pi = 0; pi < tun->peer_count; pi++) {
                            if (tun->peers[pi].connected && tun->peers[pi].session.valid) {
                                wg_send_keepalive_to_peer(tun, &tun->peers[pi]);
                                break;
                            }
                        }
                    } else {
                        fprintf(stderr, "[WG] recv: passive handshake failed (%d)\n", passive_err);
                    }
                }
            } else {
                wg_log("recv: not transport (type=%d)", transport->type);
            }
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        uint32_t cur_idx = __atomic_load_n(&tun->session.local_index, __ATOMIC_ACQUIRE);
        __atomic_load_n(&tun->session.rekey_in_progress, __ATOMIC_ACQUIRE);
        
        // Multi-peer: find peer by receiver_index
        WgPeer* peer = wg_find_peer_by_local_index(tun, transport->receiver_index);
        WgSession* sess = NULL;
        
#if WG_DEBUG_LOG
        fprintf(stderr, "[WG] recv: receiver_idx=0x%08x peer_found=%d\n",
                transport->receiver_index, peer ? 1 : 0);
#endif
        
        if (peer) {
            // Found matching peer
            if (transport->receiver_index == peer->session.local_index)
                sess = &peer->session;
            else if (peer->prev_session.valid &&
                     transport->receiver_index == peer->prev_session.local_index)
                sess = &peer->prev_session;
        }
        
        // Also check legacy single-peer session
        if (!sess) {
            if (transport->receiver_index == cur_idx) {
                sess = &tun->session;
            } else if (transport->receiver_index == tun->session.old_local_index) {
                sess = &tun->session;
            } else if (tun->prev_session.valid &&
                       transport->receiver_index == tun->prev_session.local_index) {
                sess = &tun->prev_session;
            }
        }
        
        if (!sess) {
            fprintf(stderr, "[WG] recv: idx mismatch got=0x%08x (peers=%d)\n",
                   transport->receiver_index, tun->peer_count);
            wg_log("recv: idx mismatch (got=%08x want=%08x prev_valid=%d prev_idx=%08x old_idx=%08x)",
                   transport->receiver_index, cur_idx,
                   tun->prev_session.valid, tun->prev_session.local_index,
                   tun->session.old_local_index);
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        uint64_t sess_elapsed = wg_time_now() - sess->last_handshake;
        if (sess_elapsed >= (uint64_t)WG_REJECT_AFTER_TIME * 1000000000ULL) {
            wg_log("recv: session expired, dropping transport");
            if (peer && sess == &peer->prev_session) {
                crypto_wipe(&peer->prev_session, sizeof(peer->prev_session));
                peer->prev_session.valid = false;
            }
            if (sess == &tun->prev_session) {
                crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
                tun->prev_session.valid = false;
            }
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        size_t ciphertext_len = received - sizeof(WgTransport);
        size_t plaintext_len = ciphertext_len - WG_AEAD_TAG_LEN;

        if (plaintext_len == 0) {
            sess->last_received = wg_time_now();
            if (peer) { peer->last_sent = wg_time_now(); peer->connected = true; }
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        int err = wg_aead_decrypt(transport->encrypted_data, sess->receiving_key, transport->counter, transport->encrypted_data, ciphertext_len, NULL, 0);
        if (err != 0) {
            fprintf(stderr, "[WG] recv: decrypt FAILED (ctr=%llu)\n", (unsigned long long)transport->counter);
            wg_log("recv: decrypt failed (ctr=%llu)", (unsigned long long)transport->counter);
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        if (!wg_counter_validate(&sess->replay, transport->counter)) {
            wg_log("recv: replay detected (ctr=%llu)", (unsigned long long)transport->counter);
            if (slot) wg_recv_pool_release(&tun->recv_pool, slot);
            continue;
        }

        sess->last_received = wg_time_now();
        sess->receiving_counter = transport->counter + 1;
        if (peer) peer->connected = true;

        wg_mutex_lock(&tun->send_mutex);
        wg_update_endpoint_from_recv(tun);
        wg_mutex_unlock(&tun->send_mutex);

        /* Hand plaintext to the consumer. */
#if WG_DEBUG_LOG
        fprintf(stderr, "[WG] recv: transport plaintext %zu bytes (peer_ip=0x%08x)\n",
                plaintext_len, peer ? (unsigned)peer->ip_raw : 0);
#endif
        if (tun->recv_cb && slot) {
            int retained = tun->recv_cb(tun->recv_cb_user, slot, transport->encrypted_data, plaintext_len);
            if (!retained) wg_recv_pool_release(&tun->recv_pool, slot);
        } else if (slot) {
            wg_recv_pool_release(&tun->recv_pool, slot);
        }
    }

    wg_log("recv thread exiting, total=%llu", (unsigned long long)total_recv);
    return NULL;
}

static void* keepalive_thread_func(void* arg) {
    WgTunnel* tun = (WgTunnel*)arg;
    wg_thread_set_affinity(WG_THREAD_NAME_SEND);
    uint64_t keepalive_interval_ms = tun->keepalive_interval * 1000;
    uint64_t check_interval_ms = keepalive_interval_ms > 0 && keepalive_interval_ms < WG_REKEY_CHECK_INTERVAL_MS
        ? keepalive_interval_ms
        : WG_REKEY_CHECK_INTERVAL_MS;

#define WG_KEEPALIVE_TIMEOUT_NS  ((uint64_t)WG_KEEPALIVE_TIMEOUT  * 1000000000ULL)
#define WG_ZERO_KEY_TIMEOUT_NS   ((uint64_t)(WG_REJECT_AFTER_TIME * 3) * 1000000000ULL)

    while (!wg_stop_cond_check(&tun->stop_cond)) {
        int result = wg_stop_cond_timedwait(&tun->stop_cond, check_interval_ms);

        if (result == 0)
            break;

        uint64_t now = wg_time_now();

        // Iterate all peers — send keepalives, check session expiry
        for (int i = 0; i < tun->peer_count; i++) {
            WgPeer* peer = &tun->peers[i];
            if (!peer->configured) continue;

            // Zero old keys
            if (peer->session.valid &&
                (now - peer->session.last_handshake) >= WG_ZERO_KEY_TIMEOUT_NS) {
                crypto_wipe(&peer->session, sizeof(peer->session));
                peer->session.valid = false;
                peer->connected = false;
                crypto_wipe(&peer->prev_session, sizeof(peer->prev_session));
                peer->prev_session.valid = false;
                continue;
            }

            if (!peer->session.valid)
                continue;

            // Send keepalive if needed
            if (peer->session.last_received > 0 &&
                (now - peer->last_sent) >= WG_KEEPALIVE_TIMEOUT_NS) {
                wg_mutex_lock(&tun->send_mutex);
                wg_send_keepalive_to_peer(tun, peer);
                wg_mutex_unlock(&tun->send_mutex);
                continue;
            }

            // Periodic keepalive
            if (tun->keepalive_interval > 0 &&
                (now - peer->last_sent) >= (uint64_t)tun->keepalive_interval * 1000000000ULL) {
                wg_mutex_lock(&tun->send_mutex);
                wg_send_keepalive_to_peer(tun, peer);
                wg_mutex_unlock(&tun->send_mutex);
            }
        }

        // Legacy single-peer session
        if (tun->session.valid &&
            (now - tun->session.last_handshake) >= WG_ZERO_KEY_TIMEOUT_NS) {
            crypto_wipe(&tun->session, sizeof(tun->session));
            tun->session.valid = false;
            crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
            tun->prev_session.valid = false;
        }
    }

    return NULL;
}

int wg_start(WgTunnel* tun) {
    if (!tun)
        return WG_ERR_INVALID_CONFIG;

    // Allow passive mode: no session needed if peers are configured
    if (!tun->session.valid && tun->peer_count == 0)
        return WG_ERR_NOT_CONNECTED;

    if (tun->running)
        return WG_ERR_ALREADY_RUNNING;

    tun->stop_cond.pred = false;

    if (wg_thread_create(&tun->recv_thread, recv_thread_func, tun) != 0)
        return WG_ERR_THREAD;

    if (wg_thread_create(&tun->keepalive_thread, keepalive_thread_func, tun) != 0) {
        wg_stop_cond_signal(&tun->stop_cond);
        wg_thread_join(&tun->recv_thread, NULL);
        return WG_ERR_THREAD;
    }

    tun->running = true;
    return WG_OK;
}

void wg_stop(WgTunnel* tun) {
    if (!tun || !tun->running)
        return;

    wg_stop_cond_signal(&tun->stop_cond);

    wg_thread_join(&tun->recv_thread, NULL);
    wg_thread_join(&tun->keepalive_thread, NULL);

    tun->running = false;
}

int wg_send(WgTunnel* tun, const void* data, size_t len) {
    if (!tun || !tun->session.valid)
        return WG_ERR_NOT_CONNECTED;

    if (wg_session_expired(tun))
        return WG_ERR_NOT_CONNECTED;

    size_t packet_size = sizeof(WgTransport) + len + WG_AEAD_TAG_LEN;
    if (packet_size > WG_MAX_PACKET_SIZE)
        return WG_ERR_BUFFER_TOO_SMALL;

    wg_mutex_lock(&tun->send_mutex);

    uint8_t* packet = tun->send_buffer;
    WgTransport* transport = (WgTransport*)packet;
    transport->type = WG_MSG_TRANSPORT;
    memset(transport->reserved, 0, sizeof(transport->reserved));
    transport->receiver_index = tun->session.remote_index;
    transport->counter = tun->session.sending_counter++;

    wg_aead_encrypt(transport->encrypted_data, tun->session.sending_key, transport->counter, data, len, NULL, 0);

    int sent = wg_socket_send(tun, packet, packet_size);
    if (sent >= 0)
        tun->last_sent = wg_time_now();

    wg_mutex_unlock(&tun->send_mutex);

    if (sent < 0)
        return WG_ERR_SOCKET;

    return (int)len;
}

int wg_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms) {
    if (!tun || !tun->session.valid)
        return WG_ERR_NOT_CONNECTED;

    uint8_t packet[WG_MAX_PACKET_SIZE];

    int received = wg_socket_recv(tun, packet, WG_MAX_PACKET_SIZE, timeout_ms);
    if (received < 0)
        return received;

    if ((size_t)received < sizeof(WgTransport) + WG_AEAD_TAG_LEN)
        return WG_ERR_DECRYPT;

    WgTransport* transport = (WgTransport*)packet;

    if (transport->type != WG_MSG_TRANSPORT)
        return WG_ERR_DECRYPT;

    if (transport->receiver_index != tun->session.local_index)
        return WG_ERR_DECRYPT;

    size_t ciphertext_len = received - sizeof(WgTransport);
    size_t plaintext_len = ciphertext_len - WG_AEAD_TAG_LEN;

    if (plaintext_len > len)
        return WG_ERR_BUFFER_TOO_SMALL;

    if (plaintext_len == 0) {
        tun->session.last_received = wg_time_now();
        return 0;
    }

    int err = wg_aead_decrypt(buf, tun->session.receiving_key, transport->counter, transport->encrypted_data, ciphertext_len, NULL, 0);
    if (err != 0)
        return WG_ERR_DECRYPT;

    if (!wg_counter_validate(&tun->session.replay, transport->counter))
        return WG_ERR_DECRYPT;

    tun->session.last_received = wg_time_now();
    tun->session.receiving_counter = transport->counter + 1;

    return (int)plaintext_len;
}

int wg_get_ip(WgTunnel* tun, struct in_addr* addr) {
    if (!tun || !addr)
        return WG_ERR_INVALID_CONFIG;
    *addr = tun->tunnel_ip;
    return WG_OK;
}

void wg_close(WgTunnel* tun) {
    if (!tun)
        return;

    wg_stop(tun);
    wg_socket_close(tun);
    wg_recv_pool_destroy(&tun->recv_pool);
    wg_stop_cond_fini(&tun->stop_cond);
    wg_mutex_fini(&tun->send_mutex);
    crypto_wipe(tun->static_private, WG_KEY_LEN);
    crypto_wipe(tun->preshared_key, WG_KEY_LEN);
    crypto_wipe(&tun->session, sizeof(tun->session));
    crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
    free(tun);
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int wg_key_from_base64(uint8_t key[WG_KEY_LEN], const char* base64) {
    if (!base64 || strlen(base64) < 43)
        return -1;

    size_t out_idx = 0;
    for (size_t i = 0; i < 43 && out_idx < WG_KEY_LEN; i += 4) {
        int a = b64_decode_char(base64[i]);
        int b = b64_decode_char(base64[i + 1]);
        int c = (i + 2 < 43) ? b64_decode_char(base64[i + 2]) : 0;
        int d = (i + 3 < 43) ? b64_decode_char(base64[i + 3]) : 0;

        if (a < 0 || b < 0)
            return -1;

        if (out_idx < WG_KEY_LEN) key[out_idx++] = (a << 2) | (b >> 4);
        if (out_idx < WG_KEY_LEN && base64[i + 2] != '=') key[out_idx++] = (b << 4) | (c >> 2);
        if (out_idx < WG_KEY_LEN && base64[i + 3] != '=') key[out_idx++] = (c << 6) | d;
    }

    return (out_idx == WG_KEY_LEN) ? 0 : -1;
}

int wg_key_to_base64(char* base64, size_t len, const uint8_t key[WG_KEY_LEN]) {
    if (len < 45)
        return -1;

    size_t out_idx = 0;
    for (size_t i = 0; i < WG_KEY_LEN; i += 3) {
        uint32_t n = ((uint32_t)key[i] << 16);
        if (i + 1 < WG_KEY_LEN) n |= ((uint32_t)key[i + 1] << 8);
        if (i + 2 < WG_KEY_LEN) n |= key[i + 2];

        base64[out_idx++] = b64_table[(n >> 18) & 0x3F];
        base64[out_idx++] = b64_table[(n >> 12) & 0x3F];
        base64[out_idx++] = (i + 1 < WG_KEY_LEN) ? b64_table[(n >> 6) & 0x3F] : '=';
        base64[out_idx++] = (i + 2 < WG_KEY_LEN) ? b64_table[n & 0x3F] : '=';
    }
    base64[out_idx] = '\0';

    return 0;
}

uint32_t wg_get_session_index(WgTunnel* tun) {
    if (!tun || !tun->session.valid)
        return 0;
    return tun->session.local_index;
}

int wg_canary_check(WgTunnel *tun) {
    if (!tun) return 1;  // no tunnel = no corruption to check
    if (tun->canary_begin != WG_CANARY_MAGIC) {
        fprintf(stderr, "[WG-CORRUPT] canary_begin=0x%08lx (expected 0x%08x)\n",
                (unsigned long)tun->canary_begin, WG_CANARY_MAGIC);
        return 0;
    }
    if (tun->canary_end != WG_CANARY_MAGIC) {
        fprintf(stderr, "[WG-CORRUPT] canary_end=0x%08lx (expected 0x%08x)\n",
                (unsigned long)tun->canary_end, WG_CANARY_MAGIC);
        return 0;
    }
    return 1;
}
