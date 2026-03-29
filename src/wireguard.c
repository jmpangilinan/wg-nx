#include "wg_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>

#define WG_MAX_PACKET_SIZE 2048

static uint8_t g_recv_packet[WG_MAX_PACKET_SIZE];

#define WG_KEEPALIVE_DEFAULT 25
#define WG_REKEY_CHECK_INTERVAL_MS 10000

static int wg_jitter_ms(void) {
    return (int)(wg_random_index() % 334);
}

static void (*wg_log_func)(const char* msg) = NULL;

void wg_set_log_callback(void (*func)(const char* msg)) {
    wg_log_func = func;
}

void wg_log(const char* fmt, ...) {
    if (!wg_log_func)
        return;
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    wg_log_func(buf);
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

    if (config->has_preshared_key) {
        memcpy(tun->preshared_key, config->preshared_key, WG_KEY_LEN);
        tun->has_psk = true;
    }

    if (wg_resolve_endpoint(tun, config->endpoint_host, config->endpoint_port) != WG_OK) {
        free(tun);
        return NULL;
    }

    tun->socket_fd = -1;
    tun->session.valid = false;
    tun->running = false;
    tun->recv_cb = NULL;
    tun->recv_cb_user = NULL;

    if (wg_mutex_init(&tun->send_mutex, false) != 0) {
        free(tun);
        return NULL;
    }

    if (wg_stop_cond_init(&tun->stop_cond) != 0) {
        wg_mutex_fini(&tun->send_mutex);
        free(tun);
        return NULL;
    }

    return tun;
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

    wg_log("connect: opening socket");
    if (tun->socket_fd < 0) {
        int err = wg_socket_open(tun);
        if (err != WG_OK) {
            wg_log("socket_open failed: %d", err);
            return err;
        }
    }
    wg_log("socket_fd=%d", tun->socket_fd);

    WgHandshakeInit init_msg;
    WgHandshakeState state;
    uint8_t recv_buf[256];

    int err = WG_ERR_TIMEOUT;
    for (int attempt = 0; attempt < WG_MAX_TIMER_HANDSHAKES; attempt++) {
        wg_log("connect: attempt %d", attempt + 1);

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

        if ((size_t)received < sizeof(WgHandshakeResponse)) {
            err = WG_ERR_HANDSHAKE;
            crypto_wipe(&state, sizeof(state));
            continue;
        }

        WgHandshakeResponse* response = (WgHandshakeResponse*)recv_buf;
        err = wg_handshake_response(tun, response, &state);
        if (err == WG_OK)
            break;

        wg_log("connect: response failed (%d), retrying", err);
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
    uint8_t* packet = g_recv_packet;
    uint64_t total_recv = 0;
    uint64_t last_log = 0;

    wg_log("recv thread started");

    while (!wg_stop_cond_check(&tun->stop_cond)) {
        int received = wg_socket_recv(tun, packet, WG_MAX_PACKET_SIZE, 100);

        if (received < 0) {
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
            continue;
        }

        WgTransport* transport = (WgTransport*)packet;
        wg_log("recv: type=%d size=%d rekey=%d", transport->type, received, tun->session.rekey_in_progress);

        if (transport->type != WG_MSG_TRANSPORT) {
            if (transport->type == WG_MSG_HANDSHAKE_RESPONSE && tun->session.rekey_in_progress) {
                wg_log("recv: handshake_response rekey=%d", tun->session.rekey_in_progress);
                if ((size_t)received <= sizeof(tun->pending_response)) {
                    memcpy(tun->pending_response, packet, received);
                    tun->pending_response_len = received;
                    wg_log("recv: stored handshake response for rekey");
                }
            } else if (transport->type == WG_MSG_COOKIE_REPLY) {
                if ((size_t)received >= sizeof(WgCookieReply)) {
                    wg_process_cookie_reply(tun, (const WgCookieReply*)packet);
                    tun->pending_cookie = true;
                }
            } else if (transport->type == WG_MSG_HANDSHAKE_INIT) {
                if (!tun->session.rekey_in_progress) {
                    wg_log("recv: server-initiated handshake, triggering rekey");
                    tun->session.rekey_in_progress = true; /* keepalive thread will pick it up */
                }
            } else {
                wg_log("recv: not transport (type=%d)", transport->type);
            }
            continue;
        }

        uint32_t cur_idx = __atomic_load_n(&tun->session.local_index, __ATOMIC_ACQUIRE);
        __atomic_load_n(&tun->session.rekey_in_progress, __ATOMIC_ACQUIRE);
        WgSession* sess = NULL;
        if (transport->receiver_index == cur_idx) {
            sess = &tun->session;
        } else if (transport->receiver_index == tun->session.old_local_index) {
            sess = &tun->session;
        } else if (tun->prev_session.valid &&
                   transport->receiver_index == tun->prev_session.local_index) {
            sess = &tun->prev_session;
        } else {
            wg_log("recv: idx mismatch (got=%08x want=%08x prev_valid=%d prev_idx=%08x old_idx=%08x)",
                   transport->receiver_index, cur_idx,
                   tun->prev_session.valid, tun->prev_session.local_index,
                   tun->session.old_local_index);
            continue;
        }

        uint64_t sess_elapsed = wg_time_now() - sess->last_handshake;
        if (sess_elapsed >= (uint64_t)WG_REJECT_AFTER_TIME * 1000000000ULL) {
            wg_log("recv: session expired, dropping transport");
            if (sess == &tun->prev_session) {
                crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
                tun->prev_session.valid = false;
            }
            continue;
        }

        size_t ciphertext_len = received - sizeof(WgTransport);
        size_t plaintext_len = ciphertext_len - WG_AEAD_TAG_LEN;

        if (plaintext_len == 0) {
            sess->last_received = wg_time_now();
            continue;
        }

        int err = wg_aead_decrypt(transport->encrypted_data, sess->receiving_key, transport->counter, transport->encrypted_data, ciphertext_len, NULL, 0);
        if (err != 0) {
            wg_log("recv: decrypt failed (ctr=%llu)", (unsigned long long)transport->counter);
            continue;
        }

        if (!wg_counter_validate(&sess->replay, transport->counter)) {
            wg_log("recv: replay detected (ctr=%llu)", (unsigned long long)transport->counter);
            continue;
        }

        sess->last_received = wg_time_now();
        sess->receiving_counter = transport->counter + 1;

        wg_mutex_lock(&tun->send_mutex);
        wg_update_endpoint_from_recv(tun);
        wg_mutex_unlock(&tun->send_mutex);

        if (tun->recv_cb)
            tun->recv_cb(tun->recv_cb_user, transport->encrypted_data, plaintext_len);
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
    uint64_t last_keepalive = wg_time_now();

#define WG_KEEPALIVE_TIMEOUT_NS  ((uint64_t)WG_KEEPALIVE_TIMEOUT  * 1000000000ULL)
#define WG_DEAD_PEER_TIMEOUT_NS  ((uint64_t)(WG_KEEPALIVE_TIMEOUT + WG_REKEY_TIMEOUT) * 1000000000ULL)
#define WG_ZERO_KEY_TIMEOUT_NS   ((uint64_t)(WG_REJECT_AFTER_TIME * 3) * 1000000000ULL)

    while (!wg_stop_cond_check(&tun->stop_cond)) {
        int result = wg_stop_cond_timedwait(&tun->stop_cond, check_interval_ms);

        if (result == 0)
            break;

        uint64_t now = wg_time_now();

        if (tun->session.valid &&
            (now - tun->session.last_handshake) >= WG_ZERO_KEY_TIMEOUT_NS) {
            wg_log("keepalive: session keys exceeded REJECT_AFTER_TIME×3, zeroing");
            crypto_wipe(&tun->session, sizeof(tun->session));
            tun->session.valid = false;
            crypto_wipe(&tun->prev_session, sizeof(tun->prev_session));
            tun->prev_session.valid = false;
            continue;
        }

        if (!tun->session.valid)
            continue;

        if (tun->session.last_received > 0 &&
            (now - tun->session.last_received) >= WG_DEAD_PEER_TIMEOUT_NS &&
            !tun->session.rekey_in_progress) {
            wg_log("keepalive: dead peer detected, rekeying");
            wg_rekey(tun);
            last_keepalive = wg_time_now();
            continue;
        }

        bool server_triggered = tun->session.rekey_in_progress && !wg_needs_rekey(tun);
        if (wg_needs_rekey(tun) || server_triggered) {
            wg_rekey(tun);
            last_keepalive = wg_time_now();
            continue;
        }

        if (tun->session.last_received > 0 &&
            (now - tun->last_sent) >= WG_KEEPALIVE_TIMEOUT_NS) {
            wg_mutex_lock(&tun->send_mutex);
            wg_send_keepalive(tun);
            wg_mutex_unlock(&tun->send_mutex);
            last_keepalive = now;
            continue;
        }

        if (tun->keepalive_interval > 0 && (now - last_keepalive) >= (uint64_t)tun->keepalive_interval * 1000000000ULL) {
            wg_mutex_lock(&tun->send_mutex);
            wg_send_keepalive(tun);
            wg_mutex_unlock(&tun->send_mutex);
            last_keepalive = now;
        }
    }

    return NULL;
}

int wg_start(WgTunnel* tun) {
    if (!tun)
        return WG_ERR_INVALID_CONFIG;

    if (!tun->session.valid)
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

    uint8_t* packet = g_recv_packet;

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
