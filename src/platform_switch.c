#include "wg_internal.h"

// WG_DEBUG_LOG: set to 1 for hot-path logging
#define WG_DEBUG_LOG 0
#include <switch.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

// ─── Relay integration ──────────────────────────────────────────
// When set, socket layer uses relay instead of real UDP
// send_fn(peer_hash, data, len) — peer_hash is 36-byte relay peer ID
static void (*g_relay_send)(const uint8_t*, const void*, size_t) = NULL;

// ─── 512-slot blocking ring buffer ──────────────────────────
// Producer blocks when full, eliminating silent packet loss.
// Critical for IP fragment reassembly (HEVC I-frames).
#define RING_SLOTS 256
#define RING_DATA_MAX 2044

struct __attribute__((aligned(64))) ring_slot {
    volatile uint16_t len;
    uint8_t data[RING_DATA_MAX];
};

static struct ring_slot g_ring[RING_SLOTS];
static volatile uint32_t g_wseq_local = 0;
static volatile uint32_t g_wseq __attribute__((aligned(64))) = 0;

void wg_set_relay_send(void (*send_fn)(const uint8_t*, const void*, size_t)) {
    g_relay_send = send_fn;
}

void wg_relay_input(const void *data, size_t len) {
    if (len > RING_DATA_MAX) return;
    // Block if consumer is too far behind (ring full)
    static int ring_full_logged = 0;
    while (g_wseq_local - g_wseq >= RING_SLOTS - 4) {
        if (!ring_full_logged) {
            fprintf(stderr, "[WG] RING FULL! wseq_local=%u wseq=%u slots=%d\n", g_wseq_local, g_wseq, RING_SLOTS);
            ring_full_logged = 1;
        }
        svcSleepThread(100000);  // 100µs
    }
    uint32_t seq = g_wseq_local;
    uint32_t idx = seq & (RING_SLOTS - 1);
    
    g_ring[idx].len = (uint16_t)len;
    memcpy((void*)g_ring[idx].data, data, len);
    g_wseq_local = seq + 1;
}

// Commit: publish all packets written since last commit to consumer.
// Called once after processing a full WebSocket recv() burst.
void wg_relay_commit(void) {
    __asm__ __volatile__("" ::: "memory");  // compiler barrier
    g_wseq = g_wseq_local;
}

int wg_socket_open(WgTunnel* tun) {
    if (g_relay_send) {
        tun->socket_fd = 0;  // dummy fd
        return WG_OK;
    }
    tun->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tun->socket_fd < 0)
        return WG_ERR_SOCKET;

    int yes = 1;
    setsockopt(tun->socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    int rcvbuf = 0x19000;
    setsockopt(tun->socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    int flags = fcntl(tun->socket_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(tun->socket_fd, F_SETFL, flags | O_NONBLOCK);
    }

    return WG_OK;
}

int wg_socket_send(WgTunnel* tun, const void* data, size_t len) {
    if (g_relay_send) { fprintf(stderr, "[WG] relay_send %zu bytes (legacy, no hash)\n", len); g_relay_send(NULL, data, len); return (int)len; }
    for (int retry = 0; retry < 10; retry++) {
        ssize_t sent = sendto(tun->socket_fd, data, len, 0,
                              (struct sockaddr*)&tun->endpoint,
                              sizeof(tun->endpoint));
        if (sent >= 0)
            return (int)sent;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return WG_ERR_SOCKET;
        wg_sleep_ms(1);
    }
    return WG_ERR_SOCKET;
}

int wg_socket_send_to(WgTunnel* tun, const uint8_t* relay_hash, const void* data, size_t len) {
    (void)tun;
    if (g_relay_send) {
#if WG_DEBUG_LOG
        fprintf(stderr, "[WG] relay_send_to %zu bytes hash=%.4s...\n", len, relay_hash ? (const char*)relay_hash : "null");
#endif
        g_relay_send(relay_hash, data, len);
        return (int)len;
    }
    return WG_ERR_SOCKET;
}

int wg_socket_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms) {
    if (g_relay_send) {
        // Full FIFO drain: consume ALL packets in order from g_wseq.
        // Batch commit (wg_relay_commit) ensures we never see partial writes.
        // Core 2 is dedicated — FIFO delay can't starve Core 1 producer.
        static uint32_t rseq = 0;
        uint64_t deadline = wg_time_now() + (uint64_t)timeout_ms * 1000000ULL;
        
        while (wg_time_now() < deadline) {
            uint32_t w = g_wseq;
            __asm__ __volatile__("dmb ish" ::: "memory");
            
            if (rseq >= w) {
                svcSleepThread(50000);  // 50µs — more responsive for fragment bursts
                continue;
            }
            
            // Catch up if fell far behind (scheduling jitter)
            if (w - rseq > RING_SLOTS) rseq = w - RING_SLOTS + 1;
            
            // Drain next packet in strict FIFO order
            uint32_t idx = rseq & (RING_SLOTS - 1);
            uint16_t slot_len = g_ring[idx].len;
            if (slot_len == 0) {
                rseq++;
                continue;
            }
            
            size_t n = slot_len < len ? slot_len : len;
            memcpy(buf, (const void*)g_ring[idx].data, n);
            rseq++;
            return (int)n;
        }
        return WG_ERR_TIMEOUT;
    }
    struct pollfd pfd;
    pfd.fd = tun->socket_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0)
        return WG_ERR_SOCKET;
    if (ret == 0)
        return WG_ERR_TIMEOUT;

    if (!(pfd.revents & POLLIN))
        return WG_ERR_SOCKET;

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    ssize_t received = recvfrom(tun->socket_fd, buf, len, 0,
                                (struct sockaddr*)&src, &src_len);
    if (received < 0)
        return WG_ERR_SOCKET;

    tun->recv_src = src;
    tun->recv_src_valid = true;

    return (int)received;
}

void wg_update_endpoint_from_recv(WgTunnel* tun) {
    if (tun->recv_src_valid) {
        tun->endpoint = tun->recv_src;
        tun->recv_src_valid = false;
    }
}

void wg_socket_close(WgTunnel* tun) {
    if (tun->socket_fd >= 0) {
        close(tun->socket_fd);
        tun->socket_fd = -1;
    }
}

uint64_t wg_time_now(void) {
    return armTicksToNs(armGetSystemTick());
}

void wg_sleep_ms(int ms) {
    svcSleepThread((int64_t)ms * 1000000LL);
}

static uint32_t wg_random_u32(void) {
    uint32_t val;
    randomGet(&val, sizeof(val));
    return val;
}

void wg_generate_keypair(uint8_t private_key[WG_KEY_LEN], uint8_t public_key[WG_KEY_LEN]) {
    randomGet(private_key, WG_KEY_LEN);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    crypto_x25519_public_key(public_key, private_key);
}

uint32_t wg_random_index(void) {
    return wg_random_u32();
}

int wg_resolve_endpoint(WgTunnel* tun, const char* host, uint16_t port) {
    // Handle loopback directly (getaddrinfo may hang on Switch)
    if (host && strcmp(host, "127.0.0.1") == 0) {
        struct sockaddr_in *sa = (struct sockaddr_in*)&tun->endpoint;
        memset(sa, 0, sizeof(*sa));
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return WG_OK;
    }

    struct addrinfo hints;
    struct addrinfo* result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int err = getaddrinfo(host, port_str, &hints, &result);
    if (err != 0)
        return WG_ERR_SOCKET;

    if (result && result->ai_family == AF_INET) {
        memcpy(&tun->endpoint, result->ai_addr, sizeof(tun->endpoint));
        freeaddrinfo(result);
        return WG_OK;
    }

    if (result)
        freeaddrinfo(result);

    return WG_ERR_SOCKET;
}
