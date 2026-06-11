#ifndef WG_INTERNAL_H
#define WG_INTERNAL_H

#include "wireguard.h"
#include "wg_thread.h"
#include "monocypher.h"
#include <stdbool.h>
#include <stdio.h>

#define WG_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_IDENTIFIER "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WG_LABEL_MAC1 "mac1----"
#define WG_LABEL_COOKIE "cookie--"

// Canary magic to detect buffer overflows
#define WG_CANARY_MAGIC 0xDEADC0DE

#define WG_HASH_LEN 32
#define WG_AEAD_TAG_LEN 16
#define WG_TIMESTAMP_LEN 12
#define WG_COOKIE_LEN 16
#define WG_MAC_LEN 16
#define WG_RELAY_HASH_LEN 36

#define WG_REKEY_AFTER_MESSAGES  ((uint64_t)1 << 60)
#define WG_COUNTER_WINDOW_SIZE   8192
#define WG_REJECT_AFTER_MESSAGES (UINT64_MAX - WG_COUNTER_WINDOW_SIZE - 1)

#define WG_RECV_SLOT_CAP   2048
#define WG_RECV_POOL_SIZE  256

#define WG_MAX_PEERS 64

struct WgRecvSlot {
    struct WgRecvSlot* next;
    uint8_t data[WG_RECV_SLOT_CAP];
};

typedef struct {
    WgRecvSlot* slots;
    WgRecvSlot* free_head;
    WgMutex free_mutex;
    bool initialized;
} WgRecvPool;

#define WG_COUNTER_WORDS (WG_COUNTER_WINDOW_SIZE / (sizeof(uint64_t) * 8))
typedef struct {
    uint64_t counter;
    uint64_t backtrack[WG_COUNTER_WORDS];
} WgReplayCounter;
#define WG_REKEY_AFTER_TIME      120
#define WG_REJECT_AFTER_TIME     180
#define WG_REKEY_ATTEMPT_TIME    90
#define WG_REKEY_TIMEOUT         5
#define WG_MAX_TIMER_HANDSHAKES  18
#define WG_KEEPALIVE_TIMEOUT     10
#define WG_COOKIE_SECRET_MAX_AGE 120

typedef enum {
    WG_MSG_HANDSHAKE_INIT = 1,
    WG_MSG_HANDSHAKE_RESPONSE = 2,
    WG_MSG_COOKIE_REPLY = 3,
    WG_MSG_TRANSPORT = 4,
} WgMsgType;

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t sender_index;
    uint8_t ephemeral[WG_KEY_LEN];
    uint8_t encrypted_static[WG_KEY_LEN + WG_AEAD_TAG_LEN];
    uint8_t encrypted_timestamp[WG_TIMESTAMP_LEN + WG_AEAD_TAG_LEN];
    uint8_t mac1[WG_MAC_LEN];
    uint8_t mac2[WG_MAC_LEN];
} WgHandshakeInit;

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t sender_index;
    uint32_t receiver_index;
    uint8_t ephemeral[WG_KEY_LEN];
    uint8_t encrypted_nothing[WG_AEAD_TAG_LEN];
    uint8_t mac1[WG_MAC_LEN];
    uint8_t mac2[WG_MAC_LEN];
} WgHandshakeResponse;

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t receiver_index;
    uint64_t counter;
    uint8_t encrypted_data[];
} WgTransport;

#define WG_COOKIE_NONCE_LEN 24
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t receiver_index;
    uint8_t nonce[WG_COOKIE_NONCE_LEN];
    uint8_t encrypted_cookie[WG_COOKIE_LEN + WG_AEAD_TAG_LEN];
} WgCookieReply;

typedef struct {
    uint8_t hash[WG_HASH_LEN];
    uint8_t chaining_key[WG_HASH_LEN];
    uint8_t ephemeral_private[WG_KEY_LEN];
} WgHandshakeState;

typedef struct {
    uint8_t sending_key[WG_KEY_LEN];
    uint8_t receiving_key[WG_KEY_LEN];
    uint64_t sending_counter;
    uint64_t receiving_counter;
    uint32_t local_index;
    uint32_t old_local_index;
    uint32_t remote_index;
    uint64_t last_handshake;
    uint64_t last_received;
    bool valid;
    bool rekey_in_progress;
    WgReplayCounter replay;
} WgSession;

// ─── Multi-peer support ──────────────────────────────────────

typedef struct WgPeer {
    uint8_t public_key[WG_KEY_LEN];       // peer's static public key
    uint8_t relay_hash[WG_RELAY_HASH_LEN]; // relay peer hash (sha-XXXX...)
    struct in_addr tunnel_ip;              // peer's NetBird IP
    uint32_t ip_raw;                      // IP in network byte order
    
    WgSession session;
    WgSession prev_session;
    WgHandshakeState pending_hs;  // stored during active handshake init
    bool hs_pending;               // true if handshake is in progress
    
    bool configured;     // slot is in use
    bool connected;      // session established
    
    uint64_t last_sent;
    uint8_t last_mac1[WG_MAC_LEN];
} WgPeer;

struct WgTunnel {
    uint8_t static_private[WG_KEY_LEN];
    uint8_t static_public[WG_KEY_LEN];
    
    // Legacy single-peer fields (kept for backward compat with wg_connect/wg_rekey)
    uint8_t peer_public[WG_KEY_LEN];
    uint8_t preshared_key[WG_KEY_LEN];
    bool has_psk;
    struct in_addr tunnel_ip;
    struct sockaddr_in endpoint;
    uint16_t keepalive_interval;
    int socket_fd;
    WgSession session;          // legacy (keep for wg_connect path)
    WgSession prev_session;     // legacy
    
    // ─── Multi-peer ───
    WgPeer peers[WG_MAX_PEERS];
    int peer_count;
    
    // Canary to detect buffer overflows
    uint32_t canary_begin;
    
    // Cookie (shared across all peers)
    uint8_t cookie[WG_COOKIE_LEN];
    bool has_cookie;
    uint64_t cookie_timestamp;
    uint8_t last_mac1[WG_MAC_LEN];

    WgThread recv_thread;
    WgThread keepalive_thread;
    WgStopCond stop_cond;
    WgMutex send_mutex;
    uint8_t send_buffer[2048];
    WgRecvCallback recv_cb;
    void* recv_cb_user;
    bool running;

    uint64_t last_sent;

    uint8_t pending_response[256];
    int pending_response_len;
    bool pending_cookie;

    struct sockaddr_in recv_src;
    bool recv_src_valid;

    WgRecvPool recv_pool;
    
    uint32_t canary_end;  // must be last field — detect overflow
};

// ─── Peer management ───
WgPeer* wg_add_peer(WgTunnel* tun, const uint8_t public_key[WG_KEY_LEN],
                    const uint8_t relay_hash[WG_RELAY_HASH_LEN], uint32_t ip_raw);
WgPeer* wg_find_peer_by_ip(WgTunnel* tun, uint32_t ip_raw);
WgPeer* wg_find_peer_by_local_index(WgTunnel* tun, uint32_t local_index);
WgPeer* wg_find_peer_by_public_key(WgTunnel* tun, const uint8_t public_key[WG_KEY_LEN]);

// ─── Send to a specific peer ───
int wg_send_to_peer(WgTunnel* tun, WgPeer* peer, const void* data, size_t len);
void wg_send_keepalive_to_peer(WgTunnel* tun, WgPeer* peer);

int wg_recv_pool_init(WgRecvPool* pool);
void wg_recv_pool_destroy(WgRecvPool* pool);
WgRecvSlot* wg_recv_pool_acquire(WgRecvPool* pool);
void wg_recv_pool_release(WgRecvPool* pool, WgRecvSlot* slot);

void wg_hash(uint8_t out[WG_HASH_LEN], const void* data, size_t len);
void wg_hash2(uint8_t out[WG_HASH_LEN], const void* a, size_t a_len, const void* b, size_t b_len);
void wg_mac(uint8_t out[WG_MAC_LEN], const uint8_t* key, size_t key_len, const void* data, size_t len);
void wg_hmac(uint8_t* out, size_t out_len, const uint8_t* key, size_t key_len, const void* data, size_t data_len);
void wg_kdf1(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len);
void wg_kdf2(uint8_t out1[WG_HASH_LEN], uint8_t out2[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len);
void wg_kdf3(uint8_t out1[WG_HASH_LEN], uint8_t out2[WG_HASH_LEN], uint8_t out3[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* input, size_t input_len);
void wg_mix_hash(WgHandshakeState* state, const void* data, size_t len);
void wg_mix_key(WgHandshakeState* state, const void* input, size_t len);
int wg_aead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter, const void* plaintext, size_t plaintext_len, const void* ad, size_t ad_len);
int wg_aead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter, const void* ciphertext, size_t ciphertext_len, const void* ad, size_t ad_len);
int wg_xaead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_COOKIE_NONCE_LEN], const void* ciphertext, size_t ciphertext_len, const void* ad, size_t ad_len);

void wg_timestamp(uint8_t out[WG_TIMESTAMP_LEN]);
uint64_t wg_time_now(void);
void wg_sleep_ms(int ms);

bool wg_counter_validate(WgReplayCounter* rc, uint64_t counter);

int wg_handshake_init(WgTunnel* tun, WgHandshakeInit* msg, WgHandshakeState* state);
int wg_handshake_init_peer(WgTunnel* tun, WgPeer* peer, WgHandshakeInit* msg, WgHandshakeState* state);
int wg_handshake_init_process_response(WgTunnel* tun, WgPeer* peer, const WgHandshakeResponse* msg);
int wg_handshake_init_process(WgTunnel* tun, const WgHandshakeInit* msg);
int wg_handshake_response(WgTunnel* tun, const WgHandshakeResponse* msg, WgHandshakeState* state);
int wg_process_cookie_reply(WgTunnel* tun, const WgCookieReply* msg);

int wg_socket_open(WgTunnel* tun);
int wg_socket_send(WgTunnel* tun, const void* data, size_t len);
int wg_socket_send_to(WgTunnel* tun, const uint8_t* relay_hash, const void* data, size_t len);
int wg_socket_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms);

// Relay integration: replace socket layer with relay transport
void wg_set_relay_send(void (*send_fn)(const uint8_t* peer_hash, const void* data, size_t len));
void wg_relay_input(const void *data, size_t len);
void wg_relay_commit(void);
void wg_socket_close(WgTunnel* tun);
void wg_update_endpoint_from_recv(WgTunnel* tun);

uint32_t wg_random_index(void);
int wg_resolve_endpoint(WgTunnel* tun, const char* host, uint16_t port);

extern bool wg_log_enabled;
void wg_log_impl(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
#define wg_log(...) do { if (__builtin_expect(wg_log_enabled, 0)) wg_log_impl(__VA_ARGS__); } while (0)

#endif
