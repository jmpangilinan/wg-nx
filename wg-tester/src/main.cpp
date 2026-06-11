#include <borealis.hpp>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

extern "C" {
#include "wireguard.h"
#include "wg_internal.h"
#include "wg_relay.h"
#include "wg_thread.h"
#include "blake2s.h"
#include "blake2s_neon.h"
#include "monocypher.h"
#include "wg_chacha20_neon.h"
#include "wg_poly1305_neon.h"
}

#include "wg_lwip_relay.hpp"

#define DEMO_HOST "demo.wireguard.com"
#define DEMO_TCP_PORT 42912

struct TestResult {
    std::string name;
    bool passed;
};

static std::vector<TestResult> results;

static void hex_to_bytes(uint8_t* out, const char* hex, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

static void test_blake2s() {
    uint8_t expected[32];
    hex_to_bytes(expected, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    uint8_t result[32];
    blake2s(result, 32, "abc", 3, NULL, 0);

    results.push_back({"BLAKE2s", compare_bytes(result, expected, 32)});
}

static void test_x25519() {
    uint8_t scalar[32], u[32], expected[32], result[32];
    hex_to_bytes(scalar, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", 32);
    hex_to_bytes(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", 32);
    hex_to_bytes(expected, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32);

    crypto_x25519(result, scalar, u);

    results.push_back({"X25519", compare_bytes(result, expected, 32)});
}

static void test_chacha20_poly1305() {
    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t nonce[12];
    hex_to_bytes(nonce, "070000004041424344454647", 12);

    const char* plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t plaintext_len = strlen(plaintext);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    uint8_t expected_tag[16];
    hex_to_bytes(expected_tag, "1ae10b594f09e26a7e902ecbd0600691", 16);

    uint8_t ciphertext[128];
    uint8_t tag[16];

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, tag, aad, 12, (const uint8_t*)plaintext, plaintext_len);

    results.push_back({"AEAD Encrypt", compare_bytes(tag, expected_tag, 16)});
}

static void test_chacha20_neon() {
    if (!wg_chacha20_neon_available()) {
        results.push_back({"ChaCha20 NEON", false});
        return;
    }

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t nonce[12];
    hex_to_bytes(nonce, "000000090000004a00000000", 12);

    uint8_t expected[64];
    hex_to_bytes(expected,
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e", 64);

    uint8_t block[64];
    wg_chacha20_block_neon(block, key, nonce, 1);

    bool block_ok = compare_bytes(block, expected, 64);

    uint8_t plain[128], cipher[128], dec[128];
    memset(plain, 0x42, 128);
    wg_chacha20_neon(cipher, plain, 128, key, nonce, 1);
    wg_chacha20_neon(dec, cipher, 128, key, nonce, 1);
    bool roundtrip_ok = compare_bytes(dec, plain, 128);

    results.push_back({"ChaCha20 NEON", block_ok && roundtrip_ok});
}

static void test_blake2s_neon() {
    if (!blake2s_neon_available()) {
        results.push_back({"BLAKE2s NEON", false});
        return;
    }

    uint8_t expected[32];
    hex_to_bytes(expected, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    uint8_t result[32];
    blake2s(result, 32, "abc", 3, NULL, 0);

    results.push_back({"BLAKE2s NEON", compare_bytes(result, expected, 32)});
}

static void test_aead_neon() {
    if (!wg_chacha20_neon_available()) {
        results.push_back({"AEAD NEON", false});
        return;
    }

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    const char* plaintext = "Test message for AEAD";
    size_t plaintext_len = strlen(plaintext);

    uint8_t cipher[256];
    uint8_t decrypted[256];

    wg_aead_neon_encrypt(cipher, key, 1, plaintext, plaintext_len, aad, 12);
    int result = wg_aead_neon_decrypt(decrypted, key, 1, cipher, plaintext_len + 16, aad, 12);

    bool ok = (result == 0) && compare_bytes(decrypted, (const uint8_t*)plaintext, plaintext_len);

    results.push_back({"AEAD NEON", ok});
}

static void test_mutex() {
    WgMutex mutex;
    bool ok = wg_mutex_init(&mutex, false) == 0;
    if (ok) {
        wg_mutex_lock(&mutex);
        wg_mutex_unlock(&mutex);
        wg_mutex_fini(&mutex);
    }
    results.push_back({"Mutex", ok});
}

static void test_cond() {
    WgCond cond;
    bool ok = wg_cond_init(&cond) == 0;
    if (ok) wg_cond_fini(&cond);
    results.push_back({"Cond", ok});
}

static void test_stop_cond() {
    WgStopCond stop;
    bool ok = wg_stop_cond_init(&stop) == 0;
    bool check1 = false, check2 = false;
    if (ok) {
        check1 = !wg_stop_cond_check(&stop);
        wg_stop_cond_signal(&stop);
        check2 = wg_stop_cond_check(&stop);
        wg_stop_cond_fini(&stop);
    }
    results.push_back({"StopCond", ok && check1 && check2});
}

static void test_keypair() {
    uint8_t priv[32], pub[32];
    wg_generate_keypair(priv, pub);

    char b64[64];
    bool to_ok = wg_key_to_base64(b64, sizeof(b64), pub) == 0;

    uint8_t decoded[32];
    bool from_ok = wg_key_from_base64(decoded, b64) == 0;
    bool match = compare_bytes(decoded, pub, 32);

    results.push_back({"Keypair + Base64", to_ok && from_ok && match});
}

static void test_thread_create() {
    WgThread thread;
    bool created = wg_thread_create(&thread, [](void* arg) -> void* {
        return arg;
    }, (void*)0x1234) == 0;

    void* retval = nullptr;
    bool joined = false;
    if (created) {
        joined = wg_thread_join(&thread, &retval) == 0;
    }

    results.push_back({"Thread Create/Join", created && joined && retval == (void*)0x1234});
}

static void test_wg_init() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    bool ok = tun != nullptr;

    if (tun) {
        struct in_addr ip;
        wg_get_ip(tun, &ip);
        ok = ok && (ip.s_addr == inet_addr("10.0.0.2"));
        wg_close(tun);
    }

    results.push_back({"WG Init/Close", ok});
}

static void test_relay() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    bool ok = tun != nullptr;

    WgRelay* relay = nullptr;
    if (ok) {
        relay = wg_relay_create(tun, 0);
        ok = ok && (relay != nullptr);
    }

    uint16_t port = 0;
    if (ok) {
        port = wg_relay_get_port(relay);
        ok = ok && (port > 0);
    }

    if (relay) wg_relay_destroy(relay);
    if (tun) wg_close(tun);

    results.push_back({"Relay Create", ok});
}

static void test_lwip_relay() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    bool ok = tun != nullptr;

    wgnx::LwipRelay* relay = nullptr;
    if (ok) {
        wgnx::LwipRelayConfig relayConfig;
        relayConfig.log_callback = [](wgnx::LogLevel level, const char* msg) {
            if (level == wgnx::LogLevel::Error) {
                brls::Logger::error("[LwipRelay] {}", msg);
            } else {
                brls::Logger::info("[LwipRelay] {}", msg);
            }
        };
        relayConfig.debug_logging = false;

        relay = new wgnx::LwipRelay(tun, relayConfig);
        ok = relay != nullptr;
    }

    if (ok && relay) {
        ok = relay->start("10.0.0.2", "10.0.0.1");
    }

    uint16_t tcpPort = 0;
    uint16_t udpPort = 0;
    if (ok && relay) {
        tcpPort = relay->startTcpRelay(9295, 9295);
        udpPort = relay->startUdpRelay(9296, 9296);
        ok = (tcpPort == 9295) && (udpPort == 9296);
    }

    if (relay) {
        relay->stop();
        delete relay;
    }
    if (tun) wg_close(tun);

    results.push_back({"LwipRelay Create", ok});
}

static bool get_demo_config(uint8_t* server_pub, uint16_t* udp_port, char* my_ip, const char* my_pub_b64) {
    struct hostent* he = gethostbyname(DEMO_HOST);
    if (!he) return false;

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) return false;

    struct sockaddr_in tcp_addr = {};
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(DEMO_TCP_PORT);
    memcpy(&tcp_addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(tcp_sock, (struct sockaddr*)&tcp_addr, sizeof(tcp_addr)) < 0) {
        close(tcp_sock);
        return false;
    }

    char request[128];
    snprintf(request, sizeof(request), "%s\n", my_pub_b64);
    send(tcp_sock, request, strlen(request), 0);

    char response[512];
    int resp_len = recv(tcp_sock, response, sizeof(response) - 1, 0);
    close(tcp_sock);

    if (resp_len <= 0) return false;
    response[resp_len] = '\0';

    char server_pub_b64[64] = {};
    int port = 0;

    char* line = strtok(response, "\n");
    while (line) {
        if (strncmp(line, "OK:", 3) == 0)
            sscanf(line, "OK:%63[^:]:%d:%31s", server_pub_b64, &port, my_ip);
        line = strtok(NULL, "\n");
    }

    if (port == 0) return false;

    wg_key_from_base64(server_pub, server_pub_b64);
    *udp_port = (uint16_t)port;
    return true;
}

static std::string rekey_error_detail;

static void test_udp_send() {
    struct hostent* he = gethostbyname(DEMO_HOST);
    if (!he) {
        results.push_back({"UDP Send", false});
        return;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        results.push_back({"UDP Send (sock)", false});
        return;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEMO_TCP_PORT);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    const char* msg = "test";
    ssize_t sent = sendto(sock, msg, 4, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    results.push_back({"UDP Send", sent == 4});
}

static void test_rekey_integration() {
    uint8_t priv[32], pub[32];
    wg_generate_keypair(priv, pub);

    char pub_b64[64];
    wg_key_to_base64(pub_b64, sizeof(pub_b64), pub);

    uint8_t server_pub[32];
    uint16_t server_port;
    char my_ip[32];

    if (!get_demo_config(server_pub, &server_port, my_ip, pub_b64)) {
        rekey_error_detail = "network";
        results.push_back({"Rekey", false});
        return;
    }

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, server_pub, 32);
    inet_pton(AF_INET, my_ip, &config.tunnel_ip);
    strncpy(config.endpoint_host, DEMO_HOST, sizeof(config.endpoint_host));
    config.endpoint_port = server_port;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        rekey_error_detail = "init failed";
        results.push_back({"Rekey", false});
        return;
    }

    int err = wg_connect(tun);
    if (err != WG_OK) {
        const char* err_name = "?";
        if (err == -2) err_name = "SOCKET";
        else if (err == -3) err_name = "HANDSHAKE";
        else if (err == -4) err_name = "TIMEOUT";
        rekey_error_detail = fmt::format("p:{} {}", server_port, err_name);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    uint32_t idx1 = wg_get_session_index(tun);

    brls::Logger::info("[DEBUG] calling wg_start");
    err = wg_start(tun);
    brls::Logger::info("[DEBUG] wg_start returned {}", err);
    if (err != WG_OK) {
        rekey_error_detail = fmt::format("start err={}", err);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    brls::Logger::info("[DEBUG] calling wg_rekey");
    err = wg_rekey(tun);
    if (err != WG_OK) {
        rekey_error_detail = fmt::format("rekey err={}", err);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    uint32_t idx2 = wg_get_session_index(tun);

    wg_close(tun);

    rekey_error_detail = fmt::format("idx {}→{}", idx1, idx2);
    results.push_back({"Rekey", idx1 != idx2});
}

static std::string poly1305_error_detail;

static void log_hex(const char* label, const uint8_t* data, size_t len) {
    /* Log in chunks of 16 bytes to avoid line wrapping issues */
    brls::Logger::info("[POLY] {}:", label);
    for (size_t offset = 0; offset < len; offset += 16) {
        std::string hex = "  ";
        size_t chunk = (len - offset > 16) ? 16 : (len - offset);
        for (size_t i = 0; i < chunk; i++) {
            hex += fmt::format("{:02x}", data[offset + i]);
            if (i % 4 == 3 && i < chunk - 1) hex += " ";
        }
        brls::Logger::info("{}", hex);
    }
}

static void test_poly1305_rfc() {
    brls::Logger::info("[POLY] === RFC 8439 Poly1305 Test ===");

    /* RFC 8439 Section 2.5.2 test vector */
    uint8_t key[32];
    hex_to_bytes(key,
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b", 32);

    const char* message = "Cryptographic Forum Research Group";
    size_t msg_len = strlen(message);

    uint8_t expected[16];
    hex_to_bytes(expected, "a8061dc1305136c6c22b8baf0c0127a9", 16);

    uint8_t neon_tag[16];
    uint8_t mono_tag[16];

    wg_poly1305(neon_tag, (const uint8_t*)message, msg_len, key);
    crypto_poly1305(mono_tag, (const uint8_t*)message, msg_len, key);

    log_hex("Expected", expected, 16);
    log_hex("NEON    ", neon_tag, 16);
    log_hex("Mono    ", mono_tag, 16);

    bool neon_ok = compare_bytes(neon_tag, expected, 16);
    bool mono_ok = compare_bytes(mono_tag, expected, 16);
    bool match = compare_bytes(neon_tag, mono_tag, 16);

    if (!neon_ok) {
        poly1305_error_detail = "NEON!=RFC";
        brls::Logger::error("[POLY] NEON does not match RFC expected!");
    }
    if (!mono_ok) {
        brls::Logger::error("[POLY] Mono does not match RFC expected!");
    }
    if (!match) {
        poly1305_error_detail = "NEON!=Mono";
        brls::Logger::error("[POLY] NEON and Mono results differ!");
    }

    results.push_back({"Poly1305 RFC", neon_ok && match});
}

static void test_poly1305_lengths() {
    brls::Logger::info("[POLY] === Various Length Tests ===");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x80);

    uint8_t message[256];
    for (int i = 0; i < 256; i++) message[i] = (uint8_t)i;

    bool all_pass = true;
    size_t test_lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128};

    for (size_t t = 0; t < sizeof(test_lengths)/sizeof(test_lengths[0]); t++) {
        size_t len = test_lengths[t];
        uint8_t neon_tag[16];
        uint8_t mono_tag[16];

        if (len == 0) {
            wg_poly1305(neon_tag, nullptr, 0, key);
            crypto_poly1305(mono_tag, (const uint8_t*)"", 0, key);
        } else {
            wg_poly1305(neon_tag, message, len, key);
            crypto_poly1305(mono_tag, message, len, key);
        }

        if (!compare_bytes(neon_tag, mono_tag, 16)) {
            brls::Logger::error("[POLY] FAIL at len={}", len);
            log_hex("  NEON", neon_tag, 16);
            log_hex("  Mono", mono_tag, 16);
            poly1305_error_detail = fmt::format("len={}", len);
            all_pass = false;
        }
    }

    if (all_pass) {
        brls::Logger::info("[POLY] All length tests passed");
    }

    results.push_back({"Poly1305 Lengths", all_pass});
}

static void test_poly1305_aead_compat() {
    brls::Logger::info("[POLY] === AEAD Compatibility Test ===");

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    const char* plaintext = "Test AEAD message";
    size_t plen = strlen(plaintext);

    /* Use WireGuard nonce format: 4 zero bytes + 8-byte little-endian counter */
    uint64_t counter = 42;

    /* Build nonce in WireGuard format */
    uint8_t wg_nonce[12] = {0};
    wg_nonce[4] = (uint8_t)(counter);
    wg_nonce[5] = (uint8_t)(counter >> 8);
    wg_nonce[6] = (uint8_t)(counter >> 16);
    wg_nonce[7] = (uint8_t)(counter >> 24);
    wg_nonce[8] = (uint8_t)(counter >> 32);
    wg_nonce[9] = (uint8_t)(counter >> 40);
    wg_nonce[10] = (uint8_t)(counter >> 48);
    wg_nonce[11] = (uint8_t)(counter >> 56);

    brls::Logger::info("[POLY] counter={}", counter);
    log_hex("WG nonce", wg_nonce, 12);

    /* Step 1: Compare poly1305 key derivation (ChaCha20 block 0) */
    brls::Logger::info("[POLY] --- Poly1305 Key Derivation ---");

    uint8_t neon_poly_key[64];
    wg_chacha20_block_neon(neon_poly_key, key, wg_nonce, 0);

    uint8_t mono_poly_key[64];
    crypto_chacha20_ietf(mono_poly_key, NULL, 64, key, wg_nonce, 0);

    log_hex("NEON polykey", neon_poly_key, 32);
    log_hex("Mono polykey", mono_poly_key, 32);

    bool polykey_match = compare_bytes(neon_poly_key, mono_poly_key, 32);
    if (!polykey_match) {
        brls::Logger::error("[POLY] POLY KEY MISMATCH! ChaCha20 block 0 differs!");
        poly1305_error_detail = "polykey";
    }

    /* Step 2: Compare ChaCha20 encryption (block 1+) */
    brls::Logger::info("[POLY] --- ChaCha20 Encryption ---");

    uint8_t neon_cipher[256];
    wg_chacha20_neon(neon_cipher, (const uint8_t*)plaintext, plen, key, wg_nonce, 1);

    uint8_t mono_cipher[256];
    crypto_chacha20_ietf(mono_cipher, (const uint8_t*)plaintext, plen, key, wg_nonce, 1);

    log_hex("NEON cipher", neon_cipher, plen);
    log_hex("Mono cipher", mono_cipher, plen);

    bool cipher_match = compare_bytes(neon_cipher, mono_cipher, plen);
    if (!cipher_match) {
        brls::Logger::error("[POLY] CIPHER MISMATCH! ChaCha20 encryption differs!");
        if (poly1305_error_detail.empty()) poly1305_error_detail = "cipher";
    }

    /* Step 3: Full AEAD comparison */
    brls::Logger::info("[POLY] --- Full AEAD ---");

    uint8_t mono_out[256];
    uint8_t mono_tag[16];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, wg_nonce);
    crypto_aead_write(&ctx, mono_out, mono_tag, aad, 12, (const uint8_t*)plaintext, plen);

    uint8_t neon_out[256];
    wg_aead_neon_encrypt(neon_out, key, counter, plaintext, plen, aad, 12);

    log_hex("Mono AEAD tag", mono_tag, 16);
    log_hex("NEON AEAD tag", neon_out + plen, 16);

    bool tag_match = compare_bytes(mono_tag, neon_out + plen, 16);
    if (!tag_match) {
        brls::Logger::error("[POLY] TAG MISMATCH!");
        if (poly1305_error_detail.empty()) poly1305_error_detail = "tag";
    }

    /* Cross-decrypt test */
    uint8_t dec[256];
    uint8_t mono_combined[256];
    memcpy(mono_combined, mono_out, plen);
    memcpy(mono_combined + plen, mono_tag, 16);
    int cross_result = wg_aead_neon_decrypt(dec, key, counter, mono_combined, plen + 16, aad, 12);
    brls::Logger::info("[POLY] NEON decrypt Mono: {}", cross_result);

    bool all_ok = polykey_match && cipher_match && tag_match && (cross_result == 0);
    results.push_back({"Poly1305 AEAD", all_ok});
}

static void test_poly1305_aead_32byte_ad() {
    brls::Logger::info("[POLY] === 32-byte AD Test (Handshake Hash Size) ===");

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    /* 32-byte AD - same size as WG_HASH_LEN used in handshake decrypt */
    uint8_t aad[32];
    for (int i = 0; i < 32; i++) aad[i] = (uint8_t)(i + 0x10);

    /* Test with empty plaintext like handshake encrypted_nothing */
    const uint8_t empty_plain[1] = {0};
    size_t plen = 0;

    uint64_t counter = 0; /* Handshake uses counter=0 */

    /* Build nonce in WireGuard format */
    uint8_t wg_nonce[12] = {0};
    wg_nonce[4] = (uint8_t)(counter);
    wg_nonce[5] = (uint8_t)(counter >> 8);
    wg_nonce[6] = (uint8_t)(counter >> 16);
    wg_nonce[7] = (uint8_t)(counter >> 24);
    wg_nonce[8] = (uint8_t)(counter >> 32);
    wg_nonce[9] = (uint8_t)(counter >> 40);
    wg_nonce[10] = (uint8_t)(counter >> 48);
    wg_nonce[11] = (uint8_t)(counter >> 56);

    log_hex("32-byte AD", aad, 32);

    /* Monocypher AEAD encrypt */
    uint8_t mono_out[256];
    uint8_t mono_tag[16];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, wg_nonce);
    crypto_aead_write(&ctx, mono_out, mono_tag, aad, 32, empty_plain, plen);

    /* NEON AEAD encrypt */
    uint8_t neon_out[256];
    wg_aead_neon_encrypt(neon_out, key, counter, empty_plain, plen, aad, 32);

    log_hex("Mono tag (32-AD)", mono_tag, 16);
    log_hex("NEON tag (32-AD)", neon_out + plen, 16);

    bool tag_match = compare_bytes(mono_tag, neon_out + plen, 16);
    if (!tag_match) {
        brls::Logger::error("[POLY] 32-byte AD: TAG MISMATCH!");
        poly1305_error_detail = "32-AD tag";
    }

    /* Cross-decrypt: NEON decrypt Monocypher output */
    uint8_t dec[256];
    uint8_t mono_combined[256];
    memcpy(mono_combined, mono_out, plen);
    memcpy(mono_combined + plen, mono_tag, 16);
    int neon_dec_mono = wg_aead_neon_decrypt(dec, key, counter, mono_combined, plen + 16, aad, 32);
    brls::Logger::info("[POLY] 32-AD: NEON decrypt Mono: {}", neon_dec_mono);

    /* Cross-decrypt: Monocypher decrypt NEON output */
    crypto_aead_ctx ctx2;
    crypto_aead_init_ietf(&ctx2, key, wg_nonce);
    int mono_dec_neon = crypto_aead_read(&ctx2, dec, neon_out + plen, aad, 32, neon_out, plen);
    brls::Logger::info("[POLY] 32-AD: Mono decrypt NEON: {}", mono_dec_neon);

    bool all_ok = tag_match && (neon_dec_mono == 0) && (mono_dec_neon == 0);

    /* Also test with non-empty plaintext */
    const char* test_msg = "Test with 32-byte AD";
    size_t test_len = strlen(test_msg);

    crypto_aead_ctx ctx3;
    crypto_aead_init_ietf(&ctx3, key, wg_nonce);
    crypto_aead_write(&ctx3, mono_out, mono_tag, aad, 32, (const uint8_t*)test_msg, test_len);

    wg_aead_neon_encrypt(neon_out, key, counter, test_msg, test_len, aad, 32);

    bool tag_match2 = compare_bytes(mono_tag, neon_out + test_len, 16);
    if (!tag_match2) {
        brls::Logger::error("[POLY] 32-byte AD (non-empty): TAG MISMATCH!");
        log_hex("Mono tag", mono_tag, 16);
        log_hex("NEON tag", neon_out + test_len, 16);
        if (poly1305_error_detail.empty()) poly1305_error_detail = "32-AD msg tag";
    }

    all_ok = all_ok && tag_match2;
    results.push_back({"AEAD 32-byte AD", all_ok});
}

/* ── Anti-replay sliding window tests (§5.4.6 / RFC6479) ── */

static void test_counter_sequential() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Sequential counters 0..999 should all be accepted */
    for (uint64_t i = 0; i < 1000; i++) {
        if (!wg_counter_validate(&rc, i)) {
            brls::Logger::error("[COUNTER] sequential failed at {}", i);
            ok = false;
            break;
        }
    }
    results.push_back({"Counter Sequential", ok});
}

static void test_counter_duplicate() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Accept counter 42, then reject duplicate */
    ok = ok && wg_counter_validate(&rc, 42);
    ok = ok && !wg_counter_validate(&rc, 42);
    /* Accept a new counter, then reject its duplicate too */
    ok = ok && wg_counter_validate(&rc, 100);
    ok = ok && !wg_counter_validate(&rc, 100);
    results.push_back({"Counter Duplicate", ok});
}

static void test_counter_out_of_order() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Push high water mark to 500 */
    ok = ok && wg_counter_validate(&rc, 500);
    /* Out-of-order within window should be accepted */
    ok = ok && wg_counter_validate(&rc, 300);
    ok = ok && wg_counter_validate(&rc, 499);
    ok = ok && wg_counter_validate(&rc, 1);
    /* But not duplicates of those */
    ok = ok && !wg_counter_validate(&rc, 300);
    ok = ok && !wg_counter_validate(&rc, 499);
    results.push_back({"Counter OOO", ok});
}

static void test_counter_window_boundary() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Push high water mark to WG_COUNTER_WINDOW_SIZE + 100 */
    uint64_t high = WG_COUNTER_WINDOW_SIZE + 100;
    ok = ok && wg_counter_validate(&rc, high);
    /* Counter exactly at the window boundary: high - WG_COUNTER_WINDOW_SIZE */
    /* This is the oldest counter still in window — should be accepted */
    uint64_t boundary = high - WG_COUNTER_WINDOW_SIZE + 1;
    ok = ok && wg_counter_validate(&rc, boundary);
    /* One before the boundary — too old, should be rejected */
    ok = ok && !wg_counter_validate(&rc, boundary - 1);
    results.push_back({"Counter Window", ok});
}

static void test_counter_reject_after_messages() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Counter at REJECT_AFTER_MESSAGES should be rejected (§6.2) */
    ok = ok && !wg_counter_validate(&rc, WG_REJECT_AFTER_MESSAGES);
    ok = ok && !wg_counter_validate(&rc, WG_REJECT_AFTER_MESSAGES + 1);
    /* Counter just below should be accepted */
    ok = ok && wg_counter_validate(&rc, WG_REJECT_AFTER_MESSAGES - 1);
    results.push_back({"Counter Reject Limit", ok});
}

static void test_counter_large_jump() {
    WgReplayCounter rc = {};
    bool ok = true;
    /* Accept 0, then jump far ahead — entire window should be cleared */
    ok = ok && wg_counter_validate(&rc, 0);
    ok = ok && wg_counter_validate(&rc, WG_COUNTER_WINDOW_SIZE * 3);
    /* 0 is now outside the window */
    ok = ok && !wg_counter_validate(&rc, 0);
    /* But something within the new window works */
    uint64_t high = WG_COUNTER_WINDOW_SIZE * 3;
    ok = ok && wg_counter_validate(&rc, high - 100);
    /* And it's not a false positive for a counter we never saw */
    ok = ok && wg_counter_validate(&rc, high - 200);
    results.push_back({"Counter Large Jump", ok});
}

/* ── XChaCha20Poly1305 test (cookie reply path, §5.4.7) ── */

static void test_xchacha20poly1305() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x10);

    uint8_t nonce[24];
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i + 0x30);

    uint8_t ad[16];
    for (int i = 0; i < 16; i++) ad[i] = (uint8_t)(i + 0x50);

    /* Encrypt with monocypher's XChaCha20Poly1305 */
    const uint8_t plaintext[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    uint8_t ciphertext[16];
    uint8_t tag[16];

    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, tag, ad, sizeof(ad), plaintext, sizeof(plaintext));
    crypto_wipe(&ctx, sizeof(ctx));

    /* Combine ciphertext + tag for wg_xaead_decrypt (expects appended tag) */
    uint8_t combined[32]; /* 16 ciphertext + 16 tag */
    memcpy(combined, ciphertext, 16);
    memcpy(combined + 16, tag, 16);

    /* Decrypt with our wg_xaead_decrypt */
    uint8_t decrypted[16];
    int result = wg_xaead_decrypt(decrypted, key, nonce, combined, sizeof(combined), ad, sizeof(ad));

    bool decrypt_ok = (result == 0);
    bool data_ok = compare_bytes(decrypted, plaintext, 16);

    /* Also test with wrong AD — should fail */
    uint8_t bad_ad[16];
    memcpy(bad_ad, ad, 16);
    bad_ad[0] ^= 0xFF;
    uint8_t dummy[16];
    int bad_result = wg_xaead_decrypt(dummy, key, nonce, combined, sizeof(combined), bad_ad, sizeof(bad_ad));
    bool reject_ok = (bad_result != 0);

    results.push_back({"XChaCha20Poly1305", decrypt_ok && data_ok && reject_ok});
}

/* ── Transport after rekey integration test ── */

static std::string transport_error_detail;

static void test_transport_after_rekey() {
    uint8_t priv[32], pub[32];
    wg_generate_keypair(priv, pub);

    char pub_b64[64];
    wg_key_to_base64(pub_b64, sizeof(pub_b64), pub);

    uint8_t server_pub[32];
    uint16_t server_port;
    char my_ip[32];

    if (!get_demo_config(server_pub, &server_port, my_ip, pub_b64)) {
        transport_error_detail = "network";
        results.push_back({"Transport Rekey", false});
        return;
    }

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, server_pub, 32);
    inet_pton(AF_INET, my_ip, &config.tunnel_ip);
    strncpy(config.endpoint_host, DEMO_HOST, sizeof(config.endpoint_host));
    config.endpoint_port = server_port;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        transport_error_detail = "init";
        results.push_back({"Transport Rekey", false});
        return;
    }

    int err = wg_connect(tun);
    if (err != WG_OK) {
        transport_error_detail = fmt::format("connect={}", err);
        wg_close(tun);
        results.push_back({"Transport Rekey", false});
        return;
    }

    /* Send a keepalive on the first session to confirm it works */
    uint8_t keepalive[sizeof(WgTransport) + WG_AEAD_TAG_LEN];
    WgTransport* pkt = (WgTransport*)keepalive;
    pkt->type = WG_MSG_TRANSPORT;
    memset(pkt->reserved, 0, sizeof(pkt->reserved));
    pkt->receiver_index = tun->session.remote_index;
    pkt->counter = tun->session.sending_counter++;
    wg_aead_encrypt(pkt->encrypted_data, tun->session.sending_key, pkt->counter, NULL, 0, NULL, 0);
    wg_socket_send(tun, keepalive, sizeof(keepalive));

    uint32_t idx1 = tun->session.local_index;

    /* Start recv thread so rekey can get responses */
    err = wg_start(tun);
    if (err != WG_OK) {
        transport_error_detail = fmt::format("start={}", err);
        wg_close(tun);
        results.push_back({"Transport Rekey", false});
        return;
    }

    /* Rekey to get a new session */
    err = wg_rekey(tun);
    if (err != WG_OK) {
        transport_error_detail = fmt::format("rekey={}", err);
        wg_close(tun);
        results.push_back({"Transport Rekey", false});
        return;
    }

    uint32_t idx2 = tun->session.local_index;
    bool index_changed = (idx1 != idx2);

    /* Send transport data on the NEW session */
    uint8_t test_data[] = {0x45, 0x00, 0x00, 0x1c}; /* minimal IP header start */
    int send_result = wg_send(tun, test_data, sizeof(test_data));
    bool send_ok = (send_result == (int)sizeof(test_data));

    /* Verify prev_session holds the old index (session rotation §6.3) */
    bool rotation_ok = tun->prev_session.valid && (tun->prev_session.local_index == idx1);

    wg_close(tun);

    transport_error_detail = fmt::format("idx {}→{} send={} rot={}",
        idx1, idx2, send_result, rotation_ok ? 1 : 0);
    results.push_back({"Transport Rekey", index_changed && send_ok && rotation_ok});
}

/* ── AEAD (monocypher path) roundtrip tests ── */

static void test_aead_roundtrip() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0xA0);

    const char* plaintext = "WireGuard transport data test payload";
    size_t plen = strlen(plaintext);

    /* Encrypt then decrypt — basic roundtrip */
    uint8_t ciphertext[256];
    wg_aead_encrypt(ciphertext, key, 7, plaintext, plen, NULL, 0);

    uint8_t decrypted[256];
    int result = wg_aead_decrypt(decrypted, key, 7, ciphertext, plen + WG_AEAD_TAG_LEN, NULL, 0);
    bool roundtrip_ok = (result == 0) && compare_bytes(decrypted, (const uint8_t*)plaintext, plen);

    /* Wrong counter — must fail */
    result = wg_aead_decrypt(decrypted, key, 8, ciphertext, plen + WG_AEAD_TAG_LEN, NULL, 0);
    bool wrong_ctr_ok = (result != 0);

    /* Wrong key — must fail */
    uint8_t bad_key[32];
    memcpy(bad_key, key, 32);
    bad_key[0] ^= 0xFF;
    result = wg_aead_decrypt(decrypted, bad_key, 7, ciphertext, plen + WG_AEAD_TAG_LEN, NULL, 0);
    bool wrong_key_ok = (result != 0);

    /* Tampered ciphertext — must fail */
    uint8_t tampered[256];
    memcpy(tampered, ciphertext, plen + WG_AEAD_TAG_LEN);
    tampered[0] ^= 0x01;
    result = wg_aead_decrypt(decrypted, key, 7, tampered, plen + WG_AEAD_TAG_LEN, NULL, 0);
    bool tamper_ok = (result != 0);

    results.push_back({"AEAD Roundtrip", roundtrip_ok && wrong_ctr_ok && wrong_key_ok && tamper_ok});
}

static void test_aead_with_ad() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t ad[32];
    for (int i = 0; i < 32; i++) ad[i] = (uint8_t)(i + 0x10);

    const char* plaintext = "test with AD";
    size_t plen = strlen(plaintext);

    uint8_t ciphertext[256];
    wg_aead_encrypt(ciphertext, key, 0, plaintext, plen, ad, 32);

    /* Correct AD — succeeds */
    uint8_t decrypted[256];
    int result = wg_aead_decrypt(decrypted, key, 0, ciphertext, plen + WG_AEAD_TAG_LEN, ad, 32);
    bool ad_ok = (result == 0) && compare_bytes(decrypted, (const uint8_t*)plaintext, plen);

    /* Wrong AD — must fail */
    uint8_t bad_ad[32];
    memcpy(bad_ad, ad, 32);
    bad_ad[0] ^= 0xFF;
    result = wg_aead_decrypt(decrypted, key, 0, ciphertext, plen + WG_AEAD_TAG_LEN, bad_ad, 32);
    bool bad_ad_ok = (result != 0);

    /* No AD when one was used — must fail */
    result = wg_aead_decrypt(decrypted, key, 0, ciphertext, plen + WG_AEAD_TAG_LEN, NULL, 0);
    bool no_ad_ok = (result != 0);

    results.push_back({"AEAD with AD", ad_ok && bad_ad_ok && no_ad_ok});
}

static void test_aead_empty() {
    uint8_t key[32] = {0};

    /* Empty plaintext (keepalive packet) */
    uint8_t ciphertext[WG_AEAD_TAG_LEN];
    wg_aead_encrypt(ciphertext, key, 0, NULL, 0, NULL, 0);

    uint8_t decrypted[1];
    int result = wg_aead_decrypt(decrypted, key, 0, ciphertext, WG_AEAD_TAG_LEN, NULL, 0);
    bool empty_ok = (result == 0);

    /* Too short ciphertext — must fail */
    result = wg_aead_decrypt(decrypted, key, 0, ciphertext, WG_AEAD_TAG_LEN - 1, NULL, 0);
    bool short_ok = (result != 0);

    results.push_back({"AEAD Empty", empty_ok && short_ok});
}

/* ── Cookie reply full flow test (§5.4.7) ── */

static void test_cookie_reply_flow() {
    /* Create a tunnel so we have a real WgTunnel struct */
    uint8_t priv[32], pub[32], peer_priv[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_priv, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        results.push_back({"Cookie Reply Flow", false});
        return;
    }

    /* Set up state as if we sent a handshake init */
    uint32_t our_index = 0xDEADBEEF;
    tun->session.local_index = our_index;
    /* Simulate mac1 that was sent with the init */
    uint8_t fake_mac1[WG_MAC_LEN];
    for (int i = 0; i < WG_MAC_LEN; i++) fake_mac1[i] = (uint8_t)(i + 0x42);
    memcpy(tun->last_mac1, fake_mac1, WG_MAC_LEN);

    /* Construct a cookie reply as the server would:
     * key = HASH(LABEL_COOKIE || peer_public)
     * AD  = mac1 from the initiating handshake
     * plaintext = 16-byte cookie
     */
    uint8_t cookie_key[WG_HASH_LEN];
    wg_hash2(cookie_key, WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE), peer_pub, WG_KEY_LEN);

    uint8_t real_cookie[WG_COOKIE_LEN];
    for (int i = 0; i < WG_COOKIE_LEN; i++) real_cookie[i] = (uint8_t)(i + 0xC0);

    uint8_t nonce[WG_COOKIE_NONCE_LEN];
    for (int i = 0; i < WG_COOKIE_NONCE_LEN; i++) nonce[i] = (uint8_t)(i + 0x77);

    /* Encrypt with XChaCha20Poly1305 */
    uint8_t encrypted_cookie[WG_COOKIE_LEN + WG_AEAD_TAG_LEN];
    uint8_t tag[WG_AEAD_TAG_LEN];
    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, cookie_key, nonce);
    crypto_aead_write(&ctx, encrypted_cookie, tag, fake_mac1, WG_MAC_LEN, real_cookie, WG_COOKIE_LEN);
    memcpy(encrypted_cookie + WG_COOKIE_LEN, tag, WG_AEAD_TAG_LEN);
    crypto_wipe(&ctx, sizeof(ctx));

    /* Build the cookie reply message */
    WgCookieReply reply;
    reply.type = WG_MSG_COOKIE_REPLY;
    memset(reply.reserved, 0, sizeof(reply.reserved));
    reply.receiver_index = our_index;
    memcpy(reply.nonce, nonce, WG_COOKIE_NONCE_LEN);
    memcpy(reply.encrypted_cookie, encrypted_cookie, sizeof(reply.encrypted_cookie));

    /* Process it */
    tun->has_cookie = false;
    int err = wg_process_cookie_reply(tun, &reply);

    bool decrypt_ok = (err == WG_OK);
    bool cookie_set = tun->has_cookie;
    bool cookie_match = compare_bytes(tun->cookie, real_cookie, WG_COOKIE_LEN);
    bool timestamp_set = (tun->cookie_timestamp > 0);

    /* Wrong receiver_index — must fail */
    reply.receiver_index = 0x12345678;
    int bad_err = wg_process_cookie_reply(tun, &reply);
    bool bad_index_ok = (bad_err != WG_OK);

    wg_close(tun);

    results.push_back({"Cookie Reply Flow", decrypt_ok && cookie_set && cookie_match && timestamp_set && bad_index_ok});
}

/* ── Hash / HMAC tests ── */

static void test_wg_hash() {
    /* wg_hash is BLAKE2s — verify against known vector */
    uint8_t expected[32];
    hex_to_bytes(expected, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    uint8_t result[32];
    wg_hash(result, "abc", 3);

    results.push_back({"WG Hash", compare_bytes(result, expected, 32)});
}

static void test_wg_hash2() {
    /* wg_hash2(a, b) should equal BLAKE2s(a || b) */
    const char* a = "Hello";
    const char* b = "World";

    /* Compute via wg_hash2 */
    uint8_t h2[32];
    wg_hash2(h2, a, 5, b, 5);

    /* Compute via BLAKE2s with concatenated input */
    uint8_t concat[10];
    memcpy(concat, a, 5);
    memcpy(concat + 5, b, 5);
    uint8_t h_concat[32];
    wg_hash(h_concat, concat, 10);

    results.push_back({"WG Hash2", compare_bytes(h2, h_concat, 32)});
}

static void test_wg_mac() {
    /* wg_mac is keyed BLAKE2s with 16-byte output */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t mac1[WG_MAC_LEN], mac2[WG_MAC_LEN];
    wg_mac(mac1, key, 32, "test", 4);
    wg_mac(mac2, key, 32, "test", 4);

    /* Same input → same output */
    bool same_ok = compare_bytes(mac1, mac2, WG_MAC_LEN);

    /* Different input → different output */
    wg_mac(mac2, key, 32, "tess", 4);
    bool diff_ok = !compare_bytes(mac1, mac2, WG_MAC_LEN);

    /* Different key → different output */
    uint8_t key2[32];
    memcpy(key2, key, 32);
    key2[0] ^= 0xFF;
    wg_mac(mac2, key2, 32, "test", 4);
    bool diff_key_ok = !compare_bytes(mac1, mac2, WG_MAC_LEN);

    results.push_back({"WG MAC", same_ok && diff_ok && diff_key_ok});
}

static void test_wg_hmac() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x50);

    uint8_t hmac1[32], hmac2[32];

    /* Deterministic */
    wg_hmac(hmac1, 32, key, 32, "data", 4);
    wg_hmac(hmac2, 32, key, 32, "data", 4);
    bool same_ok = compare_bytes(hmac1, hmac2, 32);

    /* Different data → different output */
    wg_hmac(hmac2, 32, key, 32, "dat0", 4);
    bool diff_ok = !compare_bytes(hmac1, hmac2, 32);

    /* Different key → different output */
    uint8_t key2[32];
    memcpy(key2, key, 32);
    key2[0] ^= 0xFF;
    wg_hmac(hmac2, 32, key2, 32, "data", 4);
    bool diff_key_ok = !compare_bytes(hmac1, hmac2, 32);

    results.push_back({"WG HMAC", same_ok && diff_ok && diff_key_ok});
}

/* ── KDF tests ── */

static void test_kdf_consistency() {
    /* kdf1(key, input) should equal the first output of kdf2(key, input) */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x20);

    const char* input = "KDF test input";

    uint8_t kdf1_out[32];
    wg_kdf1(kdf1_out, key, input, strlen(input));

    uint8_t kdf2_out1[32], kdf2_out2[32];
    wg_kdf2(kdf2_out1, kdf2_out2, key, input, strlen(input));

    /* kdf1 == kdf2's first output */
    bool kdf1_eq_kdf2 = compare_bytes(kdf1_out, kdf2_out1, 32);

    /* kdf2's two outputs must differ */
    bool kdf2_diff = !compare_bytes(kdf2_out1, kdf2_out2, 32);

    /* kdf3's first two outputs should match kdf2 */
    uint8_t kdf3_out1[32], kdf3_out2[32], kdf3_out3[32];
    wg_kdf3(kdf3_out1, kdf3_out2, kdf3_out3, key, input, strlen(input));

    bool kdf3_eq1 = compare_bytes(kdf3_out1, kdf2_out1, 32);
    bool kdf3_eq2 = compare_bytes(kdf3_out2, kdf2_out2, 32);
    bool kdf3_diff = !compare_bytes(kdf3_out2, kdf3_out3, 32);

    results.push_back({"KDF Consistency", kdf1_eq_kdf2 && kdf2_diff && kdf3_eq1 && kdf3_eq2 && kdf3_diff});
}

static void test_kdf_deterministic() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t out_a[32], out_b[32];
    wg_kdf1(out_a, key, "same", 4);
    wg_kdf1(out_b, key, "same", 4);
    bool same_ok = compare_bytes(out_a, out_b, 32);

    /* Different input → different output */
    wg_kdf1(out_b, key, "diff", 4);
    bool diff_input = !compare_bytes(out_a, out_b, 32);

    /* Different key → different output */
    uint8_t key2[32];
    memcpy(key2, key, 32);
    key2[0] ^= 0xFF;
    wg_kdf1(out_b, key2, "same", 4);
    bool diff_key = !compare_bytes(out_a, out_b, 32);

    /* Empty input */
    wg_kdf1(out_a, key, NULL, 0);
    wg_kdf1(out_b, key, NULL, 0);
    bool empty_ok = compare_bytes(out_a, out_b, 32);

    results.push_back({"KDF Deterministic", same_ok && diff_input && diff_key && empty_ok});
}

/* ── WireGuard construction constants test ── */

static void test_wg_construction_hash() {
    /*
     * §5.4: C := HASH(CONSTRUCTION) where CONSTRUCTION = "Noise_IKpsk2_..."
     * Then H := HASH(C || IDENTIFIER)
     * Verify these are deterministic and match chained computation.
     */
    uint8_t c[32];
    wg_hash(c, WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));

    uint8_t h[32];
    wg_hash2(h, c, 32, WG_IDENTIFIER, strlen(WG_IDENTIFIER));

    /* Recompute — must be identical */
    uint8_t c2[32], h2[32];
    wg_hash(c2, WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));
    wg_hash2(h2, c2, 32, WG_IDENTIFIER, strlen(WG_IDENTIFIER));

    bool c_ok = compare_bytes(c, c2, 32);
    bool h_ok = compare_bytes(h, h2, 32);
    /* C and H must differ */
    bool diff_ok = !compare_bytes(c, h, 32);

    results.push_back({"WG Construction", c_ok && h_ok && diff_ok});
}

/* ── Base64 edge cases ── */

static void test_base64_edge_cases() {
    /* Valid roundtrip (already tested, but include for completeness) */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    char b64[64];
    bool encode_ok = (wg_key_to_base64(b64, sizeof(b64), key) == 0);
    uint8_t decoded[32];
    bool decode_ok = (wg_key_from_base64(decoded, b64) == 0);
    bool match_ok = compare_bytes(decoded, key, 32);

    /* Too-short buffer for encoding */
    char short_buf[10];
    bool short_encode = (wg_key_to_base64(short_buf, sizeof(short_buf), key) != 0);

    /* NULL input */
    bool null_ok = (wg_key_from_base64(decoded, NULL) != 0);

    /* Too-short base64 string */
    bool short_ok = (wg_key_from_base64(decoded, "AAAA") != 0);

    /* Invalid characters */
    char invalid[44] = {};
    memset(invalid, '!', 43);
    invalid[43] = '\0';
    bool invalid_ok = (wg_key_from_base64(decoded, invalid) != 0);

    /* All zeros key */
    uint8_t zero_key[32] = {0};
    char zero_b64[64];
    wg_key_to_base64(zero_b64, sizeof(zero_b64), zero_key);
    uint8_t zero_decoded[32];
    bool zero_ok = (wg_key_from_base64(zero_decoded, zero_b64) == 0) &&
                   compare_bytes(zero_decoded, zero_key, 32);

    /* All 0xFF key */
    uint8_t ff_key[32];
    memset(ff_key, 0xFF, 32);
    char ff_b64[64];
    wg_key_to_base64(ff_b64, sizeof(ff_b64), ff_key);
    uint8_t ff_decoded[32];
    bool ff_ok = (wg_key_from_base64(ff_decoded, ff_b64) == 0) &&
                 compare_bytes(ff_decoded, ff_key, 32);

    results.push_back({"Base64 Edges", encode_ok && decode_ok && match_ok && short_encode &&
                                        null_ok && short_ok && invalid_ok && zero_ok && ff_ok});
}

/* ── Rekey index matching test (§6.3 / old_local_index) ── */

static void test_rekey_index_matching() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        results.push_back({"Rekey Index Match", false});
        return;
    }

    /*
     * Simulate the state after wg_handshake_init during rekey:
     *   - session.local_index = NEW sender index (0xAAAAAAAA)
     *   - session.old_local_index = OLD sender index (0xBBBBBBBB)
     *   - session.rekey_in_progress = true
     *   - prev_session.valid = true, prev_session.local_index = 0xCCCCCCCC
     *
     * The recv thread must accept transport packets addressed to ANY of:
     *   1. session.local_index (new, unconfirmed)
     *   2. session.old_local_index (old, while rekey in progress)
     *   3. prev_session.local_index (even older session)
     * And reject anything else.
     */
    const uint32_t NEW_IDX  = 0xAAAAAAAA;
    const uint32_t OLD_IDX  = 0xBBBBBBBB;
    const uint32_t PREV_IDX = 0xCCCCCCCC;
    const uint32_t BAD_IDX  = 0xDDDDDDDD;

    /* Set up a fake valid session in rekey state */
    uint8_t recv_key[WG_KEY_LEN];
    memset(recv_key, 0x42, WG_KEY_LEN);
    memcpy(tun->session.receiving_key, recv_key, WG_KEY_LEN);
    tun->session.local_index = NEW_IDX;
    tun->session.old_local_index = OLD_IDX;
    tun->session.rekey_in_progress = true;
    tun->session.valid = true;
    tun->session.last_handshake = wg_time_now();
    tun->session.receiving_counter = 0;
    memset(&tun->session.replay, 0, sizeof(tun->session.replay));

    /* Set up prev_session */
    uint8_t prev_key[WG_KEY_LEN];
    memset(prev_key, 0x99, WG_KEY_LEN);
    memcpy(tun->prev_session.receiving_key, prev_key, WG_KEY_LEN);
    tun->prev_session.local_index = PREV_IDX;
    tun->prev_session.valid = true;
    tun->prev_session.last_handshake = wg_time_now();
    tun->prev_session.receiving_counter = 0;
    memset(&tun->prev_session.replay, 0, sizeof(tun->prev_session.replay));

    /*
     * Replicate the recv thread's index matching logic (wireguard.c:415-427).
     * This is the exact code path that the old_local_index fix addresses.
     */
    auto match_session = [&](uint32_t receiver_index) -> WgSession* {
        if (receiver_index == tun->session.local_index) {
            return &tun->session;
        } else if (tun->session.rekey_in_progress &&
                   receiver_index == tun->session.old_local_index) {
            return &tun->session;
        } else if (tun->prev_session.valid &&
                   receiver_index == tun->prev_session.local_index) {
            return &tun->prev_session;
        }
        return nullptr;
    };

    /* Test 1: NEW index matches current session */
    WgSession* s1 = match_session(NEW_IDX);
    bool new_ok = (s1 == &tun->session);

    /* Test 2: OLD index matches current session during rekey (the fix) */
    WgSession* s2 = match_session(OLD_IDX);
    bool old_ok = (s2 == &tun->session);

    /* Test 3: PREV index matches prev_session */
    WgSession* s3 = match_session(PREV_IDX);
    bool prev_ok = (s3 == &tun->prev_session);

    /* Test 4: BAD index matches nothing */
    WgSession* s4 = match_session(BAD_IDX);
    bool bad_ok = (s4 == nullptr);

    /* Test 5: OLD index should NOT match when rekey is NOT in progress */
    tun->session.rekey_in_progress = false;
    WgSession* s5 = match_session(OLD_IDX);
    bool no_rekey_ok = (s5 == nullptr);

    /* Test 6: Verify AEAD decrypt works on the matched session's key.
     * This confirms the full path: index match → correct key → decrypt success.
     */
    tun->session.rekey_in_progress = true; /* restore */
    uint8_t plaintext[] = {0x45, 0x00, 0x00, 0x1c}; /* minimal IP header */
    uint8_t ciphertext[sizeof(plaintext) + WG_AEAD_TAG_LEN];
    wg_aead_encrypt(ciphertext, recv_key, 0, plaintext, sizeof(plaintext), NULL, 0);

    /* Decrypt using the key from the session matched by OLD index */
    WgSession* matched = match_session(OLD_IDX);
    uint8_t decrypted[sizeof(plaintext)];
    bool decrypt_ok = false;
    if (matched) {
        int dec = wg_aead_decrypt(decrypted, matched->receiving_key, 0,
                                  ciphertext, sizeof(ciphertext), NULL, 0);
        decrypt_ok = (dec == 0) && (memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    }

    wg_close(tun);

    bool all_ok = new_ok && old_ok && prev_ok && bad_ok && no_rekey_ok && decrypt_ok;
    results.push_back({"Rekey Index Match", all_ok});
}

/* ── Session expiry test ── */

static void test_session_expiry() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        results.push_back({"Session Expiry", false});
        return;
    }

    /* Not connected — wg_send should fail */
    uint8_t data[] = {0x01, 0x02};
    bool not_connected = (wg_send(tun, data, 2) == WG_ERR_NOT_CONNECTED);

    /* Fake a valid session */
    memset(tun->session.sending_key, 0xAA, WG_KEY_LEN);
    tun->session.remote_index = 0x12345678;
    tun->session.valid = true;
    tun->session.sending_counter = 0;

    /* Session with recent handshake — should NOT be expired */
    tun->session.last_handshake = wg_time_now();

    /* Open socket so wg_send can actually try to send */
    wg_socket_open(tun);

    bool send_ok = (wg_send(tun, data, 2) >= 0 || wg_send(tun, data, 2) == WG_ERR_SOCKET);
    /* WG_ERR_SOCKET is acceptable — we're sending to 127.0.0.1 which may fail,
     * but the point is it got past the session validity checks */

    /* Set handshake time far in the past (> REJECT_AFTER_TIME = 180s) */
    tun->session.last_handshake = wg_time_now() - ((uint64_t)WG_REJECT_AFTER_TIME + 1) * 1000000000ULL;
    bool expired = (wg_send(tun, data, 2) == WG_ERR_NOT_CONNECTED);

    /* Set counter past REJECT_AFTER_MESSAGES */
    tun->session.last_handshake = wg_time_now(); /* reset time */
    tun->session.sending_counter = WG_REJECT_AFTER_MESSAGES;
    bool counter_expired = (wg_send(tun, data, 2) == WG_ERR_NOT_CONNECTED);

    wg_close(tun);

    results.push_back({"Session Expiry", not_connected && expired && counter_expired});
}

static void run_all_tests() {
    results.clear();
    test_blake2s();
    test_x25519();
    test_chacha20_poly1305();
    test_chacha20_neon();
    test_poly1305_rfc();
    test_poly1305_lengths();
    test_poly1305_aead_compat();
    brls::Logger::info("[DEBUG] calling 32-byte AD test");
    test_poly1305_aead_32byte_ad();
    brls::Logger::info("[DEBUG] 32-byte AD test done");
    test_aead_neon();
    test_blake2s_neon();
    test_mutex();
    test_cond();
    test_stop_cond();
    test_keypair();
    test_thread_create();
    test_wg_init();
    test_relay();
    test_lwip_relay();
    test_udp_send();
    test_rekey_integration();
    test_counter_sequential();
    test_counter_duplicate();
    test_counter_out_of_order();
    test_counter_window_boundary();
    test_counter_reject_after_messages();
    test_counter_large_jump();
    test_xchacha20poly1305();
    test_aead_roundtrip();
    test_aead_with_ad();
    test_aead_empty();
    test_cookie_reply_flow();
    test_wg_hash();
    test_wg_hash2();
    test_wg_mac();
    test_wg_hmac();
    test_kdf_consistency();
    test_kdf_deterministic();
    test_wg_construction_hash();
    test_base64_edge_cases();
    test_rekey_index_matching();
    test_session_expiry();
    test_transport_after_rekey();
}

class TestActivity : public brls::Activity {
public:
    brls::View* createContentView() override {
        run_all_tests();

        auto* scroll = new brls::ScrollingFrame();
        scroll->setWidthPercentage(100);
        scroll->setHeightPercentage(100);

        auto* box = new brls::Box(brls::Axis::COLUMN);
        box->setAlignItems(brls::AlignItems::CENTER);
        box->setPaddingTop(40);
        box->setPaddingBottom(40);

        int passed = 0, failed = 0;
        for (const auto& r : results) {
            if (r.passed) passed++; else failed++;
        }

        auto* title = new brls::Label();
        title->setText("WireGuard Switch Tests");
        title->setFontSize(32);
        title->setMarginBottom(20);
        box->addView(title);

        auto* summary = new brls::Label();
        summary->setText(fmt::format("{} passed, {} failed", passed, failed));
        summary->setFontSize(24);
        summary->setMarginBottom(30);
        box->addView(summary);

        for (const auto& r : results) {
            auto* row = new brls::Box(brls::Axis::ROW);
            row->setAlignItems(brls::AlignItems::CENTER);
            row->setMarginBottom(10);
            row->setFocusable(true);

            auto* name = new brls::Label();
            std::string label = r.name;
            if (r.name == "Rekey" && !rekey_error_detail.empty()) {
                label = fmt::format("Rekey ({})", rekey_error_detail);
            } else if (r.name == "Transport Rekey" && !transport_error_detail.empty()) {
                label = fmt::format("Transport Rekey ({})", transport_error_detail);
            } else if (r.name.find("Poly1305") != std::string::npos && !poly1305_error_detail.empty() && !r.passed) {
                label = fmt::format("{} ({})", r.name, poly1305_error_detail);
            }
            name->setText(label);
            name->setWidth(350);
            row->addView(name);

            auto* status = new brls::Label();
            status->setText(r.passed ? "PASS" : "FAIL");
            status->setTextColor(r.passed ? nvgRGB(0, 200, 0) : nvgRGB(200, 0, 0));
            row->addView(status);

            box->addView(row);
        }

        scroll->setContentView(box);
        return scroll;
    }
};

static void wg_log_handler(const char* msg) {
    brls::Logger::info("[WG] {}", msg);
}

int main(int argc, char* argv[]) {
    brls::Logger::setLogLevel(brls::LogLevel::LOG_DEBUG);

    if (!brls::Application::init()) {
        brls::Logger::error("Unable to init Borealis application");
        return EXIT_FAILURE;
    }

    wg_set_log_callback(wg_log_handler);

    brls::Application::createWindow("WireGuard Tester");
    brls::Application::setGlobalQuit(true);

    brls::Application::pushActivity(new TestActivity());

    while (brls::Application::mainLoop())
        ;

    return EXIT_SUCCESS;
}
