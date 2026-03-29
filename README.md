# wg-nx

Note:
This is a personal project, and as such, I will most likely not provide any support at all for this outside of personal use cases

Userland WireGuard library for Nintendo Switch.

![tester](readme/wg-nx.jpg)

## Cryptography

| Algorithm | Implementation | Reference |
|-----------|---------------|-----------|
| ChaCha20 | ARM NEON (`src/wg_chacha20_neon.c`) | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) |
| Poly1305 | ARM NEON (`src/wg_poly1305_neon.c`) | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) |
| BLAKE2s | ARM NEON (`src/blake2s_neon.c`) | [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693) |
| X25519 ECDH | [Monocypher](https://monocypher.org/) | [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) |

Monocypher provides X25519 and is used as a reference for verifying NEON correctness in tests.

### Protocol

| Component | Reference |
|-----------|-----------|
| WireGuard | [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf) |
| Noise IKpsk2 | [Noise Protocol Framework](http://www.noiseprotocol.org/noise.html) |


## API

### Error Codes

```c
typedef enum {
    WG_OK = 0,
    WG_ERR_INVALID_CONFIG = -1,
    WG_ERR_SOCKET = -2,
    WG_ERR_HANDSHAKE = -3,
    WG_ERR_TIMEOUT = -4,
    WG_ERR_DECRYPT = -5,
    WG_ERR_NOT_CONNECTED = -6,
    WG_ERR_BUFFER_TOO_SMALL = -7,
    WG_ERR_THREAD = -8,
    WG_ERR_ALREADY_RUNNING = -9,
} WgError;
```

### Configuration

```c
#define WG_KEY_LEN 32
#define WG_MAX_ENDPOINT 256

typedef struct {
    uint8_t private_key[WG_KEY_LEN];
    struct in_addr tunnel_ip;
    uint8_t peer_public_key[WG_KEY_LEN];
    char endpoint_host[WG_MAX_ENDPOINT];
    uint16_t endpoint_port;
    uint16_t keepalive_interval;
    uint8_t preshared_key[WG_KEY_LEN];
    int has_preshared_key;
} WgConfig;
```

### Tunnel Lifecycle

```c
WgTunnel* wg_init(const WgConfig* config);
int wg_connect(WgTunnel* tun);
int wg_start(WgTunnel* tun);
void wg_stop(WgTunnel* tun);
void wg_close(WgTunnel* tun);
```

### Send/Receive

```c
typedef void (*WgRecvCallback)(void* user, const void* data, size_t len);

int wg_send(WgTunnel* tun, const void* data, size_t len);
int wg_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms);
void wg_set_recv_callback(WgTunnel* tun, WgRecvCallback cb, void* user);
```

### Session Management

```c
int wg_rekey(WgTunnel* tun);
uint32_t wg_get_session_index(WgTunnel* tun);
int wg_get_ip(WgTunnel* tun, struct in_addr* addr);
```

### Key Utilities

```c
void wg_generate_keypair(uint8_t private_key[WG_KEY_LEN], uint8_t public_key[WG_KEY_LEN]);
int wg_key_from_base64(uint8_t key[WG_KEY_LEN], const char* base64);
int wg_key_to_base64(char* base64, size_t len, const uint8_t key[WG_KEY_LEN]);
```

### Logging

```c
void wg_set_log_callback(void (*func)(const char* msg));
```

### UDP Relay

For apps that expect a normal UDP socket:

```c
typedef struct WgRelay WgRelay;

WgRelay* wg_relay_create(WgTunnel* tun, uint16_t local_port);
int wg_relay_start(WgRelay* relay);
void wg_relay_stop(WgRelay* relay);
void wg_relay_destroy(WgRelay* relay);
uint16_t wg_relay_get_port(WgRelay* relay);
```

### lwIP TCP/UDP Relay

For apps that need full TCP/UDP connectivity over the tunnel, the `lwip-relay/` module provides a relay using the lwIP TCP/IP stack.

```cpp
namespace wgnx {

enum class LogLevel {
    Debug,
    Info,
    Error
};

struct LwipRelayConfig {
    std::function<void(LogLevel level, const char* message)> log_callback;
    std::function<void()> thread_affinity_callback;
    bool debug_logging = false;
};

class LwipRelay {
public:
    explicit LwipRelay(WgTunnel* tunnel, const LwipRelayConfig& config = {});
    ~LwipRelay();

    bool start(const std::string& tunnelIp, const std::string& targetIp);
    void stop();

    uint16_t startTcpRelay(uint16_t targetPort, uint16_t localPort);
    uint16_t startUdpRelay(uint16_t targetPort, uint16_t localPort);

    void handleIncomingPacket(const void* data, size_t len);
    void tick();

    bool isRunning() const;
};

}
```

#### Example

```cpp
#include <wg_lwip_relay.hpp>

wgnx::LwipRelayConfig config;
config.log_callback = [](wgnx::LogLevel level, const char* msg) {
    printf("[WG] %s\n", msg);
};
config.debug_logging = false;

wgnx::LwipRelay relay(tunnel, config);
relay.start("10.0.0.2", "10.0.0.1");

relay.startTcpRelay(9295, 9295);
relay.startUdpRelay(9296, 9296);

wg_set_recv_callback(tunnel, [](void* ctx, const void* data, size_t len) {
    static_cast<wgnx::LwipRelay*>(ctx)->handleIncomingPacket(data, len);
}, &relay);

relay.stop();
```

## Testing

`wg-tester/` provides a borealis app that tests crypto primitives, threading, and a small integration rekey test against the publicly available wireguard demo server.

```bash
./dev.sh --build-only
./dev.sh <SWITCH_IP>
```
