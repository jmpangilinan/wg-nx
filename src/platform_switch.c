#include "wg_internal.h"
#include <switch.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

int wg_socket_open(WgTunnel* tun) {
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

int wg_socket_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms) {
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
