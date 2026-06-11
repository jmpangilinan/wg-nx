#include "wg_relay.h"
#include "wg_internal.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#define RELAY_MAX_PACKET 65535
#define RELAY_POLL_TIMEOUT_MS 100

struct WgRelay {
    WgTunnel* tunnel;
    int local_socket;
    uint16_t local_port;
    struct sockaddr_in client_addr;
    int has_client;
    WgThread relay_thread;
    WgStopCond stop_cond;
    int running;
};

static int relay_recv_callback(void* user, WgRecvSlot* slot, const void* data, size_t len) {
    (void)slot;
    WgRelay* relay = (WgRelay*)user;

    if (!relay->has_client)
        return 0;

    sendto(relay->local_socket, data, len, 0,
           (struct sockaddr*)&relay->client_addr,
           sizeof(relay->client_addr));
    return 0;
}

static void* relay_thread_func(void* arg) {
    WgRelay* relay = (WgRelay*)arg;
    wg_thread_set_affinity(WG_THREAD_NAME_RELAY);
    uint8_t buf[RELAY_MAX_PACKET];
    struct sockaddr_in from_addr;
    socklen_t from_len;

    while (!wg_stop_cond_check(&relay->stop_cond)) {
        struct pollfd pfd;
        pfd.fd = relay->local_socket;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, RELAY_POLL_TIMEOUT_MS);
        if (ret <= 0)
            continue;

        if (!(pfd.revents & POLLIN))
            continue;

        from_len = sizeof(from_addr);
        ssize_t received = recvfrom(relay->local_socket, buf, sizeof(buf), 0,
                                    (struct sockaddr*)&from_addr, &from_len);

        if (received <= 0)
            continue;

        relay->client_addr = from_addr;
        relay->has_client = 1;

        wg_send(relay->tunnel, buf, received);
    }

    return NULL;
}

WgRelay* wg_relay_create(WgTunnel* tun, uint16_t local_port) {
    if (!tun)
        return NULL;

    WgRelay* relay = calloc(1, sizeof(WgRelay));
    if (!relay)
        return NULL;

    relay->tunnel = tun;
    relay->local_port = local_port;
    relay->has_client = 0;
    relay->running = 0;

    relay->local_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (relay->local_socket < 0) {
        free(relay);
        return NULL;
    }

    int yes = 1;
    setsockopt(relay->local_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = htons(local_port);

    if (bind(relay->local_socket, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        close(relay->local_socket);
        free(relay);
        return NULL;
    }

    if (local_port == 0) {
        socklen_t len = sizeof(bind_addr);
        getsockname(relay->local_socket, (struct sockaddr*)&bind_addr, &len);
        relay->local_port = ntohs(bind_addr.sin_port);
    }

    if (wg_stop_cond_init(&relay->stop_cond) != 0) {
        close(relay->local_socket);
        free(relay);
        return NULL;
    }

    return relay;
}

int wg_relay_start(WgRelay* relay) {
    if (!relay || relay->running)
        return -1;

    wg_set_recv_callback(relay->tunnel, relay_recv_callback, relay);

    int err = wg_start(relay->tunnel);
    if (err != WG_OK)
        return err;

    relay->stop_cond.pred = false;

    if (wg_thread_create(&relay->relay_thread, relay_thread_func, relay) != 0) {
        wg_stop(relay->tunnel);
        return -1;
    }

    relay->running = 1;
    return 0;
}

void wg_relay_stop(WgRelay* relay) {
    if (!relay || !relay->running)
        return;

    wg_stop_cond_signal(&relay->stop_cond);
    wg_thread_join(&relay->relay_thread, NULL);
    wg_stop(relay->tunnel);

    relay->running = 0;
}

void wg_relay_destroy(WgRelay* relay) {
    if (!relay)
        return;

    wg_relay_stop(relay);
    wg_stop_cond_fini(&relay->stop_cond);

    if (relay->local_socket >= 0)
        close(relay->local_socket);

    free(relay);
}

uint16_t wg_relay_get_port(WgRelay* relay) {
    if (!relay)
        return 0;
    return relay->local_port;
}
