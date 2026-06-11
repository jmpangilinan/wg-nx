#include "wg_lwip_relay.hpp"
#include "wg_netif.h"
#include <cstring>
#include <cstdarg>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

extern "C" {
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/ip.h"
}

namespace wgnx {

static constexpr size_t LOG_BUFFER_SIZE = 512;

LwipRelay::LwipRelay(WgTunnel* tunnel, const LwipRelayConfig& config)
    : tunnel_(tunnel)
    , config_(config)
    , running_(false)
    , initialized_(false) {
    memset(&netif_, 0, sizeof(netif_));
    memset(&tunnelAddr_, 0, sizeof(tunnelAddr_));
    memset(&targetAddr_, 0, sizeof(targetAddr_));
    for (auto& h : slotHolders_) {
        h.in_use = 0;
        h.tunnel = nullptr;
        h.slot = nullptr;
    }
}

LwipRelay::~LwipRelay() {
    stop();
}

void LwipRelay::log(LogLevel level, const char* fmt, ...) {
    if (!config_.log_callback) {
        return;
    }
    if (level == LogLevel::Debug && !config_.debug_logging) {
        return;
    }

    char buf[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    config_.log_callback(level, buf);
}

bool LwipRelay::start(const std::string& tunnelIp, const std::string& targetIp) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (running_) {
        return false;
    }

    if (!initialized_) {
        lwip_init();
        initialized_ = true;
    }

    if (inet_pton(AF_INET, tunnelIp.c_str(), &tunnelAddr_) != 1) {
        log(LogLevel::Error, "LwipRelay: invalid tunnel IP: %s", tunnelIp.c_str());
        return false;
    }

    if (inet_pton(AF_INET, targetIp.c_str(), &targetAddr_) != 1) {
        log(LogLevel::Error, "LwipRelay: invalid target IP: %s", targetIp.c_str());
        return false;
    }

    ip4_addr_t netmask, gw;
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);

    netif_add(&netif_, &tunnelAddr_, &netmask, &gw, tunnel_, wg_netif_init, ip_input);
    netif_set_default(&netif_);
    netif_set_up(&netif_);

    log(LogLevel::Info, "LwipRelay: netif created with IP %s", tunnelIp.c_str());

    /* Self-pipe via a connected loopback UDP pair — libnx's BSD sockets
     * don't implement AF_UNIX, so socketpair() is unavailable here. */
    wakeFd_[0] = socket(AF_INET, SOCK_DGRAM, 0);
    wakeFd_[1] = socket(AF_INET, SOCK_DGRAM, 0);
    if (wakeFd_[0] < 0 || wakeFd_[1] < 0) {
        log(LogLevel::Error, "LwipRelay: wake socket create failed");
        if (wakeFd_[0] >= 0) { close(wakeFd_[0]); wakeFd_[0] = -1; }
        if (wakeFd_[1] >= 0) { close(wakeFd_[1]); wakeFd_[1] = -1; }
        netif_set_down(&netif_);
        netif_remove(&netif_);
        return false;
    }
    sockaddr_in wakeAddr{};
    wakeAddr.sin_family = AF_INET;
    wakeAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    wakeAddr.sin_port = 0;
    if (bind(wakeFd_[0], (sockaddr*)&wakeAddr, sizeof(wakeAddr)) < 0) {
        log(LogLevel::Error, "LwipRelay: wake bind failed");
        close(wakeFd_[0]); wakeFd_[0] = -1;
        close(wakeFd_[1]); wakeFd_[1] = -1;
        netif_set_down(&netif_);
        netif_remove(&netif_);
        return false;
    }
    socklen_t wakeLen = sizeof(wakeAddr);
    if (getsockname(wakeFd_[0], (sockaddr*)&wakeAddr, &wakeLen) < 0 ||
        connect(wakeFd_[1], (sockaddr*)&wakeAddr, sizeof(wakeAddr)) < 0) {
        log(LogLevel::Error, "LwipRelay: wake connect failed");
        close(wakeFd_[0]); wakeFd_[0] = -1;
        close(wakeFd_[1]); wakeFd_[1] = -1;
        netif_set_down(&netif_);
        netif_remove(&netif_);
        return false;
    }
    fcntl(wakeFd_[0], F_SETFL, fcntl(wakeFd_[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(wakeFd_[1], F_SETFL, fcntl(wakeFd_[1], F_GETFL, 0) | O_NONBLOCK);

    pollFds_.reserve(32);

    running_ = true;
    wg_set_recv_callback(tunnel_, &LwipRelay::onTunnelRecv, this);
    loopThread_ = std::thread(&LwipRelay::runLoop, this);

    return true;
}

void LwipRelay::signalWake() {
    if (wakeFd_[1] < 0) return;
    char c = 1;
    (void)write(wakeFd_[1], &c, 1);
}

void LwipRelay::stop() {
    running_ = false;

    /* Unregister recv callback before joining so no new slots enter the queue. */
    if (tunnel_) {
        wg_set_recv_callback(tunnel_, nullptr, nullptr);
    }

    signalWake();  /* break the blocking poll in runLoop */

    if (loopThread_.joinable()) {
        loopThread_.join();
    }

    if (wakeFd_[0] >= 0) { close(wakeFd_[0]); wakeFd_[0] = -1; }
    if (wakeFd_[1] >= 0) { close(wakeFd_[1]); wakeFd_[1] = -1; }

    /* Drain any slots still in the queue that never reached lwIP. */
    {
        std::lock_guard<std::mutex> qlock(queueMutex_);
        while (!incomingQueue_.empty()) {
            auto& front = incomingQueue_.front();
            if (tunnel_ && front.slot) {
                wg_recv_slot_release(tunnel_, front.slot);
            }
            incomingQueue_.pop();
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& pair : tcpListeners_) {
        close(pair.second);
    }
    tcpListeners_.clear();

    for (auto& pair : tcpConnections_) {
        if (pair.second->localSock >= 0) {
            close(pair.second->localSock);
        }
        if (pair.second->pcb) {
            tcp_abort(pair.second->pcb);
        }
    }
    tcpConnections_.clear();

    for (auto& pair : udpBindings_) {
        if (pair.second->localSock >= 0) {
            close(pair.second->localSock);
        }
        if (pair.second->pcb) {
            udp_remove(pair.second->pcb);
        }
    }
    udpBindings_.clear();

    if (netif_.flags & NETIF_FLAG_UP) {
        netif_set_down(&netif_);
        netif_remove(&netif_);
    }

    log(LogLevel::Info, "LwipRelay: stopped");
}

uint16_t LwipRelay::startTcpRelay(uint16_t targetPort, uint16_t localPort) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (tcpListeners_.find(localPort) != tcpListeners_.end()) {
        return localPort;
    }

    int sock = createTcpListener(localPort);
    if (sock < 0) {
        return 0;
    }

    tcpListeners_[localPort] = sock;
    log(LogLevel::Info, "LwipRelay: TCP listener on port %u -> %u", localPort, targetPort);
    signalWake();
    return localPort;
}

uint16_t LwipRelay::startUdpRelay(uint16_t targetPort, uint16_t localPort) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (udpBindings_.find(localPort) != udpBindings_.end()) {
        return localPort;
    }

    int sock = createUdpSocket(localPort);
    if (sock < 0) {
        return 0;
    }

    struct udp_pcb* pcb = udp_new();
    if (!pcb) {
        close(sock);
        return 0;
    }

    ip_addr_t localAddr;
    ip_addr_copy_from_ip4(localAddr, tunnelAddr_);
    err_t err = udp_bind(pcb, &localAddr, localPort);
    if (err != ERR_OK) {
        log(LogLevel::Error, "LwipRelay: udp_bind failed: %d", (int)err);
        udp_remove(pcb);
        close(sock);
        return 0;
    }

    auto binding = std::make_shared<UdpBinding>();
    binding->localSock = sock;
    binding->pcb = pcb;
    binding->localPort = localPort;
    binding->targetPort = targetPort;
    binding->hasClient = false;

    udp_recv(pcb, onUdpRecv, binding.get());
    udpBindings_[localPort] = binding;

    log(LogLevel::Info, "LwipRelay: UDP socket on port %u -> %u", localPort, targetPort);
    signalWake();
    return localPort;
}

int LwipRelay::onTunnelRecv(void* user, WgRecvSlot* slot, const void* data, size_t len) {
    return static_cast<LwipRelay*>(user)->handleIncomingPacket(slot, data, len);
}

int LwipRelay::handleIncomingPacket(WgRecvSlot* slot, const void* data, size_t len) {
    if (!running_ || !slot || !data || len == 0) {
        return 0;
    }
    /* Only wake if the queue was empty. Otherwise the lwIP thread is either
     * already processing or will pick this up on its next drain — saves a
     * write/read syscall pair per packet during bursts. */
    bool was_empty;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        was_empty = incomingQueue_.empty();
        incomingQueue_.push({slot, static_cast<const uint8_t*>(data), len});
    }
    if (was_empty) signalWake();
    return 1;
}

void LwipRelay::processIncomingQueue() {
    /* Cap per-iteration drain so downstream consumers (e.g. the chiaki video
     * decoder) get packets in small batches rather than one huge burst.
     * If more remain, we re-arm the wake so the loop comes right back. */
    constexpr size_t kMaxPerIteration = 16;

    std::vector<IncomingSlot> packets;
    bool more = false;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        size_t n = std::min(incomingQueue_.size(), kMaxPerIteration);
        packets.reserve(n);
        for (size_t i = 0; i < n; i++) {
            packets.push_back(incomingQueue_.front());
            incomingQueue_.pop();
        }
        more = !incomingQueue_.empty();
    }
    for (const auto& pkt : packets) {
        WgSlotPbuf* holder = nullptr;
        for (auto& h : slotHolders_) {
            if (!h.in_use) { holder = &h; break; }
        }
        if (!holder) {
            /* No holder free — lwIP is holding too many. Drop and release slot. */
            wg_recv_slot_release(tunnel_, pkt.slot);
            continue;
        }
        wg_netif_input_slot(&netif_, tunnel_, pkt.slot, pkt.data, pkt.len, holder);
    }
    if (more) signalWake();
}

void LwipRelay::tick() {
    sys_check_timeouts();
}

void LwipRelay::runLoop() {
    if (config_.thread_affinity_callback) {
        config_.thread_affinity_callback();
    }

    log(LogLevel::Info, "LwipRelay: loop started");

    /* Event-driven: block in a single poll() watching the wake pipe and all
     * managed sockets. The 200ms timeout bounds lwIP timer accuracy, still
     * well within TCP's 500ms retransmit floor, and halves idle wake-up
     * syscalls vs the previous 50ms. */
    constexpr int kPollTimeoutMs = 200;

    while (running_) {
        pollFds_.clear();
        pollFds_.push_back({wakeFd_[0], POLLIN, 0});

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& pair : tcpListeners_) {
                pollFds_.push_back({pair.second, POLLIN, 0});
            }
            for (auto& pair : tcpConnections_) {
                if (pair.second->connected) {
                    pollFds_.push_back({pair.first, POLLIN, 0});
                }
            }
            for (auto& pair : udpBindings_) {
                pollFds_.push_back({pair.second->localSock, POLLIN, 0});
            }
        }

        poll(pollFds_.data(), pollFds_.size(), kPollTimeoutMs);

        if (!running_) break;

        /* Drain any queued wake bytes. */
        if (pollFds_[0].revents & POLLIN) {
            char buf[64];
            while (read(wakeFd_[0], buf, sizeof(buf)) > 0) {}
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            processIncomingQueue();
            pollTcpListeners();
            pollTcpConnections();
            pollUdpSockets();
            sys_check_timeouts();
        }
    }

    log(LogLevel::Info, "LwipRelay: loop ended");
}

void LwipRelay::pollTcpListeners() {
    for (auto& pair : tcpListeners_) {
        uint16_t localPort = pair.first;
        int listenSock = pair.second;

        pollfd pfd;
        pfd.fd = listenSock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, 0);
        if (ret <= 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(listenSock, (sockaddr*)&clientAddr, &clientLen);
        if (clientSock < 0) {
            continue;
        }

        int flags = fcntl(clientSock, F_GETFL, 0);
        fcntl(clientSock, F_SETFL, flags | O_NONBLOCK);

        struct tcp_pcb* pcb = tcp_new();
        if (!pcb) {
            close(clientSock);
            continue;
        }

        auto conn = std::make_shared<TcpConnection>();
        conn->localSock = clientSock;
        conn->pcb = pcb;
        conn->localPort = localPort;
        conn->targetPort = localPort;
        conn->connected = false;

        tcp_arg(pcb, conn.get());
        tcp_err(pcb, onTcpError);

        tcpConnections_[clientSock] = conn;

        ip_addr_t destAddr;
        ip_addr_copy_from_ip4(destAddr, targetAddr_);

        log(LogLevel::Info, "LwipRelay: new TCP connection, connecting to target port %u", localPort);

        err_t err = tcp_connect(pcb, &destAddr, localPort, onTcpConnected);
        if (err != ERR_OK) {
            log(LogLevel::Error, "LwipRelay: tcp_connect failed: %d", (int)err);
            tcp_abort(pcb);
            close(clientSock);
            tcpConnections_.erase(clientSock);
        }
    }
}

void LwipRelay::pollTcpConnections() {
    std::vector<int> toRemove;

    for (auto& pair : tcpConnections_) {
        int sock = pair.first;
        auto& conn = pair.second;

        if (!conn->connected) {
            continue;
        }

        pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, 0);
        if (ret < 0) {
            toRemove.push_back(sock);
            continue;
        }

        if (ret > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t received = recv(sock, buf, sizeof(buf), 0);

            if (received <= 0) {
                if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    log(LogLevel::Info, "LwipRelay: local socket closed");
                    if (conn->pcb) {
                        tcp_close(conn->pcb);
                        conn->pcb = nullptr;
                    }
                    toRemove.push_back(sock);
                }
                continue;
            }

            if (conn->pcb) {
                err_t err = tcp_write(conn->pcb, buf, (u16_t)received, TCP_WRITE_FLAG_COPY);
                if (err == ERR_OK) {
                    tcp_output(conn->pcb);
                    log(LogLevel::Debug, "LwipRelay: sent %zd bytes to target", received);
                } else {
                    log(LogLevel::Error, "LwipRelay: tcp_write failed: %d", (int)err);
                }
            }
        }

        if (pfd.revents & (POLLERR | POLLHUP)) {
            toRemove.push_back(sock);
        }
    }

    for (int sock : toRemove) {
        auto it = tcpConnections_.find(sock);
        if (it != tcpConnections_.end()) {
            if (it->second->localSock >= 0) {
                close(it->second->localSock);
            }
            if (it->second->pcb) {
                tcp_abort(it->second->pcb);
            }
            tcpConnections_.erase(it);
        }
    }
}

void LwipRelay::pollUdpSockets() {
    for (auto& pair : udpBindings_) {
        auto& binding = pair.second;

        pollfd pfd;
        pfd.fd = binding->localSock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, 0);
        if (ret <= 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        uint8_t buf[2048];
        sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);

        ssize_t received = recvfrom(binding->localSock, buf, sizeof(buf), 0,
                                    (sockaddr*)&fromAddr, &fromLen);
        if (received <= 0) {
            continue;
        }

        binding->clientAddr = fromAddr;
        binding->hasClient = true;

        struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)received, PBUF_RAM);
        if (!p) {
            continue;
        }

        memcpy(p->payload, buf, received);

        ip_addr_t destAddr;
        ip_addr_copy_from_ip4(destAddr, targetAddr_);

        udp_sendto(binding->pcb, p, &destAddr, binding->targetPort);
        pbuf_free(p);

        log(LogLevel::Debug, "LwipRelay: sent %zd UDP bytes to target port %u", received, binding->targetPort);
    }
}

int LwipRelay::createTcpListener(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (listen(sock, 5) < 0) {
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

int LwipRelay::createUdpSocket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    int rcvbuf = 0x19000;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

err_t LwipRelay::onTcpConnected(void* arg, struct tcp_pcb* pcb, err_t err) {
    TcpConnection* conn = (TcpConnection*)arg;
    if (!conn) {
        return ERR_ARG;
    }

    if (err != ERR_OK) {
        return err;
    }

    conn->connected = true;
    tcp_recv(pcb, onTcpRecv);
    tcp_sent(pcb, onTcpSent);

    return ERR_OK;
}

err_t LwipRelay::onTcpRecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
    TcpConnection* conn = (TcpConnection*)arg;
    if (!conn) {
        if (p) pbuf_free(p);
        return ERR_ARG;
    }

    if (!p || err != ERR_OK) {
        if (conn->localSock >= 0) {
            close(conn->localSock);
            conn->localSock = -1;
        }
        return ERR_OK;
    }

    ssize_t sent = send(conn->localSock, p->payload, p->len, 0);
    (void)sent;

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

err_t LwipRelay::onTcpSent(void* arg, struct tcp_pcb* pcb, u16_t len) {
    (void)arg;
    (void)pcb;
    (void)len;
    return ERR_OK;
}

void LwipRelay::onTcpError(void* arg, err_t err) {
    TcpConnection* conn = (TcpConnection*)arg;
    if (conn) {
        conn->pcb = nullptr;
    }
    (void)err;
}

void LwipRelay::onUdpRecv(void* arg, struct udp_pcb* pcb, struct pbuf* p,
                          const ip_addr_t* addr, u16_t port) {
    (void)pcb;
    (void)addr;
    (void)port;

    UdpBinding* binding = (UdpBinding*)arg;
    if (!binding || !p) {
        if (p) pbuf_free(p);
        return;
    }

    if (!binding->hasClient) {
        pbuf_free(p);
        return;
    }

    ssize_t sent = sendto(binding->localSock, p->payload, p->len, 0,
                          (sockaddr*)&binding->clientAddr, sizeof(binding->clientAddr));
    (void)sent;

    pbuf_free(p);
}

}
