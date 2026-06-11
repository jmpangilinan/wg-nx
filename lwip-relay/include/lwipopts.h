#ifndef LWIP_HDR_LWIPOPTS_H
#define LWIP_HDR_LWIPOPTS_H

#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        (32 * 1024)
#define MEMP_NUM_PBUF                   128
#define MEMP_NUM_UDP_PCB                8
#define MEMP_NUM_TCP_PCB                8
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG                64
#define PBUF_POOL_SIZE                  128
#define PBUF_POOL_BUFSIZE               1600

#define LWIP_SUPPORT_CUSTOM_PBUF        1

#define LWIP_TCP                        1
#define LWIP_TCP_KEEPALIVE              1
#define LWIP_TCP_RTO_TIME               1000
#define TCP_KEEPIDLE_DEFAULT            30000  /* was 5000 — kernel is 7200000 */
#define TCP_KEEPINTVL_DEFAULT           10000  /* was 3000 — kernel is 75000 */
#define TCP_KEEPCNT_DEFAULT             9      /* was 20 — kernel is 9 */
#define TCP_MSS                         1400
#define TCP_SND_BUF                     (32 * 1024)
#define TCP_SND_QUEUELEN                64
#define TCP_WND                         (32 * 1024)
#define LWIP_TCP_TIMESTAMPS             1
#define LWIP_TCP_SACK_OUT               1

#define LWIP_UDP                        1

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0

#define LWIP_DHCP                       0
#define LWIP_DNS                        0
#define LWIP_ICMP                       1
#define LWIP_RAW                        0
#define LWIP_IGMP                       0
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0

#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1
#define CHECKSUM_CHECK_TCP              1

#define LWIP_STATS                      0
#define LWIP_DEBUG                      0

#endif
