#ifndef WG_NETIF_H
#define WG_NETIF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "wireguard.h"

typedef struct {
    struct pbuf_custom pc;
    WgTunnel* tunnel;
    WgRecvSlot* slot;
    int in_use;
} WgSlotPbuf;

err_t wg_netif_init(struct netif *netif);
void wg_netif_input(struct netif *netif, const void *data, size_t len);
/* Zero-copy input. Wraps the slot in a custom pbuf; when lwIP releases the
 * last reference, the slot is returned to the tunnel's pool. `holder` must
 * outlive the pbuf (typically a preallocated WgSlotPbuf per slot). */
void wg_netif_input_slot(struct netif *netif, WgTunnel *tunnel, WgRecvSlot *slot,
                         const void *data, size_t len, WgSlotPbuf *holder);
void wg_netif_set_tunnel(struct netif *netif, WgTunnel *tunnel);

#ifdef __cplusplus
}
#endif

#endif
