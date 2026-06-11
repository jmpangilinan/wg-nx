#ifndef WG_RELAY_H
#define WG_RELAY_H

#include "wireguard.h"
#include <stdint.h>

typedef struct WgRelay WgRelay;

WgRelay* wg_relay_create(WgTunnel* tun, uint16_t local_port);
int wg_relay_start(WgRelay* relay);
void wg_relay_stop(WgRelay* relay);
void wg_relay_destroy(WgRelay* relay);
uint16_t wg_relay_get_port(WgRelay* relay);

#endif
