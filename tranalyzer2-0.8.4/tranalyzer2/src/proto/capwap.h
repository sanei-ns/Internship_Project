/*
 * capwap.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __CAPWAP_H__
#define __CAPWAP_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


//#define CAPWAP_SWAP_FC  1 // Swap frame control (required for Cisco)


// CAPWAP - Control And Provisioning of Wireless Access Points

#define CAPWAP_CTRL_PORT 5246
#define CAPWAP_DATA_PORT 5247
//#define CAPWAP_CTRL_PORT_N 0x7e14 // 5246
//#define CAPWAP_DATA_PORT_N 0x7f14 // 5247

typedef struct {
    uint8_t type:4;    // 0: CAPWAP header, 1: CAPWAP DTLS header (encrypted)
    uint8_t version:4; // 0
} __attribute__((packed)) capwap_preamble_t;

typedef struct {
    // Preamble
    uint8_t type:4;       // 0: CAPWAP header, 1: CAPWAP DTLS header (encrypted)
    uint8_t version:4;    // 0

    uint16_t rid_hi:3;    // Radio ID number for this packet
    uint16_t hlen:5;      // length of the CAPWAP transport header in 4-byte words
    uint16_t flags_t:1;   // Type (0: payload is an IEEE 802.3 frame, 1: native format indicated by wbid)
    uint16_t wbid:5;      // Wireless binding identifier (0/2: reserved, 1: IEEE 802.11, 3: EPCGlobal)
    uint16_t rid_low:2;

    uint8_t flags_res:3;  // MUST be 0
    uint8_t flags_k:1;    // Keep-Alive
    uint8_t flags_m:1;    // Radio MAC
    uint8_t flags_w:1;    // Wireless
    uint8_t flags_l:1;    // Last
    uint8_t flags_f:1;    // Fragment

    uint16_t frag_id;     // fragment ID
    uint16_t frag_off;    // fragment offset (13), reserved (3) MUST be 0

    // Radio MAC address (optional, require the M bit)
    //uint8_t radio_mac_len;   // Length of the MAC address field
    //uint8_t *radio_mac_len;  // MAC address field (variable length)
    // Wireless Specific Information (optional, require the W bit)
    //uint8_t ws_info_len;     // Length of the ws_info field
    //uint8_t *ws_info;        // variable length
} __attribute__((packed)) capwap_header_t;

extern bool t2_is_capwap(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_capwap(uint8_t *pktptr, packet_t *packet);

#endif // __CAPWAP_H__
