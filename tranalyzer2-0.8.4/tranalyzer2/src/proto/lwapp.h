/*
 * lwapp.h
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

#ifndef __LWAPP_H__
#define __LWAPP_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


//#define LWAPP_SWAP_FC  1 // Swap frame control (required for Cisco)


// LWAPP - Lightweight Access Point Protocol

#define LWAPP_DATA_PORT 12222
#define LWAPP_CTRL_PORT 12223
//#define LWAPP_DATA_PORT_N 0xbe2f // 12222
//#define LWAPP_CTRL_PORT_N 0xbf2f // 12223

typedef struct {
    uint8_t flags;   // Version (2), Radio ID (3), Control (1), Fragment (1), Not Last (1)
    uint8_t frag_id; // Fragment ID
    uint16_t len;    // Length
    uint16_t status;
} __attribute__((packed)) lwapp_header_t;

extern bool t2_is_lwapp(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_lwapp(uint8_t *pktptr, packet_t *packet);

#endif // __LWAPP_H__
