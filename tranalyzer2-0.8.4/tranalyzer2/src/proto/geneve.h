/*
 * geneve.h
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

#ifndef __GENEVE_H__
#define __GENEVE_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


// GENEVE - Generic Network Virtualization Encapsulation

#define GENEVE_PORT 6081
//#define GENEVE_PORT_N 0xc117 // 6081

typedef struct {
    uint8_t optlen:6;     // Number of 4 bytes words
    uint8_t version:2;    // 0
    uint8_t reserved1:6;  // MUST be 0
    uint8_t critical:1;   // Critical options present
    uint8_t oam:1;        // OAM packet
    uint16_t proto;       // Protocol type
    uint32_t reserved2:8; // MUST be 0
    uint32_t vni:24;      // Virtual Network Identifier (VNI)
    // Variable Length Options
} __attribute__((packed)) geneve_header_t;

extern bool t2_is_geneve(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_geneve(uint8_t *pktptr, packet_t *packet);

#endif // __GENEVE_H__
