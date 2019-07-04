/*
 * vxlan.h
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

#ifndef __VXLAN_H__
#define __VXLAN_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


// VXLAN - Virtual eXtensible Local Area Network

#define VXLAN_PORT     4789
#define VXLAN_OLD_PORT 8472

//#define VXLAN_PORT_N     0xb512 // 4789
//#define VXLAN_OLD_PORT_N 0x1821 // 8472

typedef struct {
    uint8_t flags;        // bit 5 MUST be 1 (VXLAN Network ID (VNI)), the rest is reserved (0)
    uint8_t reserved1;    // MUST be 0
    uint16_t groupid;     // Group Policy ID
    uint32_t vni:24;      // VXLAN Segment ID/Network Identifier
    uint32_t reserved2:8; // MUST be 0
} __attribute__((packed)) vxlan_header_t;


// VXLAN-GPE - Virtual eXtensible Local Area Network Generic Protocol Extension

#define VXLAN_GPE_PORT 4790
//#define VXLAN_GPE_PORT_N 0xb612 // 4790

#define VXLAN_GPE_FLAG_V(f) ((f) & 0x03) // Version
#define VXLAN_GPE_FLAG_I(f) ((f) & 0x08) // Instance Bit
#define VXLAN_GPE_FLAG_P(f) ((f) & 0x04) // Next Protocol Bit
#define VXLAN_GPE_FLAG_O(f) ((f) & 0x01) // OAM Flag Bit

// Next Protocol
#define VXLAN_GPE_NP_IPV4 0x1
#define VXLAN_GPE_NP_IPV6 0x2
#define VXLAN_GPE_NP_ETH  0x3
#define VXLAN_GPE_NP_NSH  0x4
#define VXLAN_GPE_NP_MPLS 0x5

typedef struct {
    uint8_t flags;        // 00VIP0O
    uint16_t reserved1;   // MUST be 0
    uint8_t next_proto;   // Next Protocol
    uint32_t vni:24;      // VXLAN Segment ID/Network Identifier
    uint32_t reserved2:8; // MUST be 0
} __attribute__((packed)) vxlan_gpe_header_t;


// NSH - Network Service Header

#define NSH_FLAG_LEN(f) (((f) & 0x3f00) >> 8) // Number of 4-bytes words

typedef struct {
    union {
        uint16_t flags;
        // TODO fix endianness in struct
        //struct {
        //    uint16_t ver:2;
        //    uint16_t flag_o:1;    // Operations, Administration and Maintenance (OAM) packet
        //    uint16_t flag_r:1;    // MUST be 0
        //    uint16_t reserved2:6;
        //    uint16_t len:6;
        //};
    };
    uint8_t md_type:4;
    uint8_t reserved3:4; // MUST be 0
    uint8_t next_proto;
} __attribute__((packed)) nsh_header_t;

extern bool t2_is_vxlan(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_vxlan(uint8_t *pktptr, packet_t *packet);

#endif // __VXLAN_H__
