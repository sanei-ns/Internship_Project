/*
 * vrrpDecode.h
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

#ifndef __VRRP_DECODE_H__
#define __VRRP_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define VRRP_NUM_VRID  5 // number of unique virtual router ID to store
#define VRRP_NUM_IP   25 // number of unique IPs to store
#define VRRP_RT        1 // whether or not to output routing tables
#if VRRP_RT == 1
#define VRRP_SUFFIX "_vrrp.txt"
#endif // VRRP_RT == 1

// plugin defines
#if IPV6_ACTIVATE == 2
#define VRRP_IP_TYPE bt_ipx_addr
#elif IPV6_ACTIVATE == 1
#define VRRP_IP_TYPE bt_ip6_addr
#define VRRP_IP_SIZE l_bt_ip6_addr
#else // IPV6_ACTIVATE == 0
#define VRRP_IP_TYPE bt_ip4_addr
#define VRRP_IP_SIZE l_bt_ip4_addr
#endif

#define VRRP_MCAST_4ADDR 0x120000e0 // 224.0.0.18
//#define VRRP_MCAST_6ADDR ff02::12 // TODO

#define VRRP_TTL      255
#define VRRP_TYPE_ADV   1 // Advertisement

#define VRRP_AUTH_MAX 8 // authentication data max length (8 bytes)

// Authentication type
#define VRRP_AUTH_NONE   0 // No authentication
#define VRRP_AUTH_SIMPLE 1 // Simple text password
#define VRRP_AUTH_AH     2 // AH, IP Authentication Header

typedef struct {
    uint8_t  type:4;         // 1 (Advertisement)
    uint8_t  version:4;      // 2/3
    uint8_t  vrid;           // Virtual Router ID
    uint8_t  pri;            // Priority (default: 100, owner: 255, stop: 0)
    uint8_t  ip_cnt;         // IP address count
    union {
        // VRRPv2
        struct {
            uint8_t  atype;  // Authentication type
            uint8_t  advint; // Advertisement interval (default: 1s)
        };
        // VRRPv3
        uint16_t maxadvint; // Maximum Advertisement interval (default: 100 cs (=1s))
                            // maxadvint(12), reserved(4)
    };
    uint16_t chksum;         // Checksum
    //uint32_t ip[ip_cnt];   // IP addresses
    //uint8_t adata;         // Authentication data (Variable length, 0 to 8 bytes)
} vrrp_t;

// Status variable
#define VRRP_STAT_VRRP       0x0001 // flow is VRRP
#define VRRP_STAT_VER        0x0002 // invalid version
#define VRRP_STAT_TYPE       0x0004 // invalid type
#define VRRP_STAT_CHKSUM     0x0008 // invalid checksum
#define VRRP_STAT_TTL        0x0010 // invalid TTL (should be 255)
#define VRRP_STAT_DEST_IP    0x0020 // invalid destination IP (should be 224.0.0.18)
//#define VRRP_STAT_DEST_MAC 0x0040 // invalid destination MAC (should be 00:00:5e:00:01:routerID)
#define VRRP_STAT_TRUNC_VRID 0x0100 // Virtual Router ID list truncated... increase VRRP_NUM_VRID
#define VRRP_STAT_TRUNC_IP   0x0200 // IP list truncated... increase VRRP_NUM_IP
#define VRRP_STAT_SNAP       0x4000 // Packet snapped
#define VRRP_STAT_MALFORMED  0x8000 // Malformed packet... covert channel?

// sample plugin structures
typedef struct {
#if VRRP_NUM_IP > 0
#if IPV6_ACTIVATE > 0
    uint32_t ip[VRRP_NUM_IP][4];
#else // IPV6_ACTIVATE == 0
    uint32_t ip[VRRP_NUM_IP][1];
#endif // IPV6_ACTIVATE == 0
    uint32_t sip_cnt;   // number of stored IP
#endif // VRRP_NUM_IP > 0
    uint32_t vrid_cnt;  // total number of router IDs
    uint16_t stat;
    uint8_t  version;
    uint8_t  type;
    char     auth[VRRP_AUTH_MAX+1];
    uint8_t  atype;
    uint8_t  minadvint;
    uint8_t  maxadvint;
    uint8_t  vrid[VRRP_NUM_VRID];
    uint8_t  minpri;
    uint8_t  maxpri;
} vrrp_flow_t;

// plugin struct pointer for potential dependencies
extern vrrp_flow_t *vrrp_flows;

#endif // __VRRP_DECODE_H__
