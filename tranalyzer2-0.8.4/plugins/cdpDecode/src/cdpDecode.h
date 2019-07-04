/*
 * cdpDecode.h
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

#ifndef __CDP_DECODE_H__
#define __CDP_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define CDP_STRLEN   512 // maximum length of strings to store

// plugin defines

#define CDP_TLV_DEVICE_ID    0x0001 // Device ID
#define CDP_TLV_ADDRESSES    0x0002 // Addresses
#define CDP_TLV_PORT_ID      0x0003 // Port ID
#define CDP_TLV_CAPS         0x0004 // Capabilities
#define CDP_TLV_SW_VERSION   0x0005 // Software Version
#define CDP_TLV_PLATFORM     0x0006 // Platform
#define CDP_TLV_IP_PREFIXES  0x0007 // IP Prefixes
#define CDP_TLV_PROTO_HELLO  0x0008 // Protocol Hello
#define CDP_TLV_VTP_MNGMT    0x0009 // VTP Management Domain
#define CDP_TLV_NATIVE_VLAN  0x000a // Native VLAN
#define CDP_TLV_DUPLEX       0x000b // Duplex
#define CDP_TLV_VOIP_VLAN_Q  0x000f // VoIP VLAN Query
#define CDP_TLV_POWER_CONS   0x0010 // Power Consumption
#define CDP_TLV_TRUST_BMAP   0x0012 // Trust Bitmap
#define CDP_TLV_UNTRUST_PORT 0x0013 // Untrusted Port CoS
#define CDP_TLV_MNGMT_ADDR   0x0016 // Management Address
#define CDP_TLV_POWER_REQ    0x0019 // Power Requested
#define CDP_TLV_POWER_AVAIL  0x001a // Power Available

// Status variable
#define CDP_STAT_CDP  0x01 // Flow is CDP
#define CDP_STAT_STR  0x20 // String truncated... increase CDP_STRLEN
#define CDP_STAT_LEN  0x40 // Invalid TLV length
#define CDP_STAT_SNAP 0x80 // Snapped payload

typedef struct {
    char device[CDP_STRLEN+1];
    char platform[CDP_STRLEN+1];
    char port[CDP_STRLEN+1];
    char vtpdom[CDP_STRLEN+1];
    uint32_t caps;
    uint32_t tlv_types;
    uint16_t vlan;
    uint8_t duplex;
    uint8_t stat;
    uint8_t ttl;
    uint8_t version;
} cdp_flow_t;

// plugin struct pointer for potential dependencies
extern cdp_flow_t *cdp_flows;

#endif // __CDP_DECODE_H__
