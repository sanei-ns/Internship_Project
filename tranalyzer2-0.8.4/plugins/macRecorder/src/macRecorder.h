/*
 * macRecorder.h
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

#ifndef __MAC_RECORDER_H__
#define __MAC_RECORDER_H__

// local includes
#include "networkHeaders.h"

// user defines
#define MR_MAC_FMT  1 // format for mac addresses: 0: hex, 1: mac, 2: int
#define MR_NPAIRS   1 // whether or not to report number of distinct pairs
#define MR_MANUF    1 // 0: no manufacturers, 1: short names, 2: long names
#define MR_MACLBL   0 // 0: no mac label, 1: mac labeling
#define MR_MAX_MAC 16 // max number of output MAC address per flow

#define MR_MANUF_FILE "manuf.txt"


// plugin defines

#if MR_MAC_FMT == 0
#define MR_MAC_TYPE bt_hex_64   // MAC as hex
#elif MR_MAC_FMT == 1
#define MR_MAC_TYPE bt_mac_addr // MAC (string)
#else // MR_MAC_FMT == 2
#define MR_MAC_TYPE bt_uint_64  // MAC as int
#endif // MR_MAC_FMT

#if MR_MANUF == 1
#define MR_MANUF_MAXL 32
#define MR_MANUF_TYPE bt_string_class
#elif MR_MANUF > 0
#define MR_MANUF_MAXL 128
#define MR_MANUF_TYPE bt_string
#endif


// plugin structs

#define MACM_UINT64(macm) (((macm)->mac64 & 0x0000ffffffffffff))

typedef union {
    char mac[ETH_ALEN];
    uint64_t mac64;
} __attribute__((packed)) macm_t;

typedef struct macList_s {
    ethDS_t ethHdr;
    uint64_t numPkts;
    struct macList_s *next;
} macList_t;

typedef struct {
    uint32_t num_entries;
    macList_t *macList;
} macRecorder_t;

extern macRecorder_t *macArray; // the big struct for all flows

#endif // __MAC_RECORDER_H__
