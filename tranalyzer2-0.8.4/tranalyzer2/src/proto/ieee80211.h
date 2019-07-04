/*
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

#ifndef __IEEE80211_H__
#define __IEEE80211_H__

#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "networkHeaders.h"


// OS X fix
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define IEEE80211_FT_MGMT  0 // 0x0000
#define IEEE80211_FT_CTRL  1 // 0x0004
#define IEEE80211_FT_DATA  2 // 0x0008

// data subtype
#define IEEE80211_FST_DATA_DATA                0
#define IEEE80211_FST_DATA_DATA_CFACK          1 // Data + CF-ACK
#define IEEE80211_FST_DATA_DATA_CFPOLL         2 // Data + CF-Poll
#define IEEE80211_FST_DATA_DATA_CFACKPOLL      3 // Data + CF-ACK + CF-Poll
#define IEEE80211_FST_DATA_NULL                4 // No data
#define IEEE80211_FST_DATA_CFACK               5 // CF-ACK (no data)
#define IEEE80211_FST_DATA_CFPOLL              6 // CF-Poll (no data)
#define IEEE80211_FST_DATA_CFACKPOLL           7 // CF-ACK + CF-Poll (no data)
#define IEEE80211_FST_DATA_QOS_DATA            8 // QoS Data
#define IEEE80211_FST_DATA_QOS_DATA_CFACK      9 // QoS Data + CF-ACK
#define IEEE80211_FST_DATA_QOS_DATA_CFPOLL    10 // QoS Data + CF-Poll
#define IEEE80211_FST_DATA_QOS_DATA_CFACKPOLL 11 // QoS Data + CF-ACK + CF-Poll
#define IEEE80211_FST_DATA_QOS_NULL           12 // QoS Null (no data)
#define IEEE80211_FST_DATA_RESERVED           13
#define IEEE80211_FST_DATA_QOS_CFPOLL         14 // QoS CF-Poll (no data)
#define IEEE80211_FST_DATA_QOS_CFACKPOLL      15 // QoS CF-ACK + CF-Poll (no data)

typedef struct {
// IEEE802.11 little endian
#define IEEE80211_FC_TYPE(fc) (((fc)->type & 0xc) >> 2)
#define IEEE80211_FC_SUBTYPE(fc) ((fc)->type >> 4)
#define IEEE80211_FC_IS_WDS(fc) (((fc)->flags & 0x3) == 0x3) // 4 addresses
#define IEEE80211_FC_HAS_WEP(fc) ((fc)->flags & 0x40)
// IEEE802.11 big endian (Cisco)
#define IEEE80211_FC_TYPE_BE(fc) (((fc)->flags & 0xc) >> 2)
#define IEEE80211_FC_SUBTYPE_BE(fc) ((fc)->flags >> 4)
#define IEEE80211_FC_IS_WDS_BE(fc) (((fc)->type & 0x3) == 0x3) // 4 addresses
#define IEEE80211_FC_HAS_WEP_BE(fc) ((fc)->type & 0x40)
    uint8_t type;   // subtype(4), type(2), version=0(2)
    uint8_t flags;  // order, wep, more_data, pwr_mgmt,
                    // retry, more_frag, from_ds, to_ds
} __attribute__ ((__packed__)) ieee80211_frame_control;

typedef struct {
    ieee80211_frame_control fc;
    uint16_t duration_id;
    uint8_t addr1[ETH_ALEN];
    uint8_t addr2[ETH_ALEN];
    uint8_t addr3[ETH_ALEN];
    uint16_t seq_ctrl;
} __attribute__((__packed__)) ieee80211_hdr_3addr;

typedef struct {
    ieee80211_hdr_3addr hdr;
    uint16_t qos_ctrl;
} __attribute__((__packed__)) ieee80211_qos_hdr;

extern uint8_t *t2_process_ieee80211(uint8_t *pktptr, bool big_endian, packet_t *packet);

#endif /* __IEEE80211_H__ */
