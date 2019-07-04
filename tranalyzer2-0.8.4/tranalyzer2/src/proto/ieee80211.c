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

#include "packetCapture.h"
#include "proto/t2_proto.h"
#include "hashTable.h"
#include "hdrDesc.h"
#include "ieee80211.h"
#include "main.h"

// IEEE 802.11 wireless LAN

inline uint8_t *t2_process_ieee80211(uint8_t *pktptr, bool big_endian, packet_t *packet) {
#if T2_PRI_HDRDESC == 1
    if (packet->hdrDescPos == 0) {
        T2_PKTDESC_ADD_HDR(packet, "wlan");
    } else {
        T2_PKTDESC_ADD_HDR(packet, ":wlan");
    }
#endif

    const ieee80211_frame_control * const fc = (ieee80211_frame_control*)pktptr;

    uint8_t type, subtype;
    bool has_wep, is_wds;

    if (big_endian) {
        type    = IEEE80211_FC_TYPE_BE(fc);
        subtype = IEEE80211_FC_SUBTYPE_BE(fc);
        is_wds  = IEEE80211_FC_IS_WDS_BE(fc);
        has_wep = IEEE80211_FC_HAS_WEP_BE(fc);
    } else {
        type    = IEEE80211_FC_TYPE(fc);
        subtype = IEEE80211_FC_SUBTYPE(fc);
        is_wds  = IEEE80211_FC_IS_WDS(fc);
        has_wep = IEEE80211_FC_HAS_WEP(fc);
    }

    if (has_wep) return NULL; // frame is protected

    uint8_t fc_len = 0;
    switch (type) {
        case IEEE80211_FT_DATA:
            switch (subtype) {
                case IEEE80211_FST_DATA_DATA:
                case IEEE80211_FST_DATA_DATA_CFACK:
                case IEEE80211_FST_DATA_DATA_CFPOLL:
                case IEEE80211_FST_DATA_DATA_CFACKPOLL:
                    fc_len = sizeof(ieee80211_hdr_3addr);
                    break;
                case IEEE80211_FST_DATA_QOS_DATA:
                case IEEE80211_FST_DATA_QOS_DATA_CFACK:
                case IEEE80211_FST_DATA_QOS_DATA_CFPOLL:
                case IEEE80211_FST_DATA_QOS_DATA_CFACKPOLL:
                    fc_len = sizeof(ieee80211_qos_hdr);
                    break;
                default:
                    return NULL;
            }
            break;
        case IEEE80211_FT_MGMT:
        case IEEE80211_FT_CTRL:
        default:
            // unknown type
            return NULL;
    }

    if (is_wds) fc_len += ETH_ALEN;

    pktptr += fc_len;

    // Mysterious OLPC stuff (According to Wireshark)
    if (*pktptr == 0 && *(pktptr+1) == 0) {
        pktptr += 2;
    }
    if ((*(pktptr + 2) & 0x3) != 0x3) { // Control field is 2 bytes
        pktptr++;
    }

    packet->etherLLC = (etherLLCHeader_t*)(pktptr - 2);
    T2_PKTDESC_ADD_HDR(packet, ":llc");
    pktptr += 6; // jump to ether type

    return pktptr;
}
