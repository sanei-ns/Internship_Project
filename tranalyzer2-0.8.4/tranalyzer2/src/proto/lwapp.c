/*
 * lwapp.c
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

#include "lwapp.h"
#include "packetCapture.h"
#include "hdrDesc.h"
#include "ieee80211.h"
#include "main.h"
#include "vlan.h"


#if LWAPP == 1

inline bool t2_is_lwapp(uint16_t sport, uint16_t dport) {
    return ((sport == LWAPP_DATA_PORT || sport == LWAPP_CTRL_PORT) && dport > 1024) ||
           ((dport == LWAPP_DATA_PORT || dport == LWAPP_CTRL_PORT) && sport > 1024);
}


// This function assumes pktptr points to the LWAPP header, i.e.,
// the caller MUST check that the source or destination port is LWAPP_DATA
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_lwapp(uint8_t *pktptr, packet_t *packet) {
    uint8_t * const start = pktptr;
    const l2Header_t * const oldL2Hdr = packet->layer2Header;
    const l3Header_t * const oldL3Hdr = packet->layer3Header;

    if (packet->srcPort == LWAPP_CTRL_PORT ||
        packet->dstPort == LWAPP_CTRL_PORT)
    {
        pktptr += 6; // Skip AP Identity
    }

    lwapp_header_t *lwapp = (lwapp_header_t*)pktptr;
    pktptr += sizeof(*lwapp);
    if (pktptr >= packet->end_packet) {
        return start;
    }

    const uint16_t skip = (uint16_t)(pktptr - (uint8_t*)packet->layer2Header);

    //if ((lwapp->flags & 0xc0) != 0) return start; // Version MUST be 0

    T2_PKTDESC_ADD_HDR(packet, ":lwapp");
    T2_SET_STATUS(packet, L3_CAPWAP);

    if ((lwapp->flags & 0x04) == 0x04 /*|| ((lwapp->flags & 0x02) == 0x02 && lwapp->frag_id != 0)*/) {
        // ignore control packets and fragments
        T2_SET_STATUS(packet, STPDSCT);
        return start;
    }

    // IEEE 802.11 (little endian, big endian for cisco)
#if LWAPP_SWAP_FC == 1
    pktptr = t2_process_ieee80211(pktptr, true, packet);
#else // LWAPP_SWAP_FC == 0
    pktptr = t2_process_ieee80211(pktptr, false, packet);
#endif // LWAPP_SWAP_FC == 0
    if (!pktptr) goto lwapp_reset;

    // check for 802.1Q/ad signature (VLANs)
    _8021Q_t *shape = (_8021Q_t*)pktptr;
    if (packet->snapL2Length - skip >= sizeof(_8021Q_t)) {
        shape = t2_process_vlans(shape, packet);
    }

    if (pktptr == (uint8_t*)shape) {
        // No VLAN, skip ethertype
        pktptr += 2;
    } else {
        pktptr = (uint8_t*)shape;
        const uint16_t shapeid = ntohs(shape->identifier);
        if (shapeid <= LLC_LEN || shapeid == ETHERTYPE_JUMBO_LLC) {
            T2_PKTDESC_ADD_HDR(packet, ":llc");
            packet->etherLLC = (etherLLCHeader_t*)pktptr;
            pktptr = ((u_char*)packet->etherLLC+8); // jump to ether type
            shape = (_8021Q_t*)pktptr;
        }
    }

    if (shape->identifier == ETHERTYPE_IPn) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        numV4Packets--;
        packet->layer3Header = (l3Header_t*)pktptr;
        dissembleIPv4Packet(packet);
        return NULL;
#else // IPV6_ACTIVATE == 1
        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
        T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
    } else if (shape->identifier == ETHERTYPE_IPV6n) {
        numV4Packets--;
#if IPV6_ACTIVATE > 0
        packet->layer3Header = (l3Header_t*)pktptr;
        dissembleIPv6Packet(packet);
        return NULL;
#else // IPV6_ACTIVATE == 0
        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
        numV6Packets++;
#endif // IPV6_ACTIVATE == 0
    } else {
        // Seen: ARP, EAPOL, LLDP, CDP, WLCCP, TDLS
        T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
    }

lwapp_reset:
    // LWAPP could not be processed... revert changes
    // XXX status, globalWarn and hdrDesc are NOT reverted
    packet->snapL2Length += skip;
    packet->layer2Header = oldL2Hdr;
    packet->layer3Header = oldL3Hdr;
    T2_SET_STATUS(packet, STPDSCT);

    return start;
}

#endif // LWAPP == 1
