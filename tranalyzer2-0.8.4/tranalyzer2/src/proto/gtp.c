/*
 * gtp.c
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

#include "gtp.h"
#include "packetCapture.h"
#include "hdrDesc.h"
#include "main.h"


#if GTP == 1

inline bool t2_is_gtp(uint16_t sport, uint16_t dport) {
    return ((sport == GTP_USER_PORT || sport == GTP_CTRL_PORT || sport == GTP_DATA_PORT) && dport > 1024) ||
           ((dport == GTP_USER_PORT || dport == GTP_CTRL_PORT || dport == GTP_DATA_PORT) && sport > 1024);
}


// This function assumes pktptr points to the GTP header, i.e.,
// the caller MUST check that the source or destination port is GTP
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_gtp(uint8_t *pktptr, packet_t *packet) {
    uint8_t * const start = pktptr;

    // Only process GTP messages of type T-PDU (0xff)
    if (*(pktptr+1) != 0xff) return start;

    const uint8_t version = ((*pktptr & 0xe0) >> 5);

    // skip GTP headers (flags depend on the version...)
    uint8_t skip = 8; // GTP header
    if (version == 0) { // GTP release 97/98 version
        skip += 12;
    } else if (version == 1) { // GTP release 99 version
        if (*pktptr & 0x07) skip += 4;
        if (*pktptr & 0x04) skip += *(pktptr + skip) << 2;
    } else if (version == 2) {
        // TODO
        T2_SET_STATUS(packet, STPDSCT);
        return pktptr;
    }
    pktptr += skip;

    if (pktptr >= packet->end_packet) return start;

    if ((*pktptr & 0xf0) == 0x40) {
        T2_PKTDESC_ADD_HDR(packet, ":gtp");
        T2_SET_STATUS(packet, L3_GTP);
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        numV4Packets--;
        packet->layer3Header = (l3Header_t*)pktptr;
        dissembleIPv4Packet(packet);
        return NULL;
#else // IPV6_ACTIVATE == 1
        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
        T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
    } else if ((*pktptr & 0xf0) == 0x60) {
        T2_PKTDESC_ADD_HDR(packet, ":gtp");
        T2_SET_STATUS(packet, L3_GTP);
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
    } // TODO PPP

    T2_SET_STATUS(packet, STPDSCT);

    return pktptr - skip;
}

#endif // GTP == 1
