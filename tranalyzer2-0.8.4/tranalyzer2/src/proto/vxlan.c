/*
 * vxlan.c
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

#include "vxlan.h"
#include "packetCapture.h"
#include "hdrDesc.h"
#include "main.h"
#include "vlan.h"


#if VXLAN == 1

inline bool t2_is_vxlan(uint16_t sport, uint16_t dport) {
    return ((sport == VXLAN_PORT || sport == VXLAN_GPE_PORT || sport == VXLAN_OLD_PORT) && dport > 1024) ||
           ((dport == VXLAN_PORT || dport == VXLAN_GPE_PORT || dport == VXLAN_OLD_PORT) && dport > 1024);
}


// This function assumes pktptr points to the VXLAN header, i.e.,
// the caller MUST check that the source or destination port is VXLAN
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_vxlan(uint8_t *pktptr, packet_t *packet) {
    uint8_t * const start = pktptr;
    const l2Header_t * const oldL2Hdr = packet->layer2Header;
    const l3Header_t * const oldL3Hdr = packet->layer3Header;

    const bool gpe = (packet->srcPort == VXLAN_GPE_PORT || packet->dstPort == VXLAN_GPE_PORT);

    vxlan_header_t *vxlan = (vxlan_header_t*)pktptr;
    pktptr += sizeof(vxlan_header_t);
    if (pktptr >= packet->end_packet) return start;

    const uint16_t skip = (uint16_t)(pktptr - (uint8_t*)packet->layer2Header);

    if (gpe) {
        vxlan_gpe_header_t *vxlan_gpe = (vxlan_gpe_header_t*)vxlan;
        if (vxlan_gpe->reserved1 != 0 || vxlan_gpe->reserved2 != 0) return start; // reserved MUST be 0
        packet->snapL2Length -= skip;
        packet->layer2Header = (l2Header_t*)pktptr;
        T2_SET_STATUS(packet, L3_VXLAN);
        T2_PKTDESC_ADD_HDR(packet, ":vxlan_gpe");
        if (VXLAN_GPE_FLAG_P(vxlan->flags)) {
            uint8_t next_proto = vxlan_gpe->next_proto;
vxlan_next_proto:
            switch (next_proto) {
                case VXLAN_GPE_NP_IPV4:
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                    numV4Packets--;
                    packet->layer3Header = (l3Header_t*)pktptr;
                    dissembleIPv4Packet(packet);
                    return NULL;
#else // IPV6_ACTIVATE == 1
                    T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                    T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
                    break;
#endif // IPV6_ACTIVATE == 1
                case VXLAN_GPE_NP_IPV6:
                    numV4Packets--;
#if IPV6_ACTIVATE > 0
                    packet->layer3Header = (l3Header_t*)pktptr;
                    dissembleIPv6Packet(packet);
                    return NULL;
#else // IPV6_ACTIVATE == 0
                    T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                    T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
                    numV6Packets++;
                    break;
#endif // IPV6_ACTIVATE == 0
                case VXLAN_GPE_NP_ETH:
                    break;
                case VXLAN_GPE_NP_MPLS:
                    T2_PKTDESC_ADD_HDR(packet, ":mpls");
                    // TODO
                    return start;
                case VXLAN_GPE_NP_NSH:
                    T2_PKTDESC_ADD_HDR(packet, ":nsh");
                    nsh_header_t *nsh = (nsh_header_t*)pktptr;
                    pktptr += (NSH_FLAG_LEN(nsh->flags) << 2);
                    next_proto = nsh->next_proto;
                    goto vxlan_next_proto;
                default:
                    T2_ERR("Unhandled VXLAN-GPE next protocol 0x%02x", vxlan_gpe->next_proto);
                    goto vxlan_reset;
            }
        }
    } else if (vxlan->reserved1 != 0 || vxlan->reserved2 != 0) {
        // reserved MUST be 0
        return start;
    } else {
        T2_SET_STATUS(packet, L3_VXLAN);
        T2_PKTDESC_ADD_HDR(packet, ":vxlan");
        packet->snapL2Length -= skip;
        packet->layer2Header = (l2Header_t*)pktptr;
    }

    T2_PKTDESC_ADD_HDR(packet, ":eth");
    pktptr += 12; // jump to ethertype

    // check for 802.1Q/ad signature (VLANs)
    _8021Q_t *shape = (_8021Q_t*)pktptr;
    if (packet->snapL2Length >= sizeof(_8021Q_t)) {
        shape = t2_process_vlans(shape, packet);
    }
    if (pktptr != (uint8_t*)shape) pktptr = (uint8_t*)shape;
    else pktptr += 2; // skip ethertype

    switch (shape->identifier) {
        case ETHERTYPE_IPn:
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            numV4Packets--;
            packet->layer3Header = (l3Header_t*)pktptr;
            dissembleIPv4Packet(packet);
            return NULL;
#else // IPV6_ACTIVATE == 1
            T2_PKTDESC_ADD_HDR(packet, ":ipv4");
            T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
            break;
#endif // IPV6_ACTIVATE == 1
        case ETHERTYPE_IPV6n:
            numV4Packets--;
#if IPV6_ACTIVATE > 0
            packet->layer3Header = (l3Header_t*)pktptr;
            dissembleIPv6Packet(packet);
            return NULL;
#else // IPV6_ACTIVATE == 0
            T2_PKTDESC_ADD_HDR(packet, ":ipv6");
            T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
            numV6Packets++;
            break;
#endif // IPV6_ACTIVATE == 0
        case ETHERTYPE_PPPoE_Dn:
            T2_PKTDESC_ADD_HDR(packet, ":pppoed");
            T2_SET_STATUS(packet, L2_PPPoE_D);
            packet->pppoEHdr = (pppoEH_t*)&shape->vlanID;
            break;
        case ETHERTYPE_PPPoE_Sn:
            T2_PKTDESC_ADD_HDR(packet, ":pppoes");
            T2_SET_STATUS(packet, L2_PPPoE_S);
            packet->pppoEHdr = (pppoEH_t*)&shape->vlanID;
            packet->pppHdr = (pppHu_t*)(packet->pppoEHdr + 1);
            T2_PKTDESC_ADD_HDR(packet, ":ppp");
            if (packet->pppoEHdr->pppProt == PPP_IP4n) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                numV4Packets--;
                packet->layer3Header = (l3Header_t*)packet->pppHdr;
                dissembleIPv4Packet(packet);
                return NULL;
#else // IPV6_ACTIVATE == 1
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)packet->pppHdr)->ip_p);
#endif // IPV6_ACTIVATE == 1
            } else if (packet->pppoEHdr->pppProt == PPP_IP6n) {
                numV4Packets--;
#if IPV6_ACTIVATE > 0
                packet->layer3Header = (l3Header_t*)packet->pppHdr;
                dissembleIPv6Packet(packet);
                return NULL;
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)packet->pppHdr)->next_header);
                numV6Packets++;
#endif // IPV6_ACTIVATE == 0
            } else {
                T2_PKTDESC_ADD_PPPPROTO(packet, packet->pppoEHdr->pppProt);
            }
            break;
        default:
            T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
            break;
    }

vxlan_reset:
    // VXLAN could not be processed... revert changes
    // XXX status, globalWarn and hdrDesc are NOT reverted
    packet->snapL2Length += skip;
    packet->layer2Header = oldL2Hdr;
    packet->layer3Header = oldL3Hdr;
    T2_SET_STATUS(packet, STPDSCT);

    return start;
}

#endif // VXLAN == 1
