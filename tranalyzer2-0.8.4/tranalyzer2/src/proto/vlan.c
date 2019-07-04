/*
 * vlan.c
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

#include "vlan.h"
#include "packetCapture.h"
#include "hdrDesc.h"
#include "main.h"


// Scroll all VLAN headers
inline _8021Q_t *t2_process_vlans(_8021Q_t *shape, packet_t *packet) {
    if (shape->identifier != ETHERTYPE_VLANn &&
        shape->identifier != ETHERTYPE_QINQn)
    {
        // No VLAN
        return shape;
    }

    T2_SET_STATUS(packet, L2_VLAN);

#if (AGGREGATIONFLAG & VLANID) == 0
    packet->vlans = (uint32_t*)((uint8_t*)shape+2);
#endif

    uint8_t count = 0;
    const uint8_t * const endPkt = packet->end_packet - 4;
    while ((shape->identifier == ETHERTYPE_VLANn ||
            shape->identifier == ETHERTYPE_QINQn) &&
           (uint8_t*)shape <= endPkt)
    {
        if ((shape->vlanID & VLANID_MASK16n) == 0) {
            packet->status |= FS_VLAN0;
            globalWarn |= FS_VLAN0;
        }
        shape++;
        count++;
    }

    packet->vlanHdrCnt += count;

    T2_PKTDESC_ADD_REPHDR(packet, ":vlan", count);
    vlanHdrCntMx = MAX(vlanHdrCntMx, packet->vlanHdrCnt);

#if (AGGREGATIONFLAG & VLANID) == 0
    packet->innerVLANID = ntohs((shape-1)->vlanID) & VLANID_MASK16;
#endif

    return shape;
}
