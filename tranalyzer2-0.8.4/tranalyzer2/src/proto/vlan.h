/*
 * vlan.h
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

#ifndef __VLAN_H__
#define __VLAN_H__

// includes
#include <stdint.h>
#include "networkHeaders.h"


// VLAN - Virtual Local Area Network

#define VLANID_MASK16      0x0fff
#define VLANID_MASK16n     0xff0f
#define VLAN_ID_MASK32     0x0fff0000
#define VLAN_ID_MASK32n    0x0000ff0f
#define VLAN_ETYPE_MASK32  0x0000ffff
#define VLAN_ETYPE_MASK32n 0xffff0000

//typedef struct {
//    uint16_t identifier;
//    uint16_t vlanID;
//} _8021Q_t;

extern _8021Q_t *t2_process_vlans(_8021Q_t *pktptr, packet_t *packet);

#endif // __VLAN_H__
