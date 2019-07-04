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

#ifndef STPDECODE_H_
#define STPDECODE_H_

// global includes

// local includes
#include "global.h"

// user defines

// plugin defines

// STP Protocol Identifier
#define STP_PROTO_STP 0x0000 // Spanning Tree Protocol

// STP Protocol Version Identifier
#define STP_PROTO_VERSION_STP  0 // Spanning Tree
#define STP_PROTO_VERSION_RSTP 2 // Rapid Spanning Tree
#define STP_PROTO_VERSION_MSTP 3 // Multiple Spanning Tree
#define STP_PROTO_VERSION_SPB  4 // Shortest Path Tree

// STP BPDU Type
#define STP_BPDU_T_CONFIG 0x00 // Configuration
#define STP_BPDU_T_RST    0x02 // Rapid/Multiple Spanning Tree
#define STP_BPDU_T_TCN    0x80 // Topology Change Notification

// STP BPDU Flags
#define STP_BPDU_F_CHANGE_ACK 0x01 // Topology Change Acknowledgment
#define STP_BPDU_F_AGREEMENT  0x02 // Agreement
#define STP_BPDU_F_FORWARDING 0x04 // Forwarding
#define STP_BPDU_F_LEARNING   0x08 // Learning
#define STP_BPDU_F_PORT_ROT   0x30 // Port Role:
                                   //     0x00: Unknown,
                                   //     0x10: Alternate or Backup,
                                   //     0x20: Root,
                                   //     0x30: Designated
#define STP_BPDU_F_PROPOSAL   0x40 // Proposal
#define STP_BPDU_F_CHANGE     0x80 // Topology Change

// stpStat
#define STP_STAT_STP 0x01 // Flow/packet is STP

// protocol structures

typedef struct {
	uint16_t proto;    // Protocol Identifier (0x0000)
	uint8_t  version;  // Protocol Version Identifier:
	                   //    0: Spanning Tree,
	                   //    2: Rapid Spanning Tree
	                   //    3: Multiple Spanning Tree
	uint8_t  type;     // BPDU Type
	uint8_t  flags;    // BPDU Flags
	union {
		uint64_t root; // Root Identifier
		struct {
#define STP_ROOT_PRIO(stp) (uint16_t)(ntohs((stp)->rootPrio_Ext) & 0xf000)
#define STP_ROOT_EXT(stp)  (uint16_t)(ntohs((stp)->rootPrio_Ext) & 0x0fff)
			uint16_t rootPrio_Ext;     // Root Bridge Priority and Root Bridge System ID Extension
			uint8_t  rootHw[ETH_ALEN]; // Root Bridge System ID
		};
	};
	uint32_t rootCost; // Root Path Cost
	union {
#define STP_BRIDGE_PRIO(stp) (uint16_t)(ntohs((stp)->bridgePrio_Ext) & 0xf000)
#define STP_BRIDGE_EXT(stp)  (uint16_t)(ntohs((stp)->bridgePrio_Ext) & 0x0fff)
		uint64_t bridge;   // Bridge Identifier
		struct {
			uint16_t bridgePrio_Ext;     // Bridge Priority and Bridge System ID Extension
			uint8_t  bridgeHw[ETH_ALEN]; // Bridge System ID
		};
	};
	uint16_t port;     // Port Identifier
	uint16_t msgAge;   // Message Age
	uint16_t maxAge;   // Max Age
	uint16_t hello;    // Hello Time
	uint16_t forward;  // Forward Delay
	uint8_t  ver1Len;  // Version 1 Length
	//uint16_t ver3Len;  // Version 3 Length
	// TLVs ((R)PVST+)
	//     uint16_t type;  // 0x0000: Originating VLAN
	//     uint16_t len;   // 2
	//     uint16_t value; // Originating VLAN
	// TODO MST Extension
} __attribute__((packed)) stpMsg_t;

typedef struct {
    uint16_t type;  // 0x0000: Originating VLAN
    uint16_t len;   // 2
    uint16_t value;
} pvstpTLV_t;

// plugin structure

typedef struct {
	//uint16_t proto;
	uint8_t version;
	uint8_t type;
	uint8_t flags;
	uint8_t stat;
} stpFlow_t;

// plugin struct pointer for potential dependencies
extern stpFlow_t *stpFlows;

#endif // STPDECODE_H_
