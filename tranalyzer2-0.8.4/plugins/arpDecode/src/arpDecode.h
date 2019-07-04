/*
 * arpDecode.h
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

#ifndef __ARP_DECODE_H__
#define __ARP_DECODE_H__


#include "global.h"


// user defines

#define MAX_IP 10 // Max. number of MAC/IP pairs to list (max 255)


// plugin defines

// ARP opcode
#define ARP_OPCODE_REQ   1
#define ARP_OPCODE_REP   2
#define RARP_OPCODE_REQ  3
#define RARP_OPCODE_REP  4
#define DRARP_OPCODE_REQ 5
#define DRARP_OPCODE_REP 6
#define DRARP_OPCODE_ERR 7
#define INARP_OPCODE_REQ 8
#define INARP_OPCODE_REP 9

// Use those packets to build the ARP table
#define ARP_SUPPORTED_OPCODE ( \
    1 << ARP_OPCODE_REQ  | \
    1 << ARP_OPCODE_REP  | \
    1 << RARP_OPCODE_REP   \
)

// arpStat
#define ARP_DET   0x01 // ARP detected
#define ARP_FULL  0x02 // MAC/IP list truncated... increase MAX_IP
#define ARP_GRAT  0x08 // Gratuitous ARP
#define ARP_SPOOF 0x80 // ARP spoofing (same IP assigned to multiple MAC)

// protocol structure

typedef struct {
	uint16_t hwType;
	uint16_t protoType;
	uint8_t  hwSize;
	uint8_t  protoSize;
	int16_t  opCode;
	uint8_t  srcMAC[ETH_ALEN];
	uint32_t srcIP;
	uint8_t  dstMAC[ETH_ALEN];
	uint32_t dstIP;
} __attribute__((packed)) arpMsg_t;

// plugin structure

typedef struct {
    uint32_t ip[MAX_IP];
    uint16_t ipCnt[MAX_IP];
    uint16_t opCode;
    uint16_t hwType;
    uint16_t cnt;
    uint8_t mac[MAX_IP][ETH_ALEN];
    uint8_t stat;
} arpFlow_t;

// plugin struct pointer for potential dependencies
extern arpFlow_t *arpFlows;

#endif // __ARP_DECODE_H__
