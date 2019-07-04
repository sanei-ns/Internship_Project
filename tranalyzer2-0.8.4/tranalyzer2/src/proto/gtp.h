/*
 * gtp.h
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

#ifndef __GTP_H__
#define __GTP_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


// GTP - GPRS Tunneling Protocol

#define GTP_CTRL_PORT 2123
#define GTP_USER_PORT 2152
#define GTP_DATA_PORT 3386

//#define GTP_CTRL_PORT_N 0x4b08 // 2123
//#define GTP_USER_PORT_N 0x6808 // 2152
//#define GTP_DATA_PORT_N 0x3a0d // 3386

typedef struct {
    uint8_t  version:3;
    uint8_t  proto:1;    // Protocol Type: 1: GTP, 0: GTP'
    uint8_t  reserved:4; // MUST be 1
    uint8_t  msgT;       // Message Type
    uint16_t len;        // Message Length
    uint16_t seqnum;     // Sequence number
    uint16_t flabel;     // Flow Label
    uint8_t  llc_fn;     // LLC Frame Number
    uint8_t  reserved2;  // MUST be 0
    uint16_t reserved3;  // MUST be 1
    uint64_t tid;        // Tunnel Identifier (TID)
} __attribute__((packed)) gtpv0_header_t;

typedef struct {
    uint8_t  version:3;
    uint8_t  proto:1;    // Protocol Type: 1: GTP, 0: GTP'
    uint8_t  reserved:1; // MUST be 0
    uint8_t  flag_e:1;   // Extension header flag (E)
    uint8_t  flag_s:1;   // Sequence number flag (S)
    uint8_t  flag_pn:1;  // N-PDU number flag (PN)
    uint8_t  msgT;       // Message Type
    uint16_t len;        // Message Length
    uint32_t teid;       // Tunnel Endpoint Identifier (TEID)
    // The following fields are only present if one of E, S or PN flag is set
    //uint16_t seqnum;   // Sequence number
    //uint8_t npdunum;   // N-PDU number
    //uint8_t nexthdr;   // Next extension header type
} __attribute__((packed)) gtpv1_header_t;

typedef struct {
    uint8_t  version:3;
    uint8_t  flag_p:1;    // Piggybacking flag (P)
    uint8_t  flag_t:1;    // TEID flag (T)
    uint8_t  reserved:3;  // Reserved
    uint8_t  msgT;        // Message Type
    uint16_t len;         // Message Length
    // The following field is only present if T flag is set
    //uint32_t teid;      // Tunnel Endpoint Identifier (TEID)
    //uint32_t seqnum:24; // Sequence number
    //uint32_t seqnum:8;  // Reserved
} __attribute__((packed)) gtpv2_header_t;

typedef struct {
    uint8_t  version:3;
    uint8_t  proto:1;    // Protocol Type: 0: GTP', 1: GTP
    uint8_t  reserved:3; // MUST be 1
    uint8_t  hdrlen:1;   // Header length (version 0 only): 0: 20 bytes (as per GTPv0), 1: 6 bytes (this header)
    uint8_t  msgT;       // Message Type
    uint16_t len;        // Message Length
    uint16_t seqnum;   // Sequence number
} __attribute__((packed)) gtp_prime_header_t;

extern bool t2_is_gtp(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_gtp(uint8_t *pktptr, packet_t *packet);

#endif // __GTP_H__
