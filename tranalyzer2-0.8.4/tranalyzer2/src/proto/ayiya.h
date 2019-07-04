/*
 * ayiya.h
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

#ifndef __AYIYA_H__
#define __AYIYA_H__

// includes
#include <stdbool.h>
#include <stdint.h>
#include "networkHeaders.h"


// AYIYA: Anything in Anything

#define AYIYA_PORT 5072
//#define AYIYA_PORT_N 0xd013 // 5072

typedef struct {
    uint8_t  id_type:4;   // 0: none, 1: integer, 2: ASCII string
    uint8_t  id_len:4;    // Identity length (2^id_len)
    uint8_t  hash_meth:4; // 0: no hash, 1: md5, 2: sha1
    uint8_t  sig_len:4;   // Signature length (sig_len << 2)
    uint8_t  opcode:4;    // 0: No Operation / Heartbeat, 1: Forward, 2: Echo Request
                          // 3: Echo Request and Forward, 4: Echo Response, 5: MOTD,
                          // 6: Query Request, 7: Query Response
    uint8_t  auth_meth:4; // 0: no authentication, 1: hash using a shared secret,
                          // 2: hash using a public/private key method
    uint8_t  next_header;
    uint32_t epoch;
    // Identity  (1 << id_len)
    // Signature (sig_len << 2)
} __attribute__((packed)) ayiyaHeader_t;

extern bool t2_is_ayiya(uint16_t sport, uint16_t dport);
extern uint8_t *t2_process_ayiya(uint8_t *pktptr, packet_t *packet);

#endif // __AYIYA_H__
