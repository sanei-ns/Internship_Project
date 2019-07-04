/*
 * tcpStates.h
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

#ifndef __TCP_STATES_H__
#define __TCP_STATES_H__

#include "global.h"

// User defines

// Local Plugin defines

// Local definition of the states
#define STATE_NEW           0
#define STATE_ESTABLISHED   1
#define STATE_CLOSING       2
#define STATE_CLOSED        3
#define STATE_RESET         4
#define STATE_BOGUS       255

// Local definition of the timeouts
#define TIMEOUT_RESET         0.1f // 100 ms
#define TIMEOUT_NEW         120.0f // 2 minutes
#define TIMEOUT_ESTABLISHED 610.0f // 10 minutes
#define TIMEOUT_CLOSING     120.0f // 2 minutes
#define TIMEOUT_CLOSED       10.0f // 10 seconds

// Anomalies
#define MAL_CON_EST  0x01 // Malformed connection establishement
#define MAL_TEARDWN  0x02 // Malformed teardown
#define MAL_FLGS_EST 0x04 // Malformed flags during established connection
#define PKTS_TERM    0x08 // More packets after teardown
#define PKTS_RST     0x10 // More packets after reset seen
#define RST_TRANS    0x40 // Reset from sender seen
#define EVIL         0x80 // Potential evil behavior

// basic struct to recognize the states
typedef struct {
    uint64_t syn_seq_num;
    uint64_t fin_seq_num;
    uint8_t  anomalies;
    uint8_t  state;
    uint8_t  syn_seen:1;
    uint8_t  syn_ackd:1;
    uint8_t  fin_seen:1;
    uint8_t  fin_ackd:1;
    uint8_t  fin_scan:1;
} tcp_connection_t;

extern tcp_connection_t *tcp_connections;

#endif // __TCP_STATES_H__
