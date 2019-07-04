/*
 * findexer.h
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

#ifndef __findexer_H__
#define __findexer_H__

// global includes
#include <stdint.h>
#include <sys/queue.h>

#define FINDEXER_SPLIT  1 // whether or not to split the output file (-W option)
#define FINDEXER_SUFFIX "_flows.xer"

// ------------------------- DO NOT EDIT BELOW HERE -------------------------

#define FINDEXER_PLUGIN_NAME "findexer"
#define FINDEXER_MAGIC  0x32455845444e4946 // FINDEXE2 : findexer v2
// initial number of packet offsets allocated in the findexerFlow_t struct
#define FINDEXER_INITIAL_PACKET_ALLOC 8

// findexer flow flags
enum FlowFlag {
    REVERSE_FLOW, // flow is a B flow
    FIRST_XER,    // this is the first .xer file in which this flow appears
    LAST_XER,     // this is the last .xer file in which this flow appears
    // reserved for future flags
};

// macro to transform a FlowFlag into its bitmask representation
#define TO_BITMASK(x) (1 << (x))

// findexer flow structure
typedef struct findexerFlow_s {
    unsigned long flowIndex;
    uint64_t packetCount;
    uint64_t* packetOffsets;
    size_t packetAllocated;
    // struct for queue of open flows in current PCAP
    TAILQ_ENTRY(findexerFlow_s) entries;
    uint8_t flags;
} findexerFlow_t;

#endif // __findexer_H__
