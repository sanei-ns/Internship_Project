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

#ifndef __BASIC_STATS_H__
#define __BASIC_STATS_H__

// local includes

#include "global.h"


// User defines

#define BS_AGRR_CNT  0  // 1: add A+B counts 0: A+B counts off
#define BS_REV_CNT   1  // 1: add reverse counts from opposite flow, 0: native send counts
#define BS_STATS     1  // 1: basic statistics, 0: only counts
#define BS_PL_STATS  1  // 1: basic Packet Length statistics, 0: only counts
#define BS_IAT_STATS 1  // 1: basic IAT statistics, 0: only counts
#define BS_VAR       0  // 0: no var calc, 1: variance
#define BS_STDDEV    1  // 0: no stddev calc, 2: stddev

#define BS_XCLD      0  // if (BS_STATS) {
                        //   0: include all
                        //   1: include (BS_XMIN,UINT16_MAX],
                        //   2: include [0,BS_XMAX),
                        //   3: include [BS_XMIN,BS_XMAX]
                        //   4: exclude (BS_XMIN,BS_XMAX)
                        // }
#define BS_XMIN      1           // if (BS_XCLD) minimal packet length
#define BS_XMAX      UINT16_MAX  // if (BS_XCLD) maximal packet length

// MAC OSX only
#define BS_GEOLOC  0 // whether (1) or not (0) to add the country to the IPs
                     // with max bytes/packets

// Plugin defines

#ifndef __APPLE__
#include "basicFlow.h"
#if BFO_SUBNET_TEST == 1
// BS_GEOLOC is automatically activated (when possible) on Linux
#undef BS_GEOLOC
#define BS_GEOLOC 1
#endif // BFO_SUBNET_TEST == 1
#endif // !__APPLE__

#define BS_VARSTD (BS_VAR > 0 || BS_STDDEV > 0)


// structs

typedef struct {
    uint64_t numTPkts;  // Number of packets transmitted.
    uint64_t numTBytes; // Number of bytes transmitted (depends on PACKETLENGTH)
    uint64_t totTBytes; // Number of bytes transmitted (total rawLength)
#if BS_STATS == 1
#if BS_XCLD > 0
    uint64_t numTPkts0; // Number of packets transmitted pktlen > 0
#endif
    struct timeval lst;
    float avePktSzf;
#if BS_VARSTD > 0
    float varPktSz;
    float varIATSz;
#endif
    float aveIATSzf;
    float minIAT;
    float maxIAT;
    uint16_t minL3PktSz; // Smallest L3 packet size detected
    uint16_t maxL3PktSz; // Largest L3 packet size detected
#endif // BS_STATS == 1
} bSFlow_t;

// plugin struct pointer for potential dependencies
extern bSFlow_t *bSFlow;


// global variables for esom dependencies

#if ESOM_DEP == 1

#if (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGRR_CNT == 1)
int64_t oNumPkts, oNumBytes; // num of packets/bytes of opposite flow
#endif

#if BS_AGRR_CNT == 1
uint64_t aggPkts, aggBytes;
#endif

#if BS_STATS == 1
float packet_sym_ratio, byte_sym_ratio; // packet- and byte asymmetry
float packetsPerSec, bytesPerSec;
float avePktSize;
#endif

#endif // ESOM_DEP == 1

#endif // __BASIC_STATS_H__
