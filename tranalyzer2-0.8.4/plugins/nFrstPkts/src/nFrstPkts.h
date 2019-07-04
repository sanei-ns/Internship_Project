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

#ifndef __N_FRST_PKTS_H__
#define __N_FRST_PKTS_H__

// local includes
#include "global.h"

// User config parameters
#define NFRST_IAT         1 // 0: Time releative to flow start; 1: Interarrival Time; 2: Absolute Time
#define NFRST_BCORR       0 // 0: A,B start at 0.0; 1: B shift by flow start; if (NFRST_IAT == 0)
#define NFRST_MINIATS     0 // minimal IAT sec to define a puls
#define NFRST_MINIATU     0 // minimal IAT usec to define a puls
#define NFRST_MINPLENFRC  2 // minimal Puls length fraction
#define NFRST_PLAVE       1 // 1: Packet Length Average; 0: Sum(PL) (BPP); if (NFRST_MINIATS|NFRST_MINIATU) > 0
#define NFRST_PKTCNT      20 // defines how many first packets are recorded
#define NFRST_HDRINFO     0 // add L3,L4 Header length
#define NFRST_XCLD        0 // 0: include all, 1: include [NFRST_XMIN,NFRST_XMAX]
#define NFRST_XMIN        1           // min PL boundary; NFRST_XCLD=1
#define NFRST_XMAX        UINT16_MAX  // max PL boundary; NFRST_XCLD=1

//
#define NFRST_MINIAT (NFRST_MINIATS || NFRST_MINIATU)

#if NFRST_MINPLENFRC > 0
#define NFRST_NINPLSS (NFRST_MINIATS/NFRST_MINPLENFRC)
#define NFRST_NINPLSU (NFRST_MINIATU/NFRST_MINPLENFRC)
#else // NFRST_MINPLENFRC == 0
#define NFRST_NINPLSS NFRST_MINIATS
#define NFRST_NINPLSU NFRST_MINIATU
#endif // NFRST_MINPLENFRC

// struct to save basic statistic of a single packet
typedef struct {
	struct timeval iat;
#if NFRST_MINIAT > 0
	struct timeval piat;
#endif // NFRST_MINIAT > 0
	uint32_t pktLen;
#if NFRST_HDRINFO == 1
	uint8_t l3HDLen;
	uint8_t l4HDLen;
#endif // NFRST_HDRINFO == 1
} pkt_t;

// struct to collect the stats of the first n packets of a flow
typedef struct {
	struct timeval lstPktTm;
	struct timeval lstPktTm0;
#if NFRST_BCORR > 0
	struct timeval tdiff;
#endif // NFRST_BCORR > 0
#if NFRST_MINIAT > 0
	struct timeval lstPktPTm;
	struct timeval lstPktiat;
	uint32_t puls;
#endif // NFRST_MINIAT > 0
	uint32_t pktCnt;
	pkt_t pkt[NFRST_PKTCNT];
} nFrstPkts_t;

// Pointer for potential dependencies
extern nFrstPkts_t *nFrstPkts;

#endif // __N_FRST_PKTS_H__
