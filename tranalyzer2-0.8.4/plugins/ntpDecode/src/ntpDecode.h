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

#ifndef NTPDECODE_H_
#define NTPDECODE_H_

// global includes

// local includes
#include "global.h"

// user defines

#define NTP_TS       1 // 1: print NTP timestamps, 0: no timestamps
#define NTP_LIVM_HEX 0 // Leap indicator, version number and mode:
                       // 0: split into three values, 0: aggregated hex number

// plugin defines

#define L3_NTPn  0x7B00
#define NTPTSHFT 0x83AA7E80
#define NTPVER   0x1C

// stat
#define NTP_DTCT 0x01 // NTP port detected

// ntpDecode plugin structures

typedef struct {
	uint8_t liVerMd;
	uint8_t stratum;
	uint8_t pollInt;
	uint8_t precsion;
	uint32_t rootDel;
	uint32_t rootDisp;
	uint32_t refClkID;
	uint64_t refCTime;
	uint64_t origCTime;
	uint64_t recSTime;
	uint64_t tranSTime;
} ntp_t;

typedef struct { // always large variables first to limit memory fragmentation
#if NTP_TS == 1
	uint64_t tS[4];
#endif // NTP_TS == 1
	uint32_t rootDelMin;
	uint32_t rootDelMax;
	uint32_t rootDispMin;
	uint32_t rootDispMax;
	uint32_t refClkID;
	uint8_t stat;
	uint8_t livm;
	uint8_t strat;
	uint8_t pollInt;
	uint8_t prec;
} ntpFlow_t;

// plugin struct pointer for potential dependencies
extern ntpFlow_t *ntpFlow;

#endif // NTPDECODE_H_
