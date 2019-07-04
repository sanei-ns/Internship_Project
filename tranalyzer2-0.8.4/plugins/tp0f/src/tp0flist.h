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

#ifndef P0FLIST_H_
#define P0FLIST_H_

// global plugin defines
#include "global.h"

// user defines

// plugin defines
#define MAXLINELN 4096 // maximal file input line buffer length
#define TCPOPTMAX 40   // maximal number of stored tcp option codes in memory and processed per flow (s. tp0f.c)

// clst

#define CLST_IP     0x01 // consider IP version
#define CLST_MSS    0x02 // calculate win size from MSS
#define CLST_MTU    0x04 // calculate win size from MTU, aka MSS
#define CLST_MSS_DC 0x08 // MSS don't care
#define CLST_WS_DC  0x10 // WS don't care
#define CLST_PLD    0x20 // consider payload info

// ipF

#define IPF_DF      0x40

// global plugin structs

typedef struct {
	uint32_t mss;
	uint32_t wsize;
	uint16_t id;
	uint16_t qoptF;
	uint8_t clst;
	uint8_t ws;
	uint8_t ipv;
	uint8_t ipF;
	uint8_t tcpF;
	uint8_t ittl;
	uint8_t olen;
	uint8_t ntcpopt;
	uint8_t tcpopt[TCPOPTMAX];
	uint8_t pad;
	uint8_t pldl;
	uint8_t nclass;
	uint8_t nprog;
	uint8_t nver;
} tp0flist_t;


typedef struct {
	uint32_t count;
	tp0flist_t *tp0flists;
} tp0flist_table_t;

uint32_t tp0flist_init(tp0flist_table_t *table, const char *tp0ffile);

#endif // POFLIST_H_
