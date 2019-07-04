/*
 * tp0f.h
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

#ifndef __TP0F_H__
#define __TP0F_H__

// global includes

// local includes
#include "global.h"

// user defines
#define TP0FRULES   1 // 0: standard OS guessing; 1: OS guessing and p0f L3/4 rules
#define TP0FHSH     1 // 0: no IP hash; 1: IP hash to recognize IP already classified
#define TP0FRC      0 // 0: only human readable; 1: add classifier numbers
#define TP0FL34FILE "tp0fL34.txt"

// plugin defines

// Status variable
#define TP0F_TSSIG    0x01 // SYN tp0f rule fired
#define TP0F_TSASIG   0x02 // SYN-ACK tp0f rule fired
#define TP0F_ASN      0x40 // Already Seen IP by tP0f
#define TP0F_L4OPTBAD 0x80 // tcp option length or content corrupt


// plugin structure

typedef struct {
	uint16_t rID;
	uint8_t stat;
	uint8_t clss;
	uint8_t prog;
	uint8_t ver;
	uint8_t dist;
} tp0fFlow_t;

// plugin struct pointer for potential dependencies
extern tp0fFlow_t *tp0fFlows;

#endif // __TP0F_H__
