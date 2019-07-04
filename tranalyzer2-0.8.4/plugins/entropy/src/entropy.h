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

#ifndef ENTROPY_H_
#define ENTROPY_H_

// Local includes

#include "global.h"


// user defines

#define ENT_THRES         2  // threshold for minimal string length
#define ENT_ALPHA_D       0  // 1: print Alphabet distribution in flow file
#define ENT_D_OFFSET      0  // start of entropy calc in payload

// experimental
#define ENT_FLOW          0  // global flow entropy: 1: entropy, 0 output; 2: + distribution
#define ENT_NTUPLE       55  // number of entropy tuples: if ENT_FLOW > 0


// plugin defines

#define ENT_MAXPBIN (1 << 8) // N = 8 Bit Word, vocabulary: 256


// plugin structures

typedef struct {
	uint32_t numBytes;              // Number of bytes collected
	uint32_t binCount[ENT_MAXPBIN]; // Count of each bin value
} entropyFlow_t;

extern entropyFlow_t *entropyFlow;

#endif // ENTROPY_H_
