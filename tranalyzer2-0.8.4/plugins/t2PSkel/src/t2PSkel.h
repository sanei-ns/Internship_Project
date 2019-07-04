/*
 * t2PSkel.h
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

#ifndef __T2_PSKEL_H__
#define __T2_PSKEL_H__

// Global includes
//#include <stdio.h>
//#include <string.h>

// Local includes
#include "global.h"

/* ========================================================================== */
/* USER CONFIGURATION                                                         */
/* ========================================================================== */

#define T2PSKEL_IP    0 // whether or not to output IP (var2)
#define T2PSKEL_VAR1  0 // whether or not to output var1
#define T2PSKEL_VEC   0 // whether or not to output t2p

#define T2PSKEL_FNAME "filename.txt"

/* ========================================================================== */
/* END USER CONFIGURATION                                                     */
/* ========================================================================== */

// plugin defines
#define NUM    5
#define WURST 10

#define T2PSKEL_PORT 1234

// Status variable
#define T2PSKEL_STAT_MYPROT 0x01 // use this in onFlowGenerated to flag flows of interest

// sample plugin structures
typedef struct { // always large variables first to limit memory fragmentation
    double var7[NUM][WURST];
#if T2PSKEL_VAR1 == 1
    uint64_t var1;
#endif // T2PSKEL_VAR1 == 1
#if T2PSKEL_IP == 1
    ip4Addr_t var2;
#endif // T2PSKEL_IP == 1
    uint32_t numAlarms;
    uint32_t var3;
    uint16_t var4;
    uint16_t var5[NUM];
    char text[16];
    uint8_t var6[NUM];
    uint8_t stat;
} t2PSkel_flow_t;

// plugin struct pointer for potential dependencies
extern t2PSkel_flow_t *t2PSkel_flows;

#endif // __T2_PSKEL_H__
