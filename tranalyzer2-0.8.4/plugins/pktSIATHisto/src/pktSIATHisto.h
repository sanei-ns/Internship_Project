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

#ifndef __PKTSIATHISTO_H__
#define __PKTSIATHISTO_H__

// local includes
#include "global.h"
#include "rbTree.h"


// User defines

#define HISTO_NODEPOOL_FACTOR 17 // multiplication factor redblack tree nodepool:
                                 // sizeof(nodepool) = HISTO_NODEPOOL_FACTOR * mainHashMap->hashChainTableSize
#define PRINT_HISTO            1 // 1: print histo to flow file
#define HISTO_PRINT_BIN        0 // 1: Bin number; 0: Minimum of assigned inter arrival time.
                                 // (Example: Bin = 10 -> iat = [50:55) -> min(iat) = 50ms)
#define HISTO_EARLY_CLEANUP    0 // 1: after onFlowTerminate tree information is destroyed
                                 // Do NOT switch on when dependent plugin, such as descriptiveStats is loaded!!
#define HISTO_DEBUG            0 // enables debug output

#define PSI_XCLD               0 // 1: include (BS_XMIN,UINT16_MAX]
#define PSI_XMIN               1 // if (PSI_XCLD] minimal packet length starts at PSI_XMIN
#define PSI_MOD                0 // > 1: modulo factor of packet length

#define IATSECMAX              3 // max # of section in statistics, last section comprises all elements > IATBINBuN

//#define PSI_XMAX      UINT16_MAX // if [PSI_XCLD] maximal packet length


// User statistics definitions

// integer flexible bin

#if (IATSECMAX < 1 || IATSECMAX > 6)
#undef IATSECMAX
#define IATSECMAX 3
#endif // (IATSECMAX < 1 || IATSECMAX > 6)

#define IATNORM      1000 // select ms as basic unit

#define IATBINBu1     200 // bin boundary of section one: [0, 200)ms
#define IATBINBu2     400
#define IATBINBu3    1000
#define IATBINBu4   10000
#define IATBINBu5  100000
#define IATBINBu6 1000000

#define IATBINWu1       1 // bin width 5ms
#define IATBINWu2       5
#define IATBINWu3      10
#define IATBINWu4      20
#define IATBINWu5      50
#define IATBINWu6     100

#define IATBINNu1 IATBINBu1 / IATBINWu1 // # of bins in section one
#define IATBINNu2 (IATBINBu2 - IATBINBu1) / IATBINWu2 + IATBINNu1
#define IATBINNu3 (IATBINBu3 - IATBINBu2) / IATBINWu3 + IATBINNu2
#define IATBINNu4 (IATBINBu4 - IATBINBu3) / IATBINWu4 + IATBINNu3
#define IATBINNu5 (IATBINBu5 - IATBINBu4) / IATBINWu5 + IATBINNu4
#define IATBINNu6 (IATBINBu6 - IATBINBu5) / IATBINWu6 + IATBINNu5

//#define IATBINUMAX IATBINNu3 + 1
#define TOKENHELPER(x, y) x ## y
#define TOKENPASTE(x ,y) TOKENHELPER(x, y)
#define IATBINUMAX TOKENPASTE(IATBINNu, IATSECMAX) + 1 // automated setting of timebin dimension

// float flexible bin

//#define IATBINBF1    0.2f
//#define IATBINBF2    0.4f
//#define IATBINBF3    1.0f
//#define IATBINBF4   10.0f
//#define IATBINBF5  100.0f

//#define IATBINWF1  0.005f
//#define IATBINWF2  0.01f
//#define IATBINWF3  0.02f
//#define IATBINWF4  0.1f
//#define IATBINWF5  1.0f

//#define IATBINWIF1 1.0f / IATBINWF1
//#define IATBINWIF2 1.0f / IATBINWF2
//#define IATBINWIF3 1.0f / IATBINWF3
//#define IATBINWIF4 1.0f / IATBINWF4
//#define IATBINWIF5 1.0f / IATBINWF5

//#define IATBINNFU1 IATBINBF1 / IATBINWIF1
//#define IATBINNFU2 (IATBINBF2 - IATBINBF1) / IATBINWIF2 + IATBINNFU1
//#define IATBINNFU3 (IATBINBF3 - IATBINBF2) / IATBINWIF3 + IATBINNFU2
//#define IATBINNFU4 (IATBINBF4 - IATBINBF3) / IATBINWIF4 + IATBINNFU3
//#define IATBINNFU5 (IATBINBF5 - IATBINBF4) / IATBINWIF5 + IATBINNFU4

//#define IATBINFMAX IATBIINF3 + 1


/* structs */
typedef struct {
	uint32_t numPackets;      // 4
	rbNode_t *iat_tree; // 4
} psiat_val_t;

typedef struct {
	uint32_t numPackets;                      // the total amount of packets inside the tree. 4 bytes
	rbNode_t *packetTree;               // the root of the stored tree. 4 bytes
	struct timeval lastPacketTime;            // 8 bytes
	uint32_t numPacketsInTimeBin[IATBINUMAX]; // stores the packets with a specific IAT, so we don't
	                                          // need to traverse the tree several times. 372 bytes
} pktSIAT_t;                                  // 388 bytes

int32_t bin2iat(uint32_t bin);

extern rbTreeNodePool_t *pktSIAT_treeNodePool;
extern pktSIAT_t *pktSIAT_trees;
extern psiat_val_t *psiat_vals;

#endif // __PKTSIATHISTO_H__
