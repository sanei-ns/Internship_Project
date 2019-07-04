/*
 * hashTable.h
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

/*
 * The principal design of this hashTable implementation is as follows:
 * It is a closed hashTable, that means the hashing function returns a
 * bucketnumber which points on an attached list of bucket entries. Each of
 * the bucket entries contains a - hashTable wide - unique number between zero
 * and HASHCHAINTABLESIZE, which can be used for example to access an array. The
 * collection of the free numbers is done by the freeList. Each plugin can
 * define its own hashTable if necessary and use the functions listed below.
 * PLEASE NOTE:
 * The mapping of the hashTable entries on the unique numbers is not explicit!
 * If an entry is removed out of the hashTable and re-inserted later, it will
 * get a different unique number with big probability!
 */

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

// includes
#include "networkHeaders.h"

#define HASH_FUNCTION  8 // Hash function to use:
                         //   0: standard
                         //   1: Murmur3 32-bits
                         //   2: Murmur3 128-bits (truncated to 64-bits)
                         //   3: xxHash 32-bits
                         //   4: xxHash 64-bits
                         //   5: CityHash64
                         //   6: MUM-V2 64-bits
                         //   7: hashlittle 32-bits
                         //   8: wyhash 64-bits
                         //   9: FastHash32
                         //  10: FastHash64

#define HASHTABLE_DEBUG    0 // a debug flag to enable extreme debug
#define HASHTABLE_NAME_LEN 7 // maximum length of a hashTable's name

#define HASHTABLE_ENTRY_NOT_FOUND ULONG_MAX

#if HASH_FUNCTION == 0

// a mix function used by the hashing function
#define mix(a, b, c) { \
  a -= b; a -= c; a ^= (c >> 13); \
  b -= c; b -= a; b ^= (a <<  8); \
  c -= a; c -= b; c ^= (b >> 13); \
  a -= b; a -= c; a ^= (c >> 12); \
  b -= c; b -= a; b ^= (a << 16); \
  c -= a; c -= b; c ^= (b >>  5); \
  a -= b; a -= c; a ^= (c >>  3); \
  b -= c; b -= a; b ^= (a << 10); \
  c -= a; c -= b; c ^= (b >> 15); \
}

#endif // HASH_FUNCTION == 0

// structs

// The structure for the hashBuckets, 19 Bytes -> 20 Bytes allocated
typedef struct hashBucket {
	struct hashBucket *nextBucket;
	char *data;
} hashBucket_t;

/*typedef struct {
	in_addr_t ip_src; // 4
	in_addr_t ip_dst; // 4
	uint16_t vlan_id; // 2 eigentlich 1.5
	uint16_t port_src; // 2
	uint16_t port_dst; // 2
	u_int8_t protocol; // 1
} hashData_t;

typedef union {
	char data[15];
	hashData_t hashDatas;
} hashBucketData_t;*/

// The structure to collect all necessary information for a single hashMap
typedef struct {
	unsigned long hashTableSize;
	unsigned long hashChainTableSize;
	hashBucket_t **hashTable;
	hashBucket_t *hashChainTable;
	hashBucket_t *freeBucket; // points to the first free bucket
	unsigned long freeListSize;
	unsigned long dataLength;
	char name[HASHTABLE_NAME_LEN+1];
} hashMap_t;

// functions
// initializes a hashMap
hashMap_t *hashTable_init(float scaleFactor, unsigned long dataLength, const char *name);

// looks, if a combination of all parameters is already stored in the hashMap,
// if not HASHTABLE_ENTRY_NOT_FOUND is returned
extern unsigned long hashTable_lookup(hashMap_t *hashMap, const char *data);

// the function that generates a hash value, used by the other functions
extern unsigned long hashTable_hash(const char *data, unsigned long dataLength);

// inserts a combination of all parameters in the hashMap
extern unsigned long hashTable_insert(hashMap_t *hashMap, const char *data);

// removes a combination of all parameters in the hashMap
extern unsigned long hashTable_remove(hashMap_t *hashMap, const char *data);

// completely destroys a hash table
void hashTable_destroy(hashMap_t *hashMap);

#endif // __HASHTABLE_H__
