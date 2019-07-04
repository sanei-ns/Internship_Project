/*
 * hashTable.c
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

#include "hashTable.h"
#include "global.h"
#if HASH_FUNCTION > 8
#include "hash/fasthash.h"
#elif HASH_FUNCTION == 8
#include "hash/wyhash.h"
#elif HASH_FUNCTION == 7
#include "hash/hashlittle.h"
#elif HASH_FUNCTION == 6
#include "hash/mum.h"
#elif HASH_FUNCTION == 5
#include "hash/city.h"
#elif HASH_FUNCTION == 3 || HASH_FUNCTION == 4
#include "hash/xxhash.h"
#elif HASH_FUNCTION == 1 || HASH_FUNCTION == 2
#include "hash/murmur3.h"
#endif // HASH_FUNCTION == 1 || HASH_FUNCTION == 2

#include <math.h>


// Variables

uint32_t hashFactor = HASHFACTOR;


// Functions protototypes

#if HASHTABLE_DEBUG != 0
static void hashTable_print(hashMap_t *hashMap, const char *title);
#endif


/*
 * Initializes a hashMap
 *   - the scale factor can be submitted to change the base size of the hash table
 *   - the name is used for error reporting
 */
hashMap_t *hashTable_init(float scaleFactor, unsigned long dataLength, const char *name) {
#if DEBUG != 0
	if (scaleFactor < 1.0f) T2_WRN("Scale factor for hashMap is smaller than 1.0");
#endif

	hashMap_t *hashMap = calloc(1, sizeof(hashMap_t));
	if (UNLIKELY(!hashMap)) {
		T2_ERR("Could not allocate memory for hashMap");
		exit(1);
	}

	const size_t len = name ? strlen(name) : 0;
	if (len > 0) {
		memcpy(hashMap->name, name, MIN(len, HASHTABLE_NAME_LEN));
	}

	hashMap->dataLength = dataLength;

	const float factor = hashFactor * scaleFactor;
	hashMap->hashTableSize = ceilf(HASHTABLE_BASE_SIZE * factor);
	hashMap->hashChainTableSize = ceilf(HASHCHAINTABLE_BASE_SIZE * factor);

	hashMap->hashTable = calloc(hashMap->hashTableSize, sizeof(hashBucket_t*));
	if (UNLIKELY(!hashMap->hashTable)) {
		T2_ERR("Could not allocate memory for hashMap->hashTable");
		free(hashMap);
		exit(1);
	}

	hashMap->hashChainTable = calloc(hashMap->hashChainTableSize, sizeof(hashBucket_t));
	if (UNLIKELY(!hashMap->hashChainTable)) {
		T2_ERR("Could not allocate memory for hashMap->hashChainTable");
		free(hashMap->hashTable);
		free(hashMap);
		exit(1);
	}

	const unsigned long size = hashMap->hashChainTableSize;

	char *data;
	if (UNLIKELY(!(data = malloc(size * dataLength)))) {
		T2_ERR("Could not allocate memory for hashMap data");
		free(hashMap->hashChainTable);
		free(hashMap->hashTable);
		free(hashMap);
		exit(1);
	}

	uint_fast32_t i, pos = 0;
	// note the 'minus one' (last bucket has no next bucket)
	for (i = 0; i < size-1; i++, pos += dataLength) {
		hashMap->hashChainTable[i].data = &data[pos];
		hashMap->hashChainTable[i].nextBucket = &hashMap->hashChainTable[i+1];
	}
	hashMap->hashChainTable[i].data = &data[pos]; // last bucket

	hashMap->freeBucket = &hashMap->hashChainTable[0];
	hashMap->freeListSize = hashMap->hashChainTableSize;

#if HASHTABLE_DEBUG != 0
	hashTable_print(hashMap, "init  ");
#endif

	return hashMap;
}


/* looks if a combination of all parameters is already stored in the hashMap,
 * if not HASHTABLE_ENTRY_NOT_FOUND is returned */
inline unsigned long hashTable_lookup(hashMap_t *hashMap, const char *data) {
	if (UNLIKELY(!hashMap)) {
		T2_PERR("hashTable_lookup", "HashMap does not exist"); // Programming error
		exit(1);
	}

	const unsigned long hash = hashTable_hash(data, hashMap->dataLength) % hashMap->hashTableSize;
	hashBucket_t *currBucket = hashMap->hashTable[hash];
	while (currBucket) {
		if (memcmp(currBucket->data, data, hashMap->dataLength) == 0) {
			return (currBucket - hashMap->hashChainTable);
		}

		currBucket = currBucket->nextBucket;
	}

	return HASHTABLE_ENTRY_NOT_FOUND;
}


/* the function that generates a hash value, used by the other functions */
inline unsigned long hashTable_hash(const char *data, unsigned long dataLength) {
#if HASH_FUNCTION == 10
	static const uint32_t seed = 0;
	return fasthash32(data, dataLength, seed);
#elif HASH_FUNCTION == 9
	static const uint64_t seed = 0;
	return fasthash64(data, dataLength, seed);
#elif HASH_FUNCTION == 8
	static const uint64_t seed = 0;
	return wyhash(data, dataLength, seed);
#elif HASH_FUNCTION == 7
	static const uint32_t seed = 0;
	return hashlittle(data, dataLength, seed);
#elif HASH_FUNCTION == 6
	static const uint64_t seed = 0;
	return mum_hash(data, dataLength, seed);
#elif HASH_FUNCTION == 5
	return CityHash64(data, dataLength);
#elif HASH_FUNCTION == 4
	static const unsigned long long seed = 0;
	return XXH64(data, dataLength, seed);
#elif HASH_FUNCTION == 3
	static const unsigned int seed = 0;
	return XXH32(data, dataLength, seed);
#elif HASH_FUNCTION == 2
	static const uint32_t seed = 0;
	uint64_t hash[2] = {};
	MurmurHash3_x64_128(data, dataLength, seed, &hash);
	return hash[0];
#elif HASH_FUNCTION == 1
	static const uint32_t seed = 0;
	uint32_t hash = 0;
	MurmurHash3_x86_32(data, dataLength, seed, &hash);
	return hash;
#else // HASH_FUNCTION == 0
	unsigned long hash = 0;
	for (unsigned long i = 0; i < dataLength; i++) {
		hash += data[i];
		hash += (hash << 10);
		hash ^= (hash >>  6);
	}

	hash += (hash <<  3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
#endif // HASH_FUNCTION == 0
}


/* inserts a combination of all parameters in the hashMap */
inline unsigned long hashTable_insert(hashMap_t *hashMap, const char *data) {
	if (UNLIKELY(!hashMap)) {
		T2_PERR("hashTable_insert", "HashMap does not exist"); // Programming error
		exit(1);
	}

	if (UNLIKELY(hashMap->freeListSize == 0)) {
		if (!(globalWarn & RMFLOW_HFULL) && (hashMap == mainHashMap)) {
			uint32_t f = captureFileSize / (24 + bytesProcessed + numPackets * 16);
			if (f < 2) f = 2;
			if (f > 16) {
				f = 16;

#if HASH_AUTOPILOT == 1
			}
			T2_PWRN("Hash Autopilot", "%s HashMap full: flushing %d oldest flow(s)", hashMap->name, NUMFLWRM);
			T2_PINF("Hash Autopilot", "Fix: Invoke Tranalyzer with '-f %"PRIu32"'", f * hashFactor);
		}
		if (hashMap == mainHashMap) {
			lruRmLstFlow();
		} else {
			//T2_ERR("%s HashMap full", hashMap->name);
			//terminate();
			return HASHTABLE_ENTRY_NOT_FOUND;
		}
#else // HASH_AUTOPILOT == 0
				T2_ERR("%s HashMap full", hashMap->name);
				T2_INF("Fix: Invoke Tranalyzer with '-f %"PRIu32"'", hashFactor * f / 4);
			} else {
				T2_ERR("%s HashMap full", hashMap->name);
				T2_INF("Fix: Invoke Tranalyzer with '-f %"PRIu32"'", f * hashFactor);
			}
		}
		if (hashMap != mainHashMap) T2_ERR("%s HashMap full", hashMap->name);
		terminate();
#endif // HASH_AUTOPILOT
	}

	const unsigned long hash = hashTable_hash(data, hashMap->dataLength) % hashMap->hashTableSize;

	/* take a free bucket from the front of the free list */
	hashBucket_t *currBucket = hashMap->freeBucket;
	hashMap->freeBucket = hashMap->freeBucket->nextBucket;

	/* point the nextPointer on the current first bucket */
	currBucket->nextBucket = hashMap->hashTable[hash];

	/* place the current bucket at the front of the hashTable */
	hashMap->hashTable[hash] = currBucket;

	/* fill it with the right values */
	memcpy(currBucket->data, data, hashMap->dataLength);

	hashMap->freeListSize--;

#if HASHTABLE_DEBUG != 0
	hashTable_print(hashMap, "insert");
#endif

	return (currBucket - hashMap->hashChainTable);
}


/* removes a combination of all parameters in the hashMap */
inline unsigned long hashTable_remove(hashMap_t *hashMap, const char *data) {
	if (UNLIKELY(!hashMap)) {
		T2_PERR("hashTable_remove", "HashMap does not exist"); // Programming error
		exit(1);
	}

	const unsigned long hash = hashTable_hash(data, hashMap->dataLength) % hashMap->hashTableSize;
	hashBucket_t *currBucket = hashMap->hashTable[hash];
	hashBucket_t *prevBucket = currBucket;
	while (currBucket) {
		if (memcmp(currBucket->data, data, hashMap->dataLength) == 0) {

			/* set the pointers of the hashBucket */
			if (prevBucket == currBucket) {
				hashMap->hashTable[hash] = currBucket->nextBucket;
			} else {
				prevBucket->nextBucket = currBucket->nextBucket;
			}

			/* reinsert bucket into free list */
			currBucket->nextBucket = hashMap->freeBucket;
			hashMap->freeBucket = currBucket;

			hashMap->freeListSize++;

#if HASHTABLE_DEBUG != 0
			hashTable_print(hashMap, "remove");
#endif

			return 0;
		}

		prevBucket = currBucket;
		currBucket = currBucket->nextBucket;
	}

	return HASHTABLE_ENTRY_NOT_FOUND;
}


void hashTable_destroy(hashMap_t *hashMap) {
	if (UNLIKELY(!hashMap)) return;

	if (LIKELY(hashMap->hashChainTable != NULL)) {
		free(hashMap->hashChainTable[0].data);
		hashMap->hashChainTable[0].data = NULL;
		free(hashMap->hashChainTable);
		hashMap->hashChainTable = NULL;
	}

	free(hashMap->hashTable);
	hashMap->hashTable = NULL;

	free(hashMap);
}


#if HASHTABLE_DEBUG != 0
static void hashTable_print(hashMap_t *hashMap, const char *title) {
	fprintf(stdout, "HashTable after %s: -----------------------------------\n", title);
	unsigned long j;
	hashBucket_t *bucket;
	const unsigned long size = hashMap->hashTableSize;
	for (unsigned long i = 0; i < size; i++) {
		fprintf(stdout, "%ld:", i);
		j = 0;
		bucket = hashMap->hashTable[i];
		while (bucket) {
			j++;
			bucket = bucket->nextBucket;
		}
		fprintf(stdout, "%ld\n", j);
	}
	fprintf(stdout, "-----------------------------------------------------------\n");
}
#endif // HASHTABLE_DEBUG != 0
