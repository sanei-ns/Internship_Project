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

// local includes
#include "subnetHL6.h"
#include "t2log.h"
#ifdef __APPLE__
#include "missing.h" // for htobe64
#endif

#include <string.h>


subnettable6_t* subnet_init6(const char *dir, const char *filename) {

	subnettable6_t *tableP;
	if (UNLIKELY(!(tableP = malloc(sizeof(*tableP))))) {
		T2_PERR("basicFlow", "Failed to allocate memory for subnettable6");
		exit(1);
	}

	FILE *file = t2_open_file(dir, filename, "r");
	if (UNLIKELY(!file)) {
		free(tableP);
		return NULL;
	}

	subnet6_t srec;
	if (UNLIKELY(fread(&srec, sizeof(srec), 1, file) != 1)) {
		T2_PERR("basicFlow", "Failed to read first record in %s", SUBNETFILE6);
		free(tableP);
		fclose(file);
		return NULL;
	}

	const uint32_t ver = srec.net.IPv4x[1] & VERMSK;
	const uint8_t rngMd = (srec.net.IPv4x[1] & ~VERMSK) >> 31;

#if VERBOSE > 0
	char hrnum[64];
	T2_CONV_NUM(srec.net.IPv4x[0]/2, hrnum);
	T2_PINF("basicFlow", "IPv6 Ver: %"PRIu32", Rev: %"PRIu32", Range Mode: %d, subnet ranges loaded: %"PRIu32"%s",
			ver, srec.net.IPv4x[2], rngMd, srec.net.IPv4x[0]/2, hrnum);
#endif // VERBOSE > 0

	if (ver != SUBVER || rngMd != SUBRNG) {
		T2_PERR("basicFlow", "IPv6 subnet file does not match plugin configuration (version %d, range mode %d)", SUBVER, SUBRNG);
		T2_PINF("basicFlow", "Try rebuilding the plugin with ./autogen.sh -f");
		free(tableP);
		fclose(file);
		exit(1);
	}

	tableP->count = (int32_t)srec.net.IPv4x[0];
	tableP->ver = srec.net.IPv4x[1];
	tableP->rev = srec.net.IPv4x[2];

	if (UNLIKELY(!tableP->count)) {
		T2_PERR("basicFlow", "Zero elements in subnetfile");
		free(tableP);
		fclose(file);
		exit(1);
	}

	if (UNLIKELY(!(tableP->subnets = malloc(sizeof(subnet6_t) * (tableP->count+1))))) {
		T2_PERR("basicFlow", "Failed to allocate memory for table->subnets");
		free(tableP);
		fclose(file);
		exit(1);
	}

	subnet6_t *subnP = tableP->subnets;
	memset(subnP, 0, sizeof(subnet6_t));
	memcpy(subnP[0].loc, SUBNET_UNK, strlen(SUBNET_UNK));
	memcpy(subnP[0].who, SUBNET_UNK, strlen(SUBNET_UNK));

	const size_t nrec = fread(&subnP[1], sizeof(subnet6_t), tableP->count, file);
	if (UNLIKELY((int32_t)nrec != tableP->count)) {
		T2_PWRN("basicFlow", "Expected %"PRId32" records in %s, only read %zu", tableP->count, SUBNETFILE6, nrec);
	}

	fclose(file);

	return tableP;
}


// this function tests whether a given IPv6 is a member of a known subnet
inline uint32_t subnet_testHL6(subnettable6_t *table, ipAddr_t net6) {

	if (!(net6.IPv6L[0] && table->count)) return 0;

	int start = 1, i = 0, end = table->count;
	ipAddr_t k = {};

	ipAddr_t net;
	net.IPv6L[0] = htobe64(net6.IPv6L[0]);
	net.IPv6L[1] = htobe64(net6.IPv6L[1]);

	while (start <= end) {
		i = (end + start) / 2;
		k = table->subnets[i].net;

		if (net.IPv6L[0] < k.IPv6L[0]) {
			end = i - 1;  // set the endpoint one under the current middle.
			continue;
		}

		if (net.IPv6L[0] == k.IPv6L[0]) {
			if (net.IPv6L[1] == k.IPv6L[1]) {
				return i;
			} else if (net.IPv6L[1] < k.IPv6L[1]) {
				end = i - 1;
				continue;
			}
		}

		start = i + 1;  // set the startpoint one over the current middle.
	}

#if SUBRNG == 1
	if (table->subnets[i].beF) {
		if (net.IPv6L[0] < k.IPv6L[0]) return i;

		if (net.IPv6L[0] == k.IPv6L[0] && net.IPv6L[1] <= k.IPv6L[1]) return i;
	} else {
		const uint8_t mask = table->subnets[i].mask;

		if (net.IPv6L[0] > k.IPv6L[0] && mask < 32) return i;

		if (net.IPv6L[0] == k.IPv6L[0]) {
			 if (net.IPv6L[1] == k.IPv6L[1]) return i;
			 if (net.IPv6L[1] > k.IPv6L[1] && mask < 32) return i;
		}
	}
#else // SUBRNG == 0
	const ipAddr_t mask = table->subnets[i].mask;
	if ((k.IPv6L[0] & mask.IPv6L[0]) == (net.IPv6L[0] & mask.IPv6L[0]) &&
	    (k.IPv6L[1] & mask.IPv6L[1]) == (net.IPv6L[1] & mask.IPv6L[1]))
	{
		return i;
	}
#endif // SUBRNG

	if (i > 0 && i <= table->count) {
		i = table->subnets[i].netVec;
		if (i > 0 && i <= table->count) return i;
	}

	return 0;
}


void subnettable6_destroy(subnettable6_t *table) {
	if (UNLIKELY(!table)) return;

	free(table->subnets);
	table->subnets = NULL;
	free(table);
}
