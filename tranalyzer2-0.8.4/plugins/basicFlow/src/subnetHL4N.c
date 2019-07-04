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
#include "subnetHL4.h"
#include "global.h"


subnettable4_t* subnet_init4() {

	//struct timeval start, end, elapsed;
	//gettimeofday(&start, NULL);

	subnettable4_t *tableP;
	if (UNLIKELY(!(tableP = malloc(sizeof(subnettable4_t))))) {
		T2_PERR("basicFlow", "Failed to allocate memory for subnettable4");
		exit(1);
	}

	FILE *file = t2_open_file(pluginFolder, SUBNETFILE4, "r");
	if (UNLIKELY(!file)) {
		free(tableP);
		return 0;
	}

	subnet4_t srec;
	fread(&srec, sizeof(subnet4_t), 1, file);
	uint32_t ver = srec.netVec & VERMSK;
	uint8_t rngMd = (srec.netVec & ~VERMSK) >> 31;

#if VERBOSE > 0
	char hrnum[64];
	T2_CONV_NUM(srec.net/2, hrnum);
	T2_PINF("basicFlow", "IPv4 Ver: %"PRIu32", Rev: %"PRIu32", Range Mode: %d, subnet ranges loaded: %"PRIu32"%s", ver, srec.netID, rngMd, srec.net/2, hrnum);
#endif // VERBOSE > 0

	if (ver != SUBVER || rngMd != SUBRNG) {
		T2_PERR("basicFlow", "IPv4 subnetfile does not match plugin configuration Version %d, Range Mode %d. Try ./autogen.sh -f", SUBVER, SUBRNG);
		free(tableP);
		fclose(file);
 		exit(1);
	}

	tableP->count = (int32_t)srec.net;
	tableP->ver = srec.netVec;
	tableP->rev = srec.netID;

	if (UNLIKELY(!tableP->count)) {
		T2_PERR("basicFlow", "Zero elements in subnetfile");
		free(tableP);
		fclose(file);
		exit(1);
	}

	if (UNLIKELY(!(tableP->subnets = malloc(sizeof(subnet4_t) * (tableP->count+1))))) {
		T2_PERR("basicFlow", "Failed to allocate memory for table->subnets");
		free(tableP);
		fclose(file);
		exit(1);
	}

	subnet4_t *subnP = tableP->subnets;
	memset(subnP, 0, sizeof(subnet4_t));
	memcpy(subnP[0].loc, SUBNET_UNK, strlen(SUBNET_UNK));
	memcpy(subnP[0].who, SUBNET_UNK, strlen(SUBNET_UNK));

	if ((int32_t)fread(&subnP[1], sizeof(subnet4_t), tableP->count, file) != tableP->count) {
		T2_PWRN("basicFlow", "File content doesn't match table count: %d", tableP->count);
	};

	fclose(file);

	//gettimeofday(&end, NULL);
	//timersub(&end, &start, &elapsed);
	//printf("%ld  %ld\n", elapsed.tv_sec, elapsed.tv_usec);

	return tableP;
}


// this function tests whether a given IPv4 is a member of a known subnet
inline uint32_t subnet_testHL4(subnettable4_t *table, in_addr_t net) {

	if (!(net && table->count)) return 0;

	int start = 1, i = 0, end = table->count;
	uint32_t j;
	uint32_t k = 0;

	net = ntohl(net);

	while (start <= end) {
		i = (end + start) / 2;
		k = table->subnets[i].net;
		if (net < k) {
			end = i - 1;         // set the endpoint one under the current middle.
			continue;
		}
		if (net == k) return i;
		else start = i + 1;      // set the startpoint one over the current middle.
	}

#if SUBRNG == 1
	j = table->subnets[i].beF;
	if (j) {
		if (net <= k) return i;
	} else {
		if (net == k) return i;
		if (net > k && table->subnets[i].mask < 32) return i;
	}
#else // SUBRNG == 0
	j = table->subnets[i].mask;
	if ((k & j) == (net & j)) return i;
#endif // SUBRNG
	if (i > 0 && (i <= table->count)) {
		i = table->subnets[i].netVec;
		if (i > 0 && (i <= table->count)) return i;
	}

	return 0;
}


void subnettable4_destroy(subnettable4_t *table) {
	if (UNLIKELY(!table)) return;

	free(table->subnets);
	table->subnets = NULL;
	free(table);
}
