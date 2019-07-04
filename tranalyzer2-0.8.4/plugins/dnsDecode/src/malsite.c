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

// local include
#include "malsite.h"
#include "t2utils.h"

// local functions

// returns the number of subnets and file table, if given
static inline uint32_t malsite_load(const char *filename, malsite_t *malsites) {
	if (UNLIKELY(!filename)) return 0;

	FILE *file = fopen(filename, "r");
	if (UNLIKELY(!file)) {
		T2_PERR("dnsDecode", "failed to open file '%s' for reading: %s", filename, strerror(errno));
		exit(1);
	}

#if MAL_DOMAIN == 1
	char domain[DMMXLN+1] = {};
	size_t len;
#else // MAL_DOMAIN == 0
	ipAddr_t ip = {};
#endif // MAL_DOMAIN

	uint32_t count = 1, id;
	char line[LNMXLN+1], malTyp[MTMXLN+1] = {};

	while (fgets(line, LNMXLN, file)) {
		// Skip comments and empty lines
		if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;
		if (malsites) {
#if MAL_DOMAIN == 1
			sscanf(line, "%"SNUM(DMMXLN)"[^\t]\t%"SCNu32"\t%"SNUM(MTMXLN)"[^\t\n]", domain, &id, malTyp);
			len = strlen(domain);
			malsites[count].len = len;
			memcpy(malsites[count].malDomain, domain, len+1);
			memcpy(malsites[count].malTyp, malTyp, strlen(malTyp)+1);
#else // MAL_DOMAIN == 0
			sscanf(line, "%x\t%x\n", &ip.IPv4x[0], &id);
			malsites[count].malIp = ip;
#endif // MAL_DOMAIN
			malsites[count].malId = id;
		}
		count++;
	}

	if (malsites) {
#if MAL_DOMAIN == 1
		T2_PINF("dnsDecode", "%"PRIu32" blacklisted domains", count);
#else // MAL_DOMAIN == 0
		T2_PINF("dnsDecode", "%"PRIu32" blacklisted IPs", count);
#endif // MAL_DOMAIN
	}

	fclose(file);

	return count;
}


inline malsitetable_t *malsite_init() {
	const size_t len = pluginFolder_len + sizeof(TMALFILE) + 1;
	if (UNLIKELY(len >= MAX_FILENAME_LEN)) {
		T2_PERR("dnsDecode", "Filename to malsite file is too long");
		exit(1);
	}

	char filename[len];
	strncpy(filename, pluginFolder, pluginFolder_len+1);
	strcat(filename, TMALFILE);

	malsitetable_t *table;
	if (UNLIKELY(!(table = malloc(sizeof(*table))))) {
		T2_PERR("dnsDecode", "Failed to allocate memory for malsitetable");
		exit(1);
	}

	table->count = malsite_load(filename, NULL); // return the numbers of lines in the malsite file.
	if (table->count == 0) {
		T2_PWRN("dnsDecode", "No valid entries in '%s'", filename);
		table->malsites = NULL;
		return table;
	}

	table->malsites = malloc((table->count + 1) * sizeof(malsite_t));
	table->count = malsite_load(filename, table->malsites);

	return table;
}


inline void malsite_destroy(malsitetable_t *table) {
	if (UNLIKELY(!table)) return;

	if (LIKELY(table->malsites != NULL)) {
		free(table->malsites);
		table->malsites = NULL;
	}

	free(table);
}


#if MAL_DOMAIN == 1

// this function tests whether a given domain name is a malware host defined in the config file
inline uint32_t maldomain_test(malsitetable_t *table, const char *dname) {
	if (!dname || *dname == '\0') return 0;

	int middle, i;
	int start = 1;
	int end = table->count;
	const malsite_t * const malsiteP = table->malsites;

	while (start <= end) {
		middle = (end + start) / 2;
		i = strcmp(dname, malsiteP[middle].malDomain);
		if (i == 0) {
			return middle; // return the located malsite codes.
		} else if (i < 0) {
			end = middle - 1; // set the endpoint one under the currently middle.
		} else {
			start = middle + 1; // set the startpoint one over the currently middle.
		}
	}

	return 0; // in case the ip isn't in the file, return 0.
}

#else // MAL_DOMAIN == 0

// this function tests whether a given IP is a malware IP defined in the config file
inline uint32_t malip_test(malsitetable_t *table, ipAddr_t ip) {
	if (!ip.IPv6L[0] || !ip.IPv6L[1]) return 0;

	uint32_t i;
	ip.IPv4x[0] = ntohl(ip.IPv4x[0]);

	int middle;
	int start = 0;
	int end = table->count - 1;
	const malsite_t * const malsiteP = table->malsites;

	while (start <= end) {
		middle = (end + start) / 2; // define middle as middle between start and end.
		i = (uint32_t) malsiteP[middle].malIp.IPv4x[0];
		if (ip.IPv4x[0] == i) {
			return middle; // return the located malsite codes.
		} else if (ip.IPv4x[0] < i) {
			end = middle - 1; // set the endpoint one under the currently middle.
		} else {
			start = middle + 1; // set the startpoint one over the currently middle.
		}
	}

	return 0; // in case the ip isn't in the file, return 0.
}
#endif // MAL_DOMAIN
