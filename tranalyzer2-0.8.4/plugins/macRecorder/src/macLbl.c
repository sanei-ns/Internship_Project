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

#include "macLbl.h"
#include "t2log.h"


maclbltable_t* maclbl_init(const char *dir, const char *filename) {
	maclbltable_t *tableP;
	if (UNLIKELY(!(tableP = malloc(sizeof(maclbltable_t))))) {
		T2_PERR("macRecorder", "Failed to allocate memory for maclbltable");
		exit(1);
	}

	FILE *file = t2_open_file(dir, filename, "r");
	if (UNLIKELY(!file)) {
		free(tableP);
		exit(1);
	}

	maclbl_t srec;
	if (UNLIKELY(fread(&srec, sizeof(maclbl_t), 1, file) != 1)) {
		T2_PERR("macRecorder", "Failed to read first record in maclblfile");
		free(tableP);
		fclose(file);
		exit(1);
	}

	tableP->count = (int32_t)srec.mac;

	if (UNLIKELY(!tableP->count)) {
		T2_PERR("macRecorder", "Zero elements in maclblfile");
		free(tableP);
		fclose(file);
		exit(1);
	}

	if (UNLIKELY(!(tableP->maclbls = malloc(sizeof(maclbl_t) * (tableP->count+1))))) {
		T2_PERR("macRecorder", "Failed to allocate memory for table->maclbls");
		free(tableP);
		fclose(file);
		exit(1);
	}

	maclbl_t *maclP = tableP->maclbls;
	maclP[0].who[0] = '-';
	maclP[0].who[1] = '\0';

	for (int_fast32_t i = 1; i <= tableP->count; i++) {
		if (UNLIKELY(fread(&maclP[i], sizeof(maclbl_t), 1, file) != 1)) {
			T2_PERR("macRecorder", "Failed to read record %"PRIdFAST32" from maclblfile", i);
			free(tableP);
			fclose(file);
			exit(1);
		}
	}

	fclose(file);

	return tableP;
}


// this function tests whether a given MAC is a member of a known maclbl
inline uint32_t maclbl_test(maclbltable_t *table, uint64_t mac) {

	if (!(mac && table->count)) return 0;

	int start = 1, i = 0, end = table->count;
	uint64_t k = 0;

	while (start <= end) {
		i = (end + start) / 2;
		k = table->maclbls[i].mac;
		if (mac < k) {
			end = i - 1;    // set the endpoint one under the current middle.
			continue;
		}
		if (mac == k) return i;
		else start = i + 1;     // set the startpoint one over the current middle.
	}

	return 0;
}


void maclbltable_destroy(maclbltable_t *table) {
	if (UNLIKELY(!table)) return;

	free(table->maclbls);
	table->maclbls = NULL;
	free(table);
}
