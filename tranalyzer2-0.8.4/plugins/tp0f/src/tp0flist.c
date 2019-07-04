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
#include "tp0flist.h"

// global definitions


// local functions

static uint32_t tp0flist_load(const char *tp0ffile, tp0flist_table_t *table) {
	char line[MAXLINELN+1];
	uint32_t count = 0, i;
	uint16_t t = 0;

	FILE *tp0flistfile;
	if (UNLIKELY(!(tp0flistfile = fopen(tp0ffile, "r")))) {
		T2_PERR("tp0f", "failed to open file '%s' for reading: %s", tp0ffile, strerror(errno));
		return 0;
	}

	tp0flist_t *tp0fLc = NULL;
	char *tcpoptP, tcpopt[256];

	if (table) tp0fLc = table->tp0flists;

	while (fgets(line, MAXLINELN, tp0flistfile)) {
		// skip comments and empty lines
		if (line[0] == '\n' || line[0] == '#' || line[0] == '%' || line[0] == ' ' || line[0] == '\t') continue;
		if (tp0fLc) {
			sscanf(line, "%"SCNu16"\t%"SCNx8"\t%"SCNx8"\t%"SCNx8"\t%"SCNx8"\t%"SCNx16"\t%"SCNu8"\t%"SCNu8"\t%"SCNu32"\t%"SCNu32",%"SCNu8"\t%"SCNu8"\t%[^\t\n]\t%"SCNu8"\t%"SCNu8"\t%"SCNu8"\t%"SCNu8, &tp0fLc->id, &tp0fLc->clst, &tp0fLc->ipv, &tp0fLc->ipF, &tp0fLc->tcpF, &tp0fLc->qoptF, &tp0fLc->ittl, &tp0fLc->olen, &tp0fLc->mss, &tp0fLc->wsize, &tp0fLc->ws, &tp0fLc->ntcpopt, tcpopt, &tp0fLc->pldl, &tp0fLc->nclass, &tp0fLc->nprog, &tp0fLc->nver);
			if (tp0fLc->ntcpopt) {
				tcpoptP = tcpopt;
				for (i = 0; i < (uint8_t)(tp0fLc->ntcpopt - 1) && i < TCPOPTMAX - 1; i++) {
				//for (i = 0; i < tp0fLc->ntcpopt - 1; i++) {
					sscanf(tcpoptP, "%"SCNx8, &tp0fLc->tcpopt[i]);
					tcpoptP += 5;
				}
				sscanf(tcpoptP, "%"SCNx16, &t);
				tp0fLc->tcpopt[i] = (uint8_t)t;
				tp0fLc->pad = t >> 8;
			}
			tp0fLc++;
		}
		count++;
	}

#if VERBOSE > 0
	if (tp0fLc) T2_PINF("tp0f", "%"PRIu32" rules loaded", count);
#endif // VERBOSE > 0

	fclose(tp0flistfile);

	if (count == 0) T2_PWRN("tp0f", "'%s' is empty", tp0ffile);

	return count;
}


uint32_t tp0flist_init(tp0flist_table_t *table, const char *tp0ffile) {
	table->count = tp0flist_load(tp0ffile, NULL); //return the numbers of lines in the tp0flist file.
	if (table->count == 0) return 0;
	table->tp0flists = calloc(table->count, sizeof(tp0flist_t)); //allocate memory dependent of the numbers of lines in the tp0flist file.
	table->count = tp0flist_load(tp0ffile, table);
	return table->count;
}
