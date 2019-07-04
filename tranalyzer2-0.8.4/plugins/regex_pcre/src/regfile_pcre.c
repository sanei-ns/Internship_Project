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

#include "regfile_pcre.h"

int16_t rex_load(const char *filename, rex_table_t *preg_table) {

	FILE *file;
	if (UNLIKELY(!(file = fopen(filename, "r")))) {
		T2_PERR("regex_pcre", "failed to open file '%s' for reading: %s", filename, strerror(errno));
		preg_table->count = 0;
		return -1;
	}

	uint32_t pcount = 0;

	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	while ((read = getline(&line, &len, file)) != -1) {
		if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;
		pcount++;
	}

	preg_table->count = pcount;

	preg_table->compRex = malloc(pcount * sizeof(pcre*));
#if RULE_OPTIMIZE == 1
	preg_table->studyRex = malloc(pcount * sizeof(pcre_extra*));
#endif

	preg_table->class = malloc(pcount * sizeof(uint16_t));
	preg_table->isstate = malloc(pcount * sizeof(uint16_t));
	preg_table->andMsk = malloc(pcount * sizeof(uint16_t));
	preg_table->andPin = malloc(pcount * sizeof(uint16_t));
	preg_table->offset = malloc(pcount * sizeof(uint16_t));

	preg_table->flags = malloc(pcount * sizeof(uint8_t));
	preg_table->alarmcl = malloc(pcount * sizeof(uint8_t));
	preg_table->severity = malloc(pcount * sizeof(uint8_t));

	uint32_t i;
	for (i = 0; i < HDRSELMX; i++) {
		preg_table->hdrSel[i] = malloc(pcount * sizeof(uint16_t));
	}

	uint8_t flags, alarmcl, hdrSel, severity;
	uint16_t cl, isstate, andMsk, andPin, dir, proto, srcPort, dstPort, offset;
	uint32_t mode;
	int z, erroffset;

	i = 0;
	rewind(file);

	uint32_t lineno = 0;
	while ((read = getline(&line, &len, file)) != -1) {
		lineno++;

		if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;

		z = sscanf(line,
				"%"SCNu16"\t%"SCNu16"\t0x%02"SCNx8"\t"      // ID, preD, Flags
				"0x%04"SCNx16"\t0x%04"SCNx16"\t%"SCNu8"\t"  // andMsk, andPin, ClassID
				"%"SCNu8"\t0x%02"SCNx8"\t0x%04"SCNx16"\t"   // Severity, Sel, Dir
				"%"SCNu16"\t%"SCNu16"\t%"SCNu16"\t"         // Proto, srcPort, dstPort
				"%"SCNu16"\t%[^\n\t]",                      // offset, Regex
				&cl, &isstate, &flags,
				&andMsk, &andPin, &alarmcl,
				&severity, &hdrSel, &dir,
				&proto, &srcPort, &dstPort,
				&offset, &line[0]);
		if (UNLIKELY(z == 0)) {
			T2_PERR("regex_pcre", "Failed to parse record at line %"PRIu32": %s", lineno, line);
			exit(-1);
		}

		mode = ((flags & 0x0f) | REGEX_MODE);

		const char *errPtr = NULL;
		if (!(preg_table->compRex[i] = pcre_compile(line, mode, &errPtr, &erroffset, NULL))) {
#if VERBOSE > 0
			T2_PWRN("regex_pcre", "PCRE ignored - # %u, class %"PRIu16", @ %d: %s", i+1, cl, erroffset, errPtr);
#endif
			continue;
		}

#if RULE_OPTIMIZE == 1
		preg_table->studyRex[i] = pcre_study(preg_table->compRex[i], 0, &errPtr);
		if (errPtr != NULL) {
#if VERBOSE > 0
			T2_PWRN("regex_pcre", "study rule ignored: # %u, @ %"PRIu16": %s", i+1, cl, errPtr);
#endif
			continue;
		}
#endif // RULE_OPTIMIZE == 1

		preg_table->class[i] = cl;
		preg_table->isstate[i] = isstate;
		preg_table->andMsk[i] = andMsk;
		preg_table->andPin[i] = andPin;
		preg_table->hdrSel[0][i] = dir;
		preg_table->hdrSel[1][i] = proto;
		preg_table->hdrSel[2][i] = srcPort;
		preg_table->hdrSel[3][i] = dstPort;
		preg_table->hdrSel[4][i] = hdrSel;
		preg_table->offset[i] = offset;
		preg_table->flags[i] = flags;
		preg_table->alarmcl[i] = alarmcl;
		preg_table->severity[i] = severity;

		i++;
	}

	free(line);
	fclose(file);

	preg_table->count = i;

#if VERBOSE > 0
	T2_PINF("regex_pcre", "%"PRIu32" regexes loaded", i);
#endif

	if (i < pcount) {
#if VERBOSE > 0
		T2_PWRN("regex_pcre", "%"PRIu32" rules have no predecessor", pcount-i);
#endif
		return -2;
	}

	return 0;
}
