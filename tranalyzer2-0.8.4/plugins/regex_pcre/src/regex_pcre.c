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

#include "regex_pcre.h"

#if LABELSCANS == 1
#include "tcpFlags.h"


// Variables from dependencies

extern tcpFlagsFlow_t *tcpFlagsFlows __attribute__((weak));
#endif // LABELSCANS


// Static variables

static rex_table_t *rex_tableP;
static uint64_t pcreAlarms;


// Tranalyzer functions

T2_PLUGIN_INIT("regex_pcre", "0.8.4", 0, 8);


#if LABELSCANS == 1
char* get_dependencies() {
	return "tcpFlags";
}
#endif // LABELSCANS


void initialize() {

	rexFlowTable = malloc(mainHashMap->hashChainTableSize * sizeof(rexFlow_t));
	if (UNLIKELY(!rexFlowTable)) {
		T2_PERR("regex_pcre", "failed to allocate memory for rexFlowTable");
		exit(1);
	}

	char filename[pluginFolder_len + sizeof(REXPOSIX_FILE) + 1];
	strncpy(filename, pluginFolder, pluginFolder_len+1);
	strcat(filename, REXPOSIX_FILE);

	rex_tableP = malloc(sizeof(rex_table_t));
	if (rex_load(filename, rex_tableP)) {
		free(rexFlowTable);
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("Regexp match count", "RgxCnt", 0, 1, bt_uint_16));
#if EXPERTMODE == 1
#if PKTTIME == 1
	bv = bv_append_bv(bv, bv_new_bv("Regexp: time, packet, byte position, regfile ID, AND mask, flags, classtype, severity match", "RgxT_N_B_RID_Amsk_F_CT_Sv", 1, 8, bt_timestamp, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_hex_8, bt_uint_8, bt_uint_8));
#else // PKTTIME == 0
	bv = bv_append_bv(bv, bv_new_bv("Regexp: packet, byte position, regfile ID, AND mask, flags, classtype, severity match", "RgxN_B_RID_Amsk_F_CT_Sv", 1, 7, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_hex_8, bt_uint_8, bt_uint_8));
#endif // PKTTIME
#else // EXPERTMODE == 0
	bv = bv_append_bv(bv, bv_new_bv("Regexp classtype ", "RgxClTyp", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("Regexp severity ", "RgxSev", 0, 1, bt_uint_8));
#endif // EXPERTMODE
//	bv = bv_append_bv(bv, bv_new_bv("Regexp classtype_severity ", "Rgx_ClTyp_sev", 0, 2, bt_uint_8, bt_uint_8));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	rexFlow_t * const rexFlowP = &(rexFlowTable[flowIndex]);
	memset(rexFlowP, '\0', sizeof(rexFlow_t));
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	rexFlow_t * const rexFlowP = &(rexFlowTable[flowIndex]);

	unsigned int count = rexFlowP->count;
	if (count >= MAXREGPOS) return;

	uint16_t length = packet->snapL7Length;
	if (PACKET_IS_IPV6(packet)) {
		if (length < 40) return;
	} else {
		if (length < 20) return;
	}

	rexFlowP->pktN++;

	const flow_t * const flowP = &flows[flowIndex];
	const uint16_t hdrSel[4] = {
		(uint16_t)(flowP->status & L3FLOWINVERT),
		flowP->layer4Protocol,
		flowP->srcPort,
		flowP->dstPort,
	};

	// match all loaded patterns
	uint_fast32_t i;
	unsigned int j, k, l;
	char *regstart = (char*)packet->layer7Header;
	for (i = 0; i < rex_tableP->count; i++) {
		k = 0x08;
		l = rex_tableP->hdrSel[4][i];
		for (j = 0; j <= 3; j++) {
			if ((l & k) && (hdrSel[j] != rex_tableP->hdrSel[j][i])) goto nxtrex;
			k >>= 1;
		}

		switch (l & 0xf0) {
			case 0x80:
				regstart = (char*)packet->layer7Header + rex_tableP->offset[i];
				length = packet->snapL7Length - rex_tableP->offset[i];
				break;
			case 0x40:
				regstart = (char*)packet->layer4Header + rex_tableP->offset[i];
				length = packet->snapL4Length - rex_tableP->offset[i];
				break;
			case 0x20:
				regstart = (char*)packet->layer3Header + rex_tableP->offset[i];
				length = packet->snapL3Length - rex_tableP->offset[i];
				break;
			case 0x10:
				regstart = (char*)packet->layer2Header + rex_tableP->offset[i];
				length = packet->snapL2Length - rex_tableP->offset[i];
				break;
		}

		int ovector[OVECCOUNT];
#if RULE_OPTIMIZE == 1
		pcre_extra *extra = rex_tableP->studyRex[i];
#else // RULE_OPTIMIZE == 0
		pcre_extra *extra = NULL;
#endif // RULE_OPTIMIZE
		if (pcre_exec(rex_tableP->compRex[i], extra, regstart, length, 0, 0, ovector, OVECCOUNT) < 0) continue;
		if (ovector[1] <= ovector[0]) continue;

		const unsigned int isstate = rex_tableP->isstate[i];
		if (isstate) {
			j = 0;
			for (l = 0; l < count; l++) {
				if (rexFlowP->pregID[l] == isstate) {
					j |= rexFlowP->andPin[l];
					if (j != rex_tableP->andPin[i]) continue;
					rexFlowP->flags[l] |= REG_F_PRE;
					goto predfound;
				}
			}
			continue;
		}

predfound:
		l = count;

#if EXPERTMODE == 1
#if PKTTIME == 1
		rexFlowP->time[l] = flowP->lastSeen;
#endif
		rexFlowP->andMsk[l] = rex_tableP->andMsk[i];
		rexFlowP->andPin[l] = rex_tableP->andPin[i];
		rexFlowP->pregPos[l] = ovector[0];
		rexFlowP->pkt[l] = rexFlowP->pktN;
#endif // EXPERTMODE == 1
		rexFlowP->flags[l] |= rex_tableP->flags[i];
		rexFlowP->pregID[l] = rex_tableP->class[i];
		rexFlowP->alarmcl[l] = rex_tableP->alarmcl[i];
		rexFlowP->severity[l] = rex_tableP->severity[i];

		if (++count >= MAXREGPOS) break;

nxtrex:
		continue;
	}

	rexFlowP->count = count;
}


void onFlowTerminate(unsigned long flowIndex) {
	rexFlow_t * const rexFlowP = &(rexFlowTable[flowIndex]);

	uint16_t rgxCnt = rexFlowP->count;

#if LABELSCANS == 1
	const tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

	bool is_scan = (tcpFlagsP->tcpFlagsT == 0x02 ||  (tcpFlagsP->tcpAnomaly & SCANMASK) ||
	                tcpFlagsP->tcpFlagsT == 0x06 || !(tcpFlagsP->tcpAnomaly & TCPRETRIES));
	if (is_scan) {
		uint8_t label = 0;
		const uint64_t ofidx = flows[flowIndex].oppositeFlowIndex;
		if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
			const rexFlow_t * const rexFlowPO = &rexFlowTable[ofidx];
			is_scan = (rexFlowP->pktN < 3 && rexFlowPO->pktN < 2);
			if (is_scan) label = 102; // response to scan
		} else {
			is_scan = (rexFlowP->pktN < 2);
			if (is_scan) label = 101; // no response to scan
		}

		if (is_scan) {
			rexFlowP->alarmcl[rgxCnt] = label;
			rexFlowP->severity[rgxCnt] = 1;
			rgxCnt++;
		}
	}
#endif // LABELSCANS == 1

	uint_fast32_t i;

	uint32_t alarms = 0;
	for (i = 0; i < rgxCnt; i++) {
		if (rexFlowP->flags[i] & REG_F_ALRM) alarms++;
	}

	pcreAlarms += alarms;
	T2_REPORT_ALARMS(alarms);

	outputBuffer_append(main_output_buffer, (char*) &rgxCnt, sizeof(uint16_t));

#if EXPERTMODE == 0
	uint32_t w = 0;
	uint32_t sevmax = rexFlowP->severity[0];
	for (i = 0; i < rgxCnt; i++) {
		if (rexFlowP->severity[i] > sevmax) {
			sevmax = rexFlowP->severity[i];
			w = i;
		}
	}
	outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->alarmcl[w]), sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->severity[w]), sizeof(uint8_t));
	return;
#else // EXPERTMODE == 1
	outputBuffer_append(main_output_buffer, (char*) &alarms, sizeof(uint32_t));
	for (i = 0; i < rgxCnt; i++) {
		if (rexFlowP->flags[i] & REG_F_ALRM) {
#if PKTTIME == 1
			const uint64_t secs = rexFlowP->time[i].tv_sec;
			outputBuffer_append(main_output_buffer, (char*) &secs, sizeof(uint64_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->time[i].tv_usec), sizeof(uint32_t));
#endif
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->pkt[i]), sizeof(uint16_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->pregPos[i]), sizeof(uint16_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->pregID[i]), sizeof(uint16_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->andMsk[i]), sizeof(uint16_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->flags[i]), sizeof(uint8_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->alarmcl[i]), sizeof(uint8_t));
			outputBuffer_append(main_output_buffer, (char*) &(rexFlowP->severity[i]), sizeof(uint8_t));
		}
	}
#endif // EXPERTMODE == 1
}


void pluginReport(FILE *stream) {
	T2_FPLOG_NUM(stream, "regex_pcre", "Number of alarms", pcreAlarms);
}


void onApplicationTerminate() {
	free(rexFlowTable);

	if (UNLIKELY(!rex_tableP)) return;

	free(rex_tableP->class);
	free(rex_tableP->andMsk);
	free(rex_tableP->andPin);
	free(rex_tableP->isstate);
	free(rex_tableP->flags);
	free(rex_tableP->alarmcl);
	free(rex_tableP->severity);
	free(rex_tableP->offset);

	uint_fast32_t i;
	for (i = 0; i < rex_tableP->count; i++) {
		pcre_free(rex_tableP->compRex[i]);
#if RULE_OPTIMIZE == 1
		pcre_free_study(rex_tableP->studyRex[i]);
#endif
	}

	free(rex_tableP->compRex);
#if RULE_OPTIMIZE == 1
	free(rex_tableP->studyRex);
#endif

	for (i = 0; i < HDRSELMX; i++) {
		free(rex_tableP->hdrSel[i]);
	}

	free(rex_tableP);
}
