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

//TODO: L7Range checks

#include "syslogDecode.h"


// Global variables

syslogFlow_t *syslogFlow;


// Static variables

static uint64_t numSyslogPkt;
static uint64_t numSysMsgCnt;

//static FILE *syslogFP;

// the human readable form for the severity
//static char *sevArr[8] = {
//	"Emergency", "Alert" , "Critical"     , "Error",
//	"Warning"  , "Notice", "Informational", "Debug"
//};

// the human readable form for the facility
// severity + facility = criticality
//static char *facArr[24] = {
//	"Kernel", "User", "Mail", "System", "Security",
//	"Intern", "Printer", "Network", "UUCP", "Clock",
//	"Authpriv", "FTP", "NTP", "LogAudit", "LogAlert",
//	"ClockDaemon", "Local0", "Local1", "Local2", "Local3",
//	"Local4", "Local5", "Local6", "Local7"
//};

// the human readable form in order to display the 3 letter month
//static char *MonArr[12] = {
//	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
//	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
//};


// Tranalyzer functions

T2_PLUGIN_INIT("syslogDecode", "0.8.4", 0, 8);


void initialize() {

	if (UNLIKELY(!(syslogFlow = calloc(mainHashMap->hashChainTableSize, sizeof(syslogFlow_t))))) {
		T2_PERR(ERROR_PREFIX, "Failed to allocate memory for syslogFlow");
		exit(-1);
	}

	/*if (sPktFile) {
		fputs("syslogStat\tsyslogSev\tsyslogFac\tsyslogMonth_day\tsyslogTime\tsyslogHostname\tsyslogProgram\tsyslogMsgt\t", sPktFile);
	}*/
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("Syslog status", "syslogStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("Syslog message count", "syslogMCnt", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("Number of Syslog severity/facility messages", "syslogSev_Fac_Cnt", 1, 3, bt_uint_8, bt_uint_8, bt_uint_16));
	return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];
	memset(sysFlowP, '\0', sizeof(syslogFlow_t));
	if (flows[flowIndex].dstPort != 514) return;
	sysFlowP->stat |= SYS_DET;
}


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];
	if (!sysFlowP->stat) return;

	const unsigned char * const l7P = (unsigned char*)packet->layer7Header;
	const uint32_t plen = packet->snapL7Length;
	if (plen < 10) return;

	char *p = memchr(l7P, '<', 2);
	if (p == NULL) {
		sysFlowP->stat = 0x00;
		return;
	}

	uint32_t i = atoi(++p);
	const uint8_t sev = i & 0x07;
	const uint8_t fac = i >> 3;
	//plen -= (p - l7P);

	if (sev >= SYS_NUM_SEV || fac >= SYS_NUM_FAC) {
		sysFlowP->stat = 0x00;
		return;
	}

	if (sysFlowP->cnt[sev][fac] < UINT16_MAX) {
		if (sysFlowP->cnt[sev][fac]++ == 0) sysFlowP->sum++;
	} else sysFlowP->stat |= SYS_CNTOVRN;

	p = memchr(p, '>', 4);
	if (p == NULL) {
		sysFlowP->stat = 0x00;
		return;
	}

	i = atoi(++p);
	if (i) {
		p = memchr(p, ' ', 12);
		if (!p) {
			sysFlowP->stat = 0x00;
			return;
		}
	}

	char *pe = p + 14;

	pe = memchr(pe, ' ', 6);
	if (pe == NULL) {
		sysFlowP->stat = 0x00;
		return;
	}

	numSyslogPkt++;
}


void onFlowTerminate(unsigned long flowIndex) {
	syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];

	if (sysFlowP->stat == 0x00) sysFlowP->sum = 0;
	numSysMsgCnt += sysFlowP->sum;

	// syslogStat
	outputBuffer_append(main_output_buffer, (char*) &sysFlowP->stat, sizeof(uint8_t));

	// syslogMCnt
	outputBuffer_append(main_output_buffer, (char*) &sysFlowP->sum, sizeof(uint32_t));

	// syslogSev_Fac_Cnt
	outputBuffer_append(main_output_buffer, (char*) &sysFlowP->sum, sizeof(uint32_t));
	if (sysFlowP->sum) {
		uint8_t i, j;
		for (i = 0 ; i < SYS_NUM_SEV; i++) {
			for (j = 0 ; j < SYS_NUM_FAC; j++) {
				if (sysFlowP->cnt[i][j]) {
					outputBuffer_append(main_output_buffer, (char*) &i, sizeof(uint8_t));
					outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint8_t));
					outputBuffer_append(main_output_buffer, (char*) &sysFlowP->cnt[i][j], sizeof(uint16_t));
				}
			}
		}
	}
}


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "syslogDecode", "Number of Syslog packets", numSyslogPkt, numPackets);
	T2_FPLOG_NUM(stream, "syslogDecode", "Number of Syslog message types", numSysMsgCnt);
}


void onApplicationTerminate() {
	free(syslogFlow);
}
