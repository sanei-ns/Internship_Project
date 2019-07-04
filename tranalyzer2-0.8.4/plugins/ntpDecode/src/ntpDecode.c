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

#include "ntpDecode.h"


// Global variables

ntpFlow_t *ntpFlow;


// Static variables

static uint64_t numNTPPkts, numNTPPkts0;


// Tranalyzer functions

T2_PLUGIN_INIT("ntpDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(ntpFlow = calloc(mainHashMap->hashChainTableSize, sizeof(ntpFlow_t))))) {
		T2_PERR("ntpDecode", "failed to allocate memory for ntpFlow");
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("NTP status, warnings and errors", "ntpStat", 0, 1, bt_hex_8));

#if NTP_LIVM_HEX == 1
	bv = bv_append_bv(bv, bv_new_bv("NTP leap indicator, version number and mode", "ntpLiVM", 0, 1, bt_hex_8));
#else // NTP_LIVM_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("NTP leap indicator, version number and mode", "ntpLi_V_M", 0, 3, bt_uint_8, bt_uint_8, bt_uint_8));
#endif // NTP_LIVM_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("NTP stratum", "ntpStrat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("NTP root reference clock ID (stratum >= 2)", "ntpRefClkId", 0, 1, bt_ip4_addr));
	bv = bv_append_bv(bv, bv_new_bv("NTP root reference string (stratum <= 1)", "ntpRefStrId", 0, 1, bt_string_class));

	bv = bv_append_bv(bv, bv_new_bv("NTP poll interval", "ntpPollInt", 0, 1, bt_uint_32));

	bv = bv_append_bv(bv, bv_new_bv("NTP precision", "ntpPrec", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("NTP root delay minimum", "ntpRtDelMin", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("NTP root delay maximum", "ntpRtDelMax", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("NTP root dispersion minimum", "ntpRtDispMin", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("NTP root dispersion maximum", "ntpRtDispMax", 0, 1, bt_float));
#if NTP_TS == 1
	bv = bv_append_bv(bv, bv_new_bv("NTP reference timestamp", "ntpRefTS", 0, 1, bt_timestamp));
	bv = bv_append_bv(bv, bv_new_bv("NTP originate timestamp", "ntpOrigTS", 0, 1, bt_timestamp));
	bv = bv_append_bv(bv, bv_new_bv("NTP receive timestamp", "ntpRecTS", 0, 1, bt_timestamp));
	bv = bv_append_bv(bv, bv_new_bv("NTP transmit timestamp", "ntpTranTS", 0, 1, bt_timestamp));
#endif // NTP_TS == 1

	return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
	ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];
	memset(ntpFlowP, '\0', sizeof(ntpFlow_t));

	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->layer4Protocol != L3_UDP) return;

	const udpHeader_t * const udpH = (udpHeader_t*)packet->layer4Header;
	if (udpH->dest != L3_NTPn) return;

	const uint8_t * const ntpDP = packet->layer7Header;
	const uint32_t * const ntpDP32 = (uint32_t*)(packet->layer7Header + 4);

	ntpFlowP->livm = *ntpDP;
	ntpFlowP->strat = ntpDP[1];
	ntpFlowP->pollInt = ntpDP[2];
	ntpFlowP->prec = ntpDP[3];

	ntpFlowP->rootDelMin = ntpFlowP->rootDelMax = ntohl(*ntpDP32);
	ntpFlowP->rootDispMin = ntpFlowP->rootDispMax = ntohl(ntpDP32[1]);

	ntpFlowP->refClkID = ntpDP32[2];

	ntpFlowP->stat = NTP_DTCT;
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {

	ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];
	if (!ntpFlowP->stat) return;

	numNTPPkts++;

	const uint8_t * const ntpDP = packet->layer7Header;
	const uint32_t * const ntpDP32 = (uint32_t*)(ntpDP+4);

	uint32_t root = ntohl(*ntpDP32);
	if (root > ntpFlowP->rootDelMax) ntpFlowP->rootDelMax = root;
	if (root < ntpFlowP->rootDelMin) ntpFlowP->rootDelMin = root;

	root = ntohl(ntpDP32[1]);
	if (root > ntpFlowP->rootDispMax) ntpFlowP->rootDispMax = root;
	if (root < ntpFlowP->rootDispMin) ntpFlowP->rootDispMin = root;

#if NTP_TS == 1
	const uint64_t * const ntpDP64 = (uint64_t*)(ntpDP+16);
	for (uint_fast8_t j = 0; j < 4; j++) ntpFlowP->tS[j] = ntpDP64[j];
#endif // NTP_TS == 1
}


void onFlowTerminate(unsigned long flowIndex) {
	ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];

	outputBuffer_append(main_output_buffer, (char*) &ntpFlowP->stat, sizeof(uint8_t));
#if NTP_LIVM_HEX == 1
	outputBuffer_append(main_output_buffer, (char*) &ntpFlowP->livm, sizeof(uint8_t));
#else // NTP_LIVM_HEX == 0
	uint8_t tmp = ntpFlowP->livm >> 6; // leap indicator
	outputBuffer_append(main_output_buffer, (char*) &tmp, sizeof(uint8_t));
	tmp = (ntpFlowP->livm & 0x38) >> 3; // version number
	outputBuffer_append(main_output_buffer, (char*) &tmp, sizeof(uint8_t));
	tmp = (ntpFlowP->livm & 0x7); // mode
	outputBuffer_append(main_output_buffer, (char*) &tmp, sizeof(uint8_t));
#endif // NTP_LIVM_HEX == 0
	outputBuffer_append(main_output_buffer, (char*) &ntpFlowP->strat, sizeof(uint8_t));

	char s[5] = {};
	if (ntpFlowP->strat < 2) {
		memcpy(s, &ntpFlowP->refClkID, 4);
		ntpFlowP->refClkID = 0;
	}
	outputBuffer_append(main_output_buffer, (char*) &ntpFlowP->refClkID, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, s, strlen(s)+1);

	uint32_t pollInt = 0;
	uint64_t prec = 0;
	float root_f[5] = {};

	if (ntpFlowP->stat) {
		pollInt = 1 << ntpFlowP->pollInt;
		prec = ~ntpFlowP->prec;
		root_f[0] = 1.0 / (1 << ++prec);
		root_f[1] = (float)(ntpFlowP->rootDelMin  >> 16) + (float)(ntpFlowP->rootDelMin  & 0x0000ffff) / 65535.0;
		root_f[2] = (float)(ntpFlowP->rootDelMax  >> 16) + (float)(ntpFlowP->rootDelMax  & 0x0000ffff) / 65535.0;
		root_f[3] = (float)(ntpFlowP->rootDispMin >> 16) + (float)(ntpFlowP->rootDispMin & 0x0000ffff) / 65535.0;
		root_f[4] = (float)(ntpFlowP->rootDispMax >> 16) + (float)(ntpFlowP->rootDispMax & 0x0000ffff) / 65535.0;
	}
	outputBuffer_append(main_output_buffer, (char*) &pollInt, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &root_f, 5*sizeof(float));

#if NTP_TS == 1
	uint64_t tS, sec[4] = {};
	uint32_t ms[4] = {};
	for (uint_fast8_t j = 0; j < 4; j++) {
		tS = htobe64(ntpFlowP->tS[j]);
		if (tS) {
			sec[j] = ((tS >> 32) - NTPTSHFT);
			ms[j] = 1000000000 * (double)(tS & 0xffffffff) / (double)0xffffffff;
			// make sure the milliseconds get rounded to the nearest value
			ms[j] = 1000 * (ms[j] / 1000.0 + 0.5);
		}
		outputBuffer_append(main_output_buffer, (char*)&sec[j], sizeof(uint64_t));
		outputBuffer_append(main_output_buffer, (char*)&ms[j], sizeof(uint32_t));
	}
#endif // NTP_TS == 1
}


static void ntp_pluginReport(FILE *stream) {
	T2_FPLOG_DIFFNUMP(stream, "ntpDecode", "Number of NTP packets", numNTPPkts, numPackets);
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
	numNTPPkts0 = 0;
#endif // DIFF_REPORT == 1
	ntp_pluginReport(stream);
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("ntpPkts\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t", numNTPPkts - numNTPPkts0); // Note the trailing tab (\t)
			break;

		case T2_MON_PRI_REPORT:
			ntp_pluginReport(stream);
			break;

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	numNTPPkts0 = numNTPPkts;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
	free(ntpFlow);
}
