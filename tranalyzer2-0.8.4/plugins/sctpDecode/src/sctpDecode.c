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

#include "sctpDecode.h"

#if (SCTP_ADL32CHK == 1 || SCTP_CRC32CHK == 1)
#include "chksum.h"
#endif // (SCTP_ADL32CHK == 1 || SCTP_CRC32CHK == 1)


// Global variables

sctpFlow_t *sctpFlow;


// Static variables

static uint16_t sctpTypeBFA;
static uint8_t sctpStatA;

#if (SCTP_CHNKVAL == 1 && SCTP_CHNKSTR == 1)
static const char *sctpChunkTypeSTr[] = {
	/*  0 */ "DATA",              // Payload data
	/*  1 */ "INIT",              // Initiation
	/*  2 */ "INIT-ACK",          // Initiation acknowledgement
	/*  3 */ "SACK",              // Selective acknowledgement
	/*  4 */ "HEARTBEAT",         // Heartbeat request
	/*  5 */ "HEARTBEAT-ACK",     // Heartbeat acknowledgement
	/*  6 */ "ABORT",             // Abort
	/*  7 */ "SHUTDOWN",          // Shutdown
	/*  8 */ "SHUTDOWN-ACK",      // Shutdown acknowledgement
	/*  9 */ "ERROR",             // Operation error
	/* 10 */ "COOKIE-ECHO",       // State cookie
	/* 11 */ "COOKIE-ACK",        // Cookie acknowledgement
	/* 12 */ "ECNE",              // Explicit congestion notification echo (reserved)
	/* 13 */ "CWR",               // Congestion window reduced (reserved)
	/* 14 */ "SHUTDOWN-COMPLETE", // Shutdown complete
};
#endif // (SCTP_CHNKVAL == 1 && SCTP_CHNKSTR == 1)


#define SCTP_SPKTMD_PRI_NONE() \
	if (sPktFile) { \
		fputs("\t\t\t\t", sPktFile); \
	}


// Tranalyzer functions

T2_PLUGIN_INIT("sctpDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(sctpFlow = calloc(mainHashMap->hashChainTableSize, sizeof(sctpFlow_t))))) {
		T2_PERR("sctpDecode", "Failed to allocate memory for sctpFlow");
		exit(-1);
	}

#if SCTP_CRC32CHK == 1
	//crc32_init();
#endif // SCTP_CRC32CHK == 1

	if (sPktFile) {
		fputs("sctpVerifTag\tsctpChunkType_Sid_Flags_Len\tsctpNChunks\tsctpStat\t", sPktFile);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("SCTP status", "sctpStat", 0, 1, bt_hex_8));
#if SCTP_ACTIVATE == 1
	bv = bv_append_bv(bv, bv_new_bv("SCTP Data stream number", "sctpDSNum", 0, 1, bt_uint_16));
#else // SCTP_ACTIVATE == 0
	bv = bv_append_bv(bv, bv_new_bv("SCTP max # of data streams", "sctpMaxDSNum", 0, 1, bt_uint_16));
#endif // SCTP_ACTIVATE
	bv = bv_append_bv(bv, bv_new_bv("SCTP Payload ID", "sctpPID", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("SCTP verification tag", "sctpVTag", 0, 1, bt_hex_32));
#if SCTP_CHNKVAL == 0
	bv = bv_append_bv(bv, bv_new_bv("SCTP aggregated type bit field", "sctpTypeBF", 0, 1, bt_hex_16));
#else // SCTP_CHNKVAL == 1
#if SCTP_CHNKSTR == 0
	bv = bv_append_bv(bv, bv_new_bv("SCTP uniq types values", "sctpType", 1, 1, bt_uint_8));
#else // SCTP_CHNKSTR == 1
	bv = bv_append_bv(bv, bv_new_bv("SCTP uniq types name", "sctpTypeN", 1, 1, bt_string_class));
#endif // SCTP_CHNKSTR
#endif // SCTP_CHNKVAL
	bv = bv_append_bv(bv, bv_new_bv("SCTP Data_Init_Abort count", "sctpCntD_I_A", 0, 3, bt_uint_16, bt_uint_16, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("SCTP aggregated chunk flags", "sctpCFlgs", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("SCTP aggregated error cause code bit field", "sctpCCBF", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("SCTP inbound streams", "sctpIS", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("SCTP outbound streams", "sctpOS", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("SCTP Initial Advertised Receiver Window", "sctpIARW", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("SCTP Initial Advertised Receiver Window Minimum", "sctpIARWMin", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("SCTP Initial Advertised Receiver Window Maximum", "sctpIARWiMax", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("SCTP Advertised Receiver Window", "sctpARW", 0, 1, bt_float));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	sctpFlow_t *sctpFlowP = &sctpFlow[flowIndex];
	memset(sctpFlowP, '\0', sizeof(sctpFlow_t));
	sctpFlowP->ct3_arwcMin = UINT32_MAX;
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	SCTP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	if (packet->layer4Type != L3_SCTP) {
		SCTP_SPKTMD_PRI_NONE();
		return;
	}

	// only 1. frag packet will be processed 4 now
	if (!t2_is_first_fragment(packet)) {
		SCTP_SPKTMD_PRI_NONE();
		return;
	}

	uint_fast16_t l3Len;
	if (PACKET_IS_IPV6(packet)) {
		const ip6Header_t * const ip6Header = (ip6Header_t*)packet->layer3Header;
		l3Len = ntohs(ip6Header->payload_len) + 40;
	} else {
		const ipHeader_t *ipHeaderP = (ipHeader_t*)packet->layer3Header;
		l3Len = ntohs(ipHeaderP->ip_len);
	}

	sctpFlow_t * const sctpFlowP = &sctpFlow[flowIndex];

	const sctpHeader_t * const sctpHdrP = (sctpHeader_t*)packet->layer4Header;
	sctpChunk_t *sctpChunkP = NULL;

#if SCTP_ACTIVATE == 1
	uint8_t *sctpL7P = (uint8_t*)packet->layer7SCTPHeader;
	int32_t sctpL7Len = packet->snapSCTPL7Length;
#else // SCTP_ACTIVATE == 0
	uint8_t *sctpL7P = (uint8_t*)packet->layer7Header;
	int32_t sctpL7Len = packet->snapL7Length;
#endif // SCTP_ACTIVATE

	sctpFlowP->verTag = ntohl(sctpHdrP->verTag);

	if (sPktFile) {
		fprintf(sPktFile, "0x%08"B2T_PRIX32"\t", sctpFlowP->verTag);
	}

	if (sctpL7Len < 4) {
		if (sPktFile) fputs("\t\t\t", sPktFile);
		return;
	}

	uint32_t i;
	if (packet->snapL3Length < l3Len) {
		sctpFlowP->stat |= (SCTP_C_CRCERR | SCTP_C_ADLERR);
	} else {
#if SCTP_CRC32CHK == 1
		i = sctp_crc32c((uint8_t*)packet->layer4Header, packet->snapL4Length);
		if (sctpHdrP->chkSum != i) sctpFlowP->stat |= SCTP_C_CRCERR;
#endif // SCTP_CRC32CHK == 1
#if SCTP_ADL32CHK == 1
		i = sctp_adler32((uint8_t*)packet->layer4Header, packet->snapL4Length);
		if (sctpHdrP->chkSum != i) sctpFlowP->stat |= SCTP_C_ADLERR;
#endif // SCTP_ADL32CHK == 1
	}

	uint8_t nChnks = 0;
	uint8_t chnkType;
	uint16_t sid;
	int32_t sctpChnkLen;
	while (sctpL7Len > 3) {
		nChnks++;
		sctpChunkP = (sctpChunk_t*)sctpL7P;
		sctpChnkLen = ntohs(sctpChunkP->len);
		if (sctpChnkLen == 0) break;
		if (sctpL7Len < sctpChnkLen) sctpFlowP->stat |= SCTP_C_TRNC;
		chnkType = sctpChunkP->type & SCTP_C_TYPE;
#if SCTP_CHNKVAL == 0
		sctpFlowP->typeBF |= (1 << chnkType);
#else // SCTP_CHNKVAL == 1
		if (sctpFlowP->numTypeS < SCTP_MAXCTYPE) {
			for (i = 0; i < sctpFlowP->numTypeS; i++) {
				if (sctpFlowP->cTypeS[i] == chnkType) goto chktfnd;
			}
			sctpFlowP->cTypeS[sctpFlowP->numTypeS++] = chnkType;
		} else sctpFlowP->stat |= SCTP_C_TPVFL;
chktfnd:
#endif // SCTP_CHNKVAL
		sctpFlowP->stat |= chnkType & SCTP_C_TACT;
		sctpFlowP->cflags |= sctpChunkP->flags;
		sid = 0;

		switch (chnkType) {
			case SCTP_CT_DATA:
				sctpFlowP->ct0_dataCnt++;
				sctpFlowP->ct0_ppi = ntohl(sctpChunkP->ppi);
				sid = ntohs(sctpChunkP->sis);
				if (sid > sctpFlowP->ct0_sid) sctpFlowP->ct0_sid = sid;
				break;
			case SCTP_CT_INIT:
				sctpFlowP->ct1_initCnt++;
				/* FALLTHRU */
			case SCTP_CT_INIT_ACK:
				sctpFlowP->ct1_2_nos_nis = sctpChunkP->ppi;
				i = ntohl(sctpChunkP->arwc);
				sctpFlowP->ct1_2_3_arwc = sctpFlowP->ct1_2_3_arwcI = i;
				goto mm;
			case SCTP_CT_SACK:
				i = ntohl(sctpChunkP->arwc);
				sctpFlowP->ct1_2_3_arwc = 0.7 * sctpFlowP->ct1_2_3_arwc + 0.3 * (float)i;
			mm:	if (i < sctpFlowP->ct3_arwcMin) sctpFlowP->ct3_arwcMin = i;
				if (i > sctpFlowP->ct3_arwcMax) sctpFlowP->ct3_arwcMax = i;
				break;
			case SCTP_CT_ABORT:
				sctpFlowP->ct6_abrtCnt++;
				break;
			case SCTP_CT_ERROR:
				sctpFlowP->ct9_cc = (1 << ntohs(sctpChunkP->cc));
				break;
			default:
				break;
		}

		sctpL7P += sctpChnkLen;
		sctpL7Len -= sctpChnkLen;

		if (sPktFile) {
			if (nChnks > 1) fputc(';', sPktFile);
#if (SCTP_CHNKVAL == 1 && SCTP_CHNKSTR == 1)
			if (chnkType < 15) fputs(sctpChunkTypeSTr[chnkType], sPktFile);
			else
#endif // (SCTP_CHNKSTR == 1 && SCTP_CHNKVAL == 1)
			fprintf(sPktFile, "%"PRIu8, chnkType);
			fprintf(sPktFile, "_%"PRIu16"_0x%02"B2T_PRIX8"_%"PRId32, sid, sctpChunkP->flags, sctpChnkLen);
		}
	}

	if (sPktFile) fprintf(sPktFile, "\t%"PRIu8"\t0x%02"PRIx8"\t", nChnks, sctpFlowP->stat);
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	const sctpFlow_t * const sctpFlowP = &sctpFlow[flowIndex];

	sctpStatA |= sctpFlowP->stat;
	sctpTypeBFA |= sctpFlowP->typeBF;

	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->stat, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct0_sid, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct0_ppi, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->verTag, sizeof(uint32_t));
#if SCTP_CHNKVAL == 0
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->typeBF, sizeof(uint16_t));
#else // SCTP_CHNKVAL == 1
	uint32_t j = sctpFlowP->numTypeS;
#if SCTP_CHNKSTR == 1
	char *p;
#endif // SCTP_CHNKTSTR == 1
	outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t));
	for (uint_fast32_t i = 0; i < j; i++) {
#if SCTP_CHNKSTR == 0
		outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->cTypeS[i], sizeof(uint8_t));
#else // SCTP_CHNKSTR == 1
		p = (char*)sctpChunkTypeSTr[sctpFlowP->cTypeS[i]];
		outputBuffer_append(main_output_buffer, p, strlen(p)+1);
#endif // SCTP_CHNKTSTR
	}
#endif // SCTP_CHNKTVAL
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct0_dataCnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct1_initCnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct6_abrtCnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->cflags, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct9_cc, sizeof(uint16_t));
	uint16_t i = ntohs(sctpFlowP->ct1_2_nis);
	outputBuffer_append(main_output_buffer, (char*)&i, sizeof(uint16_t));
	i = ntohs(sctpFlowP->ct1_2_nos);
	outputBuffer_append(main_output_buffer, (char*)&i, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct1_2_3_arwcI, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct3_arwcMin, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct3_arwcMax, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*)&sctpFlowP->ct1_2_3_arwc, sizeof(float));
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
	if (sctpStatA)   T2_FPLOG(stream, "sctpDecode", "aggregated status: 0x%02"B2T_PRIX8, sctpStatA);
	if (sctpTypeBFA) T2_FPLOG(stream, "sctpDecode", "aggregated types : 0x%04"B2T_PRIX16, sctpTypeBFA);
}


void onApplicationTerminate() {
	free(sctpFlow);
}
