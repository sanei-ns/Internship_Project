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

#include "basicStats.h"
#include "basicFlow.h"

#include <ctype.h> // for isdigit and toupper
#if BS_VARSTD > 0
#include <math.h>
#endif


// Global variables

bSFlow_t *bSFlow;


// Static variables

static struct {
#if IPV6_ACTIVATE > 0
    ipAddr_t addr;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t addr;
#endif // IPV6_ACTIVATE
#if BS_GEOLOC == 1
	uint32_t     subnet;
#endif
	uint64_t     count;
	uint_fast8_t ipver;
} ipBPktsTalker, ipBByteTalker;

// Optional dependency to basicFlow
#if BS_GEOLOC == 1
#if BFO_SUBNET_TEST == 0
#error basicFlow.h must have BFO_SUBNET_TEST=1
#endif
extern bfoFlow_t *bfoFlow __attribute__((weak));
extern void *bfo_subnet_tableP[2] __attribute__((weak));
#ifndef __APPLE__
bfoFlow_t *bfoFlow;
void *bfo_subnet_tableP[2];
#endif
#endif // BS_GEOLOC == 1


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("basicStats", "0.8.4", 0, 8,
#if defined(__APPLE__) && BS_GEOLOC == 1
        "basicFlow"
#else
        ""
#endif
);

void initialize() {

	if (UNLIKELY(!(bSFlow = calloc(mainHashMap->hashChainTableSize, sizeof(*bSFlow))))) {
		T2_PERR("basicStats", "failed to allocate memory for bSFlow");
		exit(-1);
	}

	if (sPktFile) {
		fputs("pktLen\tl7Len\t", sPktFile);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	BV_APPEND_U64(bv, "numPktsSnt", "Number of transmitted packets");
#if BS_REV_CNT == 1
	BV_APPEND_U64(bv, "numPktsRcvd", "Number of received packets");
#endif
#if BS_AGRR_CNT == 1
	BV_APPEND_U64(bv, "numPktsRTAggr", "Number of received + transmitted packets");
#endif

	BV_APPEND_U64(bv, "numBytesSnt", "Number of transmitted bytes");
#if BS_REV_CNT == 1
	BV_APPEND_U64(bv, "numBytesRcvd", "Number of received bytes");
#endif
#if BS_AGRR_CNT == 1
	BV_APPEND_U64(bv, "numBytesRTAggr", "Number of received + transmitted bytes");
#endif

#if BS_STATS == 1

#if BS_PL_STATS == 1
	BV_APPEND_U16(bv, "minPktSz", "Minimum layer 3 packet size");
	BV_APPEND_U16(bv, "maxPktSz", "Maximum layer 3 packet size");
	BV_APPEND_FLT(bv, "avePktSize", "Average layer 3 packet size");
#if BS_VAR == 1
	BV_APPEND_FLT(bv, "varPktSize", "Variance layer 3 packet size");
#endif
#if BS_STDDEV == 1
	BV_APPEND_FLT(bv, "stdPktSize", "Standard deviation layer 3 packet size");
#endif
#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
	BV_APPEND_FLT(bv, "minIAT", "Minimum IAT");
	BV_APPEND_FLT(bv, "maxIAT", "Maximum IAT");
	BV_APPEND_FLT(bv, "aveIAT", "Average IAT");
#if BS_VAR == 1
	BV_APPEND_FLT(bv, "varIAT", "Variance IAT");
#endif
#if BS_STDDEV == 1
	BV_APPEND_FLT(bv, "stdIAT", "Standard deviation IAT");
#endif
#endif // BS_IAT_STATS == 1

	BV_APPEND_FLT(bv, "pktps", "Send packets per second");
	BV_APPEND_FLT(bv, "bytps", "Send bytes per second");
	BV_APPEND_FLT(bv, "pktAsm", "Packet stream asymmetry");
	BV_APPEND_FLT(bv, "bytAsm", "Byte stream asymmetry");
#endif // BS_STATS == 1

	return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	bSFlow_t * const bSFlowP = &bSFlow[flowIndex];
	memset(bSFlowP, '\0', sizeof(bSFlow_t));

#if BS_STATS == 1
	// init variables that record a minimum
	bSFlowP->minL3PktSz = UINT16_MAX;
	bSFlowP->minIAT = 4.0e12;
	bSFlowP->lst = flows[flowIndex].lastSeen;
#endif
}


static inline void bl_claimInfo(packet_t *packet, unsigned long flowIndex) {
	bSFlow_t * const bSFlowP = &bSFlow[flowIndex];

	const uint16_t ipLength = packet->packetLength; // depends on frag and PACKETLENGTH status

	if (sPktFile) {
		fprintf(sPktFile, "%"PRIu32"\t%"PRIu16"\t", packet->rawLength, packet->packetL7Length);
	}

	// update basic statistics
	bSFlowP->numTPkts++; // depends on frag status
	bSFlowP->numTBytes += ipLength;
	bSFlowP->totTBytes += packet->rawLength;

#if BS_STATS == 1

#if BS_XCLD > 0

#if BS_XCLD == 1
	if (ipLength > BS_XMIN) {
#elif BS_XCLD == 2
	if (ipLength < BS_XMAX) {
#elif BS_XCLD == 3
	if (ipLength >= BS_XMIN && ipLength <= BS_XMAX) {
#else // BS_XCLD == 4
	if (ipLength < BS_XMIN && ipLength > BS_XMAX) {
#endif // BS_XCLD == 4
		bSFlowP->numTPkts0++; // depends on frag

#endif // BS_XCLD > 0

#if BS_PL_STATS == 1
		bSFlowP->minL3PktSz = MIN(ipLength, bSFlowP->minL3PktSz);
		bSFlowP->maxL3PktSz = MAX(ipLength, bSFlowP->maxL3PktSz);
#endif

#if BS_IAT_STATS == 1
		flow_t * const flowP = &flows[flowIndex];
		const float iat = (float)(flowP->lastSeen.tv_sec - bSFlowP->lst.tv_sec) + (float)(flowP->lastSeen.tv_usec - bSFlowP->lst.tv_usec) / 1000000.0f;
		bSFlowP->minIAT = MIN(iat, bSFlowP->minIAT);
		bSFlowP->maxIAT = MAX(iat, bSFlowP->maxIAT);
		bSFlowP->lst = flowP->lastSeen;
#endif // BS_IAT_STATS == 1

#if BS_VARSTD > 0 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)
		// estimate <> <<> >
#if BS_XCLD > 0
		const float fac = (bSFlowP->numTPkts0) ? 1.0 / (float)bSFlowP->numTPkts0 : 0;
#else // BS_XCLD == 0
		const float fac = (bSFlowP->numTPkts) ? 1.0 / (float)bSFlowP->numTPkts : 0;
#endif // BS_XCLD

		float m;

#if BS_PL_STATS == 1
		bSFlowP->avePktSzf = bSFlowP->avePktSzf * (1.0 - fac) + ipLength * fac;
		m = ipLength - bSFlowP->avePktSzf;
		bSFlowP->varPktSz = bSFlowP->varPktSz * (1.0 - fac) + m * m * fac;
#endif

#if BS_IAT_STATS == 1
		bSFlowP->aveIATSzf = bSFlowP->aveIATSzf * (1.0 - fac) + iat * fac;
		m = iat - bSFlowP->aveIATSzf;
		bSFlowP->varIATSz = bSFlowP->varIATSz * (1.0 - fac) + m * m * fac;
#endif

#endif // BS_VARSTD > 0 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)

#if BS_XCLD > 0
	}
#endif
#endif // BS_STATS == 1

#if FORCE_MODE == 1
	if (UNLIKELY(UINT64_MAX - bSFlowP->numTBytes < ipLength || bSFlowP->numTPkts >= UINT64_MAX)) {
		flow_t * const flowP = &flows[flowIndex];
		T2_RM_FLOW(flowP);
	}
#endif // FORCE_MODE == 1
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	bl_claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	bl_claimInfo(packet, flowIndex);
}


void onFlowTerminate(unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];
	const bSFlow_t * const bSFlowP = &bSFlow[flowIndex];

#if (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGRR_CNT == 1)

#if ESOM_DEP == 0
	uint64_t oNumPkts, oNumBytes;
#endif // ESOM_DEP == 0

	// get info from opposite flow
	if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		oNumPkts = bSFlow[flowP->oppositeFlowIndex].numTPkts;
		oNumBytes = bSFlow[flowP->oppositeFlowIndex].numTBytes;
	} else {
		oNumPkts = 0;
		oNumBytes = 0;
	}
#endif // (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGRR_CNT == 1)

#if BS_STATS == 1

#if ESOM_DEP == 0
	float packet_sym_ratio, byte_sym_ratio;
	float packetsPerSec, bytesPerSec;
#endif

	// packets/bytes per second
	if (flowP->duration.tv_sec != 0 || flowP->duration.tv_usec != 0) {
		const float duration = (float)(flowP->duration.tv_sec + flowP->duration.tv_usec/1000000.0f);
		packetsPerSec = bSFlowP->numTPkts / duration;
		bytesPerSec = bSFlowP->numTBytes / duration;
	} else {
		packetsPerSec = 0.0f;
		bytesPerSec = 0.0f;
	}

	// asymmetry of packets sent and received
	if (oNumPkts > 0 || bSFlowP->numTPkts > 0) {
		packet_sym_ratio = ((float)bSFlowP->numTPkts - (float)oNumPkts) / (float)(bSFlowP->numTPkts + oNumPkts);
	} else {
		packet_sym_ratio = 0.0f;
	}

	// asymmetry of bytes sent and received
	if (oNumBytes > 0 || bSFlowP->numTBytes > 0) {
		byte_sym_ratio = ((float)bSFlowP->numTBytes - (float)oNumBytes) / (float)(bSFlowP->numTBytes + oNumBytes);
	} else {
		byte_sym_ratio = 0.0f;
	}

#endif // BS_STATS == 1

#if BLOCK_BUF == 0
	OUTBUF_APPEND_U64(main_output_buffer, bSFlowP->numTPkts);

#if BS_REV_CNT == 1
	OUTBUF_APPEND_U64(main_output_buffer, oNumPkts);
#endif

#if BS_AGRR_CNT == 1
#if ESOM_DEP == 0
	uint64_t aggPkts;
#endif
	aggPkts = bSFlowP->numTPkts + oNumPkts;
	OUTBUF_APPEND_U64(main_output_buffer, aggPkts);
#endif

	OUTBUF_APPEND_U64(main_output_buffer, bSFlowP->numTBytes);
	if (bSFlowP->numTPkts > ipBPktsTalker.count) {
		ipBPktsTalker.count = bSFlowP->numTPkts;
		ipBPktsTalker.addr  = flowP->srcIP;
		ipBPktsTalker.ipver = FLOW_IS_IPV6(flowP) ? 6 : 4;
#if BS_GEOLOC == 1
		if (bfoFlow) ipBPktsTalker.subnet = bfoFlow[flowIndex].subNSrc;
#endif
	}

	if (bSFlowP->numTBytes > ipBByteTalker.count) {
        ipBByteTalker.count = bSFlowP->totTBytes;
		ipBByteTalker.addr  = flowP->srcIP;
		ipBByteTalker.ipver = FLOW_IS_IPV6(flowP) ? 6 : 4;
#if BS_GEOLOC == 1
		if (bfoFlow) ipBByteTalker.subnet = bfoFlow[flowIndex].subNSrc;
#endif
	}

#if BS_REV_CNT == 1
	OUTBUF_APPEND_U64(main_output_buffer, oNumBytes);
#endif

#if BS_AGRR_CNT == 1
#if ESOM_DEP == 0
	uint64_t aggBytes;
#endif
	aggBytes = bSFlowP->numTBytes + oNumBytes;
	OUTBUF_APPEND_U64(main_output_buffer, aggBytes);
#endif

#if BS_STATS == 1

#if BS_STDDEV == 1 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)
	float stddev;
#endif

#if BS_PL_STATS == 1
	OUTBUF_APPEND_U16(main_output_buffer, bSFlowP->minL3PktSz);
	OUTBUF_APPEND_U16(main_output_buffer, bSFlowP->maxL3PktSz);

#if ESOM_DEP == 0
	float avePktSize;
#endif

#if BS_XCLD > 0
	avePktSize = (bSFlowP->numTPkts0) ? bSFlowP->numTBytes / (float)bSFlowP->numTPkts0 : 0;
#else // BS_XCLD == 0
	avePktSize = (bSFlowP->numTPkts) ? bSFlowP->numTBytes / (float)bSFlowP->numTPkts : 0;
#endif // BS_XCLD > 0
	OUTBUF_APPEND_FLT(main_output_buffer, avePktSize);

#if BS_VAR == 1
	OUTBUF_APPEND_FLT(main_output_buffer, bSFlowP->varPktSz);
#endif

#if BS_STDDEV == 1
	stddev = sqrt(bSFlowP->varPktSz);
	OUTBUF_APPEND_FLT(main_output_buffer, stddev);
#endif

#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
	OUTBUF_APPEND_FLT(main_output_buffer, bSFlowP->minIAT);
	OUTBUF_APPEND_FLT(main_output_buffer, bSFlowP->maxIAT);
	OUTBUF_APPEND_FLT(main_output_buffer, bSFlowP->aveIATSzf);

#if BS_VAR == 1
	OUTBUF_APPEND_FLT(main_output_buffer, bSFlowP->varIATSz);
#endif

#if BS_STDDEV == 1
	stddev = sqrt(bSFlowP->varIATSz);
	OUTBUF_APPEND_FLT(main_output_buffer, stddev);
#endif

#endif // BS_IAT_STATS == 1

	OUTBUF_APPEND_FLT(main_output_buffer, packetsPerSec);
	OUTBUF_APPEND_FLT(main_output_buffer, bytesPerSec);
	OUTBUF_APPEND_FLT(main_output_buffer, packet_sym_ratio);
	OUTBUF_APPEND_FLT(main_output_buffer, byte_sym_ratio);
#endif // BS_STATS == 1

#endif // BLOCK_BUF == 0
}


#if BS_GEOLOC == 1
#define BS_FORMAT_LOC(loc) \
	if ((loc)[0] == '-' || isdigit((loc)[0])) { \
		loc = ""; \
	} else { \
		loc_str[2] = toupper((loc)[0]); \
		loc_str[3] = toupper((loc)[1]); \
		loc = loc_str; \
	}
#endif


void pluginReport(FILE *stream) {
	char *loc = "";
#if BS_GEOLOC == 1
	char loc_str[] = " (XX)"; // XX will be replaced by the country code
#endif

	char ipstr[INET6_ADDRSTRLEN];
	char str[64];

	const uint64_t numBytes = numABytes + numBBytes;

	T2_IP_TO_STR(ipBPktsTalker.addr, ipBPktsTalker.ipver, ipstr, INET6_ADDRSTRLEN);
	T2_CONV_NUM(ipBPktsTalker.count, str);
#if BS_GEOLOC == 1
		if (bfoFlow) {
			SUBNET_LOC(loc, bfo_subnet_tableP, ipBPktsTalker.ipver, ipBPktsTalker.subnet);
			BS_FORMAT_LOC(loc);
		}
#endif
	T2_FPLOG(stream, "basicStats", "Biggest Talker: %s%s: %"PRIu64"%s [%.2f%%] packets",
	        ipstr, loc, ipBPktsTalker.count, str, 100.0*ipBPktsTalker.count/numPackets);

	T2_IP_TO_STR(ipBByteTalker.addr, ipBByteTalker.ipver, ipstr, INET6_ADDRSTRLEN);
	T2_CONV_NUM(ipBByteTalker.count, str);
#if BS_GEOLOC == 1
		if (bfoFlow) {
			SUBNET_LOC(loc, bfo_subnet_tableP, ipBByteTalker.ipver, ipBByteTalker.subnet);
			BS_FORMAT_LOC(loc);
		}
#endif
	T2_FPLOG(stream, "basicStats", "Biggest Talker: %s%s: %"PRIu64"%s [%.2f%%] bytes",
	        ipstr, loc, ipBByteTalker.count, str, 100.0*ipBByteTalker.count/numBytes);
}


void onApplicationTerminate() {
	free(bSFlow);
}
