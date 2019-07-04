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

#include "nFrstPkts.h"


nFrstPkts_t *nFrstPkts;


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("nFrstPkts", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(nFrstPkts = calloc(mainHashMap->hashChainTableSize, sizeof(nFrstPkts_t))))) {
		T2_PERR("nFrstPkts", "Failed to allocate memory for packet statistics");
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("Number of signal samples", "nFpCnt", 0, 1, bt_uint_32));

#if NFRST_HDRINFO == 1
#if (NFRST_MINIAT > 0)
	bv = bv_append_bv(bv, bv_new_bv("L3Hdr, L4 Hdr, L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h)_length_IAT_Plen for the N first pkt", "HD3l_HD4l_L2L3L4Pl_Iat_nP", 1, 5, bt_uint_8, bt_uint_8, bt_uint_32, bt_duration, bt_duration));
#else // !(NFRST_MINIAT > 0)
	bv = bv_append_bv(bv, bv_new_bv("L3Hdr, L4 Hdr, L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h)_length_IAT for the N first pkt", "HD3l_HD4l_L2L3L4Pl_Iat", 1, 4, bt_uint_8, bt_uint_8, bt_uint_32, bt_duration));
#endif // (NFRST_MINIAT > 0)
#else // NFRST_HDRINFO == 0
#if (NFRST_MINIAT > 0)
	bv = bv_append_bv(bv, bv_new_bv("L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h)_length_IAT_Plen for the N first pkt", "L2L3L4Pl_Iat_nP", 1, 3, bt_uint_32, bt_duration, bt_duration));
#else // !(NFRST_MINIAT > 0)
	bv = bv_append_bv(bv, bv_new_bv("L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h)_length_IAT for the N first pkt", "L2L3L4Pl_Iat", 1, 2, bt_uint_32, bt_duration));
#endif // (NFRST_MINIAT > 0)
#endif // NFRST_HDRINFO

	return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];
	memset(nFpP, '\0', sizeof(*nFpP));
	const flow_t * const flowP = &flows[flowIndex];
	nFpP->lstPktTm0 = nFpP->lstPktTm = flowP->firstSeen;
	//nFpP->lstPktTm0 = nFpP->lstPktTm = packet->pcapHeader->ts;
#if (NFRST_IAT == 0 && NFRST_BCORR > 0)
	if (flowP->status & L3FLOWINVERT) {
		// local variables are required as the flow_t structure is packed
		// (see clang -Waddress-of-packed-member option)
		const struct timeval firstSeenB = flowP->firstSeen;
		const struct timeval firstSeenA = flows[flowP->oppositeFlowIndex].firstSeen;
		timersub(&firstSeenB, &firstSeenA, &nFpP->tdiff);
	}
#endif
}


static inline void nfp_claimInfo(packet_t *packet, unsigned long flowIndex) {
	nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];

#if NFRST_BCORR > 0 && NFRST_IAT == 0
	const flow_t * const flowP = &flows[flowIndex];
#endif

#if NFRST_MINIAT > 0
	static const struct timeval pulse = {NFRST_NINPLSS, NFRST_NINPLSU};
#endif

#if NFRST_MINIAT > 0
uu:;
#endif // NFRST_MINIAT > 0
	const uint32_t ipC = nFpP->pktCnt;
	if (ipC >= NFRST_PKTCNT) return;

	pkt_t *pP = &nFpP->pkt[ipC];

#if NFRST_HDRINFO == 1
	pP->l3HDLen = packet->l3HdrLen;
	pP->l4HDLen = packet->l4HdrLen;
#endif // NFRST_HDRINFO

	timersub(&packet->pcapHeader->ts, &nFpP->lstPktTm, &pP->iat);
#if NFRST_MINIAT > 0
	if (!nFpP->puls || (pP->iat.tv_sec < NFRST_MINIATS || (pP->iat.tv_sec == NFRST_MINIATS && pP->iat.tv_usec < NFRST_MINIATU))) {
		if (!packet->packetLength) return;
		if (!nFpP->puls) {
			nFpP->lstPktPTm = packet->pcapHeader->ts;
			nFpP->lstPktiat = pP->iat;
		}
		nFpP->lstPktTm = packet->pcapHeader->ts;
#if NFRST_XCLD > 0
		if (packet->packetLength >= NFRST_XMIN && packet->packetLength <= NFRST_XMAX)
#endif
			pP->pktLen += packet->packetLength;
		nFpP->puls++;
		return;
	} else {
#if NFRST_PLAVE == 1
		pP->pktLen /= nFpP->puls;
#endif
		timersub(&nFpP->lstPktTm, &nFpP->lstPktPTm, &pP->piat);
		timeradd(&pP->piat, &pulse, &pP->piat);
#if NFRST_IAT == 2
		pP->iat = nFpP->lstPktTm;
#elif NFRST_IAT == 1
		timersub(&nFpP->lstPktiat, &pulse, &pP->iat);
#else // NFRST_IAT == 0
		timersub(&nFpP->lstPktPTm, &nFpP->lstPktTm0, &pP->iat);
#if NFRST_BCORR > 0
		if (flowP->status & L3FLOWINVERT) timeradd(&pP->iat, &nFpP->tdiff, &pP->iat);
#endif
#endif // NFRST_IAT
		nFpP->pktCnt++;
		nFpP->puls = 0;
		goto uu;
	}

#else // NFRST_MINIAT == 0
	pP->pktLen = packet->packetLength;
#if NFRST_IAT == 2
	pP->iat = packet->pcapHeader->ts;
#elif NFRST_IAT == 1
	nFpP->lstPktTm = packet->pcapHeader->ts;
#else // NFRST_IAT == 0
#if NFRST_BCORR > 0
	if (flowP->status & L3FLOWINVERT) timeradd(&pP->iat, &nFpP->tdiff, &pP->iat);
#endif
#endif // NFRST_IAT
	nFpP->pktCnt++;
#endif // NFRST_MINIAT
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND || (packet->status & L2_FLOW) == 0) return;
	nfp_claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	nfp_claimInfo(packet, flowIndex);
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];

#if NFRST_MINIAT > 0
	if (nFpP->puls) {
		//const flow_t * const flowP = &flows[flowIndex];
		const struct timeval pulse = {NFRST_NINPLSS, NFRST_NINPLSU};
		const uint32_t ipC = nFpP->pktCnt;
		pkt_t * const pP = &nFpP->pkt[ipC];
#if NFRST_PLAVE == 1
		pP->pktLen /= nFpP->puls;
#endif
		timersub(&nFpP->lstPktTm, &nFpP->lstPktPTm, &pP->piat);
		timeradd(&pP->piat, &pulse, &pP->piat);
#if NFTST_IAT == 2
		pP->iat = nFpP->lstPktTm;
#elif NFRST_IAT == 1
		timersub(&nFpP->lstPktiat, &pulse, &pP->iat);
#else // NFRST_IAT == 0
		timersub(&nFpP->lstPktPTm, &nFpP->lstPktTm0, &pP->iat);
#endif // NFRST_IAT
		nFpP->puls = 0;
		nFpP->pktCnt++;
	}
#endif // NFRST_MINIAT

	// Number of signal samples
	outputBuffer_append(main_output_buffer, (char*) &nFpP->pktCnt, sizeof(uint32_t));

	// number of entries, because output is repeatable
	outputBuffer_append(main_output_buffer, (char*) &nFpP->pktCnt, sizeof(uint32_t));

	uint64_t secs;
	uint32_t usecs;
	for (uint_fast32_t i = 0; i < nFpP->pktCnt; i++) {

#if NFRST_HDRINFO == 1
		outputBuffer_append(main_output_buffer, (char*) &nFpP->pkt[i].l3HDLen, sizeof(uint8_t));
		outputBuffer_append(main_output_buffer, (char*) &nFpP->pkt[i].l4HDLen, sizeof(uint8_t));
#endif

		outputBuffer_append(main_output_buffer, (char*) &nFpP->pkt[i].pktLen, sizeof(uint32_t));
		secs = (uint64_t)nFpP->pkt[i].iat.tv_sec;
		outputBuffer_append(main_output_buffer, (char*) &secs, sizeof(uint64_t));

		usecs = nFpP->pkt[i].iat.tv_usec * 1000;
		outputBuffer_append(main_output_buffer, (char*) &usecs, sizeof(uint32_t));

#if NFRST_MINIAT > 0
		secs = (uint64_t)nFpP->pkt[i].piat.tv_sec;
		outputBuffer_append(main_output_buffer, (char*) &secs, sizeof(uint64_t));

		usecs = nFpP->pkt[i].piat.tv_usec * 1000;
		outputBuffer_append(main_output_buffer, (char*) &usecs, sizeof(uint32_t));
#endif
	}
}
#endif // BLOCK_BUF == 0


void onApplicationTerminate() {
	free(nFrstPkts);
}
