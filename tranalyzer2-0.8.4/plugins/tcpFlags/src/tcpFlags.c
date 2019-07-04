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

#include "tcpFlags.h"

#if IPCHECKSUM > 0
#include "chksum.h"
#endif // IPCHECKSUM > 0

#include <math.h>


// Global variables

tcpFlagsFlow_t *tcpFlagsFlows;


// Static variables

static uint16_t ipFlgsA, tcpFlgsA;
static uint64_t winMinCnt, tcpPktvCnt;
static uint64_t totalTCPScans, totalTCPScans0;
static uint64_t totalTCPSuccScans, totalTCPSuccScans0;
static uint64_t totalTCPRetry, totalTCPRetry0;

// Tranalyzer plugin functions

T2_PLUGIN_INIT("tcpFlags", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(tcpFlagsFlows = calloc(mainHashMap->hashChainTableSize, sizeof(tcpFlagsFlow_t))))) {
		T2_PERR("tcpFlags", "Failed to allocate memory for tcpFlagsFlows");
		exit(-1);
	}

	if (sPktFile) {
		fputs("ipTOS\tipID\tipIDDiff\tipFrag\tipTTL\t"
		      "ipHdrChkSum\tipCalChkSum\t"
		      "l4HdrChkSum\tl4CalChkSum\t"
		      "ipFlags\t"
#if IPV6_ACTIVATE > 0
		      "ip6HHOptLen\tip6HHOpts\tip6DOptLen\tip6DOpts\t"
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		      "ipOptLen\tipOpts\t"
#endif // IPV6_ACTIVATE == 1 || IPV6_ACTIVATE == 2
		      "seq\tack\t"
#if SEQ_ACK_NUM == 1
		      "seqDiff\tackDiff\tseqPktLen\tackPktLen\t"
#endif // SEQ_ACK_NUM == 1
		      "tcpFStat\ttcpFlags\ttcpAnomaly\ttcpWin\ttcpOptLen\ttcpOpts\t",
		      sPktFile);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("tcpFlags status", "tcpFStat", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("IP minimum delta IP ID", "ipMindIPID", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IP maximum delta IP ID", "ipMaxdIPID", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IP minimum TTL", "ipMinTTL", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IP maximum TTL", "ipMaxTTL", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IP TTL change count", "ipTTLChg", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IP Type of Service", "ipTOS", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("IP aggregated flags", "ipFlags", 0, 1, bt_hex_16));

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	//bv = bv_append_bv(bv, = bv_new_bv("IP options Packet count", "ip_OptPktCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IP options count", "ipOptCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IP aggregated options, copy-class & number", "ipOptCpCl_Num", 0, 2, bt_hex_8, bt_hex_32));
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
	bv = bv_append_bv(bv, bv_new_bv("IPv6 hop by hop destination option counts", "ip6OptCntHH_D", 0, 2, bt_uint_16, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IPv6 aggregated hop by hop destination options", "ip6OptHH_D", 0, 2, bt_hex_32, bt_hex_32));
#endif // IPV6_ACTIVATE > 0

#if SEQ_ACK_NUM == 1
	bv = bv_append_bv(bv, bv_new_bv("TCP packet seq count", "tcpPSeqCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP sent seq diff bytes", "tcpSeqSntBytes", 0, 1, bt_uint_64));
	bv = bv_append_bv(bv, bv_new_bv("TCP sequence number fault count", "tcpSeqFaultCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP packet ack count", "tcpPAckCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP flawless ack received bytes", "tcpFlwLssAckRcvdBytes", 0, 1, bt_uint_64));
	bv = bv_append_bv(bv, bv_new_bv("TCP ack number fault count", "tcpAckFaultCnt", 0, 1, bt_uint_16));
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
	bv = bv_append_bv(bv, bv_new_bv("TCP initial effective window size", "tcpInitWinSz", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP average effective window size", "tcpAveWinSz", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP minimum effective window size", "tcpMinWinSz", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP maximum effective window size", "tcpMaxWinSz", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP effective window size change down count", "tcpWinSzDwnCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP effective window size change up count", "tcpWinSzUpCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP effective window size direction change count", "tcpWinSzChgDirCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP packet count ratio below window size WINMIN threshold", "tcpWinSzThRt", 0, 1, bt_float));
#endif // WINDOWSIZE == 1

	bv = bv_append_bv(bv, bv_new_bv("TCP aggregated protocol flags (cwr, ecn, urgent, ack, push, reset, syn, fin)", "tcpFlags", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("TCP aggregated header anomaly flags", "tcpAnomaly", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP options packet count", "tcpOptPktCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP options count", "tcpOptCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP aggregated options", "tcpOptions", 0, 1, bt_hex_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP maximum Segment Length", "tcpMSS", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("TCP window scale", "tcpWS", 0, 1, bt_uint_8));

#if NAT_BT_EST == 1
	bv = bv_append_bv(bv, bv_new_bv("TCP time stamp", "tcpTmS", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP time echo reply", "tcpTmER", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("TCP estimated counter increment", "tcpEcI", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP estimated boot time", "tcpBtm", 0, 1, bt_timestamp));
#endif // NAT_BT_EST == 1

#if RTT_ESTIMATE == 1
	bv = bv_append_bv(bv, bv_new_bv("TCP trip time SYN, SYN-ACK Destination | SYN-ACK, ACK Source", "tcpSSASAATrip", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP ACK trip min", "tcpRTTAckTripMin", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP ACK trip max", "tcpRTTAckTripMax", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP ACK trip average", "tcpRTTAckTripAve", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP ACK trip jitter average", "tcpRTTAckTripJitAve", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP round trip time SYN, SYN-ACK, ACK | TCP ACK-ACK RTT", "tcpRTTSseqAA", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("TCP ACK round trip average jitter", "tcpRTTAckJitAve", 0, 1, bt_float));
#endif // RTT_ESTIMATE == 1

	return bv;
}


void onFlowGenerated(packet_t *packet, unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];

	tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];
	memset(tcpFlagsP, '\0', sizeof(*tcpFlagsP));

	tcpFlagsP->lastPktTime = flowP->lastSeen;
	tcpFlagsP->stat = IP_INT_DISSTATE;

	tcpFlagsP->ipMinIDT = 0xffff;
#if RTT_ESTIMATE == 1
	tcpFlagsP->tcpRTTAckTripMin = 0xffff;
#endif // RTT_ESTIMATE == 1

	if (flowP->status & L2_FLOW) return;

	if (PACKET_IS_IPV6(packet)) {
		const ip6Header_t * const ip6Header = (ip6Header_t*)packet->layer3Header;
		tcpFlagsP->ipTTLT    = ip6Header->ip_ttl;
		tcpFlagsP->ipMinTTLT = ip6Header->ip_ttl;
		tcpFlagsP->ipMaxTTLT = ip6Header->ip_ttl;
	} else { // IPv4
		const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
		tcpFlagsP->ipIDT = ntohs(ipHeader->ip_id);
		tcpFlagsP->ipTTLT    = ipHeader->ip_ttl;
		tcpFlagsP->ipMinTTLT = ipHeader->ip_ttl;
		tcpFlagsP->ipMaxTTLT = ipHeader->ip_ttl;
	}

	if (packet->layer4Type != L3_TCP) return;

	const tcpHeader_t * const tcpHeader = (tcpHeader_t*) packet->layer4Header;
	const unsigned char flags = (unsigned char) *((char*)tcpHeader + 13);

#if SEQ_ACK_NUM == 1
	tcpFlagsP->tcpSeqT = ntohl(tcpHeader->seq);
	tcpFlagsP->tcpAckT = ntohl(tcpHeader->ack_seq);
	tcpFlagsP->tcpPLstLen = packet->packetL7Length;
#endif // SEQ_ACK_NUM == 1

#if SPKTMD_SEQACKREL == 1
	tcpFlagsP->tcpSeqI = ntohl(tcpHeader->seq);
	tcpFlagsP->tcpAckI = ntohl(tcpHeader->ack_seq);
#endif // SPKTMD_SEQACKREL == 1

	if (flags == SYN && packet->snapL7Length) tcpFlagsP->stat |= TCP_L7CNT;
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	if (sPktFile) {
		fputs("\t\t\t\t\t"    // ipTOS, ipID, ipIDDiff, ipFrag, ipTTL
		      "\t\t\t\t\t"    // ipHdrChkSum, ipCalChkSum, l4HdrChkSum, l4CalChkSum, ipFlags
#if IPV6_ACTIVATE > 0
		      "\t\t\t\t"      // ip6HHOptLen, ip6HHOpts, ip6DOptLen, ip6DOpts
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		      "\t\t"          // ipOptLen, ipOpts
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		      "\t\t"          // seq, ack
#if SEQ_ACK_NUM == 1
		      "\t\t\t\t"      // seqDiff, ackDiff, seqPktLen, ackPktLen
#endif // SEQ_ACK_NUM == 1
		      "\t\t\t\t\t\t", // tcpFStat, tcpFlags, tcpAnomaly, tcpWin, tcpOptLen, tcpOpts
		      sPktFile);
	}
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	flow_t * const flowP = &flows[flowIndex];

	tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

	flow_t *revFlowP;
	tcpFlagsFlow_t *tcpFlagsPO;
	if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		tcpFlagsPO = &tcpFlagsFlows[flowP->oppositeFlowIndex];
		revFlowP = &flows[flowP->oppositeFlowIndex];
	} else {
		tcpFlagsPO = NULL;
		revFlowP = NULL;
	}

#if RTT_ESTIMATE == 1
	float tcpRTTemp, fac;
	tcpFlagsP->tcpPktCnt += 1.0;
#endif // RTT_ESTIMATE == 1

#if IPV6_ACTIVATE > 0
	const ip6Header_t * const ip6Header = (ip6Header_t*)packet->layer3Header;
	const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdr;
	int16_t ip6HHOptLen = 0;
	int16_t ip6DOptLen = 0;
	const uint8_t *ip6HHOpt = NULL;
	const uint8_t *ip6DOpt = NULL;
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
	int16_t ipOptLen = 0;
	const uint8_t *ipOpt = NULL;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

	const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;

	int i;
	uint16_t ipHdrChkSum = 0, ipCalChkSum = 0;
	uint16_t l4HdrChkSum = 0, l4CalChkSum = 0;
	uint16_t ipFlags = 0, ipID = 0, ipIDDiff = 0;
	uint16_t l3Len, l4Len;
	uint16_t l3HDLen, l4HDLen = 8;
	uint16_t ipFrag = 0;

	const uint16_t * const l4Header = (uint16_t*)packet->layer4Header;

	if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
		if (ip6FragHdrP) {
			// fragmentation bits (Res, MF), | tcpFlags->ipFlagsT;
			ipFlags = (ip6FragHdrP->frag_off << 1) & IP_FRAG_BITS;
			ipFrag = ntohs(ip6FragHdrP->frag_off) >> 3;
		}
		l3Len = ntohs(ip6Header->payload_len) + 40;
		l3HDLen = packet->l3HdrLen;
		l4Len = l3Len - l3HDLen;
		const ip6OptHdr_t * const ip6HHOptHdrP = (ip6OptHdr_t*)packet->ip6HHOptHdr;
		if (ip6HHOptHdrP) {
			ip6HHOptLen = ((ip6HHOptHdrP->len + 1) << 3) - 2;
			ip6HHOpt = (uint8_t*)&ip6HHOptHdrP->options;
		}
		const ip6OptHdr_t * const ip6DOptHdrP = (ip6OptHdr_t*)packet->ip6DOptHdr;
		if (ip6DOptHdrP) {
			ip6DOptLen = ((ip6DOptHdrP->len + 1) << 3) - 2;
			ip6DOpt = (uint8_t*)&ip6DOptHdrP->options;
		}
		if (ip6HHOptLen > 0 || ip6DOptLen > 0) {
			// option field truncated or crafted packet?
			if (packet->snapL3Length >= l3HDLen && l3Len >= l3HDLen) {
				for (i = 0; i < ip6HHOptLen && ip6HHOpt[i] > 0; i += (ip6HHOpt[i] > 0) ? ip6HHOpt[i+1]+2: 1) {
					tcpFlagsP->ip6HHOptionsT |= 1U << (ip6HHOpt[i] & 0x1F); // ipOptions < 32
					tcpFlagsP->ip6HHOptCntT++;
				}
				for (i = 0; i < ip6DOptLen && ip6DOpt[i] > 0; i += (ip6DOpt[i] > 0) ? ip6DOpt[i+1]+2: 1) {
					tcpFlagsP->ip6DOptionsT |= 1U << (ip6DOpt[i] & 0x1F); // ipOptions < 32
					tcpFlagsP->ip6DOptCntT++;
				}
				//tcpFlagsP->ipOptPktCntT++;
			} else ipFlags |= IP_OPT_CORRPT; // warning: crafted packet or option field not acquired
		}
		// minTTL and maxTTL, os guessing and network reversing
		if (ip6Header->ip_ttl != tcpFlagsP->ipTTLT) tcpFlagsP->ipTTLChgT++;
		if (ip6Header->ip_ttl < tcpFlagsP->ipMinTTLT) tcpFlagsP->ipMinTTLT = ip6Header->ip_ttl;
		if (ip6Header->ip_ttl > tcpFlagsP->ipMaxTTLT) tcpFlagsP->ipMaxTTLT = ip6Header->ip_ttl;
#endif // IPV6_ACTIVATE > 0
	} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		// fragmentation bits (Res, DF, MF), | tcpFlags->ipFlagsT;
		ipFlags = (uint16_t) *((char*)ipHeader + 6) & IP_FRAG_BITS;
		l3Len = ntohs(ipHeader->ip_len);
		l3HDLen = IP_HL(ipHeader) << 2;
		l4Len = l3Len - l3HDLen;
		ipOptLen = l3HDLen - 20;
		ipOpt = ((uint8_t*)ipHeader + 20);
		ipFrag = ipHeader->ip_off & FRAGIDM_N;
		if (ipOptLen > 0) {
			// option field truncated or crafted packet?
			if (packet->snapL3Length >= l3HDLen && l3Len >= l3HDLen) {
				for (i = 0; i < ipOptLen && ipOpt[i] > 0; i += (ipOpt[i] > 1) ? ipOpt[i+1]: 1) {
					tcpFlagsP->ipCpClT |= 1U << (ipOpt[i] >> 5); // copy & class
					tcpFlagsP->ipOptionsT |= 1U << (ipOpt[i] & 0x1F); // ipOptions < 32
					tcpFlagsP->ipOptCntT++;
					if (ipOpt[i+1] == 0) break;
				}
				//tcpFlagsP->ipOptPktCntT++;
			} else ipFlags |= IP_OPT_CORRPT; // warning: crafted packet or option field not acquired
		}
		// minTTL and maxTTL, os guessing and network reversing
		if (ipHeader->ip_ttl != tcpFlagsP->ipTTLT) tcpFlagsP->ipTTLChgT++;
		if (ipHeader->ip_ttl < tcpFlagsP->ipMinTTLT) tcpFlagsP->ipMinTTLT = ipHeader->ip_ttl;
		if (ipHeader->ip_ttl > tcpFlagsP->ipMaxTTLT) tcpFlagsP->ipMaxTTLT = ipHeader->ip_ttl;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	}

	// minIPID and maxIPID, good estimate for windows about load state of the source machine

	if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
		tcpFlagsP->ipTosT |= (unsigned char) (ntohs(*(uint16_t*)ip6Header) >> 4); // get TOS byte
#endif // IPV6_ACTIVATE > 0
	} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		tcpFlagsP->ipTosT |= (unsigned char) *((char*)ipHeader + 1); // get TOS byte
		ipID = ntohs(ipHeader->ip_id);

		// 1. Packet not suitable for IPID assessment, reset at inter-distance
		if (!(tcpFlagsP->stat & IP_INT_DISSTATE)) {
			ipIDDiff = ipID - tcpFlagsP->ipIDT;
			if (ipID < tcpFlagsP->ipIDT) {
				if (ipIDDiff < IP_ID_RLLOVR) ipFlags |= IP_ID_ROLL_OVER; // roll-over
				else ipFlags |= IP_ID_OUT_ORDER; // messy packet order
			}

			if (ipIDDiff < tcpFlagsP->ipMinIDT) tcpFlagsP->ipMinIDT = ipIDDiff;
			if (ipIDDiff > tcpFlagsP->ipMaxIDT) tcpFlagsP->ipMaxIDT = ipIDDiff;
		}

		// ip checksum processing
		ipHdrChkSum = ntohs(ipHeader->ip_sum);

 		if (packet->snapL3Length < l3HDLen) ipFlags |= (IP_SNP_HLEN_WRN | IP_L3CHK_SUMERR);
#if IPCHECKSUM > 0
 		else {
			ipCalChkSum = ntohs(~(Checksum((uint16_t*)ipHeader, 0, l3HDLen, 5)));
			if (ipHdrChkSum != ipCalChkSum) ipFlags |= IP_L3CHK_SUMERR;
 		}
#endif // IPCHECKSUM > 0

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	}

	// L4 Checksum processing

	// only the first header fragment has a L4 header
	if ((ipFrag & FRAGID_N) == 0x0000) {

		uint16_t chkSumWrdPos = 0, chkLen = l4Len;

		tcpFlagsP->stat |= L4CHKSUMC;

		switch (packet->layer4Type) {
			case L3_ICMP:
			case L3_IGMP:
				chkSumWrdPos = 1;
				break;
#if IPV6_ACTIVATE > 0
			case L3_ICMP6:
				chkSumWrdPos = 1;
				l4HDLen = 4;
				break;
#endif // IPV6_ACTIVATE > 0
			case L3_TCP:
				chkSumWrdPos = 8;
				l4HDLen = tcpHeader->doff<<2;
				break;
			case L3_UDPLITE:
				i = ntohs(((udpHeader_t*)packet->layer4Header)->len);
				if (LIKELY(i >= (int)sizeof(udpliteHeader_t) && i <= l4Len)) chkLen = i;
				else ipFlags |= L4_CHKCOVERR;
				/* FALLTHRU */
			case L3_UDP:
				chkSumWrdPos = 3;
				break;
			case L3_GRE:
				if (*l4Header & 0x0080) chkSumWrdPos = 2;
				else l4HDLen = 4;
				break;
			case L3_OSPF:
				chkSumWrdPos = 6;
				l4HDLen = 16;
				break;
			default:
				if (packet->snapL3Length < l3Len) ipFlags |= (IP_SNP_HLEN_WRN | IP_L4CHK_SUMERR);
				tcpFlagsP->stat &= ~L4CHKSUMC;
				goto intdis;
		}

		l4HdrChkSum = ntohs(l4Header[chkSumWrdPos]);

#if FRAGMENTATION == 1
		tcpFlagsP->l4HdrChkSum = l4HdrChkSum;
#endif // FRAGMENTATION == 1

		if (packet->snapL3Length < l3Len || packet->snapL4Length < l4Len) ipFlags |= (IP_SNP_HLEN_WRN | IP_L4CHK_SUMERR);
#if IPCHECKSUM > 1
		else if (chkSumWrdPos) {
			if (packet->layer4Type > 2) { // ICMP and IGMP use no pseudo header
				if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
					psyL3Header6_t psyL3Header6 = {
						.ip_src = ip6Header->ip_src,
						.ip_dst = ip6Header->ip_dst,
						.ip_p = packet->layer4Type << 24,
						.l4_len = htonl(l4Len),
					};
					l4CalChkSum = Checksum((uint16_t*)&psyL3Header6, 0, sizeof(psyL3Header6), 0);
#endif // IPV6_ACTIVATE > 0
				} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
					psyL3Header4_t psyL3Header4 = {
						.ip_src = ipHeader->ip_src,
						.ip_dst = ipHeader->ip_dst,
						.ip_p = ((uint16_t)packet->layer4Type) << 8,
						.l4_len = htons(l4Len),
					};
					l4CalChkSum = Checksum((uint16_t*)&psyL3Header4, 0, sizeof(psyL3Header4), 0);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				}
			}

#if FRAGMENTATION == 1
			tcpFlagsP->l4CalChkSum = Checksum(l4Header, (uint32_t)l4CalChkSum, chkLen, chkSumWrdPos); // use the largest structure pointer: TCP
			if (tcpFlagsP->l4CalChkSum != 0xffff) l4CalChkSum = ntohs(~tcpFlagsP->l4CalChkSum);
			else l4CalChkSum = ntohs(tcpFlagsP->l4CalChkSum); // fix for devils 0x0000 checksum
#else // FRAGMENTATION == 0
			l4CalChkSum = ntohs(~Checksum(l4Header, (uint32_t)l4CalChkSum, chkLen, chkSumWrdPos)); // use the largest structure pointer: TCP
			if (l4HdrChkSum != l4CalChkSum) ipFlags |= IP_L4CHK_SUMERR;
#endif // FRAGMENTATION == 0
		}

#endif // IPCHECKSUM > 1
	}
#if (FRAGMENTATION == 1 && IPCHECKSUM > 1)
	else if (tcpFlagsP->stat & L4CHKSUMC) {
		l4HdrChkSum = tcpFlagsP->l4HdrChkSum;
		tcpFlagsP->l4CalChkSum = Checksum((uint16_t*)packet->layer7Header, (uint32_t)tcpFlagsP->l4CalChkSum, packet->snapL7Length, 0); // use the largest structure pointer: TCP
		if (tcpFlagsP->l4CalChkSum != 0xffff) l4CalChkSum = ntohs(~tcpFlagsP->l4CalChkSum);
		else l4CalChkSum = ntohs(tcpFlagsP->l4CalChkSum); // fix for devils 0x0000 checksum
	}

	bool frag;

	if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
		frag = (ip6FragHdrP && (ip6FragHdrP->frag_off & MORE_FRAG6_N));
#endif // IPV6_ACTIVATE > 0
	} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		frag = (ipHeader->ip_off & MORE_FRAG_N);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	}

	if (!frag && l4HdrChkSum != l4CalChkSum) ipFlags |= IP_L4CHK_SUMERR;

#endif // (FRAGMENTATION == 1 && IPCHECKSUM > 1)

intdis: ;
	const float pktInterDis = flowP->lastSeen.tv_sec - tcpFlagsP->lastPktTime.tv_sec + (flowP->lastSeen.tv_usec - tcpFlagsP->lastPktTime.tv_usec) / 1000000.0f;
	if (!(tcpFlagsP->stat & IP_INT_DISSTATE)) {
		if (pktInterDis < 0) {
			ipFlags |= IP_PKT_INTDISN;
			globalWarn |= TIMEJUMP;
			flowP->status |= TIMEJUMP;
		}
		/*tcpFlagsP->avePktInterDis = tcpFLagsPtr->avePktInterDis*0.7 + pktInterDis*0.3;
		if (pktInterDis < 0 || fabs(pktInterDis - tcpFLagsPtr->avePktInterDis) > PKTINTDISTOLL) {
			ipFlags |= 0x4000;
			globalWarn |= TIMEJUMP;
			flowP->status |= TIMEJUMP;
		}*/
		if (pktInterDis == 0) ipFlags |= IP_PKT_INTDIS;
	}

	tcpFlagsP->lastPktTime = flowP->lastSeen;

#if FRAG_ANALYZE == 1
	if (ipFrag) { // fragments with and without L4 header
		ipFrag = ntohs(ipFrag) & IPFRAGPKTSZMAX;
		if (l3Len < IPFRAGPKTSZMIN) ipFlags |= IP_FRAG_BLW_MIN; // below minimum RFC fragments
		if (ipFrag - tcpFlagsP->ipNxtFragBgnExp > 1) ipFlags |= IP_FRAG_NXTPPOS; // fragments not at the expected position, pkt loss or attack
		tcpFlagsP->ipNxtFragBgnExp = ipFrag + (l4Len >> 3);
		if (tcpFlagsP->ipNxtFragBgnExp > IPFRAGPKTSZMAX) ipFlags |= IP_FRAG_OUT_RNG; // fragments out of buffer range, possible teardrop
	}
#endif // FRAG_ANALYZE

	tcpFlagsP->ipFlagsT |= ipFlags;
	tcpFlagsP->ipIDT = ipID;
	if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
		tcpFlagsP->ipTTLT = ip6Header->ip_ttl;
#endif // IPV6_ACTIVATE > 0
	} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		tcpFlagsP->ipTTLT = ipHeader->ip_ttl;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	}

	// Round trip estimate for non TCP

#if RTT_ESTIMATE == 1
	if (revFlowP) {
		if (tcpFlagsPO->tcpRTTFlag == TCP_RTT_SYN_ST) {
			tcpRTTemp = tcpFlagsP->tcpRTTtrip = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / 1000000.0f;
			if (tcpRTTemp < tcpFlagsP->tcpRTTAckTripMin) tcpFlagsP->tcpRTTAckTripMin = tcpRTTemp;
			if (tcpRTTemp > tcpFlagsP->tcpRTTAckTripMax) tcpFlagsP->tcpRTTAckTripMax = tcpRTTemp;
			tcpFlagsP->tcpRTTAckTripAve = tcpRTTemp;
			tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK_A;
			tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK_B;
		} else {
			tcpRTTemp = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / 1000000.0f;
			if (tcpRTTemp < tcpFlagsP->tcpRTTAckTripMin) tcpFlagsP->tcpRTTAckTripMin = tcpRTTemp;
			if (tcpRTTemp > tcpFlagsP->tcpRTTAckTripMax) tcpFlagsP->tcpRTTAckTripMax = tcpRTTemp;
			fac = 1.0 / tcpFlagsP->tcpPktCnt;
			tcpFlagsP->tcpRTTAckTripAve = tcpFlagsP->tcpRTTAckTripAve * (1.0 - fac) + tcpRTTemp * fac;
			tcpRTTemp -= tcpFlagsP->tcpRTTAckTripAve;
			tcpFlagsP->tcpRTTAckTripJitAve = tcpFlagsP->tcpRTTAckTripJitAve * (1.0 - fac) + tcpRTTemp * tcpRTTemp * fac;
			tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK_A;
			tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK_B;
		}
	}
#endif // RTT_ESTIMATE == 1

	if (sPktFile) {
		uint8_t ttl;
		uint16_t frag_off;
		if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
			ttl = ip6Header->ip_ttl;
			frag_off = (packet->ip6FragHdr) ? ntohs(packet->ip6FragHdr->frag_off) : 0;
#endif // IPV6_ACTIVATE > 0
		} else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
			ttl = ipHeader->ip_ttl;
			frag_off = ntohs(ipHeader->ip_off);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		}

		fprintf(sPktFile,
			"0x%02"B2T_PRIX8"\t"                     // ipTOS
			"0x%04"B2T_PRIX16"\t%"PRIu16"\t"         // ipID, ipIDDiff
			"0x%04"B2T_PRIX16"\t%"PRIu8"\t"          // ipFrag, ipTTL
			"0x%04"B2T_PRIX16"\t0x%04"B2T_PRIX16"\t" // ipHdrChkSum, ipCalChkSum
			"0x%04"B2T_PRIX16"\t0x%04"B2T_PRIX16"\t" // l4HdrChkSum, l4CalChkSum
			"0x%04"B2T_PRIX16"\t",                   // ipFlags
			tcpFlagsP->ipTosT, ipID, ipIDDiff, frag_off, ttl,
			ipHdrChkSum, ipCalChkSum, l4HdrChkSum, l4CalChkSum, ipFlags);

		if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
			// print all IPv6 HH options
			fprintf(sPktFile, "%d\t", ip6HHOptLen);
			if (ip6HHOptLen > 0) fprintf(sPktFile, "0x%02"B2T_PRIX8, ip6HHOpt[0]);
			for (i = 1; i < ip6HHOptLen; i++) fprintf(sPktFile, ";0x%02"B2T_PRIX8, ip6HHOpt[i]);
			fputc('\t', sPktFile);
			// print all IPv6 D options
			fprintf(sPktFile, "%d\t", ip6DOptLen);
			if (ip6DOptLen > 0) fprintf(sPktFile, "0x%02"B2T_PRIX8, ip6DOpt[0]);
			for (i = 1; i < ip6DOptLen; i++) fprintf(sPktFile, ";0x%02"B2T_PRIX8, ip6DOpt[i]);
			fputc('\t', sPktFile);
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
			fputs("\t\t", sPktFile); // ipOptLen, ipOpt
#endif // IPV6_ACTIVATE == 2
		} else { // IPv4
#if IPV6_ACTIVATE == 2
			fputs("\t\t\t\t", sPktFile); // ip6HHOptLen, ip6HHOpt, ip6DOptLen, ip6DOpt
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
			fprintf(sPktFile, "%d\t", ipOptLen);
			// print all IPv4 options
			if (ipOptLen > 0) fprintf(sPktFile, "0x%02"B2T_PRIX8, ipOpt[0]);
			for (i = 1; i < ipOptLen; i++) fprintf(sPktFile, ";0x%02"B2T_PRIX8, ipOpt[i]);
			fputc('\t', sPktFile);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
		}

		if (packet->layer4Type != L3_TCP || ipFrag & FRAGID_N) {
			// Print 8 tabs for seq, ack, tcpFStat, tcpFlags,
			// tcpAnomaly, tcpWin, tcpOptLen, tcpOpts
			fputs("\t\t\t\t\t\t\t\t", sPktFile);
#if SEQ_ACK_NUM == 1
			// Print 4 tabs for seqDiff, ackDiff, seqPktLen, ackPktLen
			fputs("\t\t\t\t", sPktFile);
#endif // SEQ_ACK_NUM == 1
		}
	}

	if (packet->layer4Type != L3_TCP || ipFrag & FRAGID_N) {
		tcpFlagsP->stat &= ~IP_INT_DISSTATE;
		return; // return if not TCP and not 1. fragment
	}

	// only TCP is processed here
	uint16_t tcpAnomaly = 0;

	// TCP flags and options
	const unsigned char tcpFlags = (unsigned char) *((char*)tcpHeader + 13);
	const unsigned char * const tcpOpt = ((uint8_t*)tcpHeader + 20);
	const int tcpOptLen = l4HDLen - 20;

	if (tcpOptLen > 0) { // consider all TCP options and set flag bits
		if (packet->snapL3Length >= (l3HDLen + l4HDLen) && l4Len >= l4HDLen) { // option field exists or crafted packet?
			for (i = 0; i < tcpOptLen && tcpOpt[i] > 0; i += (tcpOpt[i] > 1) ? tcpOpt[i+1] : 1) {
				if (tcpOpt[i] < 31) tcpFlagsP->tcpOptionsT |= 1U << tcpOpt[i];
				else tcpFlagsP->tcpOptionsT |= 1U << 31;
				if (tcpOpt[i] == 2) tcpFlagsP->tcpMssT = (tcpOpt[i+2] << 8) + tcpOpt[i+3]; // save the last MSS
				else if (tcpOpt[i] == 3) tcpFlagsP->tcpWST = tcpOpt[i+2]; // save the window scale TODO: max MSS, ave etc bandwidth and pipe length estimation
#if NAT_BT_EST == 1
				else if (tcpOpt[i] == 8) {
					const uint32_t *tcpTM = (uint32_t*)&tcpOpt[i+2];
					tcpFlagsP->tcpTmS = ntohl(*tcpTM);
					if (tcpFlagsP->tcpTmS > tcpFlagsP->tcpTmSLst) {
						tcpFlagsP->stat |= TCP_OPT_TM_DEC;
						tcpFlagsP->tcpTmSLst = tcpFlagsP->tcpTmS;
						if (!(tcpFlagsP->stat & TCP_OPT_INIT)) {
							tcpFlagsP->tcpTmSI = tcpFlagsP->tcpTmS;
							tcpFlagsP->tmOptFrstPkt = flowP->lastSeen;
							tcpFlagsP->stat |= TCP_OPT_INIT;
						}
						tcpFlagsP->tmOptLstPkt = flowP->lastSeen;
						tcpTM++;
						tcpFlagsP->tcpTmER = ntohl(*tcpTM);
					} else tcpFlagsP->stat |= TCP_OPT_TM_DEC;
				}
#endif // NAT_BT_EST == 1
				tcpFlagsP->tcpOptCntT++;
				if (tcpOpt[i+1] == 0) break;
			}
			tcpFlagsP->tcpOptPktCntT++;
		} else tcpAnomaly |= TCP_L4OPTCORRPT; // warning: crafted packet or option field not acquired
	}

	// TCP window size processing engine
	const uint32_t tcpWin = ntohs(tcpHeader->window) * (1U << tcpFlagsP->tcpWST);

#if WINDOWSIZE == 1
	tcpPktvCnt++;
	tcpFlagsP->tcpPktvCnt++;

	if (tcpWin < WINMIN) {
		winMinCnt++;
		tcpFlagsP->tcpWinMinCnt++;
	}

	if (!(tcpFlagsP->stat & TCP_WIN_INIT)) {
		tcpFlagsP->tcpWinMinT  = tcpWin;
		tcpFlagsP->tcpWinMaxT  = tcpWin;
		tcpFlagsP->tcpWinInitT = tcpWin; // save initial window size
		tcpFlagsP->tcpWinLastT = tcpWin; // first is the last Window
		tcpFlagsP->tcpWinAveT  = tcpWin; // start with average
		tcpFlagsP->stat |= TCP_WIN_INIT;
	}

	tcpFlagsP->tcpWinAveT = tcpFlagsP->tcpWinAveT * 0.7 + (float)tcpWin * 0.3; // IIR filter for winsize

	switch (tcpFlagsP->stat & TCP_WIN_UP) {

		case TCP_WIN_DWN: // tcpWin decreases
			if (tcpWin <= tcpFlagsP->tcpWinLastT) {
				if (tcpWin < tcpFlagsP->tcpWinLastT) {
					tcpFlagsP->tcpWdwnCntT++;
					if (tcpWin < tcpFlagsP->tcpWinMinT) tcpFlagsP->tcpWinMinT = tcpWin;
				}
			} else {
				tcpFlagsP->tcpWchgCntT++;
				tcpFlagsP->tcpWupCntT++;
				if (tcpWin > tcpFlagsP->tcpWinMaxT) tcpFlagsP->tcpWinMaxT = tcpWin;
				tcpFlagsP->stat |= TCP_WIN_UP;
			}
			break;

		case TCP_WIN_UP: // tcpWin increases
			if (tcpWin >= tcpFlagsP->tcpWinLastT) {
				if (tcpWin > tcpFlagsP->tcpWinLastT) {
					tcpFlagsP->tcpWupCntT++;
					if (tcpWin > tcpFlagsP->tcpWinMaxT) tcpFlagsP->tcpWinMaxT = tcpWin;
				}
			} else {
				tcpFlagsP->tcpWchgCntT++;
				tcpFlagsP->tcpWdwnCntT++;
				if (tcpWin < tcpFlagsP->tcpWinMinT) tcpFlagsP->tcpWinMinT = tcpWin;
				tcpFlagsP->stat &= ~TCP_WIN_UP;
			}
			break;
	}
#endif // WINDOWSIZE == 1

	// sequence number processing
#if SEQ_ACK_NUM == 1
	int32_t sd = 0;
	const uint32_t seq = ntohl(tcpHeader->seq);

	if ((tcpFlags & TH_ACK) == TH_ACK && tcpFlagsP->tcpSeqT != 0) { // problem at roll-over
		uint32_t seqDiff = seq - tcpFlagsP->tcpSeqT;
		sd = (int32_t)seqDiff;
		if (seq <= tcpFlagsP->tcpSeqT) {
			if (tcpFlagsPO && (tcpFlagsPO->stat & TCP_ACK_PKTLOSS)) { // same length than before then retransmit
				tcpFlagsP->tcpSeqFaultCntT++;
				if (pktInterDis > 1.0) {
					tcpAnomaly |= TCP_SEQ_RETRY; // retransmit
					totalTCPRetry++;
				}
				seqDiff = 0;
			} else if (seqDiff <= tcpWin) { // roll-over
				tcpFlagsP->tcpPSeqCntT++; // only good if all packets are ACKed
			} else {
				tcpAnomaly |= TCP_SEQ_OUTORDR; // mess in flow packet order, or packet loss at receiver
				seqDiff = 0;
			}
		} else {
			tcpFlagsP->tcpPSeqCntT++; // only good if all packets are ACKed
			if (seqDiff > tcpFlagsP->tcpPLstLen) tcpAnomaly |= TCP_SEQ_JMP;
		}

		tcpFlagsP->tcpOpSeqPktLength += seqDiff;

		if (tcpFlagsPO && tcpFlagsPO->tcpAckT > seq) {
			tcpAnomaly |= TCP_SEQ_PLSSMS; // mess in flow order, rather pcap packet loss
		}
	}

	tcpFlagsP->stat &= ~TCP_ACK_PKTLOSS; // reset packet loss on the wire

	// Acknowledge number processing

	int32_t ad = 0;
	const uint32_t ack = ntohl(tcpHeader->ack_seq);

	if ((tcpFlags & TH_ACK) == TH_ACK && tcpFlagsP->tcpAckT != 0) { // problem at roll-over
		uint32_t ackDiff = ack - tcpFlagsP->tcpAckT;
		ad = (int32_t)ackDiff;
		if (tcpFlagsP->tcpAckT == ack) {
			if (packet->snapL7Length == 0) {
				if (!(tcpFlagsP->stat & IP_INT_DISSTATE) && !(tcpFlags & (FIN|SYN|RST))) tcpAnomaly |= TCP_ACK_2;
				if (tcpFlagsPO && tcpFlagsPO->tcpSeqT >= ack && sd == 0) {
					tcpFlagsP->stat |= TCP_ACK_PKTLOSS; // packet loss
					tcpFlagsP->tcpAckFaultCntT++;
				}
			}
			ackDiff = 0;
		} else if (ack > tcpFlagsP->tcpAckT || ackDiff <= tcpWin) { // roll-over
			tcpFlagsP->tcpPAckCntT++; // only good if all packets are ACKed
		} else {
			tcpAnomaly |= TCP_ACK_OUTORDR; // mess in flow packet order
			ackDiff = 0;
		}

		tcpFlagsP->tcpOpAckPktLength += ackDiff;
	}
#endif // SEQ_ACK_NUM == 1

	// aggregated anomaly flags and RTT state machine simplest version @ init TCP handshake and ACK RTT

	if (tcpFlags == TH_NULL) tcpAnomaly |= TCP_NULL;
	else if ((tcpFlags & TH_ALL_FLAGS) == TH_XMAS) tcpAnomaly |= TCP_XMAS;
	else if ((tcpFlags & TH_ALL_FLAGS) == TH_ALL_FLAGS) tcpAnomaly |= TCP_XMAS;

	switch (tcpFlags & TH_ARSF) { // grab only relevant TCP flag bits

		case TH_SYN: // SYN
			if (tcpFlagsP->tcpRTTFlag == TCP_RTT_SYN_ST) tcpAnomaly |= TCP_SYN_RETRY; // SYN retransmit detected
			tcpFlagsP->tcpRTTFlag = TCP_RTT_SYN_ST;
			break;

#if RTT_ESTIMATE == 1
		case TH_ACK:
			if (!revFlowP) break;
			switch (tcpFlagsPO->tcpRTTFlag) {
				case TCP_RTT_SYN_ACK:
				case TCP_RTT_NO_SYN:
					tcpRTTemp = tcpFlagsP->tcpRTTtrip = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / 1000000.0f;
					if (tcpRTTemp < tcpFlagsP->tcpRTTAckTripMin) tcpFlagsP->tcpRTTAckTripMin = tcpRTTemp;
					if (tcpRTTemp > tcpFlagsP->tcpRTTAckTripMax) tcpFlagsP->tcpRTTAckTripMax = tcpRTTemp;
					tcpFlagsP->tcpRTTAckTripAve = tcpRTTemp;
					tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK_A;
					tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK_B;
					break;

				case TCP_RTT_ACK_A:
					tcpRTTemp = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / 1000000.0f;
					if (tcpRTTemp < tcpFlagsP->tcpRTTAckTripMin) tcpFlagsP->tcpRTTAckTripMin = tcpRTTemp;
					if (tcpRTTemp > tcpFlagsP->tcpRTTAckTripMax) tcpFlagsP->tcpRTTAckTripMax = tcpRTTemp;
					fac = 1.0 / tcpFlagsP->tcpPktCnt;
					tcpFlagsP->tcpRTTAckTripAve = tcpFlagsP->tcpRTTAckTripAve * (1.0 - fac) + tcpRTTemp * fac;
					tcpRTTemp -= tcpFlagsP->tcpRTTAckTripAve;
					tcpFlagsP->tcpRTTAckTripJitAve = tcpFlagsP->tcpRTTAckTripJitAve * (1.0 - fac) + tcpRTTemp * tcpRTTemp * fac;
					tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK_A;
					tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK_B | TCP_RTT_FLTCST;
					break;
			}
			break;
#endif // RTT_ESTIMATE == 1

		case TH_FIN_ACK:
			tcpAnomaly |= TCP_FIN_ACK;
			break;

		case TH_SYN_ACK:
			tcpAnomaly |= TCP_SYN_ACK;
#if RTT_ESTIMATE == 1
			if (!revFlowP) break;
			if (tcpFlagsPO->tcpRTTFlag == TCP_RTT_SYN_ST) tcpFlagsP->tcpRTTtrip = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / 1000000.0f;
			tcpFlagsP->tcpRTTAckTripAve = tcpFlagsP->tcpRTTtrip;
			tcpFlagsP->tcpRTTFlag = TCP_RTT_SYN_ACK;
#endif // RTT_ESTIMATE == 1
			break;

		case TH_RST_ACK:
			tcpAnomaly |= TCP_RST_ACK;
			break;

		case TH_SYN_FIN:
			tcpAnomaly |= TCP_SYN_FIN;
			break;

		case TH_SYN_FIN_RST:
			tcpAnomaly |= TCP_SYN_FIN_RST;
			break;

		case TH_RST_FIN:
			tcpAnomaly |= TCP_RST_FIN;
			break;
	}

//#if RTT_ESTIMATE == 1
//	if ((tcpFlags & TH_RST_FIN)) tcpFlagsP->tcpRTTFlag |= TCP_RTT_STOP;
//#endif // RTT_ESTIMATE == 1

 	if (sPktFile) {
		uint32_t seqR = ntohl(tcpHeader->seq);
		uint32_t ackR = ntohl(tcpHeader->ack_seq);

#if SPKTMD_SEQACKREL == 1
		seqR -= tcpFlagsP->tcpSeqI;
		ackR -= tcpFlagsP->tcpAckI;
#endif // SPKTMD_SEQACKREL == 1

		fprintf(sPktFile,
			"0x%08"B2T_PRIX32"\t0x%08"B2T_PRIX32"\t" // seq, ack
#if SEQ_ACK_NUM == 1
			"%"PRId32"\t%"PRId32"\t"                 // seqDiff, ackDiff
			"%"PRIu64"\t%"PRIu64"\t"                 // seqPktLen, ackPktLen
#endif // SEQ_ACK_NUM == 1
			"0x%04"B2T_PRIX16"\t0x%02"B2T_PRIX8"\t"  // tcpFStat, tcpFlags
			"0x%04"B2T_PRIX16"\t%"PRIu32"\t%d\t",    // tcpAnomaly, tcpWin, tcpOptLen
			seqR, ackR,
#if SEQ_ACK_NUM == 1
			sd, ad,
			tcpFlagsP->tcpOpSeqPktLength, tcpFlagsP->tcpOpAckPktLength,
#endif // SEQ_ACK_NUM == 1
			tcpFlagsP->stat, tcpFlags, tcpAnomaly, tcpWin, tcpOptLen);

		// print all TCP options
		if (tcpOptLen > 0) fprintf(sPktFile, "0x%02"B2T_PRIX8, tcpOpt[0]);
		for (i = 1; i < tcpOptLen; i++) fprintf(sPktFile, ";0x%02"B2T_PRIX8, tcpOpt[i]);
		fputc('\t', sPktFile);
	}

	if ((tcpFlags & TH_RST) == 0) {
#if SEQ_ACK_NUM == 1
		tcpFlagsP->tcpSeqT = seq;
		tcpFlagsP->tcpAckT = ack;
		tcpFlagsP->tcpPLstLen = packet->packetL7Length;
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
		tcpFlagsP->tcpWinLastT = tcpWin;
#endif // WINDOWSIZE == 1
	}

	// relative sequence are increased by one after SYN and FIN
#if SEQ_ACK_NUM == 1
	if (tcpFlags & TH_SYN || tcpFlags & TH_FIN) tcpFlagsP->tcpSeqT++;
#endif // SEQ_ACK_NUM == 1

	tcpFlagsP->tcpFlagsT |= tcpFlags;
	tcpFlagsP->tcpAnomaly |= tcpAnomaly;

#if FRAG_ANALYZE == 1
	if (revFlowP && (revFlowP->status & IPV4_FRAG_PENDING) && (tcpFlags & TH_RST_FIN)) tcpFlagsPO->ipFlagsT |= IP_FRAG_SEQERR;
#endif // FRAG_ANALYZE == 1

#if SCAN_DETECTOR == 1
	if (tcpFlagsP->pktCnt < TCP_SCAN_PMAX + 2) tcpFlagsP->pktCnt++;
#endif // SCAN_DETECTOR == 1

	tcpFlagsP->stat &= ~IP_INT_DISSTATE;
}


void onFlowTerminate(unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];
	tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];
	tcpFlagsFlow_t *tcpFlagsPO = NULL;

	ipFlgsA |= tcpFlagsP->ipFlagsT;
	tcpFlgsA |= tcpFlagsP->tcpAnomaly;

	const uint64_t revFlowInd = flowP->oppositeFlowIndex;
	if (revFlowInd != HASHTABLE_ENTRY_NOT_FOUND) {
		tcpFlagsPO = &tcpFlagsFlows[revFlowInd];

#if SCAN_DETECTOR == 1
		if (!(tcpFlagsPO->stat & TCP_SCAN_SU_DET) && (tcpFlagsP->pktCnt < 3 && tcpFlagsPO->pktCnt < 3) && (((tcpFlagsP->tcpFlagsT & (SYN|RST)) && (tcpFlagsPO->tcpAnomaly & (TCP_SYN_ACK|TCP_RST_ACK))) || (tcpFlagsP->tcpAnomaly & TCP_SCAN_FLAGS))) {
// && !(tcpFlagsP->tcpAnomaly & TCP_SYN_RETRY)) {
			tcpFlagsP->stat |= TCP_SCAN_SU_DET;
			tcpFlagsPO->stat |= TCP_SCAN_SU_DET;
			totalTCPSuccScans++;
		}
	} else if ((tcpFlagsP->pktCnt < TCP_SCAN_PMAX) && ((tcpFlagsP->tcpFlagsT & (SYN | RST)) || (tcpFlagsP->tcpAnomaly & TCP_SCAN_FLAGS))) {
			//&& !(tcpFlagsP->tcpAnomaly & TCP_SYN_RETRY)) {
		tcpFlagsP->stat |= TCP_SCAN_DET;
		totalTCPScans++;
#endif // SCAN_DETECTOR == 1
	}

#if FRAG_ANALYZE == 1
	if (flowP->status & IPV4_FRAG_ERR) tcpFlagsP->ipFlagsT |= IP_FRAG_SEQERR;
#endif // FRAG_ANALYZE == 1

#if SEQ_ACK_NUM == 1
	//if ((tcpFlagsP->tcpFlagsT & TH_FIN) && tcpFlagsP->tcpOpSeqPktLength > 0) tcpFlagsP->tcpOpSeqPktLength--;
	if ((tcpFlagsP->tcpFlagsT & TH_SYN) && tcpFlagsP->tcpOpSeqPktLength > 0) tcpFlagsP->tcpOpSeqPktLength--;
	if ((tcpFlagsP->tcpAnomaly & TH_FIN) && tcpFlagsP->tcpOpAckPktLength > 0) tcpFlagsP->tcpOpAckPktLength--;
	//if ((tcpFlagsP->tcpAnomaly & TH_SYN) && tcpFlagsP->tcpOpAckPktLength > 0) tcpFlagsP->tcpOpAckPktLength--;
#endif // SEQ_ACK_NUM == 1

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->stat, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipMinIDT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipMaxIDT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipMinTTLT, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipMaxTTLT, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipTTLChgT, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipTosT, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipFlagsT, sizeof(uint16_t));
	//outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipOptPktCntT, sizeof(uint16_t));

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipOptCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipCpClT, sizeof(uint8_t)); // bt_hex_8: copy,class
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ipOptionsT, sizeof(uint32_t)); // bt_hex_32: IP option
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ip6HHOptCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ip6DOptCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ip6HHOptionsT, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->ip6DOptionsT, sizeof(uint32_t));
#endif // IPV6_ACTIVATE > 0

#if SEQ_ACK_NUM == 1
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpPSeqCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpOpSeqPktLength, sizeof(uint64_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpSeqFaultCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpPAckCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpOpAckPktLength, sizeof(uint64_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpAckFaultCntT, sizeof(uint16_t));
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWinInitT, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWinAveT, sizeof(float));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWinMinT, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWinMaxT, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWdwnCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWupCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWchgCntT, sizeof(uint16_t));
	const float f1 = (tcpFlagsP->tcpPktvCnt) ? (float)tcpFlagsP->tcpWinMinCnt/(float)tcpFlagsP->tcpPktvCnt : 0.0;
	outputBuffer_append(main_output_buffer, (char*) &f1, sizeof(float));
#endif // WINDOWSIZE == 1

	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpFlagsT, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpAnomaly, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpOptPktCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpOptCntT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpOptionsT, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpMssT, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpWST, sizeof(uint8_t));

#if NAT_BT_EST == 1
	uint32_t i = 0;
	float g = 0;
	double f = 0;
	struct timeval tcpBTmS, tempT;
	if (tcpFlagsP->tcpOptionsT & TCPOPTTM) {
		timersub(&tcpFlagsP->tmOptLstPkt, &tcpFlagsP->tmOptFrstPkt, &tempT);
		g = tempT.tv_sec + tempT.tv_usec / 1000000.0;
		i = tcpFlagsP->tcpTmS - tcpFlagsP->tcpTmSI;
		if (i) {
			g /= (float)i;
			if (g < 0.002) g = 0.001;      // Cisco, Windows
			else if (g < 0.005) g = 0.004; // Linux
			else if (g < 0.02) g = 0.01;   // Linux
			else if (g < 0.2) g = 0.1;     // Solaris
			else if (g < 0.7) g = 0.1;     // OpenBSD
			else g = 1.0;
		} else { // default heuristics
			if (tcpFlagsP->ipMinTTLT > 128) g = 0.1;
			else if (tcpFlagsP->ipMinTTLT > 64) g = 0.001;
			else if (tcpFlagsP->ipMinTTLT > 32) g = 0.004;
			else g = 0.001;
		}
		f = (double)tcpFlagsP->tcpTmS * g;
	}

	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpTmS, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpTmER, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &g, sizeof(float));

	tempT.tv_sec = (uint64_t)f;
	tempT.tv_usec = (uint32_t)((f - tempT.tv_sec) * 1000000.0f);
	timersub(&tcpFlagsP->tmOptLstPkt, &tempT, &tcpBTmS);
	const uint64_t secs = tcpBTmS.tv_sec;
	outputBuffer_append(main_output_buffer, (char*) &secs, sizeof(uint64_t));
	i = tcpBTmS.tv_usec * 1000;
	outputBuffer_append(main_output_buffer, (char*) &i, sizeof(uint32_t));
#endif // NAT_BT_EST == 1

#if RTT_ESTIMATE == 1
	// tcpRTTAckTripMin, tcpRTTAckTripMax, tcpRTTAckTripAve
	outputBuffer_append(main_output_buffer, (char*) &tcpFlagsP->tcpRTTtrip, 4*sizeof(float));

	float dum = sqrt(tcpFlagsP->tcpRTTAckTripJitAve);
	outputBuffer_append(main_output_buffer, (char*) &dum, sizeof(float));

	if (!tcpFlagsPO) {
		dum = tcpFlagsP->tcpRTTtrip;
	} else if (flowP->status & L3FLOWINVERT) {
		dum = tcpFlagsP->tcpRTTAckTripAve + tcpFlagsPO->tcpRTTAckTripAve;
	} else {
		dum = tcpFlagsP->tcpRTTtrip + tcpFlagsPO->tcpRTTtrip;
	}
	outputBuffer_append(main_output_buffer, (char*) &dum, sizeof(float));

	if (tcpFlagsPO && (flowP->status & L3FLOWINVERT)) {
		dum = sqrt(tcpFlagsP->tcpRTTAckTripJitAve + tcpFlagsPO->tcpRTTAckTripJitAve);
	} else {
		dum = -1.0;
	}
	outputBuffer_append(main_output_buffer, (char*) &dum, sizeof(float));
#endif // RTT_ESTIMATE == 1

#endif // BLOCK_BUF == 0
}


void pluginReport(FILE *stream) {
	if (ipFlgsA)  T2_FPLOG(stream, "tcpFlags", "Aggregated ipFlags: 0x%04"B2T_PRIX16, ipFlgsA);
	if (tcpFlgsA) T2_FPLOG(stream, "tcpFlags", "Aggregated tcpAnomaly: 0x%04"B2T_PRIX16, tcpFlgsA);

	if (totalTCPScans || totalTCPSuccScans || totalTCPRetry) {
		char str1[64], str2[64], str3[64];
		T2_CONV_NUM(totalTCPScans, str1);
		T2_CONV_NUM(totalTCPSuccScans, str2);
		T2_CONV_NUM(totalTCPRetry, str3);
		T2_FPLOG(stream, "tcpFlags", "Number of TCP scans, succ scans, retries: %"PRIu64"%s, %"PRIu64"%s, %"PRIu64"%s", totalTCPScans, str1, totalTCPSuccScans, str2, totalTCPRetry, str3);
	}

	if (winMinCnt && tcpPktvCnt) {
		char str[64];
		T2_CONV_NUM(winMinCnt, str);
		T2_FPLOG(stream, "tcpFlags", "Number WinSz below %d: %"PRIu64"%s [%.2f%%]", WINMIN, winMinCnt, str, 100.0*winMinCnt/(double)tcpPktvCnt);
	}
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("tcpScan\ttcpSuccScan\ttcpRetries\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t", // Note the trailing tab (\t)
					totalTCPScans - totalTCPScans0, totalTCPSuccScans - totalTCPSuccScans0, totalTCPRetry - totalTCPRetry0);
			break;

		case T2_MON_PRI_REPORT:
			T2_FPLOG(stream, "tcpFlags", "Number of TCP scans, succ scans, retries: %"PRIu64", %"PRIu64", %"PRIu64, totalTCPScans - totalTCPScans0, totalTCPSuccScans - totalTCPSuccScans0, totalTCPRetry - totalTCPRetry0);
			break;

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	totalTCPScans0 = totalTCPScans;
	totalTCPSuccScans0 = totalTCPSuccScans;
	totalTCPRetry0 = totalTCPRetry;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
	free(tcpFlagsFlows);
}
