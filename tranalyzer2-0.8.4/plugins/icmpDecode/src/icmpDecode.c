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

#include "icmpDecode.h"


// Global variables

icmpFlow_t *icmpFlows;


// Static variables

static uint64_t numEchoRequests, numEchoRequests0;
static uint64_t numEchoReplies, numEchoReplies0;
static uint64_t numICMPPackets, numICMPPackets0;

#if IPV6_ACTIVATE > 0
static uint64_t numDestUnreach6[8];
static uint64_t numEcho6[2];
static uint64_t numParamProblem[3];
static uint64_t numPktTooBig;
static uint64_t numTimeExceeded6[2];
static uint64_t num_icmp6[255][8];
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static uint64_t numDestUnreach4[16];
static uint64_t numEcho4[2];
static uint64_t numRedirect[4];
static uint64_t numSourceQuench;
static uint64_t numTimeExceeded4[2];
static uint64_t numTraceroutes;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if ICMP_STATFILE == 1
#if IPV6_ACTIVATE > 0
// From 130 (MCAST_QUERY) to 158 (DUP_ADDR_CONF)
// Access with code - 130
static const char *icmp6_code_str[] = {
	"ICMP6_MCAST_QUERY",
	"ICMP6_MCAST_REP",
	"ICMP6_MCAST_DONE",
	"ICMP6_RTER_SOLICIT",
	"ICMP6_RTER_ADVERT",
	"ICMP6_NBOR_SOLICIT",
	"ICMP6_NBOR_ADVERT",
	"ICMP6_REDIRECT_MSG",
	"ICMP6_RTER_RENUM",
	"ICMP6_NODE_INFO_QUERY",
	"ICMP6_NODE_INFO_RESP",
	"ICMP6_INV_NBOR_DSM",
	"ICMP6_INV_NBOR_DAM",
	"ICMP6_MLD2",
	"ICMP6_ADDR_DISC_REQ",
	"ICMP6_ADDR_DISC_REP",
	"ICMP6_MOB_PREF_SOL",
	"ICMP6_MOB_PREF_ADV",
	"ICMP6_CERT_PATH_SOL",
	"ICMP6_CERT_PATH_ADV",
	"ICMP6_EXP_MOBI",
	"ICMP6_MRD_ADV",
	"ICMP6_MRD_SOL",
	"ICMP6_MRD_TERM",
	"ICMP6_FMIPV6",
	"ICMP6_RPL_CTRL",
	"ICMP6_ILNP_LOC_UP",
	"ICMP6_DUP_ADDR_REQ",
	"ICMP6_DUP_ADDR_CON"
};
static const char *icmp6_dest_unreach_code_str[] = {
	"ICMP6_NO_ROUTE"     , // 0
	"ICMP6_COMM_PROHIBIT", // 1
	"ICMP6_BEYOND_SCOPE" , // 2
	"ICMP6_ADDR_UNREACH" , // 3
	"ICMP6_PORT_UNREACH" , // 4
	"ICMP6_SR_FAILED"    , // 5
	"ICMP6_REJECT"       , // 6
	"ICMP6_ERROR_HDR"      // 7
};
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static const char *icmp_dest_unreach_code_str[] = {
	"ICMP_NET_UNREACH"   , //  0
	"ICMP_HOST_UNREACH"  , //  1
	"ICMP_PROT_UNREACH"  , //  2
	"ICMP_PORT_UNREACH"  , //  3
	"ICMP_FRAG_NEEDED"   , //  4
	"ICMP_SR_FAILED"     , //  5
	"ICMP_NET_UNKNOWN"   , //  6
	"ICMP_HOST_UNKNOWN"  , //  7
	"ICMP_HOST_ISOLATED" , //  8
	"ICMP_NET_ANO"       , //  9
	"ICMP_HOST_ANO"      , // 10
	"ICMP_NET_UNR_TOS"   , // 11
	"ICMP_HOST_UNR_TOS"  , // 12
	"ICMP_PKT_FILTERED"  , // 13
	"ICMP_PREC_VIOLATION", // 14
	"ICMP_PREC_CUTOFF"     // 15
};
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#endif // ICMP_STATFILE == 1


#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
#define ICMP_SPKTMD_PRI_NONE() if (sPktFile) fputs("\t\t\t", sPktFile)
#else // ICMP_PARENT == 0 || ETH_ACTIVATE == 2
#define ICMP_SPKTMD_PRI_NONE() if (sPktFile) fputs("\t\t", sPktFile)
#endif // ICMP_PARENT == 0 || ETH_ACTIVATE == 2

#define ICMP_PERCENT(num, tot) (100.0f * (num) / (float)(tot))
#define ICMP_LOG_TYPE_CODE(stream, type, code, num, tot) \
	fprintf((stream), "%s\t%s\t%"PRIu64"\t%5.3f\n", (type), (code), (num), ICMP_PERCENT((num), (tot)))


// Tranalyzer function

T2_PLUGIN_INIT("icmpDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(icmpFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*icmpFlows))))) {
		T2_PERR("icmpDecode", "failed to allocate memory for icmpFlows");
		exit(-1);
	}

	if (sPktFile) {
		fputs("icmpType\ticmpCode\t", sPktFile);
#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
		fputs("icmpPFindex\t", sPktFile);
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("ICMP Status", "icmpStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("ICMP type code count", "icmpTCcnt", 0, 1, bt_uint_8));

#if ICMP_TC_MD == 1
	bv = bv_append_bv(bv, bv_new_bv("ICMP type and code fields", "icmpType_Code", 1, 2, bt_uint_8, bt_uint_8));
#else // ICMP_TC_MD == 0
#if IPV6_ACTIVATE > 0
	bv = bv_append_bv(bv, bv_new_bv("ICMP Aggregated type H (>128), L(<32) & code bit field", "icmpBFTypH_TypL_Code", 0, 3, bt_hex_32, bt_hex_32, bt_hex_16));
	//bv = bv_append_bv(bv, bv_new_bv("ICMP Aggregated type and code", "icmpBFType_Code", 0, 2, bt_hex_64, bt_hex_16));
#else // IPV6_ACTIVATE == 0
	bv = bv_append_bv(bv, bv_new_bv("ICMP Aggregated type (<32) & code bit field", "icmpBFType_Code", 0, 2, bt_hex_32, bt_hex_16));
#endif // IPV6_ACTIVATE
#endif // ICMP_TC_MD == 0

	bv = bv_append_bv(bv, bv_new_bv("ICMP time/gateway", "icmpTmGtw", 0, 1, bt_hex_32));
	bv = bv_append_bv(bv, bv_new_bv("ICMP Echo reply/request success ratio", "icmpEchoSuccRatio", 0, 1, bt_float));

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	bv = bv_append_bv(bv, bv_new_bv("ICMP parent flowIndex", "icmpPFindex", 0, 1, bt_uint_64));
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2

	return bv;
}


void onFlowGenerated(packet_t *packet, unsigned long flowIndex) {
	icmpFlow_t * const icmpFlow = &icmpFlows[flowIndex];
	memset(icmpFlow, '\0', sizeof(*icmpFlow));

	// Only ICMP
	const uint_fast8_t proto = packet->layer4Type;
	if (proto != L3_ICMP && proto != L3_ICMP6) return;

	icmpFlow->stat |= ICMP_STAT_ICMP;

#if ICMP_FDCORR == 1
	// Only 1. frag packet will be processed
	if (!t2_is_first_fragment(packet)) return;

	uint_fast8_t j;
	if (PACKET_IS_IPV6(packet)) {
		j = (packet->layer4Header->icmpHeader.type != ICMP6_ECHO);
	} else { // IPv4
		j = (packet->layer4Header->icmpHeader.type != ICMP4_ECHO);
	}

	flow_t * const flowP = &flows[flowIndex];
	if (flowP->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		if ((flowP->status & L3FLOWINVERT) ^ j) {
			flowP->status ^= L3FLOWINVERT;
		}
	}
#endif // ICMP_FDCORR == 1
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	ICMP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {

	// Only 1. frag packet will be processed
	if (!t2_is_first_fragment(packet)) {
		ICMP_SPKTMD_PRI_NONE();
		return;
	}

	// Only ICMP
	icmpFlow_t * const icmpFlow = &icmpFlows[flowIndex];
	if (!icmpFlow->stat) {
		ICMP_SPKTMD_PRI_NONE();
		return;
	}

	const uint8_t type = packet->layer4Header->icmpHeader.type;
	const uint8_t code = packet->layer4Header->icmpHeader.code;

	// TODO if no code, do not print anything
	if (sPktFile) fprintf(sPktFile, "%"PRIu8"\t%"PRIu8"\t", type, code);

	numICMPPackets++; // count only unfragmented ICMP packets

#if ICMP_TC_MD == 1
	if (icmpFlow->numtc < ICMP_NUM) {
		icmpFlow->type[icmpFlow->numtc] = type;
		icmpFlow->code[icmpFlow->numtc] = code;
	}
#endif // ICMP_TC_MD == 1

	icmpFlow->numtc++;

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	uint64_t hasParent = 0;
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2

	if (PACKET_IS_IPV6(packet)) {

#if IPV6_ACTIVATE > 0

#if ICMP_TC_MD == 0
		if (type < 160) {
			if (type < ICMP6_NTYPE) icmpFlow->type_bfieldL |= (1U << type);
			else if (type >= ICMP6_ECHO) icmpFlow->type_bfieldH |= (1U << (type - ICMP6_ECHO));
		}
		if (code < ICMP6_NCODE) icmpFlow->code_bfield |= (1U << code);
#endif // ICMP_TC_MD == 0

		switch (type) {
			case ICMP6_ECHO:
				icmpFlow->echoReq++;
				numEcho6[0]++;
				numEchoRequests++;
				break;
			case ICMP6_ECHOREPLY:
				icmpFlow->echoRep++;
				numEcho6[1]++;
				numEchoReplies++;
				break;
			case ICMP6_DEST_UNREACH:
				if (code < 8) numDestUnreach6[code]++;
				SET_HAS_PARENT();
				break;
			case ICMP6_TIME_EXCEEDED:
				if (code < 2) numTimeExceeded6[code]++;
				else if (code < 8) num_icmp6[type][code]++;
				SET_HAS_PARENT();
				break;
			case ICMP6_PKT_TOO_BIG:
				numPktTooBig++;
				SET_HAS_PARENT();
				break;
			case ICMP6_PARAM_PROBLEM:
				if (code < 3) numParamProblem[code]++;
				else if (code < 8) num_icmp6[type][code]++;
				SET_HAS_PARENT();
				break;
			default:
				if (type < 255 && code < 8) num_icmp6[type][code]++;
				break;
		}
#endif // IPV6_ACTIVATE > 0

	} else { // IPv4

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if ICMP_TC_MD == 0
		if (type < ICMP4_NTYPE) icmpFlow->type_bfieldL |= (1U << type);
		if (code < ICMP4_NCODE) icmpFlow->code_bfield |= (1U << code);
#endif // ICMP_TC_MD == 0

		// count code

		switch (type) {
			case ICMP4_ECHO:
				numEchoRequests++;
				numEcho4[0]++;
				icmpFlow->echoReq++;
				if (!memcmp(packet->layer7Header + 6, "WANG2", 5)) {
					icmpFlow->stat |= ICMP_STAT_WANG;
				}
				break;
			case ICMP4_ECHOREPLY:
				numEchoReplies++;
				numEcho4[1]++;
				icmpFlow->echoRep++;
				break;
			case ICMP4_SOURCE_QUENCH:
				numSourceQuench++;
				SET_HAS_PARENT();
				break;
			case ICMP4_DEST_UNREACH:
				if (code < 16) numDestUnreach4[code]++;
				SET_HAS_PARENT();
				break;
			case ICMP4_TIME_EXCEEDED:
				if (code < 2) numTimeExceeded4[code]++;
				SET_HAS_PARENT();
				break;
			case ICMP4_REDIRECT:
				if (code < 4) numRedirect[code]++;
				SET_HAS_PARENT();
				break;
			//case ICMP4_TIMESTAMP:
			//	icmpFlow->tmStmp = packet->layer4Header->icmpHeader.gateway;
			//	break;
			//case ICMP4_TIMESTAMPREPLY:
			//	icmpFlow->tmStmp = packet->layer4Header->icmpHeader.gateway;
			//	break;
			case ICMP4_TRACEROUTE:
				numTraceroutes++;
				break;
			default:
				break;
		}

		icmpFlow->tmStmp = packet->layer4Header->icmpHeader.un.gateway;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

	}

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	if (!hasParent) {
		if (sPktFile) fputc('\t', sPktFile);
	} else {
		uint8_t proto;
		uint8_t l7off;
		flow_t parent = {};
		const flow_t * const flowP = &flows[flowIndex];
		parent.vlanID = flowP->vlanID;
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
		parent.ethType = packet->layer2Type;
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
		if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
			const ip6Header_t * const ip = (ip6Header_t*)(packet->layer7Header);
			proto = ip->next_header;
			l7off = 40;
			parent.srcIP = ip->ip_src;
			parent.dstIP = ip->ip_dst;
#endif // IPV6_ACTIVATE > 0
		} else { // IPv4
			const ipHeader_t * const ip = (ipHeader_t*)(packet->layer7Header);
			proto = ip->ip_p;
			l7off = (IP_HL(ip) << 2);
			parent.srcIP.IPv4 = ip->ip_src;
			parent.dstIP.IPv4 = ip->ip_dst;
		}
		parent.layer4Protocol = proto;
		switch (proto) {
			case L3_TCP:
			case L3_UDP:
			case L3_UDPLITE: {
				const tcpHeader_t * const tcp = (tcpHeader_t*) ((u_char*)packet->layer7Header + l7off);
				parent.srcPort = ntohs(tcp->source);
				parent.dstPort = ntohs(tcp->dest);
				break;
			}
			case L3_ICMP:
			case L3_ICMP6:
				// srcPort = dstPort = 0
				break;
			default:
				break;
		}
		hasParent = hashTable_lookup(mainHashMap, (char*)&parent.srcIP);
		if (hasParent == HASHTABLE_ENTRY_NOT_FOUND) {
			if (sPktFile) fputc('\t', sPktFile);
		} else {
			icmpFlow->pfi = flows[hasParent].findex;
			if (sPktFile) fprintf(sPktFile, "%"PRIu64"\t", icmpFlow->pfi);
		}
	}
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	const icmpFlow_t * const icmpFlow = &icmpFlows[flowIndex];

	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->stat, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->numtc, sizeof(uint8_t));
#if ICMP_TC_MD == 0
#if IPV6_ACTIVATE > 0
	//const uint64_t bf = ((uint64_t)icmpFlow->type_bfieldH << 32) | icmpFlow->type_bfieldL;
	//outputBuffer_append(main_output_buffer, (char*) &bf, sizeof(uint64_t));
	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->type_bfieldH, sizeof(uint32_t));
#endif // IPV6_ACTIVATE > 0
	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->type_bfieldL, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->code_bfield, sizeof(uint16_t));
#elif ICMP_TC_MD == 1
	const uint32_t j = MIN(icmpFlow->numtc, ICMP_NUM);
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (uint_fast32_t i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &icmpFlow->type[i], sizeof(uint8_t));
		outputBuffer_append(main_output_buffer, (char*) &icmpFlow->code[i], sizeof(uint8_t));
	}
#endif // ICMP_TC_MD == 1

	outputBuffer_append(main_output_buffer, (char*) &icmpFlow->tmStmp, sizeof(uint32_t));

	float tmp = 0;
	const unsigned long revFlowIndex = flows[flowIndex].oppositeFlowIndex;
	if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		const icmpFlow_t * const icmpFlowRev = &icmpFlows[revFlowIndex];
		if (icmpFlow->echoReq != 0) tmp = (float)icmpFlowRev->echoRep / (float)icmpFlow->echoReq;
		else if (icmpFlowRev->echoRep != 0) tmp = -1.0f * (float)icmpFlowRev->echoRep;
	}
	outputBuffer_append(main_output_buffer, (char*) &tmp, sizeof(float));

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	outputBuffer_append(main_output_buffer, (char*)&icmpFlow->pfi, sizeof(uint64_t));
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	const uint_fast64_t numICMP4 = numPacketsL3[L3_ICMP];
	if (numICMP4) {
		T2_FPLOG_NUMP(stream, "icmpDecode", "Number of ICMP echo request packets", numEcho4[0], numICMP4);
		T2_FPLOG_NUMP(stream, "icmpDecode", "Number of ICMP echo reply packets", numEcho4[1], numICMP4);
		const float tmp4 = (numEcho4[0] != 0) ? numEcho4[1] / (float)numEcho4[0] : 0.0f;
		if (tmp4) T2_FPLOG(stream, "icmpDecode", "ICMP echo reply / request ratio: %.2f", tmp4);
	}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
	const uint_fast64_t numICMP6 = numPacketsL3[L3_ICMP6];
	if (numICMP6) {
		T2_FPLOG_NUMP(stream, "icmpDecode", "Number of ICMPv6 echo request packets", numEcho6[0], numICMP6);
		T2_FPLOG_NUMP(stream, "icmpDecode", "Number of ICMPv6 echo reply packets", numEcho6[1], numICMP6);
		const float tmp6 = (numEcho6[0] != 0) ? numEcho6[1] / (float)numEcho6[0] : 0.0f;
		if (tmp6) T2_FPLOG(stream, "icmpDecode", "ICMPv6 echo reply / request ratio: %.2f", tmp6);
	}
#endif // IPV6_ACTIVATE > 0
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("icmpPkts\ticmpEchoReq\ticmpEchoRep\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t", // Note the trailing tab (\t)
					numICMPPackets-numICMPPackets0, numEchoRequests-numEchoRequests0, numEchoReplies-numEchoReplies0);
			break;

		case T2_MON_PRI_REPORT:
			T2_PLOG_DIFFNUMP(stream, "icmpDecode", "Number of ICMP echo request packets", numEchoRequests, numICMPPackets);
			T2_PLOG_DIFFNUMP(stream, "icmpDecode", "Number of ICMP echo reply packets", numEchoReplies, numICMPPackets);
			break;

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	numICMPPackets0 = numICMPPackets;
	numEchoRequests0 = numEchoRequests;
	numEchoReplies0 = numEchoReplies;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
#if ICMP_STATFILE == 1
	// open ICMP statistics file
	FILE *file = t2_open_file(baseFileName, ICMP_SUFFIX, "w");
	if (UNLIKELY(!file)) exit(-1);

	const uint_fast64_t numICMP4 = numPacketsL3[L3_ICMP];
	const uint_fast64_t numICMP6 = numPacketsL3[L3_ICMP6];
	const uint_fast64_t totalICMP = numICMP4 + numICMP6;

	T2_FLOG_NUMP0(file, "Total number of ICMP messages", totalICMP, numPackets);
	fputc('\n', file);

	T2_FLOG_NUMP(file, "Number of ICMP packets", numICMP4, numPackets);
	T2_FLOG_NUMP(file, "Number of ICMPv6 packets", numICMP6, numPackets);
	fputc('\n', file);

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	const float tmp4 = (numEcho4[0] != 0) ? numEcho4[1] / (float)numEcho4[0] : 0.0f;
	if (tmp4) fprintf(file, "ICMP echo reply / request ratio: %5.3f\n", tmp4);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
	const float tmp6 = (numEcho6[0] != 0) ? numEcho6[1] / (float)numEcho6[0] : 0.0f;
	if (tmp6) fprintf(file, "ICMPv6 echo reply / request ratio: %5.3f\n", tmp6);
#endif // IPV6_ACTIVATE > 0

	fputc('\n', file);

	uint_fast32_t i;

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	fputs("# ICMP Type\tCode\tPackets\tPercentage\n", file);

	ICMP_LOG_TYPE_CODE(file, "ICMP_ECHOREQUEST"  , ICMP_NOCODE, numEcho4[0]    , numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_ECHOREPLY"    , ICMP_NOCODE, numEcho4[1]    , numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_SOURCE_QUENCH", ICMP_NOCODE, numSourceQuench, numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_TRACEROUTE"   , ICMP_NOCODE, numTraceroutes , numICMP4);

	for (i = 0; i < 16; i++) {
		ICMP_LOG_TYPE_CODE(file, "ICMP_DEST_UNREACH", icmp_dest_unreach_code_str[i], numDestUnreach4[i], numICMP4);
	}

	ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_NET"    , numRedirect[0], numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_HOST"   , numRedirect[1], numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_NETTOS" , numRedirect[2], numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_HOSTTOS", numRedirect[3], numICMP4);

	ICMP_LOG_TYPE_CODE(file, "ICMP_TIME_EXCEEDED", "ICMP_EXC_TTL"     , numTimeExceeded4[0], numICMP4);
	ICMP_LOG_TYPE_CODE(file, "ICMP_TIME_EXCEEDED", "ICMP_EXC_FRAGTIME", numTimeExceeded4[1], numICMP4);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE == 2
	fputc('\n', file);
#endif // IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
	fputs("# ICMPv6 Type\tCode\tPackets\tPercentage\n", file);

	ICMP_LOG_TYPE_CODE(file, "ICMP6_ECHOREQUEST", ICMP_NOCODE, numEcho6[0] , numICMP6);
	ICMP_LOG_TYPE_CODE(file, "ICMP6_ECHOREPLY"  , ICMP_NOCODE, numEcho6[1] , numICMP6);
	ICMP_LOG_TYPE_CODE(file, "ICMP6_PKT_TOO_BIG", ICMP_NOCODE, numPktTooBig, numICMP6);

	for (i = 0; i < 8; i++) {
		ICMP_LOG_TYPE_CODE(file, "ICMP6_DEST_UNREACH", icmp6_dest_unreach_code_str[i], numDestUnreach6[i], numICMP6);
	}

	ICMP_LOG_TYPE_CODE(file, "ICMP6_TIME_EXCEEDED", "ICMP6_EXC_HOPS"    , numTimeExceeded6[0], numICMP6);
	ICMP_LOG_TYPE_CODE(file, "ICMP6_TIME_EXCEEDED", "ICMP6_EXC_FRAGTIME", numTimeExceeded6[1], numICMP6);

	ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_ERR_HDR"        , numParamProblem[0], numICMP6);
	ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_UNRECO_NEXT_HDR", numParamProblem[1], numICMP6);
	ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_UNRECO_IP6_OPT" , numParamProblem[2], numICMP6);

	uint_fast32_t j;
	for (i = 0; i < 255 ; i++) {
		for (j = 0; j < 8 ; j++) {
			if (num_icmp6[i][j]) {
				if (i >= ICMP6_MCAST_QUERY && i <= ICMP6_DUP_ADDR_CONF) {
					if (j >= 138 && j <= 140) { // codes 138, 139 and 140 have types
						fprintf(file, "%s\t%"PRIuFAST32"\t%"PRIu64"\t%5.3f\n", icmp6_code_str[i-ICMP6_MCAST_QUERY],
								j, num_icmp6[i][j], ICMP_PERCENT(num_icmp6[i][j], numICMP6));
					} else {
						ICMP_LOG_TYPE_CODE(file, icmp6_code_str[i-ICMP6_MCAST_QUERY], ICMP_NOCODE, num_icmp6[i][j], numICMP6);
					}
				} else {
					fprintf(file, "%"PRIuFAST32"\t%"PRIuFAST32"\t%"PRIu64"\t%5.3f\n", i, j,
							 num_icmp6[i][j], ICMP_PERCENT(num_icmp6[i][j], numICMP6));
				}
			}
		}
	}

#endif // IPV6_ACTIVATE > 0

	fclose(file);
#endif // ICMP_STATFILE == 1

	free(icmpFlows);
}
