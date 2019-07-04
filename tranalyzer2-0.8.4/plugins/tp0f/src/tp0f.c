/*
 * tp0f.c
 *
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

#include "tp0f.h"
#include "tp0flist.h"


// plugin variables

tp0fFlow_t *tp0fFlows;


// Static variables

#if TP0FRULES == 1
static uint64_t tp0fnumPkts;
static tp0flist_table_t *tp0flist_table;
#if TP0FHSH == 1
static hashMap_t *ipP0fHashMap;
static uint32_t *ipP0fClass;
static uint8_t tp0fAStat;
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1

static const char *osCl[] = {
	"!", "win", "unix", "other"
};
static const char *progCl[] = {
	"unknown", "Windows", "Linux", "OpenBSD", "FreeBSD",
	"Solaris", "MacOSX" , "HP-UX", "OpenVMS", "iOS",
	"BaiduSpider", "Blackberry", "NeXTSTEP", "Nintendo",
	"NMap", "tp0f", "Tru64"
};
static const char *verCl[] = {
	"unknown", "NT", "XP", "7", "8", "10",
	"10.9 or newer (sometimes iPhone or iPad)",
	"10.x", "11.x", "2.0", "2.2.x", "2.2.x-3.x",
	"2.2.x-3.x (barebone)", "2.2.x-3.x (no timestamps)",
	"2.2.x (loopback)", "2.4-2.6", "2.4.x", "2.4.x-2.6.x",
	"2.4.x (loopback)", "2.6.x", "2.6.x (Google crawler)",
	"2.6.x (loopback)", "3.11 and newer", "3.1-3.10", "3DS",
	"3.x", "3.x (loopback)", "4.x", "4.x-5.x", "5.x", "6",
	"7 or 8", "7 (Websense crawler)", "7.x", "8", "8.x",
	"8.x-9.x", "9.x", "9.x or newer", "(Android)",
	"iPhone or iPad", "NT kernel", "NT kernel 5.x",
	"NT kernel 6.x", "OS detection", "sendsyn utility",
	"SYN scan", "Wii"
};


// Tranalyzer functions

T2_PLUGIN_INIT("tp0f", "0.8.4", 0, 8);


void initialize() {
	// allocate struct for all flows and initialise to 0
	if (UNLIKELY(!(tp0fFlows = calloc(mainHashMap->hashChainTableSize, sizeof(tp0fFlow_t))))) {
		T2_PERR("tp0f", "failed to allocate memory for tp0f_flows");
		exit(-1);
	}

#if TP0FRULES == 1
	const size_t plen = pluginFolder_len;
	const size_t len = plen + sizeof(TP0FL34FILE) + 1;
	if (UNLIKELY(len > MAX_FILENAME_LEN)) {
		T2_PERR("tp0f", "filename too long");
		free(tp0fFlows);
		exit(-1);
	}

	char filename[len+1];
	strncpy(filename, pluginFolder, plen+1);
	strcat(filename, TP0FL34FILE);

	tp0flist_table = malloc(sizeof(tp0flist_table_t));
	if (UNLIKELY(!tp0flist_init(tp0flist_table, filename))) {
		free(tp0fFlows);
		exit(-1);
	}

#if TP0FHSH == 1
#if IPV6_ACTIVATE == 2
	ipP0fHashMap = hashTable_init(1.0f, sizeof(ipVAddr_t), "tp0f");
#elif IPV6_ACTIVATE == 1
	ipP0fHashMap = hashTable_init(1.0f, sizeof(ipAddr_t), "tp0f");
#else // IPV6_ACTIVATE == 0
	ipP0fHashMap = hashTable_init(1.0f, sizeof(uint32_t), "tp0f");
#endif // IPV6_ACTIVATE
	if (UNLIKELY(!ipP0fHashMap)) {
		T2_PERR("tp0f", "failed to initialise ipP0fHashMap");
		free(tp0fFlows);
		free(tp0flist_table);
		exit(-1);
	}

	ipP0fClass = calloc(ipP0fHashMap->hashChainTableSize, sizeof(uint32_t));
	if (UNLIKELY(!ipP0fClass)) {
		T2_PERR("tp0f", "failed to allocate memory for ipP0fClass");
		free(tp0fFlows);
		hashTable_destroy(ipP0fHashMap);
		free(tp0flist_table);
		exit(-1);
	}
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("tp0f status", "tp0fStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("tp0f ttl distance", "tp0fDis", 0, 1, bt_uint_8));
#if TP0FRC == 1
	bv = bv_append_bv(bv, bv_new_bv("tp0f rule number", "tp0fRN", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("tp0f class", "tp0fClass", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("tp0f program", "tp0fProg", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("tp0f version", "tp0fVer", 0, 1, bt_uint_8));
#endif // TP0FRC == 1
	bv = bv_append_bv(bv, bv_new_bv("tp0f class name", "tp0fClName", 0, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("tp0f program name", "tp0fPrName", 0, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("tp0f Version name", "tp0fVerName", 0, 1, bt_string_class));

	return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
	tp0fFlow_t * const tp0fFlowP = &tp0fFlows[flowIndex];
	memset(tp0fFlowP, '\0', sizeof(tp0fFlow_t));

	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

	uint_fast8_t ittl, ipDF/*, ipID*/;
	int l3Len;
	if (PACKET_IS_IPV6(packet)) {
		const ip6Header_t * const ip6Header = (ip6Header_t*)packet->layer3Header;
		l3Len = ntohs(ip6Header->payload_len) + 40;
		ittl = ip6Header->ip_ttl;
		ipDF = IPF_DF;
		//ipID = 1;
	} else { // IPv4
		const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
		l3Len = ntohs(ipHeader->ip_len);
		ittl = ipHeader->ip_ttl;
		ipDF = *((uint8_t*)ipHeader + 6) & IPF_DF;
		//ipID = ntohs(ipHeader->ip_id);
	}

	const uint_fast8_t l4Type = packet->layer4Type;

	tp0fFlowP->clss = 3;
	if (ittl > 128) {
		tp0fFlowP->dist = 255 - ittl;
		ittl = 255;
		tp0fFlowP->clss = 2;
		if (l4Type == 1) tp0fFlowP->prog = 4;
		else tp0fFlowP->prog = 5;
	} else if (ittl > 64) {
		tp0fFlowP->dist = 128 - ittl;
		ittl = 128;
		tp0fFlowP->clss = 1;
		tp0fFlowP->prog = 1;
	} else if (ittl > 32) {
		tp0fFlowP->dist = 64 - ittl;
		ittl = 64;
		tp0fFlowP->clss = 2;
		tp0fFlowP->prog = 2;
	} else if (ittl > 16) {
		tp0fFlowP->dist = 32 - ittl;
		ittl = 32;
		tp0fFlowP->clss = 1;
		tp0fFlowP->prog = 1;
	} else if (ittl > 8) {
		tp0fFlowP->dist = 16 - ittl;
		ittl = 16;
	}

	if (l4Type != L3_TCP) {
		// TODO check whether IP was already classified in ipP0fHashMap
		return;
	}

	const tcpHeader_t * const tcpHeader = (tcpHeader_t*) packet->layer4Header;
	const uint8_t tcpFlags = (unsigned char) *((char*)tcpHeader + 13);
	if (!((tcpFlags & 0x07) == TH_SYN)) return;

	uint32_t tcpWin = ntohs(tcpHeader->window);
	if (ittl == 255) {
		if (tcpWin == 4128) {
			tp0fFlowP->prog = 9;
		}
	} else if (ittl == 128) {
		if (tcpWin == 65535) tp0fFlowP->ver = 2;
		else if (tcpWin == 8192) tp0fFlowP->ver = 3;
	} else if (ittl == 64) {
		if (tcpWin == 65535) {
			tp0fFlowP->prog = 4;
		}
	}

#if TP0FRULES == 1
	const tp0flist_t * const tp0fLc = tp0flist_table->tp0flists, *tp0fLci;
	uint_fast32_t i;
#if TP0FHSH == 1
#if IPV6_ACTIVATE == 2
	const ipVAddr_t srcIP = {
		.ver = (packet->status & L2_IPV6) ? 6 : 4,
		.addr = flowP->srcIP
	};
#elif IPV6_ACTIVATE == 1
	const ipAddr_t srcIP = flowP->srcIP;
#else // IPV6_ACTIVATE == 0
	const uint32_t srcIP = (uint32_t)flowP->srcIP.IPv4.s_addr;
#endif // IPV6_ACTIVATE == 0
	unsigned long ipP0fIndex;
	if ((ipP0fIndex = hashTable_lookup(ipP0fHashMap, (char*)&srcIP)) != HASHTABLE_ENTRY_NOT_FOUND) {
		tp0fFlowP->stat = (ipP0fClass[ipP0fIndex] & 0x00ff) | TP0F_ASN;
		i = ipP0fClass[ipP0fIndex] >> 8;
		tp0fFlowP->rID = tp0fLc[i-1].id;
		tp0fFlowP->clss = tp0fLc[i].nclass;
		tp0fFlowP->prog = tp0fLc[i].nprog;
		tp0fFlowP->ver = tp0fLc[i].nver;
		tp0fnumPkts++;
		return;
	}
#endif // TP0FHSH == 1
	int tcpOptCnt = 0, j = 0;
	uint32_t tWS, tcpW;
	uint16_t tcpMss = 0;
	uint8_t tcpWS = 0;
	uint8_t tcpOpt[TCPOPTMAX];
	const uint16_t l4HDLen = packet->l4HdrLen;
	const uint_fast32_t tOptLen = l4HDLen - 20;
	const uint_fast16_t l3HDLen = packet->l3HdrLen;
	const int l4Len = l3Len - l3HDLen;
	const uint8_t * const tOpt = ((uint8_t*)tcpHeader + 20);
	const uint8_t l7LenSW = (packet->snapL7Length) ? 1 : 0;
	uint8_t tcpF;

	if (l4HDLen - 20 > 0) { // consider all tcpOptions and set flag bits
		if (packet->snapL3Length >= (l3HDLen + l4HDLen) && l4Len >= l4HDLen) { // option field exists or crafted packet?
			for (i = 0; i < tOptLen && tOpt[i] > 0; i += (tOpt[i] > 1) ? tOpt[i+1] : 1) {
				tcpOpt[j++] = tOpt[i] & 0x1F;
				if (tcpOptCnt < TCPOPTMAX) {
					if (tOpt[i] == 2) tcpMss = (tOpt[i+2] << 8) + tOpt[i+3]; // save the last MSS
					else if (tOpt[i] == 3) tcpWS = tOpt[i+2]; // save the Window Scale
				}
				tcpOptCnt++;
				if (tOpt[i+1] == 0) break;
			}
		} else {
			tp0fFlowP->stat |= TP0F_L4OPTBAD; // warning: crafted packet or option field not acquired
			return;
		}
	}

	j = MIN(tcpOptCnt, TCPOPTMAX);

	tcpWin *= (1 << tcpWS);
	tcpF = tcpFlags & 0x17;
	if (tcpF == TH_SYN) {
		for (i = 0; i < tp0flist_table->count; i++) {
			tp0fLci = &tp0fLc[i];
			tcpF = tp0fLci->tcpF & TH_SYN_ACK;
			if (tcpF != TH_SYN) continue;
			if (tcpOptCnt != tp0fLci->ntcpopt || ittl != tp0fLci->ittl) continue;
			tcpW = tp0fLci->wsize;
			if (tp0fLci->clst & CLST_MSS_DC) {
				if (tp0fLci->clst & CLST_WS_DC) tWS = 1 << tcpWS;
				else tWS = 1 << tp0fLci->ws;
				if (tp0fLci->clst & CLST_MSS) tcpW = tWS * tp0fLci->wsize * tcpMss;
				if (tp0fLci->clst & CLST_MTU) tcpW = tWS * tp0fLci->wsize * (tcpMss + 40);
			} else {
				if (tp0fLci->mss != tcpMss) continue;
			}
			if (tcpWin != tcpW) continue;
			if ((tp0fLci->clst & CLST_PLD) == 0) {
				if (tp0fLci->pldl != l7LenSW) continue;
			}
			if ((tp0fLci->ipF & IPF_DF) == ipDF) {
				if (memcmp(tcpOpt, tp0fLci->tcpopt, j)) continue;
				tp0fFlowP->rID = tp0fLc[i].id;
				tp0fFlowP->stat |= TP0F_TSSIG;
				tp0fnumPkts++;
				break;
			}
		}
	} else if (tcpF == TH_SYN_ACK) {
		for (i = 0; i < tp0flist_table->count; i++) {
			tp0fLci = &tp0fLc[i];
			tcpF = tp0fLci->tcpF & TH_SYN_ACK;
			if (tcpF != TH_SYN_ACK) continue;
			if (tcpOptCnt != tp0fLci->ntcpopt || ittl != tp0fLci->ittl) continue;
			tcpW = tp0fLci->wsize;
			if (tp0fLci->clst & CLST_MSS_DC) {
				if (tp0fLci->clst & CLST_WS_DC) tWS = 1 << tcpWS;
				else tWS = 1 << tp0fLci->ws;
				if (tp0fLci->clst & CLST_MSS) tcpW = tWS * tp0fLci->wsize * tcpMss;
				if (tp0fLci->clst & CLST_MTU) tcpW = tWS * tp0fLci->wsize * (tcpMss + 40);
			} else {
				if (tp0fLci->mss != tcpMss) continue;
			}
			if (tcpWin != tcpW) continue;
			if ((tp0fLci->clst & CLST_PLD) == 0) {
				if (tp0fLci->pldl != l7LenSW) continue;
			}
			if ((tp0fLci->ipF & IPF_DF) == ipDF) {
				if (memcmp(tcpOpt, tp0fLci->tcpopt, j)) continue;
				tp0fFlowP->rID = tp0fLc[i].id;
				tp0fFlowP->stat |= TP0F_TSASIG;
				tp0fnumPkts++;
				break;
			}
		}
	}

#if TP0FHSH == 1
	if (tp0fFlowP->stat & (TP0F_TSSIG | TP0F_TSASIG)) {
		ipP0fIndex = hashTable_insert(ipP0fHashMap, (char*)&srcIP);
		if (ipP0fIndex == HASHTABLE_ENTRY_NOT_FOUND) {
			if (!tp0fAStat) {
				tp0fAStat = 1;
				T2_PWRN("tp0fDecode", "%s HashMap full", ipP0fHashMap->name);
			}
			return;
		} else {
			if (tp0fAStat) {
				T2_PWRN("tp0fDecode", "%s HashMap free", ipP0fHashMap->name);
				tp0fAStat = 0;
			}
		}
		ipP0fClass[ipP0fIndex] = (tp0fFlowP->rID << 8) | tp0fFlowP->stat;
	}
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	tp0fFlow_t * const tp0fFlowP = &tp0fFlows[flowIndex];

#if TP0FRULES == 1
	const tp0flist_t * const tp0fLc = tp0flist_table->tp0flists;
	if (tp0fFlowP->rID) {
		const uint_fast8_t i = tp0fFlowP->rID - 1;
		tp0fFlowP->clss = tp0fLc[i].nclass;
		tp0fFlowP->prog = tp0fLc[i].nprog;
		tp0fFlowP->ver = tp0fLc[i].nver;
	}
#endif // TP0FRULES == 1

	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->stat, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->dist, sizeof(uint8_t));
#if TP0FRC == 1
	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->rID, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->clss, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->prog, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tp0fFlowP->ver, sizeof(uint8_t));
#endif // TP0FRC == 1
	outputBuffer_append(main_output_buffer, osCl[tp0fFlowP->clss], strlen(osCl[tp0fFlowP->clss]) + 1);
	outputBuffer_append(main_output_buffer, progCl[tp0fFlowP->prog], strlen(progCl[tp0fFlowP->prog]) + 1);
	outputBuffer_append(main_output_buffer, verCl[tp0fFlowP->ver], strlen(verCl[tp0fFlowP->ver]) + 1);
}
#endif // BLOCK_BUF == 0


#if TP0FRULES == 1
void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "tp0f", "Number of rule matches", tp0fnumPkts, numPackets);
}
#endif // TP0FRULES == 1


void onApplicationTerminate() {
	free(tp0fFlows);

#if TP0FRULES == 1
	if (tp0flist_table) {
		free(tp0flist_table->tp0flists);
		free(tp0flist_table);
	}
#if TP0FHSH== 1
	hashTable_destroy(ipP0fHashMap);
	free(ipP0fClass);
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
}
