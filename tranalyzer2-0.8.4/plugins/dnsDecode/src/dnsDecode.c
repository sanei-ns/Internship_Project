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

#include "dnsDecode.h"
#include "t2utils.h"

#if MAL_TEST == 1
#include "malsite.h"
#endif // MAL_TEST == 1


// Global plugin variables

dnsFlow_t *dnsFlow;


// Static variables

#if MAL_TEST == 1
static malsitetable_t *malsite_table;
static uint64_t dnsAlarms;
#endif // MAL_TEST == 1

static uint16_t dnsAStat;
static uint64_t totalDnsPktCnt, totalDnsPktCnt0;
static uint64_t totalDnsQPktCnt, totalDnsQPktCnt0;
static uint64_t totalDnsRPktCnt, totalDnsRPktCnt0;


// Function prototypes

#if DNS_MODE > 0
static inline uint16_t dns_parse(char *dnsName, uint16_t len, uint16_t l, uint16_t *kp, const uint8_t *dnsPayloadB, uint16_t lb, const uint16_t *nLenp);
#endif // DNS_MODE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("dnsDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(dnsFlow = calloc(mainHashMap->hashChainTableSize, sizeof(dnsFlow_t))))) {
		T2_PERR("dnsDecode", "failed to allocate memory for dnsFlow");
		exit(-1);
	}

	// Packet mode
	if (sPktFile) fputs("dnsStatus\tdnsRelPtr\t", sPktFile);

#if MAL_TEST == 1
	if (UNLIKELY(!(malsite_table = malsite_init()))) {
		free(dnsFlow);
		exit(1);
	}
#endif // MAL_TEST == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("DNS status", "dnsStat", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS last header field", "dnsHdriOPField", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS aggregated header status, opcode and return code", "dnsHStat_OpC_RetC", 0, 3, bt_hex_8, bt_hex_16, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS number of question, answer, auxiliary and additional records", "dnsCntQu_Asw_Aux_Add", 0, 4, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16));

	bv = bv_append_bv(bv, bv_new_bv("DNS DDOS AAA / Query factor", "dnsAAAqF", 0, 1, bt_float));

#if DNS_MODE > 0
	// TODO rename
#if DNS_HEXON == 1
	bv = bv_append_bv(bv, bv_new_bv("DNS type Bit Fields", "dnsTypeBF3_BF2_BF1_BF0", 0, 4, bt_hex_8, bt_hex_16, bt_hex_16, bt_hex_64));
#endif // DNS_HEXON == 1

	bv = bv_append_bv(bv, bv_new_bv("DNS Query Name", "dnsQname", 1, 1, bt_string));

#if (MAL_TEST == 1 && MAL_DOMAIN == 1)
	bv = bv_append_bv(bv, bv_new_bv("DNS Number of DNS Malware count", "dnsMalCnt", 0, 1, bt_uint_32));
#if MAL_TYPE == 1
	bv = bv_append_bv(bv, bv_new_bv("DNS Domain Malware Type", "dnsMalType", 1, 1, bt_string));
#else // MAL_TYPE == 0
	bv = bv_append_bv(bv, bv_new_bv("DNS Domain Malware Code", "dnsMalCode", 1, 1, bt_uint_32));
#endif // MAL_TYPE
#endif // (MAL_TEST == 1 && MAL_DOMAIN == 1)

	bv = bv_append_bv(bv, bv_new_bv("DNS Answer Name Record", "dnsAname", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("DNS Name CNAME entries", "dnsAPname", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("DNS Address entries IPv4", "dns4Aaddress", 1, 1, bt_ip4_addr));
	bv = bv_append_bv(bv, bv_new_bv("DNS Address entries IPv6", "dns6Aaddress", 1, 1, bt_ip6_addr));

#if (MAL_TEST == 1 && MAL_DOMAIN == 0)
	bv = bv_append_bv(bv, bv_new_bv("DNS IP Malware Code", "dnsIPMalCode", 1, 1, bt_hex_32));
#endif // (MAL_TEST == 1 && MAL_DOMAIN == 0)

	bv = bv_append_bv(bv, bv_new_bv("DNS Answer Record Type entries", "dnsAType", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS Answer Record Class entries", "dnsAClass", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS Answer Record TTL entries", "dnsATTL", 1, 1, bt_uint_32));

	bv = bv_append_bv(bv, bv_new_bv("DNS MX Record preference entries", "dnsMXpref", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS SRV Record priority entries", "dnsSRVprio", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS SRV Record weight entries", "dnsSRVwgt", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("DNS SRV Record port entries", "dnsSRVprt", 1, 1, bt_uint_16));

	bv = bv_append_bv(bv, bv_new_bv("DNS Option Status", "dnsOptStat", 1, 1, bt_hex_32));
	bv = bv_append_bv(bv, bv_new_bv("DNS Option Code Owner", "dnsOptCodeOwn", 1, 1, bt_uint_16));
#endif // DNS_MODE > 0

	return bv;
}


void onFlowGenerated(packet_t *packet, unsigned long flowIndex) {
	dnsFlow_t *dnsFlowP = &dnsFlow[flowIndex];
	memset(dnsFlowP, '\0', sizeof(dnsFlow_t));

	flow_t * const flowP = &flows[flowIndex];
	const uint_fast16_t sp = flowP->srcPort;
	const uint_fast16_t dp = flowP->dstPort;

	if (sp == DNSNPORT || dp == DNSNPORT) dnsFlowP->dnsStat = DNS_NBIOS;

	if (sp == DNSPORT || sp == DNSPORTM || sp == DNSPORTB ||
	    dp == DNSPORT || dp == DNSPORTM || dp == DNSPORTB ||
	    dnsFlowP->dnsStat == DNS_NBIOS)
	{
		dnsFlowP->dnsStat |= DNS_PRTDT;
		const uint16_t *dnsPayload = (uint16_t*)packet->layer7Header;
		if (packet->layer4Type == L3_UDP) {
			if (packet->snapL7Length < 2) return;
			dnsPayload++;
			if (flowP->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
				if (sp == dp) {
					if (*dnsPayload & DNS_QRN) flowP->status |= L3FLOWINVERT;
					else flowP->status &= ~L3FLOWINVERT;
				}
			}
		} else if (packet->layer4Type == L3_TCP) {
			const uint8_t tcpFlags = *((uint8_t*)packet->layer4Header + 13);
			if ((tcpFlags & TH_SYN_FIN_RST) != TH_SYN) dnsFlowP->dnsStat |= DNS_ERRCRPT; // if there is no syn then corrupt

			const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
			dnsFlowP->seqT = ntohl(tcpHeader->seq);
		}
	}
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	if (sPktFile) fputs("\t\t", sPktFile);
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	dnsFlow_t * const dnsFlowP = &dnsFlow[flowIndex];

	uint16_t stat = dnsFlowP->dnsStat;
	uint16_t l = 0;

	if (!(stat & DNS_PRTDT) || (stat & DNS_ERRCRPT)) goto early; // not DNS or DNS TCP starts in the middle somewhere

	// only 1. frag packet will be processed
	if (!t2_is_first_fragment(packet)) goto early;

	uint16_t *dnsPayload = (uint16_t*)packet->layer7Header;
	uint16_t sL7Len = packet->snapL7Length;

	uint16_t dnsLen, u = 0;
	uint16_t dnsQNCnt, dnsANCnt, dnsNSCnt, dnsARCnt;

	if (packet->layer4Type == L3_UDP) {
		dnsLen = sL7Len;
		if (dnsLen < DNS_MINDNSLEN) {
			dnsFlowP->dnsStat |= (DNS_ERRCRPT | DNS_WRNMLN);
			goto early; // no dns payload
		}
		if (dnsLen > 512) stat |= DNS_WRNULN;
	} else if (packet->layer4Type == L3_TCP) { // tcp: length in dns header
		const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
		const uint32_t seq = ntohl(tcpHeader->seq);
		if (sL7Len < 6) {
			dnsFlowP->seqT = seq;
			goto early;
		}
		if (dnsFlowP->seqT != seq) { // are packets missing?
			dnsFlowP->dnsStat |= DNS_ERRCRPT; 	// packets corrupt, stop processing
			goto early;
		} else dnsFlowP->seqT = seq + packet->packetL7Length; // only if payload

		if (dnsFlowP->dnsStat & DNS_FRAGS) dnsLen = dnsFlowP->dnsTLen;
		else dnsLen = dnsFlowP->dnsTLen = ntohs(*dnsPayload);

		if (dnsLen <= sL7Len) {
			stat &= ~DNS_FRAGS; // last fragment, reset frag state
		} else {
			dnsLen = sL7Len;
			dnsFlowP->dnsTLen -= dnsLen;
			stat |= (DNS_FRAGS | DNS_FRAGA); // set frag state
		}
		dnsPayload++;
	} else goto early; // Not TCP nor UDP

	if (dnsLen < DNS_LEN_REJECT) {
		dnsFlowP->dnsStat |= DNS_WRNMLN;
		goto early; // no dns payload
	}

	if (dnsFlowP->dnsStat & DNS_FRAGS) {
		if (dnsFlowP->dnsHdField & DNS_QR) totalDnsRPktCnt++;
		else totalDnsQPktCnt++;
		dnsQNCnt = dnsFlowP->dnsQNCnt;
		dnsANCnt = dnsFlowP->dnsANCnt;
		dnsNSCnt = dnsFlowP->dnsNSCnt;
		dnsARCnt = dnsFlowP->dnsARCnt;
	} else {
		totalDnsPktCnt++; // count only ip unfragmented dns packets

		dnsPayload++;
		u = ntohs(*dnsPayload);

		dnsFlowP->dnsHdField = u;
		dnsFlowP->dnsStatBfield |= ((u & 0x07F0) >> 4) | ((u & DNS_QR) >> 8);
		dnsFlowP->dnsOpCodeBfield |= (1 << ((u & 0x7800) >> 11));
		dnsFlowP->dnsRCodeBfield |= (1 << (u & 0x000F));

		if (u & DNS_QR) {
			totalDnsRPktCnt++;
			dnsFlowP->dnsAALen += dnsLen;
		} else {
			totalDnsQPktCnt++;
		}

		if (dnsLen < DNS_MINDNSLEN) goto early; // no dns payload

		dnsFlowP->dnsQNCnt = dnsQNCnt = ntohs(*(++dnsPayload));
		dnsFlowP->dnsANCnt = dnsANCnt = ntohs(*(++dnsPayload));
		dnsFlowP->dnsNSCnt = dnsNSCnt = ntohs(*(++dnsPayload));
		dnsFlowP->dnsARCnt = dnsARCnt = ntohs(*(++dnsPayload));
		dnsFlowP->dnsQNACnt += dnsQNCnt;
		dnsFlowP->dnsANACnt += dnsANCnt;
		dnsFlowP->dnsNSACnt += dnsNSCnt;
		dnsFlowP->dnsARACnt += dnsARCnt;

		if ((u & 0x4040) || (dnsFlowP->dnsOpCodeBfield & 0xffc0) || (dnsFlowP->dnsRCodeBfield & 0xf800) || (dnsQNCnt * 5 + 13 * (dnsANCnt + dnsNSCnt + dnsARCnt) - 16) > dnsLen) {
			stat |= DNS_ERRCRPT;
			dnsFlowP->dnsStat = stat;
			goto early;
		}
	}

	dnsFlowP->dnsStat = stat;

#if DNS_MODE > 0
//#if (DNS_REQA == 1 || DNS_ANSA == 1)
	uint32_t n;
//#endif // (DNS_REQA == 1 || DNS_ANSA == 1)
	register uint32_t m, j;
	uint16_t k, nLen;
	char tnBuf[DNS_HNLMAX+1];

	dnsPayload -= 5; // reset uint16_t ptr to beginning of DNS payload
	const uint8_t * const dnsPayloadB = (uint8_t*)dnsPayload; // set byte ptr

	uint16_t dnsQRNCnt;
	if (dnsFlowP->dnsQRNCnt < DNS_QRECMXI) {
		dnsQRNCnt = dnsFlowP->dnsQRNCnt;
	} else {
		dnsQRNCnt = dnsFlowP->dnsQRNCnt = DNS_QRECMXI;
		dnsFlowP->dnsStat |= DNS_WRNDEX;
	}

	uint_fast32_t i;
	for (i = 0, l = DNS_RSTART; i < dnsQNCnt; i++) {
		k = nLen = 0;
#if DNS_REQA == 1
		j = dnsFlowP->dnsQRNACnt;
#else // DNS_REQA == 0
		j = dnsQRNCnt;
#endif // DNS_REQA
		if (!dnsPayloadB[l]) {
			l++;
		} else {
			l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
			if ((packet->layer4Type == L3_UDP && l > sL7Len) || (packet->layer4Type == L3_TCP && l > sL7Len)) goto errl;
			n = strlen(tnBuf);
#if DNS_REQA == 1
			for (m = 0; m < j; m++) if (!memcmp(dnsFlowP->dnsQname[m], tnBuf, n)) break;
			if (m == j && m < DNS_QRECMXI) {
				dnsFlowP->dnsQRNACnt++;

#endif // DNS_REQA
				dnsFlowP->dnsQname[j] = realloc(dnsFlowP->dnsQname[j], n+1);
				memcpy(dnsFlowP->dnsQname[j], tnBuf, n);
				dnsFlowP->dnsQname[j][n] = '\0';
#if DNS_REQA == 1
			}
#endif // DNS_REQA
		}

		dnsPayload = (uint16_t*)(dnsPayloadB + l);

		dnsFlowP->dnsQType[dnsQRNCnt] = m = ntohs(*dnsPayload++);
		dnsFlowP->dnsQClass[dnsQRNCnt] = ntohs(*dnsPayload);

		if (m < DNS_BF0) dnsFlowP->dnsTypeBF0 |= ((uint64_t)1 << m);
#if DNS_HEXON == 1
		if (m >= DNS_BF1) dnsFlowP->dnsTypeBF1 |= (1 << (m - DNS_BF1));
		if (m >= DNS_BF2) dnsFlowP->dnsTypeBF2 |= (1 << (m - DNS_BF2));
		if (m >= DNS_BF3) dnsFlowP->dnsTypeBF3 |= (1 << (m - DNS_BF3));
#endif // DNS_HEXON == 1
		if (m == DNS_AXFR) dnsFlowP->dnsStat |= DNS_ZTRANS;
		else if (m == DNS_IXFR) dnsFlowP->dnsStat |= DNS_IZTRANS;
		else if (m == DNS_ZONEALL) dnsFlowP->dnsStat |= DNS_ANY;

		l += 4; // advance byte ptr to unit16_t ptr
		if (dnsQRNCnt < DNS_QRECMXI) dnsQRNCnt++;
		else {
			dnsFlowP->dnsStat |= DNS_WRNDEX;
			break;
		}
	}

	dnsFlowP->dnsQRNCnt = dnsQRNCnt;
	if (u & 0x8000) dnsFlowP->dnsQALen += l;
#endif // DNS_MODE > 0

#if DNS_MODE > 1
	uint16_t dnsARNCnt, recLen;
	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) {
		dnsARNCnt = dnsFlowP->dnsARNCnt;
	} else {
		dnsARNCnt = dnsFlowP->dnsARNCnt = DNS_ARECMXI;
		dnsFlowP->dnsStat |= DNS_WRNDEX;
	}

	for (i = 0; i < dnsANCnt && l+5 < dnsLen; i++) {
		k = nLen = 0;

#if DNS_ANSA == 0
		j = dnsARNCnt;
#else // DNS_ANSA == 1
		j = dnsFlowP->dnsARNACnt;
#endif // DNS_ANSA

		if (!dnsPayloadB[l]) {
			l++;
		} else {
			l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
			if (l > sL7Len) goto errl;
			n = strlen(tnBuf);
#if DNS_ANSA == 1
			for (m = 0; m < j; m++) if (!memcmp(dnsFlowP->dnsAname[m], tnBuf, n)) break;
			if (m == j && m < DNS_ARECMXI) {
				dnsFlowP->dnsARNACnt++;
#endif // DNS_ANSA
				dnsFlowP->dnsAname[j] = realloc(dnsFlowP->dnsAname[j], n+1);
				memcpy(dnsFlowP->dnsAname[j], tnBuf, n);
				dnsFlowP->dnsAname[j][n] = '\0';
#if DNS_ANSA == 1
			}
#endif // DNS_ANSA
		}

		dnsPayload = (uint16_t*)(dnsPayloadB + l);
		dnsFlowP->dnsType[dnsARNCnt] = m = ntohs(*dnsPayload++);

		if (m < DNS_BF0) dnsFlowP->dnsTypeBF0 |= ((uint64_t)1 << m);
#if DNS_HEXON == 1
		if (m >= DNS_BF1) dnsFlowP->dnsTypeBF1 |= (1 << (m - DNS_BF1));
		if (m >= DNS_BF2) dnsFlowP->dnsTypeBF2 |= (1 << (m - DNS_BF2));
		if (m >= DNS_BF3) dnsFlowP->dnsTypeBF3 |= (1 << (m - DNS_BF3));
#endif // DNS_HEXON == 1
		if (m == DNS_AXFR) dnsFlowP->dnsStat |= DNS_ZTRANS;
		else if (m == DNS_IXFR) dnsFlowP->dnsStat |= DNS_IZTRANS;
		else if (m == DNS_ZONEALL) dnsFlowP->dnsStat |= DNS_ANY;

		dnsFlowP->dnsClass[dnsARNCnt] = ntohs(*dnsPayload++);
		dnsFlowP->dnsAttl[dnsARNCnt] = ntohl(*(uint32_t*)dnsPayload);

		l += 10; // advance byte ptr to unit16_t ptr
		if (l + 4 > dnsLen) {
			if (dnsARNCnt < DNS_ARECMXI) dnsARNCnt++;
			break;
		}

		dnsPayload++;
		dnsPayload++;
		recLen = ntohs(*dnsPayload++);

		switch (m) {
			case DNS_A:
				dnsFlowP->dnsAadd[dnsARNCnt].IPv4x[0] = *(uint32_t*)(dnsPayload);
				l += 4;
				break;
			case DNS_NS:
			case DNS_CNAME:
			case DNS_PTR:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsARNCnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_SOA:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsARNCnt][n] = '\0';
				if (l > sL7Len) goto errl;
				if (dnsARNCnt < DNS_ARECMXI) dnsARNCnt++;
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsARNCnt][n] = '\0';
				l += 16;
				if (l > sL7Len) goto errl;
				dnsFlowP->dnsAttl[dnsARNCnt] = ntohl(*(uint32_t*)(dnsPayloadB+l));
				l += 4;
				break;
			case DNS_MX:
				k = nLen = 0;
				dnsFlowP->dnsMXPref[dnsARNCnt] = ntohs(*dnsPayload);
				l += 2;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsARNCnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_TXT:
				k = dnsPayloadB[l];
				if (recLen == k+1) l++;
				else k = recLen;
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], k+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], dnsPayloadB + l, k);
				dnsFlowP->dnsPname[dnsARNCnt][k] = '\0';
				l += k;
				if (l > sL7Len) goto errl;
				break;
			case DNS_AAAA:
				dnsFlowP->dnsAadd[dnsARNCnt] = *(ipAddr_t*)(dnsPayload);
				l += 16;
				break;
			case DNS_SRV:
				k = nLen = 0;
				dnsFlowP->srvPrio[dnsARNCnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvWeight[dnsARNCnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvPort[dnsARNCnt] = ntohs(*(dnsPayload));
				l += 6;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsARNCnt] = realloc(dnsFlowP->dnsPname[dnsARNCnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsARNCnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsARNCnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_OPT:
				dnsFlowP->dnsOptStat[dnsARNCnt] = ntohl(*(uint32_t*)(dnsPayload-3));
				dnsFlowP->dnsOpCode[dnsARNCnt] = ntohs(*dnsPayload);
				l += recLen;
				break;

			default:
				dnsFlowP->dnsStat |= DNS_WRNIGN;
				l += recLen;

		/*		if (dnsARNCnt < DNS_ARECMXI) dnsARNCnt++;
				dnsFlowP->dnsARNCnt = dnsARNCnt;
				dnsFlowP->dnsANCnt -= (i+1);
				goto early;
		*/
		}
		if (dnsARNCnt < DNS_ARECMXI) dnsARNCnt++;
	}

	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) dnsFlowP->dnsARNCnt = dnsARNCnt;
	else dnsFlowP->dnsARNCnt = DNS_ARECMXI;
#endif // DNS_MODE > 1

#if DNS_MODE > 2
	uint16_t dnsNRACnt;
	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) {
		dnsNRACnt = dnsFlowP->dnsARNCnt;
	} else {
		dnsNRACnt = dnsFlowP->dnsARNCnt = DNS_ARECMXI;
		dnsFlowP->dnsStat |= DNS_WRNDEX;
	}

	for (i = 0; i < dnsNSCnt && l+5 < dnsLen; i++) {
		k = nLen = 0;

#if DNS_ANSA == 0
		j = dnsNRACnt;
#else // DNS_ANSA == 1
		j = dnsFlowP->dnsARNACnt;
#endif // DNS_ANSA

		if (!dnsPayloadB[l]) {
			l++;
		} else {
			l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
			if (l > sL7Len) goto errl;
			n = strlen(tnBuf);
#if DNS_ANSA == 1
			for (m = 0; m < j; m++) if (!memcmp(dnsFlowP->dnsAname[m], tnBuf, n)) break;
			if (m == j && m < DNS_ARECMXI) {
				dnsFlowP->dnsARNACnt++;
#endif // DNS_ANSA
			dnsFlowP->dnsAname[j] = realloc(dnsFlowP->dnsAname[j], n+1);
			memcpy(dnsFlowP->dnsAname[j], tnBuf, n);
			dnsFlowP->dnsAname[j][n] = '\0';
#if DNS_ANSA == 1
			}
#endif // DNS_ANSA
		}

		dnsPayload = (uint16_t*)(dnsPayloadB + l);
		dnsFlowP->dnsType[dnsNRACnt] = m = ntohs(*dnsPayload++);

		if (m < DNS_BF0) dnsFlowP->dnsTypeBF0 |= ((uint64_t)1 << m);
#if DNS_HEXON == 1
		if (m >= DNS_BF1) dnsFlowP->dnsTypeBF1 |= (1 << (m - DNS_BF1));
		if (m >= DNS_BF2) dnsFlowP->dnsTypeBF2 |= (1 << (m - DNS_BF2));
		if (m >= DNS_BF3) dnsFlowP->dnsTypeBF3 |= (1 << (m - DNS_BF3));
#endif // DNS_HEXON == 1
		if (m == DNS_AXFR) dnsFlowP->dnsStat |= DNS_ZTRANS;
		else if (m == DNS_IXFR) dnsFlowP->dnsStat |= DNS_IZTRANS;
		else if (m == DNS_ZONEALL) dnsFlowP->dnsStat |= DNS_ANY;

		dnsFlowP->dnsClass[dnsNRACnt] = ntohs(*dnsPayload++);
		dnsFlowP->dnsAttl[dnsNRACnt] = ntohl(*(uint32_t*)dnsPayload);

		l += 10; // advance byte ptr to unit16_t ptr
		if (l + 4 > dnsLen) {
			if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
			break;
		}

		dnsPayload++;
		dnsPayload++;
		recLen = ntohs(*dnsPayload++);

		switch (m) {
			case DNS_A:
				dnsFlowP->dnsAadd[dnsNRACnt].IPv4x[0] = *(uint32_t*)(dnsPayload);
				l += 4;
				break;
			case DNS_NS:
			case DNS_CNAME:
			case DNS_PTR:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_SOA:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				l += 16;
				if (l > sL7Len) goto errl;
				dnsFlowP->dnsAttl[dnsNRACnt] = ntohl(*(uint32_t*)(dnsPayloadB+l));
				l += 4;
				break;
			case DNS_MX:
				k = nLen = 0;
				dnsFlowP->dnsMXPref[dnsNRACnt] = ntohs(*dnsPayload);
				l += 2;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_TXT:
				k = dnsPayloadB[l];
				if (recLen == k+1) l++;
				else k = recLen;
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], k+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], dnsPayloadB + l, k);
				dnsFlowP->dnsPname[dnsNRACnt][k] = '\0';
				l += k;
				if (l > sL7Len) goto errl;
				break;
			case DNS_AAAA:
				dnsFlowP->dnsAadd[dnsNRACnt] = *(ipAddr_t*)(dnsPayload);
				l += 16;
				break;
			case DNS_SRV:
				k = nLen = 0;
				dnsFlowP->srvPrio[dnsNRACnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvWeight[dnsNRACnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvPort[dnsNRACnt] = ntohs(*(dnsPayload));
				l += 6;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_OPT:
				dnsFlowP->dnsOptStat[dnsNRACnt] = ntohl(*(uint32_t*)(dnsPayload-3));
				dnsFlowP->dnsOpCode[dnsNRACnt] = ntohs(*dnsPayload);
				l += recLen;
				break;

			default:
				dnsFlowP->dnsStat |= DNS_WRNIGN;
				l += recLen;

			/*	if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
				dnsFlowP->dnsARNCnt = dnsNRACnt;
				dnsFlowP->dnsNSCnt -= (i+1);
				goto early;
			*/
		}
		if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
	}

	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) dnsFlowP->dnsARNCnt = dnsNRACnt;
	else dnsFlowP->dnsARNCnt = DNS_ARECMXI;

#endif // DNS_MODE > 2

#if DNS_MODE > 3
	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) {
		dnsNRACnt = dnsFlowP->dnsARNCnt;
	} else {
		dnsNRACnt = dnsFlowP->dnsARNCnt = DNS_ARECMXI;
		dnsFlowP->dnsStat |= DNS_WRNDEX;
	}

	for (i = 0; i < dnsARCnt && l+5 < dnsLen; i++) {
		k = nLen = 0;

#if DNS_ANSA == 0
		j = dnsNRACnt;
#else // DNS_ANSA == 1
		j = dnsFlowP->dnsARNACnt;
#endif // DNS_ANSA

		if (!dnsPayloadB[l]) {
			l++;
		} else {
			l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
			if (l > sL7Len) goto errl;
			n = strlen(tnBuf);
#if DNS_ANSA == 1
			for (m = 0; m < j; m++) if (!memcmp(dnsFlowP->dnsAname[m], tnBuf, n)) break;
			if (m == j && m < DNS_ARECMXI) {
				dnsFlowP->dnsARNACnt++;
#endif // DNS_ANSA
			dnsFlowP->dnsAname[j] = realloc(dnsFlowP->dnsAname[j], n+1);
			memcpy(dnsFlowP->dnsAname[j], tnBuf, n);
			dnsFlowP->dnsAname[j][n] = '\0';
#if DNS_ANSA == 1
			}
#endif // DNS_ANSA
		}

		dnsPayload = (uint16_t*)(dnsPayloadB + l);
		dnsFlowP->dnsType[dnsNRACnt] = m = ntohs(*dnsPayload++);

		if (m < DNS_BF0) dnsFlowP->dnsTypeBF0 |= ((uint64_t)1 << m);
#if DNS_HEXON == 1
		if (m >= DNS_BF1) dnsFlowP->dnsTypeBF1 |= (1 << (m - DNS_BF1));
		if (m >= DNS_BF2) dnsFlowP->dnsTypeBF2 |= (1 << (m - DNS_BF2));
		if (m >= DNS_BF3) dnsFlowP->dnsTypeBF3 |= (1 << (m - DNS_BF3));
#endif // DNS_HEXON == 1
		if (m == DNS_AXFR) dnsFlowP->dnsStat |= DNS_ZTRANS;
		else if (m == DNS_IXFR) dnsFlowP->dnsStat |= DNS_IZTRANS;
		else if (m == DNS_ZONEALL) dnsFlowP->dnsStat |= DNS_ANY;

		dnsFlowP->dnsClass[dnsNRACnt] = ntohs(*dnsPayload++);
		dnsFlowP->dnsAttl[dnsNRACnt] = ntohl(*(uint32_t*)dnsPayload);

		l += 10; // advance byte ptr to unit16_t ptr
		if (l + 4 > dnsLen) {
			if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
			break;
		}

		dnsPayload++;
		dnsPayload++;
		recLen = ntohs(*dnsPayload++);

		switch (m) {
			case DNS_A:
				dnsFlowP->dnsAadd[dnsNRACnt].IPv4x[0] = *(uint32_t*)(dnsPayload);
				l += 4;
				break;
			case DNS_NS:
			case DNS_CNAME:
			case DNS_PTR:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_SOA:
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
				k = nLen = 0;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				l += 16;
				if (l > sL7Len) goto errl;
				dnsFlowP->dnsAttl[dnsNRACnt] = ntohl(*(uint32_t*)(dnsPayloadB+l));
				l += 4;
				break;
			case DNS_MX:
				k = nLen = 0;
				dnsFlowP->dnsMXPref[dnsNRACnt] = ntohs(*dnsPayload);
				l += 2;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_TXT:
				k = dnsPayloadB[l];
				if (recLen == k+1) l++;
				else k = recLen;
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], k+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], dnsPayloadB + l, k);
				dnsFlowP->dnsPname[dnsNRACnt][k] = '\0';
				l += k;
				if (l > sL7Len) goto errl;
				break;
			case DNS_AAAA:
				dnsFlowP->dnsAadd[dnsNRACnt] = *(ipAddr_t*)(dnsPayload);
				l += 16;
				break;
			case DNS_SRV:
				k = nLen = 0;
				dnsFlowP->srvPrio[dnsNRACnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvWeight[dnsNRACnt] = ntohs(*(dnsPayload++));
				dnsFlowP->srvPort[dnsNRACnt] = ntohs(*(dnsPayload));
				l += 6;
				l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
				n = strlen(tnBuf);
				dnsFlowP->dnsPname[dnsNRACnt] = realloc(dnsFlowP->dnsPname[dnsNRACnt], n+1);
				memcpy(dnsFlowP->dnsPname[dnsNRACnt], tnBuf, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';
				if (l > sL7Len) goto errl;
				break;
			case DNS_OPT:
				dnsFlowP->dnsOptStat[dnsNRACnt] = ntohl(*(uint32_t*)(dnsPayload-3));
				dnsFlowP->dnsOpCode[dnsNRACnt] = ntohs(*dnsPayload);
				/*n = ntohs(*dnsPayload);
				//dnsFlowP->dnsOpt[dnsNRACnt] = realloc(dnsFlowP->dnsOpt[dnsNRACnt], n+1);
				//memcpy(dnsFlowP->dnsPname[dnsNRACnt], dnsPayloadB+l+4, n);
				dnsFlowP->dnsPname[dnsNRACnt][n] = '\0';*/
				l += recLen;
				break;

			default:
				dnsFlowP->dnsStat |= DNS_WRNIGN;
				l += recLen;

			/*	if (dnsARACnt < DNS_ARECMXI) dnsARACnt++;
				dnsFlowP->dnsARNCnt = dnsARACnt;
				dnsFlowP->dnsARCnt -= (i+1);
				goto early;
			*/

		}
		if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
	}

	if (dnsFlowP->dnsARNCnt < DNS_ARECMXI) dnsFlowP->dnsARNCnt = dnsNRACnt;
	else dnsFlowP->dnsARNCnt = DNS_ARECMXI;
#endif // DNS_MODE > 3

#if FORCE_MODE == 1
	if (dnsFlowP->dnsStat & (DNS_WRNDEX | DNS_WRNAEX)) {
		flow_t * const flowP = &flows[flowIndex];
		T2_RM_FLOW(flowP);
	}
#endif

	goto early;

#if DNS_MODE > 0
// Error Handling
errl:	dnsFlowP->dnsStat |= DNS_ERRLEN;

	if (l == 65531) dnsFlowP->dnsStat |= DNS_ERRLEN;
	if (l == 65532) dnsFlowP->dnsStat |= DNS_ERRPTR;
#endif // DNS_MODE > 0

early:	// Packet mode
	if (sPktFile)
		fprintf(sPktFile, "0x%04x\t%"PRIu16"\t", dnsFlowP->dnsStat, l);
}


void onFlowTerminate(unsigned long flowIndex) {
#if DNS_MODE > 0 || MAL_TEST == 1
	uint64_t *p64;
	static const uint64_t sc = 0x4141414141414141;
	uint_fast32_t i, n;
	uint32_t j, l, l2, l3;
	char *p, nBuf[DNS_HNLMAX+1];
	const char nil = '\0';
#endif // DNS_MODE > 0 || MAL_TEST == 1
	dnsFlow_t * const dnsFlowP = &dnsFlow[flowIndex];

	dnsAStat |= dnsFlowP->dnsStat;

#if MAL_TEST == 1
	malsite_t *malsiteP = malsite_table->malsites;
	uint32_t numAF = 0;
#if MAL_DOMAIN == 1
	uint32_t malcode[DNS_QRECMAX] = {};
#if DNS_REQA == 1
	j = dnsFlowP->dnsQRNACnt;
#else // DNS_REQA == 0
	j = dnsFlowP->dnsQRNCnt;
#endif // DNS_REQA
	if (j >= DNS_QRECMXI) j = DNS_QRECMAX;
#else // MAL_DOMAIN == 0
	uint32_t malcode[DNS_ARECMAX] = {};
#if DNS_ANSA == 1
	j = dnsFlowP->dnsARNACnt;
#else // DNS_ANSA == 0
	j = dnsFlowP->dnsARNCnt;
#endif // DNS_ANSA
	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // MAL_DOMAIN

	for (i = 0; i < j; i++) {
#if MAL_DOMAIN == 1
		malcode[i] = maldomain_test(malsite_table, dnsFlowP->dnsQname[i]);
#else // MAL_DOMAIN == 0
		malcode[i] = malip_test(malsite_table, dnsFlowP->dnsAadd[i]);
#endif // MAL_DOMAIN
		if (malcode[i]) {
			numAF++;
		}
	}

	dnsAlarms += numAF;
	T2_REPORT_ALARMS(numAF);
#endif // MAL_TEST == 1

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsStat, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsHdField, sizeof(uint16_t));

	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsStatBfield, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsOpCodeBfield, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsRCodeBfield, sizeof(uint16_t));

	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsQNACnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsANACnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsNSACnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsARACnt, sizeof(uint16_t));

	const float f = (dnsFlowP->dnsQALen != 0) ? dnsFlowP->dnsAALen / (float)dnsFlowP->dnsQALen : 0.0f;
	outputBuffer_append(main_output_buffer, (char*) &f, sizeof(float));

#if DNS_MODE > 0
#if DNS_HEXON == 1
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsTypeBF3, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsTypeBF2, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsTypeBF1, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsTypeBF0, sizeof(uint64_t));
#endif // DNS_HEXON == 1

#if DNS_REQA == 1
	j = dnsFlowP->dnsQRNACnt;
#else // DNS_REQA == 0
	j = dnsFlowP->dnsQRNCnt;
#endif // DNS_REQA
	if (j >= DNS_QRECMXI) j = DNS_QRECMAX;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		p = dnsFlowP->dnsQname[i];
		if (p) {
			n = strlen(p) + 1;
			if (dnsFlowP->dnsStat & DNS_NBIOS) {
				memcpy(nBuf, p, n);
				p64 = (uint64_t*)nBuf;
				p64[0] -= sc; p64[1] -= sc; p64[2] -= sc; p64[3] -= sc;
				for (l = 0, l2 = 0, l3 = 0; l < 16; l++, l2 += 2, l3++) nBuf[l3] = (nBuf[l2] << 4) + nBuf[l2+1];
				nBuf[16] = 0x0;
				outputBuffer_append(main_output_buffer, nBuf, strlen(nBuf)+1);
			} else outputBuffer_append(main_output_buffer, p, n);
			free(p);
		} else outputBuffer_append(main_output_buffer, &nil, 1);
	}

#if (MAL_TEST == 1 && MAL_DOMAIN == 1)
	outputBuffer_append(main_output_buffer, (char*) &numAF, sizeof(uint32_t));
#if MAL_TYPE == 1
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) outputBuffer_append(main_output_buffer, (char*) &malsiteP[malcode[i]].malTyp, strlen(malsiteP[malcode[i]].malTyp)+1);
#else // MAL_TYPE == 0
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) outputBuffer_append(main_output_buffer, (char*) &malsiteP[malcode[i]].malId, sizeof(uint32_t));
#endif // MAL_TYPE
#endif // (MAL_TEST == 1 && MAL_DOMAIN == 1)

#if DNS_ANSA == 1
	j = dnsFlowP->dnsARNACnt;
#else // DNS_ANSA == 0
	j = dnsFlowP->dnsARNCnt;
#endif // DNS_ANSA
	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		p = dnsFlowP->dnsAname[i];
		if (p) {
			n = strlen(p) + 1;
			if (dnsFlowP->dnsStat & DNS_NBIOS) {
				memcpy(nBuf, p, n);
				p64 = (uint64_t*)nBuf;
				p64[0] -= sc; p64[1] -= sc; p64[2] -= sc; p64[3] -= sc;
				for (l = 0, l2 = 0, l3 = 0; l < 16; l++, l2 += 2, l3++) nBuf[l3] = (nBuf[l2] << 4) + nBuf[l2+1];
				nBuf[16] = 0x0;
				outputBuffer_append(main_output_buffer, nBuf, strlen(nBuf)+1);
			} else outputBuffer_append(main_output_buffer, p, n);
			free(p);
		} else outputBuffer_append(main_output_buffer, &nil, 1);
	}

	j = dnsFlowP->dnsARNCnt;
	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		p = dnsFlowP->dnsPname[i];
		if (p) {
			outputBuffer_append(main_output_buffer, p, strlen(p)+1);
			free(p);
		} else outputBuffer_append(main_output_buffer, &nil, 1);
	}

	if (dnsFlowP->dnsTypeBF0 & DNS_HOST_B) {
		j = dnsFlowP->dnsARNCnt;
	} else j = 0;

	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		if (dnsFlowP->dnsType[i] == DNS_A) outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsAadd[i], sizeof(uint32_t));
		else outputBuffer_append(main_output_buffer, (char*) &ZERO, sizeof(uint32_t));
	}

	if (dnsFlowP->dnsTypeBF0 & DNS_AAAA_B) {
		j = dnsFlowP->dnsARNCnt;
	} else j = 0;

	uint64_t a[2] = {};

	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		if (dnsFlowP->dnsType[i] == DNS_AAAA) outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsAadd[i], sizeof(ipAddr_t));
		else outputBuffer_append(main_output_buffer, (char*) &a, sizeof(ipAddr_t));
	}

#if (MAL_TEST == 1 && MAL_DOMAIN == 0)
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &malcode[i], sizeof(uint32_t));
	}
#endif // (MAL_TEST == 1 && MAL_DOMAIN == 0)

	if (dnsFlowP->dnsHdField & 0x8000) j = dnsFlowP->dnsARNCnt;
	else j = dnsFlowP->dnsQRNCnt;

	if (j >= DNS_ARECMXI) j = DNS_ARECMAX;

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		if (dnsFlowP->dnsHdField & 0x8000) outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsType[i], sizeof(uint16_t));
		else outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsQType[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		if (dnsFlowP->dnsHdField & 0x8000) outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsClass[i], sizeof(uint16_t));
		else outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsQClass[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsAttl[i], sizeof(uint32_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsMXPref[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->srvPrio[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->srvWeight[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->srvPort[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsOptStat[i], sizeof(uint32_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*) &dnsFlowP->dnsOpCode[i], sizeof(uint16_t));
	}
#endif // DNS_MODE > 0
#endif // BLOCK_BUF == 0
}


static void dns_pluginReport(FILE *stream) {
	if (totalDnsPktCnt) {
		T2_FPLOG_DIFFNUMP0(stream, "dnsDecode", "Number of DNS packets", totalDnsPktCnt, numPackets);
		T2_FPLOG_DIFFNUMP(stream, "dnsDecode", "Number of DNS Q packets", totalDnsQPktCnt, totalDnsPktCnt);
		T2_FPLOG_DIFFNUMP(stream, "dnsDecode", "Number of DNS R packets", totalDnsRPktCnt, totalDnsPktCnt);
		if (dnsAStat) T2_FPLOG(stream, "dnsDecode", "Aggregated status: 0x%04"B2T_PRIX16, dnsAStat);
#if MAL_TEST == 1
		T2_FPLOG_NUM(stream, "dnsDecode", "Number of alarms", dnsAlarms);
#endif
	}
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
	totalDnsPktCnt0 = 0;
	totalDnsQPktCnt0 = 0;
	totalDnsRPktCnt0 = 0;
#endif // DIFF_REPORT == 1
	dns_pluginReport(stream);
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("dnsPkts\tdnsQPkts\tdnsRPkts\t", stream);
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t",
					totalDnsPktCnt  - totalDnsPktCnt0,
					totalDnsQPktCnt - totalDnsQPktCnt0,
					totalDnsRPktCnt - totalDnsRPktCnt0);
			break;

		case T2_MON_PRI_REPORT:
			dns_pluginReport(stream);
			break;

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	totalDnsPktCnt0 = totalDnsPktCnt;
	totalDnsQPktCnt0 = totalDnsQPktCnt;
	totalDnsRPktCnt0 = totalDnsRPktCnt;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
#if MAL_TEST == 1
	malsite_destroy(malsite_table);
#endif // MAL_TEST == 1

	free(dnsFlow);
}


#if USE_T2BUS == 1
void t2BusCallback(t2BusMsg_t msgBuf) {
}
#endif // USE_T2BUS == 1


#if DNS_MODE > 0
static inline uint16_t dns_parse(char *dnsName, uint16_t len, uint16_t l, uint16_t *kp, const uint8_t *dnsPayloadB, uint16_t lb, const uint16_t *nLenp) {
	int mxlen, n;
	uint16_t j, u;
	uint8_t sw = 1;

	if (l+1 > len) return 65531;

	uint16_t k = *kp;

	if (!dnsPayloadB[l]) {
		if (k > 0 && dnsName[k - 1] == '.') {
			dnsName[k - 1] = '\0';
		} else {
			dnsName[k] = '\0';
		}
		return ++l;
	}

	uint16_t nLen = *nLenp;

	while (1) {
		if (l + 1 >= len || l < DNS_RSTART) {
			l = 65530; // ++l -> 65531
			break;
		}
		j = *(uint16_t*)(dnsPayloadB+l);
		if (j & DNS_PTRN) {
			if ((j & DNS_PTRN) == DNS_PTRN) {
				u = ntohs(j & DNS_PTRVN);
				if (u >= l || u > len) goto ptrerr;
				dns_parse(dnsName, len, u, &k, dnsPayloadB, l, &nLen);
				*kp = k;
				return l + 2;
			} else {
ptrerr:				l = 65531; // ++l -> 65532
				break;
			}
		} else {
			mxlen = l + dnsPayloadB[l];
			nLen += dnsPayloadB[l];
			if (nLen > DNS_MXNAME || mxlen + 1 == lb) sw = 0;

			n = k + dnsPayloadB[l] - DNS_HNLMAX;
			if (n > 0) mxlen -= (n+1);

			if (mxlen > len) {
				mxlen = len;
				sw = 0;
			}

			for (j = l + 1; j <= mxlen; j++) dnsName[k++] = dnsPayloadB[j];

			if (sw) {
				l += dnsPayloadB[l] + 1;
			} else {
				l = 65530; // ++l -> 65531
				break;
			}

			if (dnsPayloadB[l] == '\0' || l >= len) break;
			if (n <= 0) dnsName[k++] = '.';
		}
	}

	dnsName[k] = '\0';
	*kp = k;

	return ++l;
}
#endif // DNS_MODE > 0
