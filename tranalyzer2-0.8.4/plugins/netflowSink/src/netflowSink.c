/*
 * netflowSink.c
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

#include "basicFlow.h"
#include "basicStats.h"
#include "tcpFlags.h"
#if ETH_ACTIVATE < 2
#include "macRecorder.h"
#endif
#include "t2utils.h"
#include "netflow9.h"

#include <netdb.h>


// Static variables

static int nfS;
static struct sockaddr_in server;
static uint32_t ipseq;
static int nfFlw4Cnt, nfFlw6Cnt;
//static int nfMFB4Cnt, nfMFBG6Cnt;
static nfBfT_t nfBfT;
static nfBf4_t nfBf4;
static nfBf6_t nfBf6;


// Static functions
static inline void sendbuf4();
static inline void sendbuf6();


// Variables from dependencies
extern bfoFlow_t *bfoFlow __attribute__((weak));
extern bSFlow_t *bSFlow __attribute__((weak));
extern tcpFlagsFlow_t *tcpFlagsFlows __attribute__((weak));

// Variable from optional dependencies
extern macRecorder_t *macArray __attribute__((weak));
macRecorder_t *macArray;


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("netflowSink", "0.8.4", 0, 8, "basicFlow,basicStats,tcpFlags");


void initialize() {
#if NF_SOCKTYPE == 1
	if (UNLIKELY(!(nfS = socket(AF_INET, SOCK_STREAM, 0)))) {
#else // NF_SOCKTYPE == 0
	if (UNLIKELY(!(nfS = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))) {
#endif // NF_SOCKTYPE == 0
		T2_PERR("netflowSink", "Failed to create socket: %s", strerror(errno));
		exit(-1);
	}

	struct hostent *host = gethostbyname(NF_SERVADD);
	server.sin_addr = *(struct in_addr*)host->h_addr;
	server.sin_family = AF_INET;
	server.sin_port = ntohs(NF_DPORT);

#if NF_SOCKTYPE == 1
	if (UNLIKELY(connect(nfS, (struct sockaddr*)&server, sizeof(server)) < 0)) {
		T2_PERR("netflowSink", "Failed to connect to socket: %s", strerror(errno));
		exit(-1);
	}
#endif // NF_SOCKTYPE == 1

	size_t written = 0, act_written;

	char *nfBP = nfBfT.nfBuff;
	netv9Hdr_t *netv9HP = &nfBfT.nfMsgT.netv9H;
	netv9HP->version = NF9_VER;
	netv9HP->count = 0x0200;
	netv9HP->upTime = 0;
	netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
	netv9HP->ipseq = 0;
	netv9HP->srcID = ntohl(T2_SENSORID);

	nv9T_t *nv9TP = &nfBfT.nfMsgT.nv9T;
	nv9TP->setID4 = FLSID;
	nv9TP->len4 = INV9T4LEN;
	nv9TP->tmpltID4 = TPLIDT4;
	nv9TP->fieldCnt4 = htons(sizeof(nv9Tv4)/4);
	memcpy((char*)nv9TP->nTDef4, (char*)nv9Tv4, sizeof(nv9Tv4));
	nv9TP->setID6 = FLSID;
	nv9TP->len6 = INV9T6LEN;
	nv9TP->tmpltID6 = TPLIDT6;
	nv9TP->fieldCnt6 = htons(sizeof(nv9Tv6)/4);
	memcpy((char*)nv9TP->nTDef6, (char*)nv9Tv6, sizeof(nv9Tv6));

	const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nv9T_t);

	while (written < bufLen) {
#if NF_SOCKTYPE == 1
		act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
		act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("netflowSink", "Failed to write flow data to socket: %s", strerror(errno));
			exit(1);
		}
		written += act_written;
	}

	netv9HP = &nfBf4.nfMsg4.netv9H;
	netv9HP->version = NF9_VER;
	netv9HP->upTime = 0;
	netv9HP->srcID = ntohl(T2_SENSORID);
	netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
	netv9HP->count = 0x0100;
	nfBf4.nfMsg4.flwSet = TPLIDT4;
	if (NF_NUM4FLWS > MAXFB4CNT) T2_PWRN("netflowSink", "Number of IPv4 flows per message too high: was reduced to %d\n", MAXFB4CNT);
	nfBf4.nfMsg4.len = htons(MSG4LEN);

	netv9HP = &nfBf6.nfMsg6.netv9H;
	netv9HP->version = NF9_VER;
	netv9HP->upTime = 0;
	netv9HP->srcID = ntohl(T2_SENSORID);
	netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
	netv9HP->count = 0x0100;
	nfBf6.nfMsg6.flwSet = TPLIDT6;
	if (NF_NUM6FLWS > MAXFB6CNT) T2_PWRN("netflowSink", "Number of IPv6 flows per message too high: was reduced to %d\n", MAXFB6CNT);
	nfBf6.nfMsg6.len = htons(MSG6LEN);
}


void onFlowTerminate(unsigned long flowIndex) {
	if (nfFlw4Cnt >= NFB4CNTC) nfFlw4Cnt = 0;
	if (nfFlw6Cnt >= NFB6CNTC) nfFlw6Cnt = 0;

	const flow_t * const flowP = &flows[flowIndex];
	const bSFlow_t * const bSFlowP = &bSFlow[flowIndex];
	const tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

#if ETH_ACTIVATE < 2
	macList_t *macListP = macArray ? macArray[flowIndex].macList : NULL;
#endif // ETH_ACTIVATE < 2

	uint32_t t;

	if (FLOW_IS_IPV4(flowP)) {
		nf9Data4_t *nfDP = &nfBf4.nfMsg4.nfD4[nfFlw4Cnt++];
		nfDP->ipVer = 4;
		nfDP->dir = flowP->status & L3FLOWINVERT;
		t = (flowP->firstSeen.tv_sec - startTStamp0.tv_sec)*1000 + (flowP->firstSeen.tv_usec - startTStamp0.tv_usec)/1000;
		if (!t) t = 1;
		nfDP->flowSSec = htonl(t);
		t = (flowP->lastSeen.tv_sec - startTStamp0.tv_sec)*1000 + (flowP->lastSeen.tv_usec - startTStamp0.tv_usec)/1000;
		if (!t) t = 1;
		nfDP->flowESec = htonl(t);
		nfDP->srcIPv4 = flowP->srcIP.IPv4.s_addr;
		nfDP->dstIPv4 = flowP->dstIP.IPv4.s_addr;
		nfDP->srcPort = htons(flowP->srcPort);
		nfDP->dstPort = htons(flowP->dstPort);
		nfDP->srcVlanId = htons(flowP->vlanID);
		nfDP->l4Proto = flowP->layer4Protocol;
		nfDP->engID = 1;
#if ETH_ACTIVATE > 1
		memcpy(nfDP->dsInMac, flowP->ethDS.ether_dhost, 12);
#else // ETH_ACTIVATE <= 1
		if (macListP) {
			macList_t *tmpList = macListP;
			memcpy(nfDP->dsInMac, tmpList->ethHdr.ether_dhost, 12);
			if ((tmpList = tmpList->next)) memcpy(nfDP->dsOutMac, tmpList->ethHdr.ether_dhost, 12);
			else memset(nfDP->dsOutMac, 0x00, 12);
		}
#endif // ETH_ACTIVATE <= 1

		if (bSFlowP) {
			nfDP->pktCnt = htobe64(bSFlowP->numTPkts);
			nfDP->byteCnt = htobe64(bSFlowP->numTBytes);
			nfDP->minL3Len = htons(bSFlowP->minL3PktSz);
			nfDP->maxL3Len = htons(bSFlowP->maxL3PktSz);
		}

		if (tcpFlagsP) {
			nfDP->tcpFlags = tcpFlagsP->tcpFlagsT;
			nfDP->ipToS = tcpFlagsP->ipTosT;
			nfDP->minTTL = tcpFlagsP->ipMinTTLT;
			nfDP->maxTTL = tcpFlagsP->ipMaxTTLT;
		}

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
		const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
		if (bfoFlowP) {
			const mplsh_t * const mplsh = (mplsh_t*)bfoFlowP->mplsh;
			const uint32_t num_mpls = bfoFlowP->num_mpls;
			for (uint_fast32_t i = 0, j = 0; i < num_mpls; i++, j += 3) {
				const uint32_t mpls = ntohl(mplsh[i].mplshu);
				memcpy(&nfDP->nfMpls[j], (char*)&mpls, 3);
			}
		}
#endif
	} else if (FLOW_IS_IPV6(flowP)) {
		nf9Data6_t *nfDP = &nfBf6.nfMsg6.nfD6[nfFlw6Cnt++];
		nfDP->ipVer = 6;
		nfDP->dir = flowP->status & L3FLOWINVERT;
		t = (flowP->firstSeen.tv_sec - startTStamp0.tv_sec)*1000 + (flowP->firstSeen.tv_usec - startTStamp0.tv_usec)/1000;
		if (!t) t = 1;
		nfDP->flowSSec = htonl(t);
		t = (flowP->lastSeen.tv_sec - startTStamp0.tv_sec)*1000 + (flowP->lastSeen.tv_usec - startTStamp0.tv_usec)/1000;
		if (!t) t = 1;
		nfDP->flowESec = htonl(t);
#if IPV6_ACTIVATE > 0
		nfDP->srcIP = flowP->srcIP;
		nfDP->dstIP = flowP->dstIP;
#endif // IPV6_ACTIVATE > 0
		nfDP->srcPort = htons(flowP->srcPort);
		nfDP->dstPort = htons(flowP->dstPort);
		nfDP->srcVlanId = htons(flowP->vlanID);
		nfDP->l4Proto = flowP->layer4Protocol;
		nfDP->engID = 1;
#if ETH_ACTIVATE > 1
		memcpy(nfDP->dsInMac, flowP->ethDS.ether_dhost, 12);
#else // ETH_ACTIVATE <= 1
		if (macListP) {
			macList_t *tmpList = macListP;
			memcpy(nfDP->dsInMac, tmpList->ethHdr.ether_dhost, 12);
			if ((tmpList = tmpList->next)) memcpy(nfDP->dsOutMac, tmpList->ethHdr.ether_dhost, 12);
			else memset(nfDP->dsOutMac, 0x00, 12);
		}
#endif // ETH_ACTIVATE <= 1

		if (bSFlowP) {
			nfDP->pktCnt = htobe64(bSFlowP->numTPkts);
			nfDP->byteCnt = htobe64(bSFlowP->numTBytes);
			nfDP->minL3Len = htons(bSFlowP->minL3PktSz);
			nfDP->maxL3Len = htons(bSFlowP->maxL3PktSz);
		}

		if (tcpFlagsP) {
			nfDP->tcpFlags = tcpFlagsP->tcpFlagsT;
			nfDP->ipToS = tcpFlagsP->ipTosT;
			nfDP->minTTL = tcpFlagsP->ipMinTTLT;
			nfDP->maxTTL = tcpFlagsP->ipMaxTTLT;
		}

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
		const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
		if (bfoFlowP) {
			const mplsh_t * const mplsh = (mplsh_t*)bfoFlowP->mplsh;
			const uint32_t num_mpls = bfoFlowP->num_mpls;
			for (uint_fast32_t i = 0, j = 0; i < num_mpls; i++, j += 3) {
				const uint32_t mpls = ntohl(mplsh[i].mplshu);
				memcpy(&nfDP->nfMpls[j], (char*)&mpls, 3);
			}
		}
#endif
	}
}


void onApplicationTerminate() {
	if (nfFlw4Cnt) {
		nfBf4.nfMsg4.len = htons(sizeof(nf9Data4_t)*nfFlw4Cnt + 4 + NFDPAD4);
		sendbuf4(nfFlw4Cnt);
	}

	if (nfFlw6Cnt) {
		nfBf6.nfMsg6.len = htons(sizeof(nf9Data6_t)*nfFlw6Cnt + 4 + NFDPAD6);
		sendbuf6(nfFlw6Cnt);
	}

	if (LIKELY(nfS)) close(nfS);
}


void bufferToSink(outputBuffer_t* buffer __attribute__((unused))) {
	if (nfFlw4Cnt >= NFB4CNTC) sendbuf4(NFB4CNTC);
	if (nfFlw6Cnt >= NFB6CNTC) sendbuf6(NFB6CNTC);
}


static inline void sendbuf4(int nfFlwCnt) {

	size_t written = 0, act_written;
	const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nf9Data4_t)*nfFlwCnt + 4 + NFDPAD4;
	char *nfBP = nfBf4.nfBuff;
	netv9Hdr_t *netv9HP = &nfBf4.nfMsg4.netv9H;

	netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
	netv9HP->ipseq = ntohl(++ipseq);

	while (written < bufLen) {
#if NF_SOCKTYPE == 1
		act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
		act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("netflowSink", "Failed to write flow data to socket: %s", strerror(errno));
			exit(1);
		}
		written += act_written;
	}

	nfFlw4Cnt = 0;
}

static inline void sendbuf6(int nfFlwCnt) {

	size_t written = 0, act_written;
	const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nf9Data6_t)*nfFlwCnt + 4 + NFDPAD6;
	char *nfBP = nfBf6.nfBuff;
	netv9Hdr_t *netv9HP = &nfBf6.nfMsg6.netv9H;

	netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
	netv9HP->ipseq = ntohl(++ipseq);

	while (written < bufLen) {
#if NF_SOCKTYPE == 1
		act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
		act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("netflowSink", "Failed to write flow data to socket: %s", strerror(errno));
			exit(1);
		}
		written += act_written;
	}

	nfFlw6Cnt = 0;
}
