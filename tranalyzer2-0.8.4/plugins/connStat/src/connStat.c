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

/*
 * Counts the number of connections between two hosts regarding the initiation
 * and termination of a communication and the number of distinct connections of
 * one host. Here, distinct means that only the number of different hosts the
 * actual host is connected to, are counted.
 *
 * Please note that because of the nature of this program, not all connections
 * of a host might be observed. For example if the program is sniffing the
 * traffic between a gateway and a local intranet, it is not able to observe
 * the connections between two hosts inside the intranet. Therefore, these
 * values are to be handled with care.
 */

#include "connStat.h"
#include "basicFlow.h"
#include <ctype.h> // for isdigit and toupper


// Static variables

// hashMaps for the number of connections
static hashMap_t *ipPHashMap, *ipSHashMap, *ipDHashMap, *portHashMap;
static uint32_t *ipPairConn, *ipSConn, *ipDConn, *portConn;
static uint64_t numSIP, numSIP0;
static uint64_t numDIP, numDIP0;
static uint64_t numPort, numPort0;
static uint64_t numSDIP, numSDIP0;

// Keep track of the IP with max connections
static struct {
#if IPV6_ACTIVATE > 0
	ipAddr_t     addr;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t    addr;
#endif // IPV6_ACTIVATE == 0
#if CS_GEOLOC == 1
	uint32_t     subnet;
#endif
	uint32_t     count;
	uint_fast8_t ipver;
} ipSConnMx, ipDConnMx;

// Optional dependency to basicFlow
#if CS_GEOLOC == 1
#if BFO_SUBNET_TEST == 0
#error basicFlow.h must have BFO_SUBNET_TEST=1
#endif
extern bfoFlow_t *bfoFlow __attribute__((weak));
extern void *bfo_subnet_tableP[2] __attribute__((weak));
#ifndef __APPLE__
bfoFlow_t *bfoFlow;
void *bfo_subnet_tableP[2];
#endif
#endif // CS_GEOLOC == 1


// Tranalyzer function

T2_PLUGIN_INIT_WITH_DEPS("connStat", "0.8.4", 0, 8,
#if defined(__APPLE__) && CS_GEOLOC == 1
        "basicFlow"
#else
        ""
#endif
);


void initialize() {
	// initialize the hashMaps
	ipPHashMap = hashTable_init(1.0f, sizeof(ipPID_t), "ipP");
	ipSHashMap = hashTable_init(1.0f, sizeof(ipHash_t), "ipS");
	ipDHashMap = hashTable_init(1.0f, sizeof(ipHash_t), "ipD");
	portHashMap = hashTable_init(1.0f, sizeof(ipPort_t), "port");

	if (UNLIKELY(!ipPHashMap || !ipSHashMap || !ipDHashMap || !portHashMap)) {
		T2_PERR("connStat", "failed to initialise hash tables");
		exit(1);
	}

	// initialize the counter arrays
	ipPairConn = calloc(ipPHashMap->hashChainTableSize, sizeof(uint32_t));
	ipSConn = calloc(ipSHashMap->hashChainTableSize, sizeof(uint32_t));
	ipDConn = calloc(ipDHashMap->hashChainTableSize, sizeof(uint32_t));
	portConn = calloc(portHashMap->hashChainTableSize, sizeof(uint32_t));

	if (UNLIKELY(!ipPairConn || !ipSConn || !ipDConn || !portConn)) {
		T2_PERR("connStat", "failed to allocate memory");
		exit(1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	BV_APPEND_U32(bv, "connSip"    , "Number of unique source IPs");
	BV_APPEND_U32(bv, "connDip"    , "Number of unique destination IPs");
	BV_APPEND_U32(bv, "connSipDip" , "Number of connections between source and destination IP");
	BV_APPEND_U32(bv, "connSipDprt", "Number of connections between source IP and destination port");
	BV_APPEND_FLT(bv, "connF"      , "the f number, experimental: connSipDprt / connSip");
	return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->status & L2_FLOW) return;

	const uint8_t ipver = FLOW_IS_IPV6(flowP) ? 6 : 4;

#if IPV6_ACTIVATE > 0
	ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE == 0
#if CS_GEOLOC == 1
	uint32_t srcNet = 0, dstNet = 0;
#endif
	uint16_t dstPort;

	if (flowP->status & L3FLOWINVERT) {
		srcIP = flowP->dstIP;
		dstIP = flowP->srcIP;
#if CS_GEOLOC == 1
		if (bfoFlow) {
			srcNet = bfoFlow[flowIndex].subNDst;
			dstNet = bfoFlow[flowIndex].subNSrc;
		}
#endif
		dstPort = flowP->srcPort;
	} else {
		srcIP = flowP->srcIP;
		dstIP = flowP->dstIP;
#if CS_GEOLOC == 1
		if (bfoFlow) {
			srcNet = bfoFlow[flowIndex].subNSrc;
			dstNet = bfoFlow[flowIndex].subNDst;
		}
#endif
		dstPort = flowP->dstPort;
	}

	const ipPID_t ipPair = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.srcIP = srcIP,
		.dstIP = dstIP,
	};

	unsigned long ipPairIndex = hashTable_lookup(ipPHashMap, (char*)&ipPair);
	if (ipPairIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		// Index was found -> increment counter
		ipPairConn[ipPairIndex]++;
	} else {
		// First connection between these two hosts
		// -> new hashMap entry and store info in array
		ipPairIndex = hashTable_insert(ipPHashMap, (char*)&ipPair);
		ipPairConn[ipPairIndex] = 1;

		// check if an entry for lower IP exists
		const ipHash_t hSIP = {
#if IPV6_ACTIVATE == 2
			.ver = ipver,
#endif
			.addr = srcIP,
		};

		unsigned long ipSIndex = hashTable_lookup(ipSHashMap, (char*)&hSIP);
		if (ipSIndex != HASHTABLE_ENTRY_NOT_FOUND) {
			// There is already an index, so increment it;
			ipSConn[ipSIndex]++;
		} else {
			// There is no entry, so generate one
			ipSIndex = hashTable_insert(ipSHashMap, (char*)&hSIP);
			ipSConn[ipSIndex] = 1;
			numSIP++;
		}

		if (ipSConnMx.count < ipSConn[ipSIndex]) {
			ipSConnMx.count = ipSConn[ipSIndex];
			ipSConnMx.ipver = ipver;
			ipSConnMx.addr = hSIP.addr;
#if CS_GEOLOC == 1
			if (bfoFlow) ipSConnMx.subnet = srcNet;
#endif
		}

		const ipHash_t hDIP = {
#if IPV6_ACTIVATE == 2
			.ver = ipver,
#endif
			.addr = dstIP,
		};

		unsigned long ipDIndex = hashTable_lookup(ipDHashMap, (char*)&hDIP);
		if (ipDIndex != HASHTABLE_ENTRY_NOT_FOUND) {
			// Index exists, so increment it;
			ipDConn[ipDIndex]++;
		} else {
			// There is no entry, so generate one
			ipDIndex = hashTable_insert(ipDHashMap, (char*)&hDIP);
			ipDConn[ipDIndex] = 1;
			numDIP++;
		}

		if (ipDConnMx.count < ipDConn[ipDIndex]) {
			ipDConnMx.count = ipDConn[ipDIndex];
			ipDConnMx.ipver = ipver;
			ipDConnMx.addr = hDIP.addr;
#if CS_GEOLOC == 1
			if (bfoFlow) ipDConnMx.subnet = dstNet;
#endif
		}
	}

#if CS_SDIPMAX == 1
	numSDIP = MAX(numSDIP, ipPairConn[ipPairIndex]);
#else // CS_SDIPMAX == 0
	numSDIP++;
#endif // CS_SDIPMAX == 0

	const ipPort_t ipPort = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.port = dstPort,
		.addr = srcIP,
	};

	unsigned long ipPortIndex = hashTable_lookup(portHashMap, (char*)&ipPort);
	if (ipPortIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		portConn[ipPortIndex]++;
	} else {
		ipPortIndex = hashTable_insert(portHashMap, (char*)&ipPort);
		portConn[ipPortIndex] = 1;
	}

	numPort = MAX(numPort, portConn[ipPortIndex]);
}


void onFlowTerminate(unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];

	if (flowP->status & L2_FLOW) {
		const float zero_f = 0.0f;

#if BLOCK_BUF == 0
		outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&zero_f, sizeof(float));
#endif

#if ESOM_DEP == 1
		sconn = ZERO;
		dconn = ZERO;
		iconn = ZERO;
		pconn = ZERO;
		fconn = zero_f;
#endif

		return;
	}

#if IPV6_ACTIVATE == 2
	const uint8_t ipver = FLOW_IS_IPV6(flowP) ? 6 : 4;
#endif

#if IPV6_ACTIVATE > 0
	ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE == 0
	uint16_t dstPort;

	if (flowP->status & L3FLOWINVERT) {
		srcIP = flowP->dstIP;
		dstIP = flowP->srcIP;
		dstPort = flowP->srcPort;
	} else {
		srcIP = flowP->srcIP;
		dstIP = flowP->dstIP;
		dstPort = flowP->dstPort;
	}

	const ipPID_t ipPair = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.srcIP = srcIP,
		.dstIP = dstIP,
	};

	const unsigned long ipPairIndex = hashTable_lookup(ipPHashMap, (char*)&ipPair);
	if (ipPairIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		T2_PWRN("connStat", "flowIndex: %lu, findex: %"PRIu64" has no IP pair number connections entry! 0x%016"B2T_PRIX64, flowIndex, flowP->findex, flowP->status);
	}

	const ipPort_t ipPort = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.port = dstPort,
		.addr = srcIP,
	};

	const unsigned long ipPortIndex = hashTable_lookup(portHashMap, (char*)&ipPort);
	if (ipPortIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		T2_PWRN("connStat", "flowIndex %lu, findex: %"PRIu64" has no srcIP, dstPort connections entry! 0x%016"B2T_PRIX64, flowIndex, flowP->findex, flowP->status);
	}

	const ipHash_t hSIP = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.addr = srcIP,
	};

	const unsigned long ipSIndex = hashTable_lookup(ipSHashMap, (char*)&hSIP);
	if (ipSIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		T2_PWRN("connStat", "flowIndex %lu, findex: %"PRIu64" has no src IP connections entry! 0x%016"B2T_PRIX64, flowIndex, flowP->findex, flowP->status);
	}

	const ipHash_t hDIP = {
#if IPV6_ACTIVATE == 2
		.ver = ipver,
#endif
		.addr = dstIP,
	};

	const unsigned long ipDIndex = hashTable_lookup(ipDHashMap, (char*)&hDIP);
	if (ipDIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		T2_PWRN("connStat", "flowIndex %lu, findex: %"PRIu64" has no dst IP connections entry! 0x%016"B2T_PRIX64, flowIndex, flowP->findex, flowP->status);
	}

#if BLOCK_BUF == 0 || ESOM_DEP == 1
	uint32_t *srcConn, *dstConn;
	unsigned long srcIPIndex, dstIPIndex;

	if (flowP->status & L3FLOWINVERT) {
		srcIPIndex = ipDIndex;
		dstIPIndex = ipSIndex;
		srcConn = ipDConn;
		dstConn = ipSConn;
	} else {
		srcIPIndex = ipSIndex;
		dstIPIndex = ipDIndex;
		srcConn = ipSConn;
		dstConn = ipDConn;
	}

	const uint32_t connSip = (srcIPIndex != HASHTABLE_ENTRY_NOT_FOUND) ? srcConn[srcIPIndex] : 0;
	const uint32_t connDip = (dstIPIndex != HASHTABLE_ENTRY_NOT_FOUND) ? dstConn[dstIPIndex] : 0;
	const uint32_t connSipDip = (ipPairIndex != HASHTABLE_ENTRY_NOT_FOUND) ? ipPairConn[ipPairIndex] : 0;
	const uint32_t connSipDprt = (ipPortIndex != HASHTABLE_ENTRY_NOT_FOUND) ? portConn[ipPortIndex] : 0;
	const float connF = (connSip != 0) ? connSipDprt / (float)connSip : 0.0f;
#endif // BLOCK_BUF == 0 || ESOM_DEP == 1

#if BLOCK_BUF == 0
	OUTBUF_APPEND_U32(main_output_buffer, connSip);
	OUTBUF_APPEND_U32(main_output_buffer, connDip);
	OUTBUF_APPEND_U32(main_output_buffer, connSipDip);
	OUTBUF_APPEND_U32(main_output_buffer, connSipDprt);
	OUTBUF_APPEND_FLT(main_output_buffer, connF);
#endif

#if ESOM_DEP == 1
	sconn = connSip;
	dconn = connDip;
	iconn = connSipDip;
	pconn = connSipDprt;
	fconn = connF;
#endif

#if CS_HSDRM == 1
	portConn[ipPortIndex]--;

	if (portConn[ipPortIndex] == 0) {
		hashTable_remove(portHashMap, (char*)&ipPort);
	}

	// decrement the ip pair connection counter until A,B flows are processed
	ipPairConn[ipPairIndex]--;

	// if all connections between src and dst are closed,
	// then decrement all other vars
	if (ipPairConn[ipPairIndex] == 0) {
		// Last connection between these two hosts, so remove entry in
		// hashTable and decrement ip connection counters for both hosts
		// and delete them if they are zero.
		hashTable_remove(ipPHashMap, (char*)&ipPair);

		// Decrement the source ip counter
		ipSConn[ipSIndex]--;

		// Check if it is zero. If it is, remove the hashTable entry
		if (ipSConn[ipSIndex] == 0) {
			hashTable_remove(ipSHashMap, (char*)&hSIP);
		}

		// Decrement the dest ip counter
		ipDConn[ipDIndex]--;

		// Check if it is zero. If it is, remove the hashTable entry
		if (ipDConn[ipDIndex] == 0) {
			hashTable_remove(ipDHashMap, (char*)&hDIP);
		}
	}
#endif // CS_HSDRM == 1
}


static void connStat_pluginReport(FILE *stream) {
	const uint64_t numSIPDiff = numSIP - numSIP0;
	T2_FPLOG_NUM(stream, "connStat", "Number of unique source IPs", numSIPDiff);

	const uint64_t numDIPDiff = numDIP - numDIP0;
	T2_FPLOG_NUM(stream, "connStat", "Number of unique destination IPs", numDIPDiff);

	const uint64_t numSDIPDiff = numSDIP - numSDIP0;
	T2_FPLOG_NUM(stream, "connStat", "Number of unique source/destination IPs connections", numSDIPDiff);

	const uint64_t numPortDiff = numPort - numPort0;
	T2_FPLOG_NUM(stream, "connStat", "Max unique number of source IP / destination port connections", numPortDiff);

	const float fave = numPortDiff / (float)numSDIPDiff;
	const float fave1 = numPortDiff / (float)numSIPDiff;
	T2_FPLOG(stream, "connStat", "IP prtcon/sdcon, prtcon/scon: %f, %f", fave, fave1);
}


#if CS_GEOLOC == 1
#define CS_FORMAT_LOC(loc) \
	if ((loc)[0] == '-' || isdigit((loc)[0])) { \
		loc = ""; \
	} else { \
		loc_str[2] = toupper((loc)[0]); \
		loc_str[3] = toupper((loc)[1]); \
		loc = loc_str; \
	}
#endif


static void report_ip_with_most_connections(FILE *stream) {
	char *loc = "";
#if CS_GEOLOC == 1
	char loc_str[] = " (XX)"; // XX will be replaced by the country code
#endif
	char str[64];
	char ipstr[INET6_ADDRSTRLEN];

	if (ipSConnMx.count) {
		T2_IP_TO_STR(ipSConnMx.addr, ipSConnMx.ipver, ipstr, INET6_ADDRSTRLEN);
		T2_CONV_NUM(ipSConnMx.count, str);
#if CS_GEOLOC == 1
		if (bfoFlow) {
			SUBNET_LOC(loc, bfo_subnet_tableP, ipSConnMx.ipver, ipSConnMx.subnet);
			CS_FORMAT_LOC(loc);
		}
#endif
		T2_FPLOG(stream, "connStat", "Source IP with max connections: %s%s: %"PRIu32"%s connections",
				ipstr, loc, ipSConnMx.count, str);
	}

	if (ipDConnMx.count) {
		T2_IP_TO_STR(ipDConnMx.addr, ipDConnMx.ipver, ipstr, INET6_ADDRSTRLEN);
		T2_CONV_NUM(ipDConnMx.count, str);
#if CS_GEOLOC == 1
		if (bfoFlow) {
			SUBNET_LOC(loc, bfo_subnet_tableP, ipDConnMx.ipver, ipDConnMx.subnet);
			CS_FORMAT_LOC(loc);
		}
#endif
		T2_FPLOG(stream, "connStat", "Destination IP with max connections: %s%s: %"PRIu32"%s connections",
				ipstr, loc, ipDConnMx.count, str);
	}
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
	numSIP0 = 0;
	numDIP0 = 0;
	numSDIP0 = 0;
	numPort0 = 0;
#endif
	connStat_pluginReport(stream);
	report_ip_with_most_connections(stream);
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("connSip\tconnDip\tconnSipDip\tconnFave\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_REPORT:
			connStat_pluginReport(stream);
#if DIFF_REPORT == 0
			report_ip_with_most_connections(stream);
#endif
			break;

		case T2_MON_PRI_VAL: {
			const uint64_t numSIPDiff = numSIP - numSIP0;
			const uint64_t numDIPDiff = numDIP - numDIP0;
			const uint64_t numSDIPDiff = numSDIP - numSDIP0;
			const uint64_t numPortDiff = numPort - numPort0;
			const float fave = numPortDiff / (float)numSDIPDiff;
			fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%.3f\t", // Note the trailing tab (\t)
					numSIPDiff, numDIPDiff, numSDIPDiff, numPortDiff, fave);
			break;
		}

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	numSIP0 = numSIP;
	numDIP0 = numDIP;
	numSDIP0 = numSDIP;
	numPort0 = numPort;
#endif
}


void saveState(FILE *stream) {
	fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64,
			numSIP, numDIP, numSDIP, numPort);
}


void restoreState(const char *str) {
	sscanf(str, "%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64,
			&numSIP, &numDIP, &numSDIP, &numPort);

#if DIFF_REPORT == 1
	numSIP0 = numSIP;
	numDIP0 = numDIP;
	numSDIP0 = numSDIP;
	numPort0 = numPort;
#endif
}


void onApplicationTerminate() {
	hashTable_destroy(ipPHashMap);
	hashTable_destroy(ipSHashMap);
	hashTable_destroy(ipDHashMap);
	hashTable_destroy(portHashMap);

	free(ipPairConn);
	free(ipSConn);
	free(ipDConn);
	free(portConn);
}
