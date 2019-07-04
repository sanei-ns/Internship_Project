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

#include "protoStats.h"


// Static variables

typedef struct {
	uint64_t pkts;
	uint64_t bytes;
} port_usage_t;

static port_usage_t tcpPortUsage[L4PORTMAX+1];
static port_usage_t udpPortUsage[L4PORTMAX+1];

#if UDPLITE_STAT == 1
static port_usage_t udplitePortUsage[L4PORTMAX+1];
#endif

#if SCTP_STAT == 1
static port_usage_t sctpPortUsage[L4PORTMAX+1];
#endif

#if ETH_STAT == 1
static char l2_ethname[L2ETHTYPEMAX+1][L2ETHMAXLEN+1];
#endif
static char tcp_portname[L4PORTMAX+1][L4PORTMAXLEN+1];
static char udp_portname[L4PORTMAX+1][L4PORTMAXLEN+1];


// Macros

#define PS_PRINT_L4PROTO(file, name, proto, portUsage, portName) { \
	char str[64]; \
	T2_CONV_NUM(numPacketsL3[proto], str); \
	fprintf(file, "\n\n# Total %s packets: %"PRIu64"%s [%.02f%%]\n", name, \
			numPacketsL3[proto], str, 100.0 * numPacketsL3[proto] / (double)numPackets); \
	T2_CONV_NUM(numBytesL3[proto], str); \
	fprintf(file, "# Total %s bytes: %"PRIu64"%s [%.02f%%]\n", name, \
			numBytesL3[proto], str, 100.0 * numBytesL3[proto] / (double)bytesProcessed); \
	if (numPacketsL3[proto] > 0) { \
		const double percent_pkts = 100.0f / (double) numPacketsL3[proto]; \
		const double percent_bytes = 100.0f / (double) numBytesL3[proto]; \
		fprintf(file, "# %s Port\t%20s\t%20s\tDescription\n", name, "Packets", "Bytes"); \
		for (uint_fast32_t i = 0; i <= L4PORTMAX; i++) { \
			if (portUsage[i].pkts > 0) { \
				fprintf(file, "%5"PRIuFAST32"\t" \
						"%20"PRIu64" [%6.02f%%]\t" /* packets */ \
						"%20"PRIu64" [%6.02f%%]\t" /* bytes   */ \
						"%s\n", i, \
						portUsage[i].pkts, portUsage[i].pkts * percent_pkts, \
						portUsage[i].bytes, portUsage[i].bytes * percent_bytes, \
						portName[i]); \
			} \
		} \
	} \
}


// Tranalyer Plugin functions

T2_PLUGIN_INIT("protoStats", "0.8.4", 0, 8);


//void initialize() {
//	// Nothing to do
//}


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];
	const uint_fast16_t dport = (flowP->status & L3FLOWINVERT) ? flowP->srcPort : flowP->dstPort;

	// check for encapsulated packet
	switch (packet->layer4Type) {

		case L3_TCP:
			tcpPortUsage[dport].pkts++;
			tcpPortUsage[dport].bytes += packet->snapLength;
			break;

		case L3_UDP:
			udpPortUsage[dport].pkts++;
			udpPortUsage[dport].bytes += packet->snapLength;
			break;

#if UDPLITE_STAT == 1
		case L3_UDPLITE:
			udplitePortUsage[dport].pkts++;
			udplitePortUsage[dport].bytes += packet->snapLength;
			return;
#endif

#if SCTP_STAT == 1
		case L3_SCTP:
			sctpPortUsage[dport].pkts++;
			sctpPortUsage[dport].bytes += packet->snapLength;
			break;
#endif

		default:
			return; // no ports
	}
}


void onApplicationTerminate() {
	FILE *file;
	uint_fast32_t i;
	char s[L4PORTMAXLEN+1];

#if ETH_STAT == 1
	// Read ethernet type decoder file
	file = t2_open_file(pluginFolder, L2ETHFILE, "r");
	if (LIKELY(file != NULL)) {
		uint32_t num1, num2;
		char ss[L2ETHMAXLEN+1];
		while (fgets(s, L2ETHMAXLEN, file)) {
			const char *p = strchr(s, '-');
			if (p && p - s < 8) {
				sscanf(s, "0x%04x-0x%04x\t%"STR(L2ETHMAXLEN)"[^\n\t]", &num1, &num2, ss);
				for (i = num1; i <= num2; i++) {
					memcpy(l2_ethname[i], ss, strlen(ss)+1);
				}
			} else {
				sscanf(s, "0x%04x\t%"STR(L2ETHMAXLEN)"[^\n\t]", &num1, ss);
				memcpy(l2_ethname[num1], ss, strlen(ss)+1);
			}
		}
		fclose(file);
	}
#endif // ETH_STAT == 1

	int z;
	char ip_protname[IPPROTMAX+1][IPPROTMAXLEN+1] = {};

	// Read proto decoder file
	file = t2_open_file(pluginFolder, PROTOFILE, "r");
	if (LIKELY(file != NULL)) {
		uint32_t num;
		for (i = 0; i <= IPPROTMAX; i++) {
			z = fscanf(file, "%"SCNu32"\t%*"STR(L4PORTMAXLEN)"[^\n\t]\t%"STR(IPPROTMAXLEN)"[^\n\t]", &num, ip_protname[i]);
			if (UNLIKELY(z != 2)) {
				T2_PWRN("protoStats", "Failed to read line %"PRIuFAST32" of file '%s': %s", i, PROTOFILE, strerror(errno));
				continue;
			}
		}
		fclose(file);
	}

	// Read port decoder file
	file = t2_open_file(pluginFolder, PORTFILE, "r");
	if (LIKELY(file != NULL)) {
		char l4P[4];
		while (1) {
			z = fscanf(file, "%"SCNuFAST32"\t%3[^\n\t]\t%*"STR(L4PORTMAXLEN)"[^\n\t]\t%"STR(L4PORTMAXLEN)"[^\n\t]", &i, l4P, s);
			if (z <= 0) break;
			if (strncmp("udp", l4P, 3) == 0) strncpy(udp_portname[i], s, L4PORTMAXLEN);
			else if (strncmp("tcp", l4P, 3) == 0) strncpy(tcp_portname[i], s, L4PORTMAXLEN);
		}
		fclose(file);
	}

	// open protocol statistics file
	file = t2_open_file(baseFileName, PROTO_SUFFIX, "w");
	if (UNLIKELY(!file)) exit(-1);

	char str[64];
	const uint64_t numBytes = bytesProcessed;
	const double percent_pkts  = 100.0f / (double)numPackets;
	const double percent_bytes = 100.0f / (double)numBytes;

#if ETH_STAT == 1
	T2_CONV_NUM(numPackets, str);
	fprintf(file, "# Total packets: %"PRIu64"%s\n", numPackets, str);
	T2_CONV_NUM(numBytes, str);
	fprintf(file, "# Total bytes: %"PRIu64"%s\n", numBytes, str);
	fprintf(file, "# L2/3 Protocol\t%20s\t%20s\tDescription\n", "Packets", "Bytes");

	// print protocol usage
	for (i = 0; i <= L2ETHTYPEMAX; i++) {
		if (numPacketsL2[i] > 0) {
			fprintf(file, "0x%04"B2T_PRIXFAST32"\t"
					"%20"PRIu64" [%6.02f%%]\t"    // packets
					"%20"PRIu64" [%6.02f%%]\t"    // bytes
					"%s\n", i,
					numPacketsL2[i], numPacketsL2[i] * percent_pkts,
					numBytesL2[i], numBytesL2[i] * percent_bytes,
					l2_ethname[i]);
		}
	}
	fprintf(file, "\n\n");
#endif // ETH_STAT == 1

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	T2_CONV_NUM(numV4Packets, str);
	fprintf(file, "# Total IPv4 packets: %"PRIu64"%s [%.02f%%]\n", numV4Packets, str, numV4Packets * percent_pkts);
#endif

#if IPV6_ACTIVATE > 0
	T2_CONV_NUM(numV6Packets, str);
	fprintf(file, "# Total IPv6 packets: %"PRIu64"%s [%.02f%%]\n", numV6Packets, str, numV6Packets * percent_pkts);
#endif

	// print protocol usage
	fprintf(file, "# L4 Protocol\t%20s\t%20s\tDescription\n", "Packets", "Bytes");
	for (i = 0; i <= IPPROTMAX; i++) {
		if (numPacketsL3[i] > 0) {
			fprintf(file, "%3"PRIuFAST32"\t"
					"%20"PRIu64" [%6.02f%%]\t"    // packets
					"%20"PRIu64" [%6.02f%%]\t"    // bytes
					"%s\n", i,
					numPacketsL3[i], numPacketsL3[i] * percent_pkts,
					numBytesL3[i], numBytesL3[i] * percent_bytes,
					ip_protname[i]);
		}
	}

	// print port usage
	PS_PRINT_L4PROTO(file, "TCP", L3_TCP, tcpPortUsage, tcp_portname);
	PS_PRINT_L4PROTO(file, "UDP", L3_UDP, udpPortUsage, udp_portname);

#if UDPLITE_STAT == 1
	PS_PRINT_L4PROTO(file, "UDP-Lite", L3_UDPLITE, udplitePortUsage, udp_portname);
#endif

#if SCTP_STAT == 1
	PS_PRINT_L4PROTO(file, "SCTP", L3_SCTP, sctpPortUsage, tcp_portname);
#endif

	fclose(file);
}
