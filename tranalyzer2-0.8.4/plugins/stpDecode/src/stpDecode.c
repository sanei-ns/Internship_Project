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

#include "stpDecode.h"


// Global variables

stpFlow_t *stpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t numStpPkts, numStpPkts0;


#define STP_SPKTMD_PRI_NONE() \
	if (sPktFile) { \
		fputs("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", sPktFile); \
	}

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("stpDecode", "0.8.4", 0, 8);


void initialize() {
#if ETH_ACTIVATE == 0
    T2_PWRN("stpDecode", "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
	if (UNLIKELY(!(stpFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*stpFlows))))) {
		T2_PERR("stpDecode", "failed to allocate memory for stpFlows");
		exit(-1);
	}

	if (sPktFile) {
		fputs("stpProto\tstpVersion\tstpType\tstpFlags\tstpRootPrio\t"
		      "stpRootHw\tstpRootCost\tstpBridgePrio\tstpBridgeHw\tstpPort\t"
		      "stpMsgAge\tstpMaxAge\tstpHello\tstpForward\tstpPvstOrigVlan\t", sPktFile);
	}
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	BV_APPEND_H8(bv, "stpStat"   , "STP status");
	//BV_APPEND_H16(bv, "stpProto", "STP Protocol Identifier"); // Always 0x0000
	BV_APPEND_U8(bv, "stpVersion", "STP Protocol Version Identifier");
	BV_APPEND_H8(bv, "stpType"   , "STP Aggregated BPDU Types");
	BV_APPEND_H8(bv, "stpFlags"  , "STP Aggregated BPDU Flags");
	return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
	stpFlow_t * const stpFlowP = &stpFlows[flowIndex];
	memset(stpFlowP, '\0', sizeof(*stpFlowP));

	if (!(packet->status & L2_FLOW)) return;

	const uint_fast16_t l2Type = packet->layer2Type;
	if ((l2Type & LLC_DCODE) != LLC_STP && l2Type != ETHERTYPE_PVSTP) return;

	stpFlowP->stat |= STP_STAT_STP;

	const stpMsg_t * const stpMsgP = (stpMsg_t*)packet->layer7Header;
	//stpFlowP->proto = stpMsgP->proto;
	stpFlowP->version = stpMsgP->version;
}


void claimLayer2Information(packet_t* packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

	stpFlow_t * const stpFlowP = &stpFlows[flowIndex];
	if (!stpFlowP->stat) {
		STP_SPKTMD_PRI_NONE();
		return;
	}

	numStpPkts++;

	const stpMsg_t * const stpMsgP = (stpMsg_t*)packet->layer7Header;
	stpFlowP->flags |= stpMsgP->flags;
	stpFlowP->type |= stpMsgP->type;

	if (!sPktFile) return;

	fprintf(sPktFile, "0x%04"B2T_PRIX16"\t%"PRIu8"\t0x%02"B2T_PRIX8"\t",
			stpMsgP->proto, stpMsgP->version, stpMsgP->type);

	if (stpMsgP->type == STP_BPDU_T_TCN) {
		fputs("\t\t\t\t\t\t\t\t\t\t\t\t", sPktFile);
		return;
	}

	char bridgeHw[32] = {}, rootHw[32] = {};
	t2_mac_to_str(&stpMsgP->rootHw[0], rootHw, sizeof(rootHw));
	t2_mac_to_str(&stpMsgP->bridgeHw[0], bridgeHw, sizeof(bridgeHw));
	fprintf(sPktFile,
			"0x%02"B2T_PRIX8"\t%"PRIu16"\t%s\t%"PRIu32"\t"
			"%"PRIu16"\t%s\t0x%04"B2T_PRIX16"\t%"PRIu16"\t"
			"%"PRIu16"\t%"PRIu16"\t%"PRIu16"\t",
			stpMsgP->flags, STP_ROOT_PRIO(stpMsgP), rootHw, ntohl(stpMsgP->rootCost),
			STP_BRIDGE_PRIO(stpMsgP), bridgeHw, ntohs(stpMsgP->port), stpMsgP->msgAge,
			stpMsgP->maxAge, stpMsgP->hello, stpMsgP->forward);
	// TODO MST Extension
	if (packet->layer2Type == ETHERTYPE_PVSTP && ((uint8_t*)stpMsgP + sizeof(stpMsg_t)) < packet->end_packet) {
		const pvstpTLV_t *tlv = (pvstpTLV_t*)((uint8_t*)stpMsgP + sizeof(stpMsg_t));
		if (tlv->type == 0 && ntohs(tlv->len) == 2) {
			fprintf(sPktFile, "%"PRIu16"\t", ntohs(tlv->value));
		} else {
			fputs("\t", sPktFile);
		}
	} else {
		fputs("\t", sPktFile);
	}
}


void claimLayer4Information(packet_t* packet __attribute__((unused)), unsigned long flowIndex __attribute__((unused))) {
    STP_SPKTMD_PRI_NONE();
}

#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	const stpFlow_t * const stpFlowP = &stpFlows[flowIndex];
	OUTBUF_APPEND_U8(main_output_buffer, stpFlowP->stat);
	//OUTBUF_APPEND_U16(main_output_buffer, stpFlowP->proto);
	OUTBUF_APPEND_U8(main_output_buffer, stpFlowP->version);
	OUTBUF_APPEND_U8(main_output_buffer, stpFlowP->type);
	OUTBUF_APPEND_U8(main_output_buffer, stpFlowP->flags);
}
#endif // BLOCK_BUF == 0


static void stp_pluginReport(FILE *stream) {
	T2_FPLOG_DIFFNUMP(stream, "stpDecode", "Number of STP packets", numStpPkts, numPackets);
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
	numStpPkts0 = 0;
#endif // DIFF_REPORT == 1
	stp_pluginReport(stream);
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("stpPkts\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t", numStpPkts - numStpPkts0); // Note the trailing tab (\t)
			break;

		case T2_MON_PRI_REPORT:
			stp_pluginReport(stream);
			break;

		default: // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	numStpPkts0 = numStpPkts;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
	free(stpFlows);
}

#endif // ETH_ACTIVATE > 0
