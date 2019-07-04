/*
 * nDPI.c
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

// local includes
#include "nDPI.h"
#include "global.h"

#if NDPI_OUTPUT_STATS != 0
#include "ndpi_protocol_ids.h"
#endif // NDPI_OUTPUT_STATS != 0

// global includes
#include <stdio.h>


// Global variables

nDPI_flow_t *nDPI_flows;


// Static variables

static uint64_t num_classified;
static struct ndpi_detection_module_struct *nDPIstruct;

#if NDPI_OUTPUT_STATS != 0
typedef struct {
    uint64_t pkts;
    uint64_t bytes;
} ndpi_stat_t;
static ndpi_stat_t nDPIstats[NDPI_MAX_SUPPORTED_PROTOCOLS];
#endif // NDPI_OUTPUT_STATS != 0


// Tranalyzer functions

T2_PLUGIN_INIT(NDPI_PLUGIN_NAME, "0.8.4", 0, 8);


void initialize() {
    // allocate struct for all flows and initialise to 0
    if (UNLIKELY(!(nDPI_flows = calloc(mainHashMap->hashChainTableSize, sizeof(nDPI_flow_t))))) {
        T2_PERR(NDPI_PLUGIN_NAME, "failed to allocate memory for nDPI flows");
        exit(-1);
    }

    // initialize nDPI global strucure
    NDPI_PROTOCOL_BITMASK all;
    nDPIstruct = ndpi_init_detection_module();

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(nDPIstruct, &all);
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    // this plugin only outputs one column with protocol classification
#if NDPI_OUTPUT_NUM != 0
    bv = bv_append_bv(bv, bv_new_bv("numerical nDPI master protocol", "nDPIMasterProto", 0, 1, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("numerical nDPI sub protocol", "nDPISubProto", 0, 1, bt_uint_16));
#endif
#if NDPI_OUTPUT_STR != 0
    bv = bv_append_bv(bv, bv_new_bv("nDPI based protocol classification", "nDPIclass", 0, 1, bt_string));
#endif
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__ ((unused)), unsigned long flowIndex) {
    flow_t *flowP = &flows[flowIndex];
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    memset(nDPI_P, 0, sizeof(nDPI_flow_t)); // set everything to 0

    // if nDPI structures are already defined in opposite flow, link them in this flow
    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
    if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        nDPI_flow_t *opposite_nDPI_P = &nDPI_flows[oppositeFlowIndex];
        nDPI_P->ndpiFlow = opposite_nDPI_P->ndpiFlow;
        // interchanging src and dst has no effect
        nDPI_P->ndpiSrc = opposite_nDPI_P->ndpiSrc;
        nDPI_P->ndpiDst = opposite_nDPI_P->ndpiDst;
        return;
    }

    // otherwise, initialize nDPI structures in this flow
    if (!(nDPI_P->ndpiFlow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT))) {
        T2_PERR(NDPI_PLUGIN_NAME, "failed to allocate memory for ndpi_flow_struct");
        terminate();
    }
    memset(nDPI_P->ndpiFlow, 0, SIZEOF_FLOW_STRUCT);
    // initialize the src/dst states
    if (!(nDPI_P->ndpiSrc = ndpi_malloc(SIZEOF_ID_STRUCT))) {
        T2_PERR(NDPI_PLUGIN_NAME, "failed to allocate memory for src ndpi_id_struct");
        terminate();
    }
    memset(nDPI_P->ndpiSrc, 0, SIZEOF_ID_STRUCT);
    if (!(nDPI_P->ndpiDst = ndpi_malloc(SIZEOF_ID_STRUCT))) {
        T2_PERR(NDPI_PLUGIN_NAME, "failed to allocate memory for src ndpi_id_struct");
        terminate();
    }
    memset(nDPI_P->ndpiDst, 0, SIZEOF_ID_STRUCT);
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    ++nDPI_P->sent_pkts;
#if NDPI_OUTPUT_STATS == 1
    nDPI_P->sent_bytes += packet->snapLength;
#endif
    if (nDPI_P->done) {
        return;
    }
    flow_t *flowP = &flows[flowIndex];

    const uint32_t tick_res = nDPIstruct->ticks_per_second;
    const uint64_t time = ((uint64_t) packet->pcapHeader->ts.tv_sec) * tick_res +
            packet->pcapHeader->ts.tv_usec / (1000000 / tick_res);

#if NDPI_GUESS_UNKNOWN != 0
    uint16_t ip_len = packet->snapL3Length;
    if (ip_len > NDPI_MAX_PKT_LEN) {
        //T2_PWRN(NDPI_PLUGIN_NAME, "packet too long: %u snapped to %u", ip_len, NDPI_MAX_PKT_LEN);
        ip_len = NDPI_MAX_PKT_LEN;
    }
    memcpy(nDPI_P->ndpi_pkt, packet->layer3Header, ip_len);
    const uint8_t * const ip_pkt = nDPI_P->ndpi_pkt;
#else // NDPI_GUESS_UNKNOWN == 0
    const uint16_t ip_len = packet->snapL3Length;
    const uint8_t * const ip_pkt = (uint8_t *)packet->layer3Header;
#endif // NDPI_GUESS_UNKNOWN != 0

    // detect protocol using nDPI
    nDPI_P->classification = ndpi_detection_process_packet(
        nDPIstruct, // nDPI global data structure
        nDPI_P->ndpiFlow, // nDPI per flow data structure
        ip_pkt,
        ip_len,
        time,
        nDPI_P->ndpiSrc,
        nDPI_P->ndpiDst);

    if (nDPI_P->classification.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
            // give up conditions: taken from ndpiReader
            (flowP->layer4Protocol == L3_UDP && nDPI_P->sent_pkts > 8) ||
            (flowP->layer4Protocol == L3_TCP && nDPI_P->sent_pkts > 10)) {
        nDPI_P->done = true;
        // newer version of nDPI do not work properly without guessing
        if (nDPI_P->classification.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
            nDPI_P->classification = ndpi_detection_giveup(nDPIstruct, nDPI_P->ndpiFlow,
                    NDPI_GUESS_UNKNOWN);
        }
        // also store classification in opposite flow
        const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
        if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            nDPI_flows[oppositeFlowIndex].classification = nDPI_P->classification;
            nDPI_flows[oppositeFlowIndex].done = true;
        }
    }
}

void onFlowTerminate(unsigned long flowIndex) {
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];
    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;

    // if nDPI detection was not finished before end of flow, try guessing
    if (!nDPI_P->done) {
        nDPI_P->classification = ndpi_detection_giveup(nDPIstruct, nDPI_P->ndpiFlow,
                NDPI_GUESS_UNKNOWN);
        if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            nDPI_flows[oppositeFlowIndex].classification = nDPI_P->classification;
        }
    }

#if (NDPI_OUTPUT_NUM | NDPI_OUTPUT_STATS) != 0
    uint16_t appProtocol = nDPI_P->classification.app_protocol;
    uint16_t masterProtocol = nDPI_P->classification.master_protocol;
    // if only app protocol is defined, move it to master protocol
    if (masterProtocol == NDPI_PROTOCOL_UNKNOWN && appProtocol != NDPI_PROTOCOL_UNKNOWN) {
        masterProtocol = appProtocol;
        appProtocol = NDPI_PROTOCOL_UNKNOWN;
    }
#endif // (NDPI_OUTPUT_NUM | NDPI_OUTPUT_STATS) != 0
#if NDPI_OUTPUT_NUM != 0
    outputBuffer_append(main_output_buffer, (char*)&masterProtocol, sizeof(masterProtocol));
    outputBuffer_append(main_output_buffer, (char*)&appProtocol, sizeof(appProtocol));
#endif
    // output nDPI protocol classification string
#if NDPI_OUTPUT_STR != 0
    char buffer[NDPI_BUFFER_LEN];
    ndpi_protocol2name(nDPIstruct, nDPI_P->classification, buffer, NDPI_BUFFER_LEN);
    outputBuffer_append(main_output_buffer, buffer, strlen(buffer) + 1);
#endif

    // release nDPI per flow structures
    if (oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND || (flowP->status & L3FLOWINVERT)) {
        ndpi_free_flow(nDPI_P->ndpiFlow);
        ndpi_free(nDPI_P->ndpiSrc);
        ndpi_free(nDPI_P->ndpiDst);
    }

    if (masterProtocol != NDPI_PROTOCOL_UNKNOWN) num_classified++;

#if NDPI_OUTPUT_STATS != 0
    // increase the stats counters
    nDPIstats[masterProtocol].pkts += nDPI_P->sent_pkts;
    nDPIstats[masterProtocol].bytes += nDPI_P->sent_bytes;
    // if there is a sub protocol, count this flow in both protocols
    // for instance DNS.Google will count in Google and in DNS
    if (appProtocol != NDPI_PROTOCOL_UNKNOWN) {
        nDPIstats[appProtocol].pkts += nDPI_P->sent_pkts;
        nDPIstats[appProtocol].bytes += nDPI_P->sent_bytes;
    }
#endif // NDPI_OUTPUT_STATS != 0
}

void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, NDPI_PLUGIN_NAME, "Number of flows classified", num_classified, totalFlows);
}

void onApplicationTerminate() {
#if NDPI_OUTPUT_STATS != 0
    // open file
    FILE *file = t2_open_file(baseFileName, NDPI_STATS_SUFFIX, "w");
    if (file == NULL) {
        exit(-1);
    }

    // print the header line
    fprintf(file, "# Protocol ID\tPackets\tBytes\tDescription\n");

    // print the frequency for each protocol
    const double percent_pkts = 100.0 / (double)numPackets;
    const double percent_bytes = 100.0 / (double)bytesProcessed;
    for (uint16_t i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; ++i) {
        const uint64_t pkt_count = nDPIstats[i].pkts;
        if (pkt_count != 0) {
            const uint64_t byte_count = nDPIstats[i].bytes;
            const double pkt_freq = pkt_count * percent_pkts;
            const double byte_freq = byte_count * percent_bytes;
            const char * const protoDescr = ndpi_get_proto_name(nDPIstruct, i);
            fprintf(file, "%3d\t"                 // i
                    "%20" PRIu64 " [%6.02f%%]\t"  // pkt_count, pkt_freq
                    "%20" PRIu64 " [%6.02f%%]\t"  // byte_count, byte_freq
                    "%s\n", i,                    // protoDescr
                    pkt_count, pkt_freq,
                    byte_count, byte_freq,
                    protoDescr);
        }
    }

    // flush and close the file
    fflush(file);
    fclose(file);
#endif // NDPI_OUTPUT_STATS != 0

    // release nDPI global structure
    if (nDPIstruct) {
        ndpi_exit_detection_module(nDPIstruct);
        nDPIstruct = NULL;
    }

    // release memory allocated for this plugin
    free(nDPI_flows);
}
