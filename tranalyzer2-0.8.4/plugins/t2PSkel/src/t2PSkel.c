/*
 * t2PSkel.c
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

#include "t2PSkel.h"


/*
 * Plugin variables that may be used by other plugins (MUST be declared in
 * the header file as 'extern t2PSkel_flow_t *t2PSkel_flows;'
 */
t2PSkel_flow_t *t2PSkel_flows;


/*
 * Variables from dependencies, i.e., other plugins, MUST be declared weak,
 * in order to prevent dlopen() from trying to resolve them. If the symbols
 * are missing, it means the required dependency was not loaded. The error
 * will be reported by loadPlugins.c when checking for the dependencies
 * listed in the get_dependencies() or T2_PLUGIN_INIT_WITH_DEPS() function.
 */
//extern pktSIAT_t *pktSIAT_trees __attribute__((weak));

/*
 * If the dependency is optional, it MUST be defined with the following two
 * statements and the dependency MUST NOT be listed in get_dependencies())
 */
//extern pktSIAT_t *pktSIAT_trees __attribute__((weak));
//pktSIAT_t *pktSIAT_trees;


/*
 * Static variables are only visible in this file
 */
static uint64_t numT2PSkelPkts;
static uint64_t numT2PSkelPkts0;

static uint8_t t2PSkelStat;

/*
 * Function prototypes
 */

static void t2PSkel_pluginReport(FILE *stream);


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
//T2_PLUGIN_INIT("t2PSkel", "0.8.4", 0, 8);
T2_PLUGIN_INIT_WITH_DEPS("t2PSkel", "0.8.4", 0, 8, "tcpFlags,tcpStates");


/*
 * This function is called before processing any packet.
 */
void initialize() {
    // allocate struct for all flows and initialise to 0
    if (UNLIKELY(!(t2PSkel_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*t2PSkel_flows))))) {
        T2_PERR("t2PSkel", "failed to allocate memory for t2PSkel_flows");
        exit(-1);
    }

    // Packet mode
    if (sPktFile) {
        fputs("pktModeColname\t", sPktFile); // Note the trailing tab (\t)
    }

#if T2PSKEL_LOAD == 1
    // Load a file from the plugin folder
    FILE *file = t2_open_file(pluginFolder, T2PSKEL_FNAME, "r");
    if (UNLIKELY(!file)) exit(1);

    //const size_t plen = pluginFolder_len;
    //char filename[pluginFolder_len + sizeof(T2PSKEL_FNAME) + 1];
    //strncpy(filename, pluginFolder, plen+1);
    //strncpy(filename+plen, T2PSKEL_FNAME, sizeof(T2PSKEL_FNAME)+1);

    //FILE *f = fopen(filename, "r");
    //if (UNLIKELY(!f)) {
    //    T2_PERR("t2PSkel", "failed to open file '%s' for reading: %s", filename, strerror(errno));
    //    exit(1);
    //}

    // TODO do something with the file

    fclose(file);
#endif // T2PSKEL_LOAD == 1
}


/*
 * This function is used to describe the columns output by the plugin
 */
binary_value_t* printHeader() {
    binary_value_t *bv = NULL;

    // 8-bits hexadecimal variable, e.g., 0x12
    BV_APPEND_H8(bv, "t2PSkelStat", "t2PSkel status");
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkel status", "t2PSkelStat", 0, 1, bt_hex_8));

    // String, e.g., "text"
    BV_APPEND_STR(bv, "t2PSkelText", "Description t2PSkelText");
    //bv = bv_append_bv(bv, bv_new_bv("Description of t2PSkelText", "t2PSkelText", 0, 1, bt_string));

#if T2PSKEL_VAR == 1
    // 64-bits unsigned variable
    BV_APPEND_U64(bv, "t2PSkelVar", "Description of t2PSkelVar");
    //bv = bv_append_bv(bv, bv_new_bv("Description of t2PSkelVar", "t2PSkelVar", 0, 1, bt_uint_64));
#endif

#if T2PSKEL_IP == 1
    // IPv4 address (32 bits), e.g., 10.0.1.2 or 0x0a000102
    // (Output format is controlled by IP4_FORMAT in utils/bin2txt.h)
    BV_APPEND_IP4(bv, "t2PSkelIP", "Description of t2PSkelIP");
    //bv = bv_append_bv(bv, bv_new_bv("Description of t2PSkelIP", "t2PSkelIP", 0, 1, bt_ip4_addr));
#endif

    // Compound: 32-bits hexadecimal value and 16-bits hexadecimal value, e.g., 0x12488421_0x14
    BV_APPEND(bv, "t2PSkelVar1_Var2", "Description of t2PSkelVar1_Var2", 2, bt_hex_32, bt_hex_16);
    //bv = bv_append_bv(bv, bv_new_bv("Description of t2PSkelVar1_Var2", "t2PSkelVar1_Var2", 0, 2, bt_hex_32, bt_hex_16));

#if T2PSKEL_VEC == 1
    // Repetitive compound: vector of two 8-bits unsigned int, e.g., 0_1;2_3;4_5;6_7;8_9
    BV_APPEND_R(bv, "t2PSkelVar3_Var4", "Description of t2PSkelVar3_Var4", 2, bt_uint_8, bt_uint_8);
    //bv = bv_append_bv(bv, bv_new_bv("Description of t2PSkelVar3_Var4", "t2PSkelVar3_Var4", 1, 2, bt_uint_8, bt_uint_8));

    // A matrix
    binary_value_t *act_bv = bv_new_bv("Matrix/Multiple Vector Output", "t2PSkelVector", 1, 1, 0);
    bv = bv_append_bv(bv, bv_add_sv_to_bv(act_bv , 0, 1, 1, bt_double));
#endif // T2PSKEL_VEC == 1

    return bv;
}


/*
 * This function is called every time a new flow is created.
 */
void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
    // Reset the structure for this flow
    t2PSkel_flow_t * const t2PSkel_flow = &t2PSkel_flows[flowIndex];
    memset(t2PSkel_flow, '\0', sizeof(*t2PSkel_flow));

    // If your plugin analyses a layer 3, 4 or 7 protocol,
    // you do not need to process layer 2 flows, e.g., ARP
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    // In this example, we are only interested in TCP
    if (flowP->layer4Protocol != L3_TCP) return;

    if (flowP->srcPort == T2PSKEL_PORT || flowP->dstPort == T2PSKEL_PORT) {
        t2PSkel_flow->stat |= T2PSKEL_STAT_MYPROT;
    }
}


#if ETH_ACTIVATE > 0
/*
 * This function is called for every packet with a layer 2.
 * If flowIndex is HASHTABLE_ENTRY_NOT_FOUND, this means the packet also
 * has a layer 4 and thus a call to claimLayer4Information() will follow.
 */
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
    const ethernetHeader_t * const ethP = (ethernetHeader_t*)packet->layer2Header;
    const mplsHdrh_t * const mplshP = (mplsHdrh_t*)packet->mpls;

    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    if (sPktFile) fputs("\t", sPktFile);
}
#endif // ETH_ACTIVATE > 0


/*
 * This function is called for every packet with a layer 4.
 */
void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
    t2PSkel_flow_t * const t2PSkelFlowP = &t2PSkel_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    const uint8_t proto = flowP->layer4Protocol;
    if (sPktFile) {
        fprintf(sPktFile, "%"PRIu8"\t", proto); // Note the trailing tab (\t)
    }

    if (!t2PSkelFlowP->stat) return; // not a t2PSkel packet

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    numT2PSkelPkts++;

    const uint16_t src_port = flowP->srcPort;
    const uint16_t dst_port = flowP->dstPort;
    const uint16_t snaplen = packet->snapL7Length;
    const uint8_t * const l7Hdr = packet->layer7Header;

    if (proto == 234) t2PSkelFlowP->numAlarms++; // dummy alarm on proto 234

    if (PACKET_IS_IPV6(packet)) {
        const ip6Header_t * const ip6Header = (ip6Header_t*)packet->layer3Header;
    } else { // IPv4
        const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
    }

    // your code
}


/*
 * This function is called once a flow is terminated.
 * Output all the statistics for the flow here.
 */
void onFlowTerminate(unsigned long flowIndex) {

    const t2PSkel_flow_t * const t2PSkelFlowP = &t2PSkel_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    t2PSkelStat |= t2PSkelFlowP->stat;

    T2_REPORT_ALARMS(t2PSkelFlowP->numAlarms);

#if BLOCK_BUF == 0
    // t2PSkelStat: 8-bits variable
    OUTBUF_APPEND_U8(main_output_buffer, t2PSkelFlowP->stat);
    //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->stat, sizeof(uint8_t));

    // t2PSkelText: String/text
    OUTBUF_APPEND_STR(main_output_buffer, t2PSkelFlowP->text);
    //outputBuffer_append(main_output_buffer, t2PSkelFlowP->text, strlen(t2PSkelFlowP->text)+1);

#if T2PSKEL_VAR1 == 1
    // t2PSkelVar: 64-bits variable
    OUTBUF_APPEND_U64(main_output_buffer, t2PSkelFlowP->var1);
    //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var1, sizeof(uint64_t));
#endif

#if T2PSKEL_IP == 1
    // t2PSkelIP: IPv4 address: 32 bits
    OUTBUF_APPEND_IP4(main_output_buffer, t2PSkelFlowP->var2);
    //OUTBUF_APPEND_U32(main_output_buffer, t2PSkelFlowP->var2.IPv4.s_addr);
    //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var2, sizeof(uint32_t));
#endif

    // t2PSkelVar1_Var2: compound: 32 and 16 bits
    OUTBUF_APPEND_U32(main_output_buffer, t2PSkelFlowP->var3);
    OUTBUF_APPEND_U16(main_output_buffer, t2PSkelFlowP->var4);
    //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var3, sizeof(uint32_t));
    //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var4, sizeof(uint16_t));

    // t2PSkelVar3_Var4: repetitive compound: vector of pairs of uint8
    uint32_t cnt = NUM;
    // First output the number of repetitions (vector length)
    OUTBUF_APPEND_NUMREP(main_output_buffer, cnt);
    //outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));

    // Then, output the vector elements
    for (uint_fast32_t i = 0; i < NUM; i++) {
        OUTBUF_APPEND_U8(main_output_buffer, t2PSkelFlowP->var5);
        OUTBUF_APPEND_U8(main_output_buffer, t2PSkelFlowP->var6);
        //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var5, sizeof(uint8_t));
        //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var6, sizeof(uint8_t));
    }

    // Matrix / Multiple vector: doubles separated by ";" and "_"
    cnt = NUM;
    // First output the number of columns
    OUTBUF_APPEND_NUMREP(main_output_buffer, cnt);
    //outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));

    for (uint_fast32_t i = 0; i < NUM; i++) {
        cnt = WURST; // number of rows
        // Then output the number of columns in this row
        OUTBUF_APPEND_NUMREP(main_output_buffer, cnt);
        //outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
        // Finally, output the entire row
        OUTBUF_APPEND(main_output_buffer, t2PSkelFlowP->var7[i], WURST * sizeof(double));
        //outputBuffer_append(main_output_buffer, (char*) &t2PSkelFlowP->var7[i][0], WURST * sizeof(double));
    }
#endif // BLOCK_BUF == 0
}


static void t2PSkel_pluginReport(FILE *stream) {
    if (t2PSkelStat) {
        T2_FPLOG(stream, "t2PSkel", "Aggregated status flags: 0x%02"B2T_PRIX8, t2PSkelStat);
        // t2PSkel: Number of t2PSkel packets: 1472 (1.47 K) [2.84%]
        T2_FPLOG_DIFFNUMP(stream, "t2PSkel", "Number of t2PSkel packets", numT2PSkelPkts, numPackets);
        if (numT2PSkelPkts) {
            const uint64_t numT2PSkelPktsDiff = numT2PSkelPkts - numT2PSkelPkts0;
            const double numPacketsDiff = numPackets - numPackets0;
            char hrnum[64];
            T2_CONV_NUM(numT2PSkelPktsDiff, hrnum);
            T2_FPLOG(stream, "t2PSkel", "Number of %s packets: %"PRIu64"%s [%.2f%%]", "t2PSkel",
                    numT2PSkelPktsDiff, hrnum, 100.0 * (numT2PSkelPktsDiff / numPacketsDiff));
        }
    }
}


/*
 * This function is used to report information regarding the plugin
 * at regular interval or when a USR1 signal is received.
 */
void monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:  // Print the name of the variables that will be output
            fputs("t2PSkelVar\tt2PSkelStat\t", stream); // Note the trailing tab (\t)
            return;

        case T2_MON_PRI_VAL:  // Print the variables to monitor
            fprintf(stream, "%"PRIu64"\t0x%02"B2T_PRIX8"\t", // Note the trailing tab (\t)
                    numT2PSkelPkts-numT2PSkelPkts0, t2PSkelStat);
            break;

        case T2_MON_PRI_REPORT:  // print a report similar to pluginReport()
            t2PSkel_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }

#if DIFF_REPORT == 1
    numT2PSkelPkts0 = numT2PSkelPkts;
#endif
}


/*
 * This function is used to report information regarding the plugin.
 * This will appear in the final report.
 */
void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numT2PSkelPkts0 = 0;
#endif
    t2PSkel_pluginReport(stream);
}


/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here
 */
void onApplicationTerminate() {
    // Save statistics in a new file
    FILE *file = t2_open_file(baseFileName, T2PSKEL_FNAME, "w");
    if (UNLIKELY(!file)) exit(1);
    fputs("Write something in the file...\n", file);
    fprintf(file, "Number of %"PRIu64" packets\n", numT2PSkelPkts);
    fclose(file);

    free(t2PSkel_flows);
}


/*
 * This function is used to save the state of the plugin.
 * Tranalyzer can then restore the state in a future execution.
 */
void saveState(FILE *stream) {
    fprintf(stream, "%"PRIu64"\t0x%02"PRIx8, numT2PSkelPkts, t2PSkelStat);
}


/*
 * This function is used to restore the state of the plugin.
 * 'str' represents the line written in saveState()
 */
void restoreState(const char *str) {
    sscanf(str, "%"SCNu64"\t0x%02"SCNx8, &numT2PSkelPkts, &t2PSkelStat);
}


#if USE_T2BUS == 1
/*
 * XXX This callback is currently NOT used
 */
void t2BusCallback(uint32_t status __attribute__((unused))) {
    // Handle t2Bus messages...
}
#endif // USE_T2BUS == 1


/*
 * This callback is only required for sink plugins
 * Refer to parse_binary2text() in utils/bin2txt.c for an example
 */
//void bufferToSink(outputBuffer_t *buffer) {
//}
