/*
 * modbus.c
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

#include "modbus.h"


// Global variables

modbus_flow_t *modbus_flows;


// Static variables

static uint64_t num_mb_pkts;


#define MB_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("\t\t\t\t\t", sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("modbus", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(modbus_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*modbus_flows))))) {
        T2_PERR("modbus", "failed to allocate memory for modbus_flows");
        exit(-1);
    }

    if (sPktFile) {
        fputs("mbTranId\tmbProtId\tmbLen\tmbUnitId\tmbFuncCode\t", sPktFile);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;

    bv = bv_append_bv(bv, bv_new_bv("Modbus status", "modbusStat", 0, 1, bt_hex_16));
    bv = bv_append_bv(bv, bv_new_bv("Modbus unit identifier", "modbusUID", 0, 1, bt_uint_8));
    bv = bv_append_bv(bv, bv_new_bv("Modbus number of packets", "modbusNPkts", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("Modbus number of exceptions", "modbusNumEx", 0, 1, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("Modbus aggreated function codes", "modbusFCBF", 0, 1, bt_hex_64));
#if MB_NUM_FUNC > 0
    bv = bv_append_bv(bv, bv_new_bv("Modbus list of function codes", "modbusFC", 1, 1, MB_FE_TYP));
#endif // MB_NUM_FUNC > 0
    bv = bv_append_bv(bv, bv_new_bv("Modbus aggregated function codes which caused exceptions", "modbusFExBF", 0, 1, bt_hex_64));
#if MB_NUM_FEX > 0
    bv = bv_append_bv(bv, bv_new_bv("Modbus list of function codes which caused exceptions", "modbusFC", 1, 1, MB_FE_TYP));
#endif // MB_NUM_FEX > 0
    bv = bv_append_bv(bv, bv_new_bv("Modbus aggregated exception codes", "modbusExCBF", 0, 1, bt_hex_16));
#if MB_NUM_EX > 0
    bv = bv_append_bv(bv, bv_new_bv("Modbus list of exception codes", "modbusExC", 1, 1, MB_FE_TYP));
#endif // MB_NUM_EX > 0

    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    modbus_flow_t *mb_flow = &modbus_flows[flowIndex];
    memset(mb_flow, '\0', sizeof(*mb_flow)); // set everything to 0

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    if (flowP->layer4Protocol == L3_TCP && (flowP->srcPort == MODBUS_PORT || flowP->dstPort == MODBUS_PORT))
        mb_flow->stat |= MB_STAT_MODBUS;
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    MB_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    modbus_flow_t *mb_flow = &modbus_flows[flowIndex];
    if (!mb_flow->stat) {
        // not a modbus packet
        MB_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint16_t snaplen = packet->snapL7Length;
    if (snaplen < sizeof(modbus_hdr_t)) {
        mb_flow->stat |= MB_STAT_SNAP;
        MB_SPKTMD_PRI_NONE();
        return;
    }

    const modbus_hdr_t *mb = (modbus_hdr_t*)packet->layer7Header;

    if (sPktFile) {
        fprintf(sPktFile,
            "%"PRIu16"\t%"PRIu16"\t%"PRIu16"\t"
            "%"PRIu8"\t"MB_PRI_FE"\t",
            ntohs(mb->tid), ntohs(mb->pid), ntohs(mb->len),
            mb->uid, mb->fc);
    }

    // Protocol Identifier
    if (mb->pid != MODBUS_PROTO) {
        MB_DBG("Non-Modbus Protocol Identifier %d in flow %"PRIu64, mb->pid, flows[flowIndex].findex);
        mb_flow->stat |= MB_STAT_PROTO;
        return;
    }

    num_mb_pkts++;
    mb_flow->nmp++;

    // Unit Identifier
    if (mb_flow->uid != 0 && mb_flow->uid != mb->uid) {
        MB_DBG("Multiple UID in flow %"PRIu64": %d and %d", flows[flowIndex].findex, mb_flow->uid, mb->uid);
        mb_flow->stat |= MB_STAT_UID;
    }
    mb_flow->uid = mb->uid;

    uint8_t tmp;

    /* Function Codes */
    if (mb->fc < 64) {
        mb_flow->fcbf |= (1 << mb->fc);
#if MB_NUM_FUNC > 0
#if MB_UNIQ_FUNC == 1
        for (uint16_t i = 0; i < mb_flow->nfc; i++) {
            if (mb_flow->fc[i] == mb->fc) return;
        }
#endif // MB_UNIQ_FUNC == 1
        if (mb_flow->nfc < MB_NUM_FUNC) {
            mb_flow->fc[mb_flow->nfc] = mb->fc;
        } else mb_flow->stat |= MB_STAT_NFUNC;
        mb_flow->nfc++;
#endif // MB_NUM_FUNC > 0

    /* Exception codes (function code + 128) */
    } else if (mb->fc >= 128 && mb->fc < 64+128) {
        mb_flow->nex++;
        tmp = mb->fc - 128;
        mb_flow->fexbf |= (1 << tmp);
#if MB_NUM_FEX > 0
#if MB_UNIQ_FEX == 1
        for (uint16_t i = 0; i < mb_flow->nfex; i++) {
            if (mb_flow->fex[i] == tmp) return;
        }
#endif // MB_UNIQ_FEX == 1
        if (mb_flow->nfex < MB_NUM_FEX) {
            mb_flow->fex[mb_flow->nfex] = tmp;
        } else mb_flow->stat |= MB_STAT_NFEX;
        mb_flow->nfex++;
#endif // MB_NUM_FEX > 0

        tmp = *(((uint8_t*)&mb->fc)+1);
        if (tmp < 16) mb_flow->exbf |= (1 << tmp);
        else mb_flow->stat |= MB_STAT_EX;
#if MB_NUM_EX > 0
#if MB_UNIQ_EX == 1
        for (uint16_t i = 0; i < mb_flow->nsex; i++) {
            if (mb_flow->exc[i] == tmp) return;
        }
#endif // MB_UNIQ_EX == 1
        if (mb_flow->nsex < MB_NUM_EX) {
            mb_flow->exc[mb_flow->nsex] = tmp;
        } else mb_flow->stat |= MB_STAT_NEXCP;
        mb_flow->nsex++;
#endif // MB_NUM_EX > 0

    } else {
        MB_DBG("Unknown function code in flow %"PRIu64": %d", flows[flowIndex].findex, mb->fc);
        mb_flow->stat |= MB_STAT_FUNC;
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    modbus_flow_t *mb_flow = &modbus_flows[flowIndex];

#if (MB_NUM_FUNC > 0 || MB_NUM_FEX > 0 || MB_NUM_EX > 0)
    uint32_t i, imax;
#endif // (MB_NUM_FUNC > 0 || MB_NUM_FEX > 0 || MB_NUM_EX > 0)

    outputBuffer_append(main_output_buffer, (char*) &mb_flow->stat, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, (char*) &mb_flow->uid, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*) &mb_flow->nmp, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &mb_flow->nex, sizeof(uint16_t));

    outputBuffer_append(main_output_buffer, (char*) &mb_flow->fcbf, sizeof(uint64_t));
#if MB_NUM_FUNC > 0
    imax = mb_flow->nfc < MB_NUM_FUNC ? mb_flow->nfc : MB_NUM_FUNC;
    outputBuffer_append(main_output_buffer, (char*) &imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, (char*) &mb_flow->fc[i], sizeof(uint8_t));
    }
#endif // MB_NUM_FUNC > 0

    outputBuffer_append(main_output_buffer, (char*) &mb_flow->fexbf, sizeof(uint64_t));
#if MB_NUM_FEX > 0
    imax = mb_flow->nfex < MB_NUM_FEX ? mb_flow->nfex : MB_NUM_FEX;
    outputBuffer_append(main_output_buffer, (char*) &imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, (char*) &mb_flow->fex[i], sizeof(uint8_t));
    }
#endif // MB_NUM_FEX > 0

    outputBuffer_append(main_output_buffer, (char*) &mb_flow->exbf, sizeof(uint16_t));
#if MB_NUM_EX > 0
    imax = mb_flow->nsex < MB_NUM_EX ? mb_flow->nsex : MB_NUM_EX;
    outputBuffer_append(main_output_buffer, (char*) &imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, (char*) &mb_flow->exc[i], sizeof(uint8_t));
    }
#endif // MB_NUM_EX > 0
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "modbus", "Number of Modbus packets", num_mb_pkts, numPackets);
}


void onApplicationTerminate() {
    free(modbus_flows);
}
