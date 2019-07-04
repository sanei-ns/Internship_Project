/*
 * snmpDecode.c
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

#include "snmpDecode.h"
#include "t2buf.h"


#define SNMP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("\t\t\t\t", sPktFile); \
    }

#define SNMP_SKIP_BER_VAL(t2buf) \
        t2buf_skip_u8(t2buf); \
        t2buf_read_u8(t2buf, &len); \
        t2buf_skip_n(t2buf, len);


// Global variables

snmp_flow_t *snmp_flows;


// Static variables

static uint64_t num_snmp[SNMP_NUM_PDU_TYPES+1];

static const char *snmp_types[] = {
    "GetRequest",
    "GetNextRequest",
    "GetResponse",
    "SetRequest",
    "Trap v1",
    "GetBulkRequest",
    "InformRequest ",
    "Trap v2",
    "Report",
};


// Tranalyzer functions

T2_PLUGIN_INIT("snmpDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(snmp_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*snmp_flows))))) {
        T2_PERR("snmpDecode", "failed to allocate memory for snmp_flows");
        exit(-1);
    }

    if (sPktFile) {
        fputs("snmpVersion\tsnmpCommunity\tsnmpUser\tsnmpType\t", sPktFile); // Note the trailing tab (\t)
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("SNMP status", "snmpStat", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("SNMP version", "snmpVer", 0, 1, bt_uint_8));
    bv = bv_append_bv(bv, bv_new_bv("SNMP community", "snmpCommunity", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SNMP username", "snmpUser", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SNMP message types", "snmpMsgT", 0, 1, bt_hex_16));
    bv = bv_append_bv(bv, bv_new_bv("SNMP number of GetRequest, GetNextRequest, GetResponse, SetRequest, Trapv1, GetBulkRequest, InformRequest, Trapv2, and Report packets", "snmpNumReq_Next_Resp_Set_Trap1_Bulk_Info_Trap2_Rep", 0, SNMP_NUM_PDU_TYPES, SNMP_NPDU_BVTYPES));
    return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), uint64_t flowIndex) {
    snmp_flow_t * const snmp_flow = &snmp_flows[flowIndex];
    memset(snmp_flow, '\0', sizeof(*snmp_flow));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    const uint_fast8_t proto = flowP->layer4Protocol;
    if (proto == L3_UDP || proto == L3_TCP) {
        const uint_fast16_t sport = flowP->srcPort;
        const uint_fast16_t dport = flowP->dstPort;
        if (sport == SNMP_PORT || sport == SNMP_TRAP_PORT ||
            dport == SNMP_PORT || dport == SNMP_TRAP_PORT)
        {
            snmp_flow->stat |= SNMP_STAT_SNMP;
        }
    }
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), uint64_t flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    SNMP_SPKTMD_PRI_NONE();
}
#endif


void claimLayer4Information(packet_t *packet, uint64_t flowIndex) {
    snmp_flow_t * const snmpFlowP = &snmp_flows[flowIndex];
    const uint16_t snaplen = packet->snapL7Length;

    if (!snmpFlowP->stat || snaplen < SNMP_MIN_HDRSIZE) { // not a SNMP packet
        SNMP_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        SNMP_SPKTMD_PRI_NONE();
        return;
    }

    num_snmp[SNMP_NUM_PDU_TYPES]++;

    const uint8_t * const l7Hdr = packet->layer7Header;
    t2buf_t t2buf = t2buf_create(l7Hdr, snaplen);

    // SNMP packets are structured as follows:
    //    Sequence:
    //      - Integer (version),
    //      - OctetString (community),
    //      - data (get-request, get-response, set-request, ...)
    //          - request-id (integer32)
    //          - error-status (integer32)
    //          - error-index (integer32)
    //          - variable-bindings list (sequence)
    //              - variable-bindings (sequence)
    //                  - object-identifier (OID)
    //                  - value (variable type)

    uint8_t tag, len;

    // TODO test return value of t2buf_* functions

    // total length of the SNMP message = len+2
    t2buf_read_u8(&t2buf, &tag);
    if (tag != SNMP_T_SEQ) {
        snmpFlowP->stat |= SNMP_STAT_MALFORMED;
        SNMP_SPKTMD_PRI_NONE();
        return;
    }
    t2buf_read_u8(&t2buf, &len);
    // TODO test len against l7len

    // version
    t2buf_read_u8(&t2buf, &tag);
    t2buf_read_u8(&t2buf, &len);
    if (tag != SNMP_T_INT || len != 1) {
        // XXX for some reason, it seems there is
        // sometimes one or two extra uint8...
        tag = len;
        t2buf_read_u8(&t2buf, &len);
        if (tag != SNMP_T_INT || len != 1) {
            tag = len;
            t2buf_read_u8(&t2buf, &len);
            if (tag != SNMP_T_INT || len != 1) {
                snmpFlowP->stat |= SNMP_STAT_MALFORMED;
                SNMP_SPKTMD_PRI_NONE();
                return;
            }
        }
    }
    t2buf_read_u8(&t2buf, &snmpFlowP->version);

    // Ignore SNMPv3 for now...
    if (snmpFlowP->version > SNMP_V2 || t2buf_left(&t2buf) < 2) {
        // msgGlobalData
        //  - msgID (Integer)
        //  - msgMaxSize (Integer)
        //  - msgFlags (OctetString)
        //  - msgSecurityModel (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // XXX WTF is that?
        t2buf_skip_n(&t2buf, 4);
        // msgAuthoritativeEngineID (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgAuthoritativeEngineBoots (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgAuthoritativeEngineTime (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgUserName (OctetString)
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        ssize_t buflen = MIN((size_t)len+1, sizeof(snmpFlowP->username));
        t2buf_readstr(&t2buf, snmpFlowP->username, len+1, T2BUF_UTF8, true);
        if (buflen != len+1) {
            snmpFlowP->stat |= SNMP_STAT_TRUNC;
            t2buf_skip_n(&t2buf, len+1-sizeof(snmpFlowP->username));
        }
        // msgAuthenticationParameters (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgPrivacyParameters (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgData (Sequence)
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        //  - contextEngineID (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        //  - contextName (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
    } else {
        // community
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        if (tag != 0x04) {
            snmpFlowP->stat |= SNMP_STAT_MALFORMED;
            if (sPktFile) fprintf(sPktFile, "%u\t\t\t\t", snmpFlowP->version);
            return;
        }
        ssize_t buflen = MIN((size_t)len+1, sizeof(snmpFlowP->community));
        t2buf_readstr(&t2buf, snmpFlowP->community, buflen, T2BUF_UTF8, true);
        if (buflen != len+1) {
            snmpFlowP->stat |= SNMP_STAT_TRUNC;
            t2buf_skip_n(&t2buf, len+1-sizeof(snmpFlowP->community));
        }

        if (t2buf_left(&t2buf) < 2) {
            if (sPktFile) {
                fprintf(sPktFile, "%u\t%s\t%s\t\t", snmpFlowP->version, snmpFlowP->community, snmpFlowP->username);
            }
            return;
        }
    }

    // Data
    uint8_t pdu_type;
    t2buf_read_u8(&t2buf, &pdu_type);
    t2buf_read_u8(&t2buf, &len);

    if (sPktFile) {
        fprintf(sPktFile, "%u\t%s\t%s\t0x%02"B2T_PRIX8"\t", snmpFlowP->version, snmpFlowP->community, snmpFlowP->username, pdu_type);
    }

    if (pdu_type == SNMP_PDU_TRAP || pdu_type == SNMP_PDU_TRAPv2) {
        // TODO
        /* enterprise (OID) */
        /* agent-addr (OID) */
        /* generic-trap (integer32) */
        /* specific-trap (integer32) */
        /* time-stamp (timeticks) */
        /* variable-bindings (sequence) */
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else if (pdu_type >= SNMP_PDU_GET_REQ && pdu_type <= SNMP_PDU_GET_BULK_REQ) {
        // TODO
        /* request-id (integer32) */
        /* error-status (integer32) */
        /* error-index (integer32) */
        /* variable-bindings (sequence) */
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else if (pdu_type == SNMP_PDU_INFO_REQ || pdu_type == SNMP_PDU_REPORT) {
        // TODO
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else {
        //T2_PERR("snmpDecode", "Unhandled data type 0x%02"B2T_PRIX8, pdu_type);
        snmpFlowP->stat |= SNMP_STAT_MALFORMED;
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(uint64_t flowIndex) {
    const snmp_flow_t * const snmpFlowP = &snmp_flows[flowIndex];
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->stat, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->version, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->community, strlen((char*)snmpFlowP->community)+1);
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->username, strlen((char*)snmpFlowP->username)+1);
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->msgT, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, (char*) &snmpFlowP->num_pkt, SNMP_NUM_PDU_TYPES * sizeof(uint64_t));
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    if (num_snmp[SNMP_NUM_PDU_TYPES]) {
        T2_FPLOG_NUMP0(stream, "snmpDecode", "Number of SNMP packets", num_snmp[SNMP_NUM_PDU_TYPES], numPackets);
        char hrnum[64];
        for (uint_fast8_t i = 0; i < SNMP_NUM_PDU_TYPES; i++) {
            if (num_snmp[i]) {
                T2_CONV_NUM(num_snmp[i], hrnum);
                T2_FPLOG(stream, "snmpDecode", "Number of SNMP %s packets: %"PRIu64"%s [%.2f%%]", snmp_types[i], num_snmp[i], hrnum, 100.0*num_snmp[i]/(double)num_snmp[SNMP_NUM_PDU_TYPES]);
            }
        }
    }
}


void onApplicationTerminate() {
    free(snmp_flows);
}
