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

#include "igmpDecode.h"
#include "chksum.h"


// Global variables

igmp_flow_t *igmp_flows;


// Static variables

static uint64_t numIGMPPackets;
static uint64_t numIGMPQueries;
static uint64_t numIGMPReports;
static uint64_t numIGMPGeneralQueries;
static uint64_t numIGMPInvalidQueries;
static uint64_t numIGMPBadChksum;
static uint64_t numIGMPBadLength;
static uint64_t numIGMPBadTTL;
static uint64_t numIGMPGroupSpecificQueries;
static uint64_t numIGMPLeave;
static uint64_t numIGMPJoin;
static uint64_t num_igmp_v[IGMP_V_N];
static uint64_t num_igmp[IGMP_TYPE_N];
static uint64_t num_dvmrp[DVMRP_CODES_N];
static uint64_t num_pimv1[PIM_V1_CODES_N];

static const char *dvmrp_code[] = {
    "__UNUSED__",
    "DVMRP_PROBE",
    "DVMRP_ROUTE_REPORT",
    "DVMRP_OLD_ASK_NEIGHBORS",
    "DVMRP_OLD_NEIGHBORS_REPLY",
    "DVMRP_ASK_NEIGHBORS",
    "DVMRP_NEIGHBORS_REPLY",
    "DVMRP_PRUNE",
    "DVMRP_GRAFT",
    "DVMRP_GRAFT_ACK"
};

static const char *pimv1_code[] = {
    "PIM_V1_QUERY",
    "PIM_V1_REGISTER",
    "PIM_V1_REGISTER_STOP",
    "PIM_V1_JOIN_PRUNE",
    "PIM_V1_RP_REACHABLE",
    "PIM_V1_ASSERT",
    "PIM_V1_GRAFT",
    "PIM_V1_GRAFT_ACK",
    "PIM_V1_MODE"
};


// Function prototypes

static const char *igmpTypeToStr(uint16_t type);


// Tranalyzer function

T2_PLUGIN_INIT("igmpDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(igmp_flows = calloc(mainHashMap->hashChainTableSize, sizeof(igmp_flow_t))))) {
        T2_PERR("igmpDecode", "Failed to allocate memory for igmp_flows");
        exit(1);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("IGMP status", "igmpStat", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("IGMP version", "igmpVersion", 1, 1, bt_int_8));
#if IGMP_TC_MD == 0
    bv = bv_append_bv(bv, bv_new_bv("IGMP aggr type", "igmpAType", 0, 1, bt_hex_32));
#endif // IGMP_TC_MD == 0
    bv = bv_append_bv(bv, bv_new_bv("IGMP multicast address", "igmpMCastAddr", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("IGMP # of Records", "igmpNRec", 0, 1, bt_uint_16));
    return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
    igmp_flow_t *igmp_flow = &igmp_flows[flowIndex];
    memset(igmp_flow, '\0', sizeof(igmp_flow_t));
}


#if IPV6_ACTIVATE == 1
void claimLayer4Information(packet_t *packet, unsigned long flowIndex __attribute__((unused))) {
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    // Only allow IGMP messages to pass through here
    if (packet->layer4Type != IPPROTO_IGMP) return;

    const uint16_t snaplen = packet->snapL4Length;
    if (snaplen == 0) return;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

#if IPV6_ACTIVATE > 0
    // IGMP is used on IPv4 networks
    if (PACKET_IS_IPV6(packet)) return;
#endif // IPV6_ACTIVATE > 0

    const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
    if (ipHeader->ip_off & FRAGID_N) return;

    igmp_flow_t *igmp_flow = &igmp_flows[flowIndex];
    igmpHeader_t *igmpHeader = (igmpHeader_t*)packet->layer4Header;

    numIGMPPackets++;

    const uint8_t igmpType = igmpHeader->type;
    num_igmp[igmpType]++;

    if (packet->snapL4Length < IGMP_MIN_LEN) {
        igmp_flow->igmp_stat |= IGMP_STAT_BAD_LENGTH;
        numIGMPInvalidQueries++;
        numIGMPBadLength++;
        return;
    }

    const struct in_addr dstIp = ipHeader->ip_dst;
    const uint8_t code = igmpHeader->code;

    struct in_addr igmpGroup = igmpHeader->group;
    int8_t igmpVersion = IGMP_UNKNOWN;

    const uint16_t calcChksum = ~Checksum((uint16_t*)packet->layer4Header, 0, packet->snapL4Length, 1);

    if (igmpHeader->checksum != calcChksum) {
        igmp_flow->igmp_stat |= IGMP_STAT_BAD_CHECKSUM;
        numIGMPBadChksum++;
    }

    switch (igmpType) {

        case IGMP_MEMBERSHIP_QUERY: {
            numIGMPQueries++;
            // see rfc3376, section 7
            if (snaplen >= IGMP_V3_QUERY_MIN_LEN) {
                igmpVersion = IGMP_V3;
                igmpv3_query_t *query = (igmpv3_query_t*)packet->layer4Header;
                if (query->nsrcs == 0) {
                    if (igmpGroup.s_addr != 0) numIGMPGroupSpecificQueries++;
                    else numIGMPGeneralQueries++;
                } else igmp_flow->igmp_nrec += htons(query->nsrcs);
                if (igmpGroup.s_addr != 0) igmp_flow->igmp_stat |= IGMP_STAT_INVALID_QUERY;
            } else if (packet->snapL4Length == IGMP_MIN_LEN) {
                if (code == 0) igmpVersion = IGMP_V1;
                else {
                    igmpVersion = IGMP_V2;
                    if (dstIp.s_addr == IGMP_ALL_HOSTS && igmpGroup.s_addr == 0) numIGMPGeneralQueries++;
                    else if (dstIp.s_addr == igmpGroup.s_addr) numIGMPGroupSpecificQueries++;
                }
            } else {
                // Invalid query
                igmp_flow->igmp_stat |= IGMP_STAT_BAD_LENGTH;
                numIGMPInvalidQueries++;
                numIGMPBadLength++;
            }
            break;
        }

        case IGMP_V1_MEMBERSHIP_REPORT:
            igmpVersion = IGMP_V1;
            numIGMPReports++;
            numIGMPJoin++;
            break;

        case IGMP_V2_MEMBERSHIP_REPORT:
            igmpVersion = IGMP_V2;
            numIGMPReports++;
            numIGMPJoin++;
            break;

        case IGMP_V2_LEAVE_GROUP:
            igmpVersion = IGMP_V2;
            numIGMPLeave++;
            if (dstIp.s_addr != IGMP_V2_ALL_ROUTERS) igmp_flow->igmp_stat |= IGMP_STAT_INVALID_QUERY;
            break;

        case IGMP_V3_MEMBERSHIP_REPORT: {
            igmpVersion = IGMP_V3;
            numIGMPReports++;
            igmpv3_report_t *report = (igmpv3_report_t*)packet->layer4Header;
            if (snaplen < sizeof(*report)) break;
            const uint16_t ngrec = htons(report->ngrec);
            if (packet->snapL4Length < sizeof(*report) + (ngrec-1)*sizeof(igmpv3_grec_t)) break;
            igmp_flow->igmp_nrec += ngrec;
            igmpGroup = dstIp;
            if (dstIp.s_addr != IGMP_V3_ALL_ROUTERS) igmp_flow->igmp_stat |= IGMP_STAT_INVALID_QUERY;
            for (uint_fast16_t i = 0; i < ngrec; i++) {
                switch (report->grec[i].type) {
                    case IGMP_V3_MODE_IS_INCLUDE:
                    case IGMP_V3_CHANGE_TO_INCLUDE:
                       numIGMPLeave++;
                       break;
                    case IGMP_V3_MODE_IS_EXCLUDE:
                    case IGMP_V3_CHANGE_TO_EXCLUDE:
                       numIGMPJoin++;
                       break;
                }
            }
            break;
        }

        /* IGMPv0 */
        case IGMP_V0_CREATE_GROUP_REQUEST:
        case IGMP_V0_CREATE_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;
        case IGMP_V0_JOIN_GROUP_REQUEST:
            igmpVersion = IGMP_V0;
            numIGMPJoin++;
            break;
        case IGMP_V0_JOIN_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;
        case IGMP_V0_LEAVE_GROUP_REQUEST:
            igmpVersion = IGMP_V0;
            numIGMPLeave++;
            break;
        case IGMP_V0_LEAVE_GROUP_REPLY:
        case IGMP_V0_CONFIRM_GROUP_REQUEST:
        case IGMP_V0_CONFIRM_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;

        /* DVMRP */
        case IGMP_DVMRP: {
            if (code < DVMRP_CODES_N) num_dvmrp[code]++;
            if (code == DVMRP_PROBE) {
                if (ipHeader->ip_ttl != 1) {
                    numIGMPBadTTL++;
                    igmp_flow->igmp_stat |= IGMP_STAT_BAD_TTL;
                }
            }
            //igmp_dvmrp_t *dvmrp = (igmp_dvmrp_t*)packet->layer4Header;
            //igmpVersion = dvmrp->maj_version;
            break;
        }

        /* PIMv1 */
        case IGMP_PIM_V1:
            if (code < PIM_V1_CODES_N) num_pimv1[code]++;
            break;

        /* Mtrace */
        case IGMP_MTRACE:
        case IGMP_MTRACE_RESP: {
            igmp_mtrace_t *mtrace = (igmp_mtrace_t*)packet->layer4Header;
            if (snaplen < sizeof(*mtrace)) break;
            igmp_flow->igmp_nrec += mtrace->hops;
            break;
        }

        /* MRD */
        case IGMP_MRD_ROUTER_ADVERT:
        case IGMP_MRD_ROUTER_SOLICIT:
        case IGMP_MRD_ROUTER_TERM:
            if (ipHeader->ip_ttl != 1) {
                numIGMPBadTTL++;
                igmp_flow->igmp_stat |= IGMP_STAT_BAD_TTL;
            }
            break;

        /* RGMP */
        case IGMP_RGMP_LEAVE_GROUP:
        case IGMP_RGMP_JOIN_GROUP:
        case IGMP_RGMP_BYE:
        case IGMP_RGMP_HELLO:
            if (ipHeader->ip_ttl != 1) {
                numIGMPBadTTL++;
                igmp_flow->igmp_stat |= IGMP_STAT_BAD_TTL;
            }
            if (dstIp.s_addr != IGMP_RGMP_ADDR) {
                numIGMPInvalidQueries++;
                igmp_flow->igmp_stat |= IGMP_STAT_INVALID_QUERY;
            }
            break;
    }

    if (igmpVersion >= 0) {
        num_igmp_v[igmpVersion]++;
        if (ipHeader->ip_ttl != 1) {
            numIGMPBadTTL++;
            igmp_flow->igmp_stat |= IGMP_STAT_BAD_TTL;
        }
    }

    igmp_flow->igmp_version = igmpVersion;
    igmp_flow->mcast_addr = igmpGroup;

#if IGMP_TC_MD == 0
    if (igmpType < IGMP_TYPEFIELD-1) igmp_flow->igmp_type_bfield |= (1 << igmpType);
#endif // IGMP_TC_MD == 0
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    const igmp_flow_t * const igmp_flow = &igmp_flows[flowIndex];
    outputBuffer_append(main_output_buffer, (char*) &igmp_flow->igmp_stat, sizeof(uint8_t));
    if (igmp_flow->igmp_version >= 0) {
        static const uint32_t one = 1;
        outputBuffer_append(main_output_buffer, (char*) &one, sizeof(uint32_t));
        outputBuffer_append(main_output_buffer, (char*) &igmp_flow->igmp_version, sizeof(int8_t));
    } else {
        static const uint32_t zero = 0;
        outputBuffer_append(main_output_buffer, (char*) &zero, sizeof(uint32_t));
    }
#if IGMP_TC_MD == 0
    outputBuffer_append(main_output_buffer, (char*) &igmp_flow->igmp_type_bfield, sizeof(uint32_t));
#endif // IGMP_TC_MD == 0
    outputBuffer_append(main_output_buffer, (char*) &igmp_flow->mcast_addr, l_bt_ip4_addr);
    outputBuffer_append(main_output_buffer, (char*) &igmp_flow->igmp_nrec, sizeof(uint16_t));
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    if (numIGMPPackets) {
        T2_FPLOG_NUMP0(stream, "igmpDecode", "Number of IGMP packets", numIGMPPackets, numPackets);
        T2_FPLOG_NUMP(stream, "igmpDecode", "Number of IGMP queries", numIGMPQueries, numIGMPPackets);
        if (numIGMPReports) {
            T2_FPLOG_NUMP0(stream, "igmpDecode", "Number of IGMP reports", numIGMPReports, numIGMPPackets);
            T2_FPLOG(stream, "igmpDecode", "IGMP query / report ratio: %.2f", numIGMPQueries/(double)numIGMPReports);
        }
    }
}


void onApplicationTerminate() {
    free(igmp_flows);

    if (numIGMPPackets == 0) return;

    // open igmp statistics file
    FILE *file = t2_open_file(baseFileName, IGMP_SUFFIX, "w");
    if (UNLIKELY(!file)) exit(-1);

    fprintf(file, "Total # of IGMP messages: \t%"PRIu64"\n", numIGMPPackets);
    fprintf(file, "IGMP / Total traffic percentage[%%]: \t%5.3f\n", 100.0f*numIGMPPackets/(float)numPackets);
    if (numIGMPReports != 0)
        fprintf(file, "IGMP query / report ratio [%%]: \t%5.3f\n\n", 100.0f*numIGMPQueries/(float)numIGMPReports);
    uint_fast16_t i;
    for (i = 0; i < IGMP_V_N; i++) {
        fprintf(file, "Number of IGMPv%"PRIuFAST16" packets: \t%"PRIu64"\n", i, num_igmp_v[i]);
    }
    fprintf(file, "Number of DVMRP packets: \t%"PRIu64"\n", num_igmp[IGMP_DVMRP]);
    fprintf(file, "Number of PIMv1 packets: \t%"PRIu64"\n\n", num_igmp[IGMP_PIM_V1]);

    fprintf(file, "Number of query messages: \t%"PRIu64"\n", numIGMPQueries);
    fprintf(file, "Number of report messages: \t%"PRIu64"\n", numIGMPReports);
    fprintf(file, "Number of JOIN requests: \t%"PRIu64"\n", numIGMPJoin);
    fprintf(file, "Number of LEAVE requests: \t%"PRIu64"\n", numIGMPLeave);
    fprintf(file, "Number of General queries: \t%"PRIu64"\n", numIGMPGeneralQueries);
    fprintf(file, "Number of Group Specific queries: \t%"PRIu64"\n", numIGMPGroupSpecificQueries);
    fprintf(file, "Number of invalid queries: \t%"PRIu64"\n", numIGMPInvalidQueries);
    // bad length: < 8, 9-11 (https://tools.ietf.org/html/rfc3376, Section 7.1)
    fprintf(file, "Number of messages with bad length: \t%"PRIu64"\n", numIGMPBadLength);
    fprintf(file, "Number of messages with bad checksum: \t%"PRIu64"\n", numIGMPBadChksum);
    fprintf(file, "Number of messages with bad TTL: \t%"PRIu64"\n", numIGMPBadTTL);

    uint_fast16_t j;
    fprintf(file, "\nIGMP Type\tCode\t# of Messages\tRelative Frequency [%%]\n");
    for (i = 0; i < IGMP_TYPE_N; i++) {
        if (num_igmp[i] != 0) {
            if (i == IGMP_DVMRP) {
                for (j = 1; j < DVMRP_CODES_N; j++)
                    if (num_dvmrp[j] != 0)
                        fprintf(file, "%s\t%s\t%"PRIu64"\t%5.3f\n", igmpTypeToStr(i), dvmrp_code[j], num_dvmrp[j], 100.0*num_dvmrp[j]/(float)numIGMPPackets);
            } else if (i == IGMP_PIM_V1) {
                for (j = 0; j < PIM_V1_CODES_N; j++)
                    if (num_pimv1[j] != 0)
                        fprintf(file, "%s\t%s\t%"PRIu64"\t%5.3f\n", igmpTypeToStr(i), pimv1_code[j], num_pimv1[j], 100.0*num_pimv1[j]/(float)numIGMPPackets);
            } else {
                fprintf(file, "%s\t - \t%"PRIu64"\t%5.3f\n", igmpTypeToStr(i), num_igmp[i], 100.0*num_igmp[i]/(float)numIGMPPackets);
            }
        }
    }

    fclose(file);
}


static const char *igmpTypeToStr(uint16_t type) {
    switch (type) {
        case IGMP_V0_CREATE_GROUP_REQUEST:
            return "IGMP_V0_CREATE_GROUP_REQUEST";
        case IGMP_V0_CREATE_GROUP_REPLY:
            return "IGMP_V0_CREATE_GROUP_REPLY";
        case IGMP_V0_JOIN_GROUP_REQUEST:
            return "IGMP_V0_JOIN_GROUP_REQUEST";
        case IGMP_V0_JOIN_GROUP_REPLY:
            return "IGMP_V0_JOIN_GROUP_REPLY";
        case IGMP_V0_LEAVE_GROUP_REQUEST:
            return "IGMP_V0_LEAVE_GROUP_REQUEST";
        case IGMP_V0_LEAVE_GROUP_REPLY:
            return "IGMP_V0_LEAVE_GROUP_REPLY";
        case IGMP_V0_CONFIRM_GROUP_REQUEST:
            return "IGMP_V0_CONFIRM_GROUP_REQUEST";
        case IGMP_V0_CONFIRM_GROUP_REPLY:
            return "IGMP_V0_CONFIRM_GROUP_REPLY";
        case IGMP_MEMBERSHIP_QUERY:
            return "IGMP_MEMBERSHIP_QUERY";
        case IGMP_V1_MEMBERSHIP_REPORT:
            return "IGMP_V1_MEMBERSHIP_REPORT";
        case IGMP_DVMRP:
            return "IGMP_DVMRP";
        case IGMP_PIM_V1:
            return "IGMP_PIM_V1";
        case IGMP_CISCO_TRACE_MSG:
            return "IGMP_CISCO_TRACE_MSG";
        case IGMP_V2_MEMBERSHIP_REPORT:
            return "IGMP_V2_MEMBERSHIP_REPORT";
        case IGMP_V2_LEAVE_GROUP:
            return "IGMP_V2_LEAVE_GROUP";
        case IGMP_MTRACE_RESP:
            return "IGMP_MTRACE_RESP";
        case IGMP_MTRACE:
            return "IGMP_MTRACE";
        case IGMP_V3_MEMBERSHIP_REPORT:
            return "IGMP_V3_MEMBERSHIP_REPORT";
        case IGMP_MRD_ROUTER_ADVERT:
            return "IGMP_MRD_ROUTER_ADVERT";
        case IGMP_MRD_ROUTER_SOLICIT:
            return "IGMP_MRD_ROUTER_SOLICIT";
        case IGMP_MRD_ROUTER_TERM:
            return "IGMP_MRD_ROUTER_TERM";
        case IGMP_IGAP_MEMBERSHIP_REPORT:
            return "IGMP_IGAP_MEMBERSHIP_REPORT";
        case IGMP_IGAP_MEMBERSHIP_QUERY:
            return "IGMP_IGAP_MEMBERSHIP_QUERY";
        case IGMP_IGAP_LEAVE_GROUP:
            return "IGMP_IGAP_LEAVE_GROUP";
        case IGMP_RGMP_LEAVE_GROUP:
            return "IGMP_RGMP_LEAVE_GROUP";
        case IGMP_RGMP_JOIN_GROUP:
            return "IGMP_RGMP_JOIN_GROUP";
        case IGMP_RGMP_BYE:
            return "IGMP_RGMP_BYE";
        case IGMP_RGMP_HELLO:
            return "IGMP_RGMP_HELLO";
        default:
            return "IGMP type unknown";
    }
}
