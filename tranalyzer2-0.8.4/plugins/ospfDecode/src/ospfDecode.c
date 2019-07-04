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

#include "ospfDecode.h"


// Global variables

ospfFlow_t *ospfFlow;


// Static variables

static FILE *ospfHelloFile;
#if OSPF_OUTPUT_DBD == 1
static FILE *ospfDBDFile;
#endif // OSPF_OUTPUT_DBD == 1
#if OSPF_OUTPUT_MSG == 1
static FILE *ospfMsgFile;
#endif // OSPF_OUTPUT_MSG == 1

static uint64_t numOSPF[OSPF_TYPE_N];         // store total number of OSPF packets at pos 0
static uint64_t numOSPFAuType[OSPF_AUTH_N+1]; // store number of unknown auth type at pos OSPF_AUTH_N
static uint64_t numOSPFLSType[OSPF_LSTYPE_N]; // store number of unknown LS type at pos 0
static uint64_t numInvalidOSPF[OSPF_STAT_N];
static uint64_t numMCastPkts;

static const char *ospfTypeStr[OSPF_TYPE_N] = {
    "0",
    "Hello",
    "DBD",
    "LSReq",
    "LSUp",
    "LSAck"
};

static const char *ospfLSTypeStr[OSPF_LSTYPE_N] = {
    "0",
    "Router",  // Router-LSA
    "Network", // Network-LSA
    "Summary", // Summary-LSA (IP network)
    "ASBR",    // Summary-LSA (ASBR)
    "ASext",   // As-external-LSA
    "MCast",   // Multicast Group LSA
    "NSSA",    // NSSA-External-LSA
    "BGP",     // External Attribute LSA for BGP
    "OP_Link", // Opaque-LSA (link-local scope)
    "OP_Area", // Opaque-LSA (area-local scope)
    "OP_AS",   // Opaque-LSA (AS scope)
};

#if OSPF_OUTPUT_MSG == 1
static const char *ospfLinkTypeStr[OSPF_LINK_TYPE_N] = {
    "0",
    "PTP",      // "Point-to-point connection to another router",
    "Transit",  // "Connection to a transit network",
    "Stub",     // "Connection to a stub network",
    "Virtual",  // "Virtual link"
};
#endif // OSPF_OUTPUT_MSG == 1


#if OSPF_OUTPUT_MSG == 1
static const char *ospfMetricToIface(uint16_t metric) {
    // Default OSPF Interface Cost (reference-bandwith (=10^8) / interface bandwidth)
    switch (metric) {
        case 0:
            return "Loopback";
        case 1:
            return "> 100 Mbps";
            //return "FDDI, TM, Fast Ethernet, Gigabit Ethernet (> 100 Mbps)";
        case 2:
            return "45 Mbps";
            //return "HSSI (45 Mbps)";
        case 6:
            return "16-Mbps";
            //return "16-Mbps Token Ring";
        case 10:
            return "10-Mbps";
            //return "10-Mbps Ethernet";
        case 25:
            return "4-Mbps";
            //return "4-Mbps Token Ring";
        case 48:
            return "2.048 Mbps";
            //return "E1 (2.048 Mbps)";
        case 64:
            return "1.544 Mbps";
            //return "T1 (1.544 Mbps)";
        case 1562:
            return "64 kbps";
            //return "DS-0 (64 kbps)";
        case 1785:
            return "56 kbps";
        case 11111:
            return "9 kbps";
            //return "Tunnel (9 kbps)";
        default:
            return "";
    }
}
#endif // OSPF_OUTPUT_MSG == 1


// Tranalyzer functions

T2_PLUGIN_INIT("ospfDecode", "0.8.4", 0, 8);


void initialize() {
    ospfHelloFile = t2_open_file(baseFileName, OSPF_HELLO_SUFFIX, "w");
    if (UNLIKELY(!ospfHelloFile)) exit(-1);

    fprintf(ospfHelloFile, "Area\tSrcIP\tNetmask\tNetwork\tRouter\n");

#if OSPF_OUTPUT_DBD == 1
    ospfDBDFile = t2_open_file(baseFileName, OSPF_DBD_SUFFIX, "w");
    if (UNLIKELY(!ospfDBDFile)) {
        fclose(ospfHelloFile);
        exit(-1);
    }
    fprintf(ospfDBDFile, "Area\tRouter ID\tLink ID\tADV Router\tAge\tSeq#\tChecksum\tLS Type\n");
#endif // OSPF_OUTPUT_DBD == 1

#if OSPF_OUTPUT_MSG == 1
    ospfMsgFile = t2_open_file(baseFileName, OSPF_MSG_SUFFIX, "w");
    if (UNLIKELY(!ospfMsgFile)) {
        fclose(ospfHelloFile);
#if OSPF_OUTPUT_DBD == 1
        fclose(ospfDBDFile);
#endif // OSPF_OUTPUT_DBD == 1
        exit(-1);
    }
    fprintf(ospfMsgFile, "Area\tMsgType\tLSType\tSrcIP\tLinkID\tNetmask_RouterIP\tADVRouter\tMetric\tIfaceType\tLinkType\n");
#endif // OSPF_OUTPUT_MSG == 1

    if (UNLIKELY(!(ospfFlow = calloc(mainHashMap->hashChainTableSize, sizeof(ospfFlow_t))))) {
        T2_PERR("ospfDecode", "failed to allocate memory for ospfFlow");
        fclose(ospfHelloFile);
#if OSPF_OUTPUT_DBD == 1
        fclose(ospfDBDFile);
#endif // OSPF_OUTPUT_DBD == 1
#if OSPF_OUTPUT_MSG == 1
        fclose(ospfMsgFile);
#endif // OSPF_OUTPUT_MSG == 1
        exit(-1);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("OSPF status", "ospfStat", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("OSPF version", "ospfVersion", 0, 1, bt_uint_8));
    bv = bv_append_bv(bv, bv_new_bv("OSPF Message Type", "ospfType", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("OSPF Authentication Type", "ospfAuType", 0, 1, bt_hex_16));
    bv = bv_append_bv(bv, bv_new_bv("OSPF Authentication Password", "ospfAuPass", 1, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("OSPF Area ID", "ospfArea", 0, 1, OSPF_AREA_TYPE));
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    ospfFlow_t * const ospfFlowP = &ospfFlow[flowIndex];
    memset(ospfFlowP, '\0', sizeof(ospfFlow_t));
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {

    if (packet->layer4Type != L3_OSPF) return;

    const uint16_t snaplen = packet->snapL7Length;
    if (snaplen <= OSPF3_HDR_LEN) return;

    const ospfHeader_t * const ospfHdrP = (ospfHeader_t*)packet->layer4Header;

    numOSPF[0]++;

    ospfFlow_t * const ospfFlowP = &ospfFlow[flowIndex];
    ospfFlowP->version = ospfHdrP->version;

    const uint8_t type = ospfHdrP->type;
    ospfFlowP->type |= (1 << type);
    if (type > 0 && type < OSPF_TYPE_N) numOSPF[type]++;

#if IPV6_ACTIVATE == 1
    const ipHeader_t * const ipHeader = NULL;
    const struct in_addr dstIp = {};
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    const ipHeader_t * const ipHeader = (ipHeader_t*)packet->layer3Header;
    const struct in_addr dstIp = ipHeader->ip_dst;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    if (PACKET_IS_IPV4(packet)) {
        if (dstIp.s_addr == OSPF_ALL_SPF_ROUTERS ||
            dstIp.s_addr == OSPF_ALL_D_ROUTERS)
        {
            numMCastPkts++;
            // when dstIP is mcast, TTL must be 1
            if (ipHeader->ip_ttl != 1) {
                ospfFlowP->stat |= OSPF_STAT_BAD_TTL;
                numInvalidOSPF[OSPF_STAT_BAD_TTL]++;
            }
        }
    }

#if OSPF_AREA_AS_IP == 1
    char areaID[INET_ADDRSTRLEN];
    ospfFlowP->areaID = ospfHdrP->areaID;
    strncpy(areaID, inet_ntoa(*(struct in_addr*)&ospfHdrP->areaID), INET_ADDRSTRLEN);
#else // OSPF_AREA_AS_IP == 0
    const uint32_t areaID = ntohl(ospfHdrP->areaID);
    ospfFlowP->areaID = areaID;
#endif // OSPF_AREA_AS_IP == 0

    if (ospfFlowP->version == 3) return; // TODO OSPFv3 not implemented

    if (PACKET_IS_IPV4(packet)) {
        // Authentication Type
        const uint16_t auType = ntohs(ospfHdrP->auType);
        ospfFlowP->auType |= (1 << auType);

        if (auType < OSPF_AUTH_N) numOSPFAuType[auType]++;
        else numOSPFAuType[OSPF_AUTH_N]++; // unknown auth type

        if (snaplen < OSPF2_HDR_LEN) return;

        switch (auType) {
            case OSPF_AUTH_NULL:
                // Authentication Type is null, but auField is non-zero... covert channel?
                if (ospfHdrP->auField != 0) ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                break;
            case OSPF_AUTH_PASSWD:
                // password contained in clear text in auField
                strncpy(ospfFlowP->auPass, (char*)&(ospfHdrP->auField), 8);
                break;
            case OSPF_AUTH_CRYPTO:
                // do nothing
                break;
            default:
                break;
        }

        switch (type) {
            case OSPF_HELLO: {
                // can be used to list routers in given area
                if (dstIp.s_addr != OSPF_ALL_SPF_ROUTERS) ospfFlowP->stat |= OSPF_STAT_BAD_DST;
                if (snaplen < OSPF2_HDR_LEN+sizeof(ospfHello_t)) return;
                if (ospfHdrP->len < sizeof(ospfHello_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    return;
                }
                const ospfHello_t * const hello = (ospfHello_t*)&ospfHdrP->data;
                const struct in_addr ip_src = ipHeader->ip_src;
                uint32_t masked = ntohl(*((uint32_t*)&ip_src)) & ntohl(hello->netmask);
                masked = ntohl(masked);
                fprintf(ospfHelloFile, "%"OSPF_PRI_AREA"\t%s", areaID, inet_ntoa(ip_src));
#if OSPF_MASK_AS_IP == 1
                fprintf(ospfHelloFile, "\t%s", inet_ntoa(*(struct in_addr*)&hello->netmask));
#else // OSPF_MASK_AS_IP == 0
                fprintf(ospfHelloFile, "\t%#08x", ntohl(hello->netmask));
#endif // OSPF_MASK_AS_IP == 0
                fprintf(ospfHelloFile, "\t%s", inet_ntoa(*(struct in_addr*)&masked));
                fprintf(ospfHelloFile, "\t%s", inet_ntoa(ospfHdrP->routerID));
                //uint_fast16_t j;
                //const uint16_t numNeighbors = (ntohs(ospfHdrP->len) - OSPF2_HDR_LEN - 20) / sizeof(uint32_t);
                //if (numNeighbors > 0) fprintf(ospfHelloFile, "\t%d", numNeighbors);
                //for (j = 0; j < numNeighbors; j++) {
                //    fprintf(ospfHelloFile, "\t%s", inet_ntoa(*(struct in_addr*)(&hello->neighbors+j)));
                //}
                //fprintf(ospfHelloFile, "\t0x%x", hello->options);
                fputc('\n', ospfHelloFile);
                if ((hello->options & OSPF_OPT_L) != 0) {
                    // LLS block present
                }
                break;
            }

            case OSPF_DB_DESCR: {
                if (snaplen < OSPF2_HDR_LEN+OSPF2_DBD_LEN) return;
                if (ospfHdrP->len < sizeof(ospfDBD_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    return;
                }
                const ospfDBD_t * const dbd = (ospfDBD_t*)&(ospfHdrP->data);
                if (dbd->flags > 7  || dbd->flags == 4 ||  // only 3 bits are used: I,M,MS
                    dbd->flags == 5 || dbd->flags == 6)    // (I), (I,MS), (I,M) not valid
                {
                    // Invalid flags combination
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                }
                uint16_t dataLen = ntohs(ospfHdrP->len) - OSPF2_HDR_LEN - OSPF2_DBD_LEN;
                if (snaplen < OSPF2_HDR_LEN+OSPF2_DBD_LEN+dataLen) return;
                ospfLSA_t *lsa;
                uint8_t lsType;
                size_t offset = 0;
                while (dataLen != 0) {
                    lsa = (ospfLSA_t*)(&(dbd->lsaHdr) + offset);
                    lsType = lsa->lsType;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPFLSType[lsType]++;
#if OSPF_OUTPUT_DBD == 1
                        fprintf(ospfDBDFile, "%"OSPF_PRI_AREA"\t%s", areaID, inet_ntoa(ospfHdrP->routerID));
                        fprintf(ospfDBDFile, "\t%s", inet_ntoa(lsa->lsaID));
                        fprintf(ospfDBDFile, "\t%s\t%d%s\t0x%x\t0x%x\t%s\n",
                                inet_ntoa(lsa->advRtr), ntohs(lsa->lsAge), OSPF_LSA_DNA(lsa) ? " (DNA)" : "",
                                ntohl(lsa->lsSeqNum), ntohs(lsa->lsChksum),
                                ospfLSTypeStr[lsType]);
#endif // OSPF_OUTPUT_DBD == 1
                        dataLen -= sizeof(*lsa);
                        offset += sizeof(*lsa);
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPFLSType[0]++;
                        // invalid record, abort processing of record
                        break;
                    }
                }
                if ((dbd->options & OSPF_OPT_L) != 0) {
                    // LLS block present
                }
                break;
            }

            case OSPF_LS_REQ: {
                if (ospfHdrP->len < sizeof(ospfLSR_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    return;
                }
                ospfLSR_t *lsr;
                uint32_t lsType;
                const uint16_t numLSR = (ntohs(ospfHdrP->len) - OSPF2_HDR_LEN) / sizeof(*lsr);
                for (uint_fast16_t j = 0; j < numLSR; j++) {
                    if (snaplen < OSPF2_HDR_LEN + j * sizeof(*lsr)) return;
                    lsr = (ospfLSR_t*)(&ospfHdrP->data+j*sizeof(ospfLSR_t));
                    lsType = ntohl(lsr->lsType);
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPFLSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                        fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsr->lsID));
                        fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsr->advRtr));
                        fputc('\n', ospfMsgFile);
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPFLSType[0]++;
                    }
                }
                break;
            }

            case OSPF_LS_UPDATE: {
                if (snaplen < OSPF2_HDR_LEN+sizeof(ospfLSU_t)) return;
                if (ospfHdrP->len < sizeof(ospfLSU_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    return;
                }
                const ospfLSU_t * const lsu = (ospfLSU_t*)&(ospfHdrP->data);
                uint8_t lsType;
                ospfLSA_t *lsa;
                size_t offset = 0;
                const uint32_t numLSA = ntohl(lsu->numLSA);
                if (snaplen < ntohs(ospfHdrP->len)) return;
                for (uint_fast32_t i = 0; i < numLSA; i++) {
                    lsa = (ospfLSA_t*)(&(lsu->lsaHdr) + offset);
                    lsType = lsa->lsType;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) numOSPFLSType[lsType]++;
                    switch (lsType) {
#if OSPF_OUTPUT_MSG == 1
                        case OSPF_LSTYPE_ROUTER: {
                            const ospfRouterLSA_t * const rlsa = (ospfRouterLSA_t*)(lsa);
                            const uint16_t numLinks = ntohs(rlsa->numLinks);
                            for (uint_fast16_t j = 0; j < numLinks; j++) {
                                const ospfRouterLSALink_t * const link = (ospfRouterLSALink_t*) (&rlsa->link+j*sizeof(*link));
                                fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                                fprintf(ospfMsgFile, "\t%s", inet_ntoa(link->linkID));
                                if (link->type == OSPF_LINK_STUB) { // linkData is the netmask
#if OSPF_MASK_AS_IP == 1
                                    fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)&link->linkData));
#else // OSPF_MASK_AS_IP == 0
                                    fprintf(ospfMsgFile, "\t%#08x", ntohl(link->linkData));
#endif // OSPF_MASK_AS_IP == 0
                                } else { // linkData is the router IP
                                    fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)&(link->linkData)));
                                }
                                fprintf(ospfMsgFile, "\t%s\t%d\t%s\t%s",
                                        inet_ntoa(lsa->advRtr), ntohs(link->tos0Metric),
                                        ospfMetricToIface(ntohs(link->tos0Metric)),
                                        ospfLinkTypeStr[link->type]);
                                fputc('\n', ospfMsgFile);
                            }
                            break;
                        }
                        case OSPF_LSTYPE_NETWORK: {
                            const ospfNetworkLSA_t * const nlsa = (ospfNetworkLSA_t*)(lsa);
                            fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->lsaID));
#if OSPF_MASK_AS_IP == 1
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)&nlsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%#08x", ntohl(nlsa->netmask));
#endif // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->advRtr));
                            //const uint16_t nr = (ntohs(lsa->lsLen) - OSPF2_LSA_LEN) / sizeof(uint32_t);
                            //if (nr > 1) fprintf(ospfMsgFile, "\t%d", nr);
                            //for (uint_fast16_t j = 1; j < nr; j++) { // j=0: netmask
                            //    fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)(&nlsa->router+(j-1))));
                            //}
                            fputc('\n', ospfMsgFile);
                            break;
                        }
                        case OSPF_LSTYPE_SUMMARY: // inter-area routes (same AS, different area)
                        case OSPF_LSTYPE_ASBR: {  // routes to AS boundary routers (different AS and area)
                            const ospfSummaryLSA_t * const slsa = (ospfSummaryLSA_t*)(lsa);
                            fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->lsaID));
#if OSPF_MASK_AS_IP == 1
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)&slsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%#08x", ntohl(slsa->netmask));
#endif // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->advRtr));
                            fprintf(ospfMsgFile, "\t%d", ntohl(slsa->metric<<8));
                            fputc('\n', ospfMsgFile);
                            break;
                        }
                        case OSPF_LSTYPE_ASEXT: {
                            const ospfASExtLSA_t * const elsa = (ospfASExtLSA_t*)(lsa);
                            fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->lsaID));
#if OSPF_MASK_AS_IP == 1
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(*(struct in_addr*)&elsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%#08x", ntohl(elsa->netmask));
#endif // OSPF_MASK_AS_IP == 0
                            fprintf(ospfMsgFile, "\t%s", inet_ntoa(lsa->advRtr));
                            fprintf(ospfMsgFile, "\t%d", ntohl(elsa->metric<<8));
                            //fprintf(ospfMsgFile, "\t%s", inet_ntoa(elsa->forwardAddr));
                            fputc('\n', ospfMsgFile);
                            break;
                        }
                        case OSPF_LSTYPE_MCAST:
                            break;
                        case OSPF_LSTYPE_NSSA:
                            break;
                        case OSPF_LSTYPE_EXTATTR:
                            break;
                        case OSPF_LSTYPE_OPAQUE_LLS:
                            break;
                        case OSPF_LSTYPE_OPAQUE_ALS:
                            break;
                        case OSPF_LSTYPE_OPAQUE_ASS:
                            break;
#endif // OSPF_OUTPUT_MSG == 1
                        default:
                            ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                            numOSPFLSType[0]++;
                            break;
                    }
                    offset += ntohs(lsa->lsLen);
                }
                break;
            }

            case OSPF_LS_ACK: {
                if (snaplen < ntohs(ospfHdrP->len)) return;
                if (ospfHdrP->len < sizeof(ospfLSA_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    return;
                }
                const uint16_t numLSA = (ntohs(ospfHdrP->len) - OSPF2_HDR_LEN) / OSPF2_LSA_LEN;
                if (numLSA == 0) break;
                ospfLSA_t *lsa;
                uint8_t lsType;
                for (uint_fast16_t j = 0; j < numLSA; j++) {
                    lsa = (ospfLSA_t*)(&ospfHdrP->data + j * OSPF2_LSA_LEN);
                    lsType = lsa->lsType;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPFLSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospfMsgFile, "%"OSPF_PRI_AREA"\t%s\t%s\t%s\t", areaID, ospfTypeStr[type], ospfLSTypeStr[lsType], inet_ntoa(ipHeader->ip_src));
                        fprintf(ospfMsgFile, "%s\t", inet_ntoa(lsa->lsaID));
                        fprintf(ospfMsgFile, "%s\n", inet_ntoa(lsa->advRtr));
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPFLSType[0]++;
                    }
                }
                break;
            }

            default:
                ospfFlowP->stat |= OSPF_STAT_BAD_TYPE;
                numInvalidOSPF[OSPF_STAT_BAD_TYPE]++;
                break;
        }
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    ospfFlow_t *ospfFlowP = &ospfFlow[flowIndex];
    outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->stat, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->version, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->type, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->auType, sizeof(uint16_t));
    const size_t len = strlen(ospfFlowP->auPass);
    if (len > 0) {
        outputBuffer_append(main_output_buffer, (char*)&ONE, sizeof(uint32_t));
        outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->auPass, len+1);
    } else { // no password
        outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t));
    }
    outputBuffer_append(main_output_buffer, (char*)&ospfFlowP->areaID, sizeof(uint32_t));
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
 	T2_FPLOG_NUMP(stream, "ospfDecode", "Number of OSPF packets", numOSPF[0], numPackets);
}


void onApplicationTerminate() {
    free(ospfFlow);

    fclose(ospfHelloFile);

#if OSPF_OUTPUT_DBD == 1
    fclose(ospfDBDFile);
#endif

#if OSPF_OUTPUT_MSG == 1
    fclose(ospfMsgFile);
#endif

    if (numOSPF[0] == 0) return; // no OSPF packets

    FILE *file = t2_open_file(baseFileName, OSPF_SUFFIX, "w");
    if (UNLIKELY(!file)) exit(-1);

    T2_FLOG_NUM(file, "Total # of OSPF packets", numOSPF[0]);
    fprintf(file, "OSPF / Total traffic [%%]: %5.3f\n\n", 100.0f*numOSPF[0]/(float)numPackets);
    if (numOSPF[OSPF_LS_UPDATE] != 0) {
        fprintf(file, "Link State Request / Update ratio [%%]: %5.3f\n", 100.0f*numOSPF[OSPF_LS_REQ]/(float)numOSPF[OSPF_LS_UPDATE]);
        fprintf(file, "Link State Update / Acknowledgment ratio [%%]: %5.3f\n\n", 100.0f*numOSPF[OSPF_LS_UPDATE]/(float)numOSPF[OSPF_LS_ACK]);
    }

    fprintf(file, "Number of multicast packets: %"PRIu64"\n\n", numMCastPkts);

    fprintf(file, "Number of packets with null authentication: %"PRIu64"\n", numOSPFAuType[OSPF_AUTH_NULL]);
    fprintf(file, "Number of packets with password authentication: %"PRIu64"\n", numOSPFAuType[OSPF_AUTH_PASSWD]);
    fprintf(file, "Number of packets with cryptographic authentication: %"PRIu64"\n", numOSPFAuType[OSPF_AUTH_CRYPTO]);
    fprintf(file, "Number of packets with unknown authentication: %"PRIu64"\n\n", numOSPFAuType[OSPF_AUTH_N]);

    uint_fast8_t i;
    for (i = 1; i < OSPF_LSTYPE_N; i++) {
        if (numOSPFLSType[i] > 0) fprintf(file, "Number of %s: %"PRIu64"\n", ospfLSTypeStr[i], numOSPFLSType[i]);
    }
    if (numOSPFLSType[0] > 0) fprintf(file, "Number of LSA with unknown type: %"PRIu64"\n", numOSPFLSType[0]);

    fprintf(file, "\nNumber of packets with bad TTL: %"PRIu64"\n", numInvalidOSPF[OSPF_STAT_BAD_TTL]);
    fprintf(file, "Number of packets with bad dest: %"PRIu64"\n", numInvalidOSPF[OSPF_STAT_BAD_DST]);
    fprintf(file, "Number of packets with bad type: %"PRIu64"\n\n", numInvalidOSPF[OSPF_STAT_BAD_TYPE]);
    //fprintf(file, "Number of OSPF packets with bad checksum: %ld\n\n", numInvalidOSPF[OSPF_STAT_BAD_CSUM]);

    // OSPF type statistics
    fprintf(file, "OSPF Type\t# of packets\tRelative Frequency [%%]\n");
    for (i = 1; i < OSPF_TYPE_N; i++) {
        fprintf(file, "%s\t%"PRIu64"\t%5.3f\n", ospfTypeStr[i], numOSPF[i], 100.0f*numOSPF[i]/(float)numOSPF[0]);
    }

    fclose(file);
}
