/*
 * arpDecode.c
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

#include "arpDecode.h"


// Global variables

arpFlow_t *arpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint8_t arpStat;

static hashMap_t *arpTable;
static uint64_t *macTable;

#define ARP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("\t\t\t\t\t\t\t\t\t\t", sPktFile); \
    }

// TODO make sure counters do not overflow
#define ARP_APPEND_MAC_IP(arpFlowP, mac_addr, ip_addr) \
    if ((arpFlowP)->cnt < MAX_IP) { \
        const uint_fast32_t cnt = (arpFlowP)->cnt; \
        memcpy((arpFlowP)->mac[cnt], (mac_addr), ETH_ALEN); \
        (arpFlowP)->ip[cnt] = (ip_addr); \
        (arpFlowP)->ipCnt[cnt]++; \
    } else { \
        (arpFlowP)->stat |= ARP_FULL; \
        if (!(arpStat & ARP_FULL)) { \
            T2_PWRN("arpDecode", "MAC/IP list full... increase MAX_IP"); \
            arpStat |= ARP_FULL; \
        } \
    } \
    (arpFlowP)->cnt++; \


// Static functions

static inline void arp_uint64_to_mac(uint64_t mac, uint8_t *dest) {
    for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
        dest[i] = (mac >> 8 * (ETH_ALEN - 1 - i)) & 0xff;
    }
}

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("arpDecode", "0.8.4", 0, 8);


void initialize() {
#if ETH_ACTIVATE == 0
    T2_PWRN("arpDecode", "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    if (UNLIKELY(!(arpFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*arpFlows))))) {
        T2_PERR("arpDecode", "failed to allocate memory for arpFlows");
        exit(-1);
    }

    if (UNLIKELY(!(arpTable = hashTable_init(1.0f, sizeof(uint32_t), "arp")))) {
        T2_PERR("arpDecode", "failed to allocate memory for arpTable");
        free(arpFlows);
        exit(-1);
    }

    if (UNLIKELY(!(macTable = calloc(arpTable->hashChainTableSize, sizeof(*macTable))))) {
        T2_PERR("arpDecode", "failed to allocate memory for macTable");
        hashTable_destroy(arpTable);
        free(arpFlows);
        exit(-1);
    }

    if (sPktFile) {
        fputs("arpStat\tarpHwType\tarpProtoType\t"
              "arpHwSize\tarpProtoSize\tarpOpcode\t"
              "arpSenderMAC\tarpSenderIP\t"
              "arpTargetMAC\tarpTargetIP\t",
              sPktFile);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv , "arpStat"      , "ARP status");
    BV_APPEND_U16(bv, "arpHwType"    , "ARP HW Type");
    BV_APPEND_H16(bv, "arpOpcode"    , "ARP opcode");
    BV_APPEND_U16(bv, "arpIpMacCnt"  , "ARP Number of distinct MAC / IP pairs");
    BV_APPEND_R(bv  , "arpMac_Ip_Cnt", "ARP MAC_IP_count ", 3, bt_mac_addr, bt_ip4_addr, bt_uint_16);
    return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
    arpFlow_t * const arpFlowP = &arpFlows[flowIndex];
    memset(arpFlowP, '\0', sizeof(*arpFlowP));

    if ((packet->status & (L2_ARP | L2_RARP)) == 0) return;

    const arpMsg_t * const arpP = (arpMsg_t*)packet->layer7Header;

    arpFlowP->stat |= ARP_DET;
    arpFlowP->hwType = ntohs(arpP->hwType);
}


void claimLayer2Information(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    arpFlow_t * const arpFlowP = &arpFlows[flowIndex];
    if (!arpFlowP->stat) {
        ARP_SPKTMD_PRI_NONE();
        return;
    }

    const arpMsg_t * const arpP = (arpMsg_t*)packet->layer7Header;

    const uint_fast16_t opCode = ntohs(arpP->opCode);
    arpFlowP->opCode |= (1 << opCode);

    const uint_fast8_t hwSize = arpP->hwSize;
    const uint_fast8_t protoSize = arpP->protoSize;

    const uint32_t srcIP = arpP->srcIP;
    const uint32_t dstIP = arpP->dstIP;

    const uint8_t *srcMAC = arpP->srcMAC;
    const uint8_t *dstMAC = arpP->dstMAC;

    if (srcIP == dstIP && (opCode == ARP_OPCODE_REQ || opCode == ARP_OPCODE_REQ)) {
        arpFlowP->stat |= ARP_GRAT;
    }

    if (((1 << opCode) & ARP_SUPPORTED_OPCODE) &&  // ARP request/reply and RARP reply
        (hwSize == ETH_ALEN && protoSize == 4))    // MAC/IPv4 pairs only
    {
        const uint32_t ip[] = { srcIP, dstIP };
        const uint8_t *mac[] = { srcMAC, dstMAC };
        const uint_fast32_t naddr = (opCode == ARP_OPCODE_REQ) ? 1 : 2;

        for (uint_fast32_t i = 0; i < naddr; i++) {
            const uint64_t mac_u64 = t2_mac_to_uint64(mac[i]);
            unsigned long hash = hashTable_lookup(arpTable, (char*)&ip[i]);
            if (hash == HASHTABLE_ENTRY_NOT_FOUND) {
                // First time seeing this IP, add it to the ARP table
                hash = hashTable_insert(arpTable, (char*)&ip[i]);
                macTable[hash] = mac_u64;
                ARP_APPEND_MAC_IP(arpFlowP, mac[i], ip[i]);
            } else {
                // IP already seen... make sure the MAC matches
                const uint64_t prevMAC_u64 = macTable[hash];
                uint8_t prevMAC_u8[ETH_ALEN];
                arp_uint64_to_mac(prevMAC_u64, prevMAC_u8);

                bool add_prev_mac;
                if (prevMAC_u64 == mac_u64) {
                    // Same MAC
                    add_prev_mac = false;
                } else {
                    // Different MAC
                    // TODO which mac to store in macTable?
                    arpFlowP->stat |= ARP_SPOOF;
                    add_prev_mac = true;
                }

                bool add_mac = true;

                for (uint_fast32_t j = 0; j < MIN(arpFlowP->cnt, MAX_IP); j++) {
                    if (arpFlowP->ip[j] == ip[i]) {
                        if (memcmp(arpFlowP->mac[j], mac[i], ETH_ALEN) == 0) {
                            // MAC/IP pair found... increment counter
                            arpFlowP->ipCnt[j]++;
                            add_mac = false;
                        } else if (add_prev_mac && memcmp(arpFlowP->mac[j], prevMAC_u8, ETH_ALEN) == 0) {
                            // prevMAC/IP pair already exists... do not add it again
                            add_prev_mac = false;
                        }
                    }
                }

                if (add_mac) {
                    ARP_APPEND_MAC_IP(arpFlowP, mac[i], ip[i]);
                }

                if (add_prev_mac) {
                    // This MAC/IP pair was actually not seen in this flow,
                    // report it anyway, but do not increment the counter
                    ARP_APPEND_MAC_IP(arpFlowP, prevMAC_u8, ip[i]);
                    if (arpFlowP->cnt <= MAX_IP) {
                        arpFlowP->ipCnt[arpFlowP->cnt-1] = 0;
                    }
                }
            }
        }
    }

    if (sPktFile) {
        // Source and Destination MAC
        char srcMacStr[32] = {}, dstMacStr[32] = {};
        if (hwSize == ETH_ALEN) {
            t2_mac_to_str(srcMAC, srcMacStr, sizeof(srcMacStr));
            t2_mac_to_str(dstMAC, dstMacStr, sizeof(dstMacStr));
        }

        // Source and Destination IP
        char srcIPStr[INET_ADDRSTRLEN], dstIPStr[INET_ADDRSTRLEN];
        if (protoSize == 4) {
            t2_ipv4_to_str(*(struct in_addr*)&srcIP, srcIPStr, sizeof(srcIPStr));
            t2_ipv4_to_str(*(struct in_addr*)&dstIP, dstIPStr, sizeof(dstIPStr));
        }

        fprintf(sPktFile,
                "0x%02"B2T_PRIX8"\t""%"PRIu16"\t0x%04"B2T_PRIX16"\t" // stat, hwType, protoType
                "%"PRIuFAST8"\t%"PRIuFAST8"\t%"PRIuFAST16"\t"        // hwSize, protoSize, opCode
                "%s\t%s\t%s\t%s\t",                                  // srcMacStr, srcIPStr, dstMacStr, dstIPStr
                arpFlowP->stat, ntohs(arpP->hwType), ntohs(arpP->protoType),
                hwSize, protoSize, opCode, srcMacStr, srcIPStr, dstMacStr, dstIPStr);
    }
}


void claimLayer4Information(packet_t* packet __attribute__((unused)), unsigned long flowIndex __attribute__((unused))) {
    ARP_SPKTMD_PRI_NONE();
}


void onFlowTerminate(unsigned long flowIndex) {
    const arpFlow_t * const arpFlowP = &arpFlows[flowIndex];

    arpStat |= arpFlowP->stat;

#if BLOCK_BUF == 0
    OUTBUF_APPEND_U8(main_output_buffer , arpFlowP->stat);
    OUTBUF_APPEND_U16(main_output_buffer, arpFlowP->hwType);
    OUTBUF_APPEND_U16(main_output_buffer, arpFlowP->opCode);
    OUTBUF_APPEND_U16(main_output_buffer, arpFlowP->cnt);

    const uint32_t cnt = MIN(arpFlowP->cnt, MAX_IP);
    OUTBUF_APPEND_NUMREP(main_output_buffer, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
        OUTBUF_APPEND(main_output_buffer, arpFlowP->mac[i], ETH_ALEN);
        OUTBUF_APPEND_U32(main_output_buffer, arpFlowP->ip[i]);
        OUTBUF_APPEND_U16(main_output_buffer, arpFlowP->ipCnt[i]);
    }
#endif // BLOCK_BUF == 0
}


static inline void arp_pluginReport(FILE *stream) {
    if (!arpStat) return;
    T2_FPLOG(stream, "arpDecode", "Aggregated status flags: 0x%02"B2T_PRIX8, arpStat);
}


void pluginReport(FILE *stream) {
    arp_pluginReport(stream);
}


void monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("arpStat\t", stream); // Note the trailing tab (\t)
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream, "%"B2T_PRIX8"\t", arpStat); // Note the trailing tab (\t)
            break;

        case T2_MON_PRI_REPORT:
            arp_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }
}


void saveState(FILE *stream) {
    fprintf(stream, "%"PRIx8, arpStat);
}


void restoreState(const char *str) {
    sscanf(str, "%"SCNx8, &arpStat);
}


void onApplicationTerminate() {
    hashTable_destroy(arpTable);
    free(macTable);
    free(arpFlows);
}

#endif // ETH_ACTIVATE > 0
