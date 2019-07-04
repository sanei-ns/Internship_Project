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

#include "dhcpDecode.h"
#include "t2buf.h"
#include "memdebug.h"


// Global variables

dhcpFlow_t *dhcpFlow;


// Typedefs
#if IPV6_ACTIVATE > 0
typedef ipAddr_t dhcp_ip_t;
#else // IPV6_ACTIVATE == 0
typedef ip4Addr_t dhcp_ip_t;
#endif // IPV6_ACTIVATE == 0

// Static variables

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static uint64_t numDHCPmsgT[DHCP_NUM_MSGT];
static uint64_t numDHCPPkts4;
static uint64_t numDHCPQR[2];
#endif

#if IPV6_ACTIVATE > 0
static uint64_t numDHCPmsgT6[DHCP_NUM_MSGT6];
static uint64_t numDHCPPkts6;
#endif

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static const char *dhcpMsgTToStr[] = {
    "Discover",
    "Offer",
    "Request",
    "Decline",
    "Acknowledgment",
    "Negative Acknowledgment",
    "Release",
    "Informational",
};
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
static const char *dhcpMsgT6ToStr[] = {
    // RFC5007
    //"Reserved", // 0
    "SOLICIT",
    "ADVERTISE",
    "REQUEST",
    "CONFIRM",
    "RENEW",
    "REBIND",
    "REPLY",
    "RELEASE",
    "DECLINE",
    "RECONFIGURE", // 10
    "INFORMATION-REQUEST",
    "RELAY-FORW",
    "RELAY-REPL",
    // RFC5007
    "LEASEQUERY",
    "LEASEQUERY-REPLY",
    // RFC5460
    "LEASEQUERY-DONE",
    "LEASEQUERY-DATA",
    // RFC6977
    "RECONFIGURE-REQUEST",
    "RECONFIGURE-REPLY",
    // RFC7341
    "DHCPV4-QUERY", // 20
    "DHCPV4-RESPONSE",
    // RFC7653
    "ACTIVELEASEQUERY",
    "STARTTLS",
    // https://www.iana.org/go/draft-ietf-dhc-dhcpv6-failover-protocol-06
    //"BNDUPD",
    //"BNDREPLY",
    //"POOLREQ",
    //"POOLRESP",
    //"UPDREQ",
    //"UPDREQALL",
    //"UPDDONE", // 30
    //"CONNECT",
    //"CONNECTREPLY",
    //"DISCONNECT",
    //"STATE",
    //"CONTACT", // 35
    //"Unassigned", // 36-255
};
#endif // IPV6_ACTIVATE > 0


#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
static hashMap_t *macMap;
static uint64_t *macArray;
#endif


// Functions prototypes

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static void dhcp4decode(packet_t *packet, unsigned long flowIndex);
#endif

#if IPV6_ACTIVATE > 0
static void dhcp6decode(packet_t *packet, unsigned long flowIndex);
#endif


#define DHCP_SPKTMD_PRI_NONE() \
    if (sPktFile) fputs("\t\t\t\t", sPktFile);


// Tranalyzer functions

T2_PLUGIN_INIT("dhcpDecode", "0.8.4", 0, 8);


void initialize() {
    // allocate struct for all flows
    if (UNLIKELY(!(dhcpFlow = calloc(mainHashMap->hashChainTableSize, sizeof(*dhcpFlow))))) {
        T2_PERR("dhcpDecode", "failed to allocate memory for dhcpFlow");
        exit(-1);
    }

#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    if (UNLIKELY(!(macMap = hashTable_init(1.0f, sizeof(dhcp_ip_t), "dhcp")))) {
        T2_PERR("dhcpDecode", "failed to allocate memory for macMap");
        free(dhcpFlow);
        exit(-1);
    }

    if (UNLIKELY(!(macArray = calloc(macMap->hashChainTableSize, sizeof(*macArray))))) {
        T2_PERR("dhcpDecode", "failed to allocate memory for macArray");
        hashTable_destroy(macMap);
        free(dhcpFlow);
        exit(-1);
    }
#endif

    if (sPktFile) fputs("dhcpMType\tdhcpHops\tdhcpTransID\tdhcpLFlow\t", sPktFile);
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;

    bv = bv_append_bv(bv, bv_new_bv("DHCP status", "dhcpStat", 0, 1, bt_hex_16));

#if IPV6_ACTIVATE > 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP message type", "dhcpMType", 0, 1, bt_hex_32));
#else // IPV6_ACTIVATE == 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP message type", "dhcpMType", 0, 1, bt_hex_16));
#endif

    bv = bv_append_bv(bv, bv_new_bv("DHCP hardware type", "dhcpHWType", 0, 1, bt_hex_64));

#if DHCP_ADD_CNT == 1
    bv = bv_append_bv(bv, bv_new_bv("DHCP client hardware addresses and count", "dhcpCHWAdd_HWCnt", 1, 2, bt_mac_addr, bt_uint_32));
#else // DHCP_ADD_CNT == 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP client hardware addresses", "dhcpCHWAdd", 1, 1, bt_mac_addr));
#endif // DHCP_ADD_CNT == 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    bv = bv_append_bv(bv, bv_new_bv("DHCP network mask", "dhcpNetmask", 0, 1, DHCPMASKTYP));
    bv = bv_append_bv(bv, bv_new_bv("DHCP gateway IP", "dhcpGWIP", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP DNS", "dhcpDnsIP", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP hop count", "dhcpHopCnt", 0, 1, bt_hex_32));
    bv = bv_append_bv(bv, bv_new_bv("DHCP server host name", "dhcpSrvName", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("DHCP boot file name", "dhcpBootFile", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("DHCP option count", "dhcpOptCnt", 0, 1, bt_uint_16));
#if DHCPBITFLD == 1
    bv = bv_append_bv(bv, bv_new_bv("DHCP options Bitfield", "dhcpOptBF1_BF2_BF3", 0, 3, bt_hex_64, bt_hex_64, bt_hex_64));
#else // DHCPBITFLD == 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP options", "dhcpOpts", 1, 1, bt_uint_8));
#endif // DHCPBITFLD
#if DHCP_ADD_CNT == 1
    bv = bv_append_bv(bv, bv_new_bv("DHCP hosts and count", "dhcpHosts_HCnt", 1, 2, bt_string, bt_uint_16));
#else // DHCP_ADD_CNT == 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP hosts", "dhcpHosts", 1, 1, bt_string));
#endif // DHCP_ADD_CNT == 0
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if DHCP_ADD_CNT == 1
    bv = bv_append_bv(bv, bv_new_bv("DHCP domains and count", "dhcpDomains_DCnt", 1, 2, bt_string, bt_uint_16));
#else // DHCP_ADD_CNT == 0
    bv = bv_append_bv(bv, bv_new_bv("DHCP domains", "dhcpDomains", 1, 1, bt_string));
#endif // DHCP_ADD_CNT == 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    bv = bv_append_bv(bv, bv_new_bv("DHCP maximum seconds elapsed", "dhcpMaxSecEl", 0, 1, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("DHCP lease time (seconds)", "dhcpLeaseT", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("DHCP renewal time (seconds)", "dhcpRenewT", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("DHCP rebind time (seconds)", "dhcpRebindT", 0, 1, bt_uint_32));

    bv = bv_append_bv(bv, bv_new_bv("DHCP requested IP", "dhcpReqIP", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP client IP", "dhcpCliIP", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP your (client) IP", "dhcpYourIP", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP next server IP", "dhcpNextServer", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP relay agent IP", "dhcpRelay", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP server identifier", "dhcpSrvId", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP message", "dhcpMsg", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("DHCP linked flow", "dhcpLFlow", 0, 1, bt_uint_64));

#if DHCP_FLAG_MAC == 1
    bv = bv_append_bv(bv, bv_new_bv("DHCP source MAC address", "dhcpSrcMac", 0, 1, bt_mac_addr));
    bv = bv_append_bv(bv, bv_new_bv("DHCP destination MAC address", "dhcpDstMac", 0, 1, bt_mac_addr));
#endif

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];
    memset(dhcpFlowP, '\0', sizeof(dhcpFlow_t)); // set everything to 0

    flow_t * const flowP = &flows[flowIndex];
    if (flowP->layer4Protocol != L3_UDP) return;

    const uint_fast16_t sp = flowP->srcPort;
    const uint_fast16_t dp = flowP->dstPort;

    if (
#if IPV6_ACTIVATE > 0
            (sp == DHCP6UDPCP && dp == DHCP6UDPSP) ||
            (sp == DHCP6UDPSP && dp == DHCP6UDPCP)
#endif
#if IPV6_ACTIVATE == 2
            ||
#endif
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            (sp == DHCP4UDPCP && dp == DHCP4UDPSP) ||
            (sp == DHCP4UDPSP && dp == DHCP4UDPCP)
#endif
        )
    {
        if (flowP->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND && PACKET_IS_IPV4(packet)) {
            const dhcpHeader_t * const dhcpHdr = (dhcpHeader_t*)packet->layer7Header;
            if (dhcpHdr->opcode == 2) flowP->status |= L3FLOWINVERT; // boot reply should be a B flow
            else if (dhcpHdr->opcode == 1) flowP->status &= ~L3FLOWINVERT;
        }
        dhcpFlowP->stat = DHCPPRTDT;
    }
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    DHCP_SPKTMD_PRI_NONE();
}
#endif


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];
    if (!dhcpFlowP->stat) {
        DHCP_SPKTMD_PRI_NONE();
        return; // only DHCP
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
        numDHCPPkts6++;
        dhcp6decode(packet, flowIndex);
#endif
    } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        numDHCPPkts4++;
        dhcp4decode(packet, flowIndex);
#endif
    }
}


#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
/**
 * Safe strlen which does not read further than max bytes.
 * Returns -1 if no NULL byte found in the first max bytes
 */
static ssize_t safe_strlen(const void *s, size_t max) {
    const void * const end = memchr(s, 0, max);
    return end == NULL ? -1 : end - s;
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static void dhcp4decode(packet_t *packet, unsigned long flowIndex) {
    const uint16_t snaplen = packet->snapL7Length;
    if (snaplen < DHCP_HDRLEN) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const dhcpHeader_t * const dhcpHdr = (dhcpHeader_t*)packet->layer7Header;

    flow_t * const flowP = &flows[flowIndex];
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    if (UNLIKELY(dhcpHdr->opcode == 0 || dhcpHdr->opcode > 2)) {
        dhcpFlowP->stat |= DHCPMALFORMD; // Invalid opcode
    } else {
        dhcpFlowP->stat |= 1 << dhcpHdr->opcode; // 1: boot request, 2: boot reply
        numDHCPQR[dhcpHdr->opcode-1]++;
    }

    dhcpFlowP->hwType |= 1 << MIN(dhcpHdr->hwType, 63);

    if (dhcpHdr->hopCnt <= 16) dhcpFlowP->hopCnt |= 1 << dhcpHdr->hopCnt;
    else dhcpFlowP->hopCnt |= 1U << 31; // invalid hopcount

    if (dhcpHdr->flags & DHCPBCST) dhcpFlowP->stat |= DHCPBCAST;

    // XXX Most versions of Windows encode this field as little-endian...
    uint16_t secEl = ntohs(dhcpHdr->num_sec);
    if (secEl > dhcpHdr->num_sec) {
        dhcpFlowP->stat |= DHCPSECELNDIAN;
        secEl = dhcpHdr->num_sec;
    }
    if (secEl > dhcpFlowP->maxSecEl) dhcpFlowP->maxSecEl = secEl;

    dhcpFlowP->cliIP = dhcpHdr->clientIP;
    dhcpFlowP->yourIP = dhcpHdr->yourIP;
    dhcpFlowP->nextSrvr = dhcpHdr->servIP;
    dhcpFlowP->relay = dhcpHdr->gwIP;

    int_fast32_t i;
    // Client MAC address
    if (dhcpHdr->hwType != 1 || dhcpHdr->hwAddrLen != ETH_ALEN) {
        // Not a MAC address
        dhcpFlowP->stat |= DHCPNONETHHW;
    } else if (dhcpFlowP->HWAddCnt >= DHCPNMMAX) {
        dhcpFlowP->stat |= DHCPNMTRUNC;
    } else {
        for (i = 0; i < dhcpFlowP->HWAddCnt; i++) {
            // MAC address already seen
            if (dhcpFlowP->clHWAdd[i][0] == dhcpHdr->clientHWaddr[0] &&
                dhcpFlowP->clHWAdd[i][1] == dhcpHdr->clientHWaddr[1])
            {
                break;
            }
        }

        // MAC address was never seen
        if (i == dhcpFlowP->HWAddCnt) {
            dhcpFlowP->clHWAdd[i][0] = dhcpHdr->clientHWaddr[0];
            dhcpFlowP->clHWAdd[i][1] = dhcpHdr->clientHWaddr[1];
            dhcpFlowP->HWAddCnt++;
        }

#if DHCP_ADD_CNT == 1
        dhcpFlowP->clHWAdd[i][2]++;
#endif
    }

    // Server host name
    size_t len;
    ssize_t slen = safe_strlen((char*)dhcpHdr->servHostName, sizeof(dhcpHdr->servHostName));
    if (slen > 0) {
        len = MIN((size_t)slen, sizeof(dhcpFlowP->serverName)-1);
        memcpy(dhcpFlowP->serverName, dhcpHdr->servHostName, len);
        dhcpFlowP->serverName[len] = '\0';
    }

    // Boot file name
    slen = safe_strlen((char*)dhcpHdr->bootFname, sizeof(dhcpHdr->bootFname));
    if (slen > 0) {
        len = MIN((size_t)slen, sizeof(dhcpFlowP->bootFile)-1);
        memcpy(dhcpFlowP->bootFile, dhcpHdr->bootFname, len);
        dhcpFlowP->bootFile[len] = '\0';
    }

    // Magic cookie
    if (dhcpHdr->optMagNum != MAGICNUMBERn) {
        dhcpFlowP->stat |= DHCPMAGNUMERR;
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const udpHeader_t * const udpHdr = (udpHeader_t*)packet->layer4Header;
    const int32_t dhcpOptLen = ntohs(udpHdr->len) - DHCPOPTUDPOFF;
    if ((int32_t)(snaplen - DHCP_HDRLEN) < dhcpOptLen) {
        // warning: crafted packet or option field not acquired
        dhcpFlowP->stat |= DHCPOPTCORRPT;
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    // Process DHCP options

    const uint8_t * const dhcpOpt = (uint8_t *)dhcpHdr + DHCP_HDRLEN;

    uint8_t msgT = 0;
    for (i = 0; i < dhcpOptLen && dhcpOpt[i] && dhcpOpt[i] != DHCPOPTEND; i += dhcpOpt[i+1] + 2) {
        const uint8_t optC = dhcpOpt[i];
        const uint8_t optL = dhcpOpt[i+1];
        switch (optC) {
            case 1: // Subnet Mask
                dhcpFlowP->netMsk = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 3: // Router
                dhcpFlowP->gw = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 6: // Domain Name Server
                dhcpFlowP->dns = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 12: // Host Name
                if (dhcpFlowP->hostNCnt >= DHCPNMMAX) {
                    dhcpFlowP->stat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->hostNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->hostN[j]);
                        // host name is sometimes null terminated...
                        if ((k == optL || k+1 == optL) && memcmp(dhcpFlowP->hostN[j], &dhcpOpt[i+2], k) == 0) break;
                    }
                    if (j == dhcpFlowP->hostNCnt) {
                        char *hostP = malloc(optL+1);
                        memcpy(hostP, &dhcpOpt[i+2], optL);
                        hostP[optL] = '\0';
                        dhcpFlowP->hostN[dhcpFlowP->hostNCnt] = hostP;
                        dhcpFlowP->hostNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->hostrep[j]++;
#endif
                }
                break;
            case 15: // Domain Name
                if (dhcpFlowP->domainNCnt >= DHCPNMMAX) {
                    dhcpFlowP->stat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->domainNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->domainN[j]);
                        // domain name is sometimes null terminated...
                        if ((k == optL || k+1 == optL) && memcmp(dhcpFlowP->domainN[j], &dhcpOpt[i+2], k) == 0) break;
                    }
                    if (j == dhcpFlowP->domainNCnt) {
                        char *domainP = malloc(optL+1);
                        memcpy(domainP, &dhcpOpt[i+2], optL);
                        domainP[optL] = '\0';
                        dhcpFlowP->domainN[dhcpFlowP->domainNCnt] = domainP;
                        dhcpFlowP->domainNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->domainrep[j]++;
#endif
                }
                break;
            case 50: // Requested IP address
                dhcpFlowP->reqIP = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 51: // IP Address Lease Time
                dhcpFlowP->leaseT = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 52: // Option Overload
                dhcpFlowP->stat |= DHCPOPTOVERL;
                break;
            case 53: // DHCP Message Type
                msgT = dhcpOpt[i+2];
                if (msgT > DHCP_NUM_MSGT || msgT == 0) {
                    T2_PWRN("dhcpDecode", "unhandled message type %"PRIu8, msgT);
                } else {
                    numDHCPmsgT[msgT-1]++;
                    dhcpFlowP->MType |= 1 << msgT;
                }
                break;
            case 54: // Server Identifier
                dhcpFlowP->srvId = *(uint32_t*)&dhcpOpt[i+2];
                break;
            //case 55: // Parameter Request List
            case 56: // Message
                len = MIN(optL, sizeof(dhcpFlowP->msg)-1);
                memcpy(dhcpFlowP->msg, &dhcpOpt[i+2], len);
                dhcpFlowP->msg[len] = '\0';
                break;
            //case 57: // Maximum DHCP Message Size
            case 58: // Renewal Time Value
                dhcpFlowP->renewT = *(uint32_t*)&dhcpOpt[i+2];
                break;
            case 59: // Rebinding Time Value
                dhcpFlowP->rebindT = *(uint32_t*)&dhcpOpt[i+2];
                break;
            //case 60: // Vendor class identifier
            case 61: // Client Identifier
                if (dhcpOpt[i+2] != 0 && dhcpOpt[i+2] != 254) {
                    if (dhcpHdr->hwType != dhcpOpt[i+2] ||
                        memcmp(&dhcpHdr->clientHWaddr[0], &dhcpOpt[i+3], optL-1) != 0)
                    {
                        //T2_PWRN("dhcpDecode", "Client identifier different from client MAC address");
                        dhcpFlowP->stat |= DHCPMISCLID;
                    }
                } else {
                    // Client Identifier is not a MAC address (254: uuid, 0: fqdn)
                }
                break;
            //case 81: // Client Fully Qualified Domain Name
            //case 93: // Client System Architecture
            //case 94: // Client Network Device Interface
            //case 97: // UUID/GUID-based Client Identifier
        }

#if DHCPBITFLD == 1
        if (optC < 64) dhcpFlowP->optT[2] |= (uint64_t)1 << (optC & DHCP64MSK);
        else if (optC < 128) dhcpFlowP->optT[1] |= (uint64_t)1 << ((optC - 64) & DHCP64MSK);
        else dhcpFlowP->optT[0] |= (uint64_t)1 << ((optC - 128) & DHCP64MSK);
#else // DHCPBITFLD == 0
        if (dhcpFlowP->optNum >= DHCPMAXOPT) {
            dhcpFlowP->stat |= DHCPOPTTRUNC;
        } else {
            uint_fast32_t j;
            for (j = 0; j < dhcpFlowP->optNum; j++) {
                if (dhcpFlowP->opt[j] == optC) break;
            }
            if (j == dhcpFlowP->optNum) {
                dhcpFlowP->opt[dhcpFlowP->optNum++] = optC;
            }
        }
#endif // DHCPBITFLD == 0

        dhcpFlowP->optCntT++;
    }

    // Missing End marker (0xff) in DHCP options
    if (dhcpOptLen > 0 && dhcpOpt[i] != DHCPOPTEND) dhcpFlowP->stat |= DHCPOPTCORRPT;

    if (msgT == DHCP_MSGT_REQUEST) {
        const uint16_t srcPort = ntohs(udpHdr->source);
        const uint16_t dstPort = ntohs(udpHdr->dest);
        const flow_t parent = {
#if ETH_ACTIVATE == 2
            .ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS,
#endif // ETH_ACTIVATE == 2
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
            .ethType = packet->layer2Type,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE == 1
            .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE == 1
            .vlanID = flowP->vlanID,
            .srcIP.IPv4 = *(struct in_addr*)&dhcpFlowP->srvId,
            .dstIP.IPv4 = *(struct in_addr*)&dhcpFlowP->reqIP,
            .layer4Protocol = flowP->layer4Protocol,
            .srcPort = srcPort,
            .dstPort = dstPort,
        };
        const uint64_t hasParent = hashTable_lookup(mainHashMap, (char*)&parent.srcIP);
        if (hasParent != HASHTABLE_ENTRY_NOT_FOUND) {
            dhcpFlowP->lflow = flows[hasParent].findex;
            dhcpFlow[hasParent].lflow = flowP->findex;
        }
#if DHCP_FLAG_MAC == 1
    } else if (msgT == DHCP_MSGT_ACK) {
        const dhcp_ip_t cliIP = {
            .IPv4x[0] = (dhcpHdr->yourIP ? dhcpHdr->yourIP : dhcpHdr->clientIP)
        };
        const uint8_t cliMac[ETH_ALEN] = {
            (dhcpHdr->clientHWaddr[0] & 0x000000ff),
            (dhcpHdr->clientHWaddr[0] & 0x0000ff00) >>  8,
            (dhcpHdr->clientHWaddr[0] & 0x00ff0000) >> 16,
            (dhcpHdr->clientHWaddr[0] & 0xff000000) >> 24,
            (dhcpHdr->clientHWaddr[1] & 0x000000ff),
            (dhcpHdr->clientHWaddr[1] & 0x0000ff00) >>  8,
        };
#if DHCP_FM_DEBUG == 1
        char ipstr[INET_ADDRSTRLEN];
        t2_ipv4_to_str(cliIP.IPv4, ipstr, INET_ADDRSTRLEN);
        char macNew[32];
        t2_mac_to_str(cliMac, macNew, sizeof(macNew));
#endif
        uint64_t mac_idx = hashTable_lookup(macMap, (char*)&cliIP);
        if (mac_idx == HASHTABLE_ENTRY_NOT_FOUND) {
            mac_idx = hashTable_insert(macMap, (char*)&cliIP);
            if (UNLIKELY(mac_idx == HASHTABLE_ENTRY_NOT_FOUND)) {
                // If hashMap is full, we stop adding entries...
                static bool warn = true;
                if (warn) {
                    T2_PWRN("dhcpDecode", "%s HashMap full", macMap->name);
                    warn = false;
                }
#if DHCP_FM_DEBUG == 1
            } else {
                T2_PINF("dhcpDecode", "Packet %"PRIu64": Added entry for IP %s: %s", numPackets, ipstr, macNew);
#endif
            }
#if DHCP_FM_DEBUG == 1
        } else {
            const uint64_t mac = macArray[mac_idx];
            if (mac != t2_mac_to_uint64(cliMac)) {
                uint8_t mac8[ETH_ALEN];
                t2_uint64_to_mac(mac, mac8);
                char macOld[32] = {};
                t2_mac_to_str(mac8, macOld, sizeof(macOld));
                T2_PWRN("dhcpDecode", "Packet %"PRIu64": An entry for IP %s already exists: %s (new value: %s)",
                        numPackets, ipstr, macOld, macNew);
            }
#endif // DHCP_FM_DEBUG == 1
        }

        if (LIKELY(mac_idx != HASHTABLE_ENTRY_NOT_FOUND)) {
            const uint64_t mac_u64 = t2_mac_to_uint64(cliMac);
            macArray[mac_idx] = mac_u64;
        }
    } else  if (msgT == DHCP_MSGT_DECLINE || msgT == DHCP_MSGT_RELEASE) {
        const dhcp_ip_t cliIP = {
            .IPv4x[0] = (dhcpHdr->yourIP ? dhcpHdr->yourIP : dhcpHdr->clientIP)
        };
#if DHCP_FM_DEBUG == 1
        char ipstr[INET_ADDRSTRLEN];
        t2_ipv4_to_str(cliIP.IPv4, ipstr, INET_ADDRSTRLEN);
        T2_PINF("dhcpDecode", "Packet %"PRIu64": Removing entry for IP %s", numPackets, ipstr);
#endif
        hashTable_remove(macMap, (char*)&cliIP);
#endif // DHCP_FLAG_MAC == 1
    }

    if (sPktFile) {
        if (msgT) fprintf(sPktFile, "%"PRIu8, msgT);
        fprintf(sPktFile, "\t%"PRIu8"\t0x%08"B2T_PRIX32"\t", dhcpHdr->hopCnt, ntohl(dhcpHdr->transID));
        if (dhcpFlowP->lflow) fprintf(sPktFile, "%"PRIu64, dhcpFlowP->lflow);
        fputc('\t', sPktFile);
    }
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


void onFlowTerminate(unsigned long flowIndex) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->stat, sizeof(dhcpFlowP->stat));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->MType, sizeof(dhcpFlowP->MType));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->hwType, sizeof(dhcpFlowP->hwType));

    uint32_t j = MIN(dhcpFlowP->HWAddCnt, DHCPNMMAX);
    outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t));
    uint_fast32_t i;
    for (i = 0; i < j; i++) {
        outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->clHWAdd[i][0], ETH_ALEN);
#if DHCP_ADD_CNT == 1
        outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->clHWAdd[i][2], sizeof(uint32_t));
#endif
    }

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if DHCPMASKFRMT == 0
    dhcpFlowP->netMsk = ntohl(dhcpFlowP->netMsk);
#endif

    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->netMsk, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->gw, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->dns, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->hopCnt, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, dhcpFlowP->serverName, strlen(dhcpFlowP->serverName)+1);
    outputBuffer_append(main_output_buffer, dhcpFlowP->bootFile, strlen(dhcpFlowP->bootFile)+1);
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->optCntT, sizeof(uint16_t));
#if DHCPBITFLD == 1
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->optT, 3*sizeof(uint64_t));
#else // DHCPBITFLD == 0
    j = MIN(dhcpFlowP->optNum, DHCPMAXOPT);
    outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t));
    for (i = 0; i < j; i++) {
        outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->opt[i], sizeof(uint8_t));
    }
#endif // DHCPBITFLD

    j = MIN(dhcpFlowP->hostNCnt, DHCPNMMAX);
    outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t));
    for (i = 0; i < j; i++) {
        outputBuffer_append(main_output_buffer, dhcpFlowP->hostN[i], strlen(dhcpFlowP->hostN[i])+1);
#if DHCP_ADD_CNT == 1
        outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->hostrep[i], sizeof(uint16_t));
#endif
        free(dhcpFlowP->hostN[i]);
    }

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    j = MIN(dhcpFlowP->domainNCnt, DHCPNMMAX);
    outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t));
    for (i = 0; i < j; i++) {
        outputBuffer_append(main_output_buffer, dhcpFlowP->domainN[i], strlen(dhcpFlowP->domainN[i])+1);
#if DHCP_ADD_CNT == 1
        outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->domainrep[i], sizeof(uint16_t));
#endif
        free(dhcpFlowP->domainN[i]);
    }

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->maxSecEl, sizeof(uint16_t));
    dhcpFlowP->leaseT = ntohl(dhcpFlowP->leaseT);
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->leaseT, sizeof(uint32_t));
    dhcpFlowP->renewT = ntohl(dhcpFlowP->renewT);
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->renewT, sizeof(uint32_t));
    dhcpFlowP->rebindT = ntohl(dhcpFlowP->rebindT);
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->rebindT, sizeof(uint32_t));

    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->reqIP, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->cliIP, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->yourIP, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->nextSrvr, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->relay, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->srvId, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, dhcpFlowP->msg, strlen(dhcpFlowP->msg)+1);
    outputBuffer_append(main_output_buffer, (char*)&dhcpFlowP->lflow, sizeof(uint64_t));

#if DHCP_FLAG_MAC == 1
    const flow_t * const flowP = &flows[flowIndex];
    const dhcp_ip_t ip[2] = { flowP->srcIP, flowP->dstIP };

    for (uint_fast8_t i = 0; i < 2; i++) {
        const uint64_t mac_idx = hashTable_lookup(macMap, (char*)&ip[i]);
        if (mac_idx != HASHTABLE_ENTRY_NOT_FOUND) {
            const uint64_t mac = macArray[mac_idx];
            uint8_t mac_u8[ETH_ALEN];
            t2_uint64_to_mac(mac, mac_u8);
            OUTBUF_APPEND(main_output_buffer, mac_u8, ETH_ALEN);
        } else {
            const uint8_t zero[ETH_ALEN] = {};
            OUTBUF_APPEND(main_output_buffer, zero, ETH_ALEN);
        }
    }
#endif // DHCP_FLAG_MAC == 1

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
}


void pluginReport(FILE *stream) {
    uint_fast8_t i;
    char hrnum[64];

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    if (numDHCPPkts4 > 0) {
        T2_FPLOG_NUMP0(stream, "dhcpDecode", "Number of DHCP packets", numDHCPPkts4, numPackets);
        T2_FPLOG_NUMP(stream, "dhcpDecode", "Number of DHCP queries", numDHCPQR[0], numDHCPPkts4);
        T2_FPLOG_NUMP(stream, "dhcpDecode", "Number of DHCP replies", numDHCPQR[1], numDHCPPkts4);
        for (i = 0; i < DHCP_NUM_MSGT; i++) {
            if (numDHCPmsgT[i] > 0) {
                T2_CONV_NUM(numDHCPmsgT[i], hrnum);
                T2_FPLOG(stream, "dhcpDecode", "Number of DHCP %s messages: %"PRIu64"%s [%.2f%%]",
                        dhcpMsgTToStr[i], numDHCPmsgT[i], hrnum, 100.0*numDHCPmsgT[i]/(double)numDHCPPkts4);
            }
        }
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    if (numDHCPPkts6 > 0) {
        T2_FPLOG_NUMP0(stream, "dhcpDecode", "Number of DHCPv6 packets", numDHCPPkts6, numPackets);
        for (i = 0; i < DHCP_NUM_MSGT6; i++) {
            if (numDHCPmsgT6[i] > 0) {
                T2_CONV_NUM(numDHCPmsgT6[i], hrnum);
                T2_FPLOG(stream, "dhcpDecode", "Number of DHCPv6 %s messages: %"PRIu64"%s [%.2f%%]",
                        dhcpMsgT6ToStr[i], numDHCPmsgT6[i], hrnum, 100.0*numDHCPmsgT6[i]/(double)numDHCPPkts6);
            }
        }
    }
#endif // IPV6_ACTIVATE > 0
}


void onApplicationTerminate() {
#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    hashTable_destroy(macMap);
    free(macArray);
#endif
    free(dhcpFlow);
}


#if IPV6_ACTIVATE > 0
static void dhcp6decode(packet_t *packet, unsigned long flowIndex) {
    const uint32_t remaining = packet->snapL7Length;
    if (remaining < 1) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const uint8_t * const ptr = packet->layer7Header;
    // TODO check return value of t2buf_* functions
    t2buf_t t2buf = t2buf_create(ptr, remaining);

    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    /* Message Type */
    uint8_t msgT;
    t2buf_read_u8(&t2buf, &msgT);

    if (msgT > 0 && msgT <= DHCP_NUM_MSGT) {
        dhcpFlowP->MType |= 1 << msgT;
        numDHCPmsgT6[msgT-1]++;
    }

    /* Transaction ID */
    uint32_t transID;
    t2buf_read_u24(&t2buf, &transID);

    /* Options */
    while (t2buf_left(&t2buf) > 4) {
        /* Option */
        uint16_t opt;
        t2buf_read_u16(&t2buf, &opt);

        /* Option Length */
        uint16_t optlen;
        t2buf_read_u16(&t2buf, &optlen);

        /* Option Value */
        switch (opt) {
            //case 8: { // Elapsed Time
            //    uint16_t ms;
            //    t2buf_read_u16(&t2buf, &ms);
            //    dhcpFlowP->maxSecEl = ms / 1000.0;
            //    break;
            //}
            case 13: // Status Code
                /* Status Code */
                t2buf_skip_u16(&t2buf);
                /* Status Message */
                uint8_t msg[255];
                if (optlen < 2) {
                    DHCP_SPKTMD_PRI_NONE();
                    dhcpFlowP->stat |= DHCPINVALIDLEN;
                    return;
                }
                t2buf_readnstr(&t2buf, msg, 255, optlen-2, T2BUF_UTF8, true);
                //T2_PERR("dhcpDecode", "DHCP Status Message: %s", msg);
                break;
            //case 16: // Vendor Class
            //    /* Enterprise ID */
            //    t2buf_skip_u32(&t2buf);
            //    /* Vendor-class-data */
            //    if (optlen < 4) {
            //        dhcpFlowP->stat |= DHCPINVALIDLEN;
            //        return;
            //    }
            //    t2buf_skip_n(&t2buf, optlen-4);
            //    break;
            case 1: { // ClientID
            //case 2: { // ServerID
                /* DUID type */
                uint16_t duid_type;
                t2buf_read_u16(&t2buf, &duid_type);
                if (duid_type != 1 && duid_type != 3) { // link-layer address (plus time)
                    // 2: Vendor-assigned unique ID based on Enterprise Number
                    t2buf_skip_n(&t2buf, optlen-2);
                    break;
                }
                /* Hardware type */
                uint16_t hw_type;
                t2buf_read_u16(&t2buf, &hw_type);
                dhcpFlowP->hwType |= 1UL << MIN(hw_type, 63);
                if (duid_type == 1) { // link-layer address plus time
                    /* DUID time */
                    t2buf_skip_u32(&t2buf);
                }
                if (hw_type != 1) {
                    // Not a MAC address
                    if (duid_type == 1) {
                        t2buf_skip_n(&t2buf, optlen-8);
                    } else {
                        t2buf_skip_n(&t2buf, optlen-4);
                    }
                    dhcpFlowP->stat |= DHCPNONETHHW;
                    break;
                }
                /* Link-layer address */
                uint8_t mac[ETH_ALEN];
                for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
                    t2buf_read_u8(&t2buf, &mac[i]);
                }
                // Client MAC address
                if (dhcpFlowP->HWAddCnt >= DHCPNMMAX) {
                    dhcpFlowP->stat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t i;
                    const uint32_t cliMac[2] = {
                        ((mac[3] << 24) | (mac[2] << 16) | (mac[1] << 8) | mac[0]),
                        ((mac[5] << 8) | mac[4]),
                    };
                    for (i = 0; i < dhcpFlowP->HWAddCnt; i++) {
                        // MAC address already seen
                        if (dhcpFlowP->clHWAdd[i][0] == cliMac[0] &&
                            dhcpFlowP->clHWAdd[i][1] == cliMac[1])
                        {
                            break;
                        }
                    }

                    // MAC address was never seen
                    if (i == dhcpFlowP->HWAddCnt) {
                        dhcpFlowP->clHWAdd[i][0] = cliMac[0];
                        dhcpFlowP->clHWAdd[i][1] = cliMac[1];
                        dhcpFlowP->HWAddCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->clHWAdd[i][2]++;
#endif
                }
                break;
            }
            //case 6: // Option request
            //    while (optlen > 1 && t2buf_left(&t2buf) > 0) {
            //        /* Requested option code */
            //        t2buf_skip_u16(&t2buf);
            //        optlen -= 2;
            //    }
            //    break;
            //case 3: // Identity Association for Non-temporary Address
            //    /* IAID */
            //    t2buf_skip_u32(&t2buf);
            //    /* T1 */
            //    t2buf_skip_u32(&t2buf);
            //    /* T2 */
            //    t2buf_skip_u32(&t2buf);
            //    break;
            //case 25: // Identity Association for Prefix Delegation
            //    /* IAID */
            //    t2buf_skip_u32(&t2buf);
            //    /* T1 */
            //    t2buf_skip_u32(&t2buf);
            //    /* T2 */
            //    t2buf_skip_u32(&t2buf);
            //    /* IA Prefix */
            //    /* Preferred lifetime */
            //    t2buf_skip_u32(&t2buf);
            //    /* Valid lifetime */
            //    t2buf_skip_u32(&t2buf);
            //    /* Prefix length */
            //    t2buf_skip_u8(&t2buf);
            //    /* Prefix */
            //    t2buf_skip_n(&t2buf, 16);
            //    break;
            case 39: // Fully Qualified Domain Name
                /* Flags */
                t2buf_skip_u8(&t2buf);
                /* Reserved */
                if (optlen < 2) {
                    dhcpFlowP->stat |= DHCPINVALIDLEN;
                    DHCP_SPKTMD_PRI_NONE();
                    return;
                }
                uint8_t fqdn[255];
                uint_fast32_t pos = 0;
                uint8_t len;
                t2buf_read_u8(&t2buf, &len);
                while (len > 0 && t2buf_left(&t2buf) > len+1) {
                    t2buf_readnstr(&t2buf, &fqdn[pos], sizeof(fqdn), len, T2BUF_UTF8, true);
                    pos += len;
                    t2buf_read_u8(&t2buf, &len);
                    if (len > 0) fqdn[pos++] = '.';
                }
                //T2_PDBG("dhcpDecode", "DHCP FQDN: %s", fqdn);
                if (dhcpFlowP->domainNCnt >= DHCPNMMAX) {
                    dhcpFlowP->stat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->domainNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->domainN[j]);
                        // domain name is sometimes null terminated...
                        if ((k == pos || k+1 == pos) && memcmp(dhcpFlowP->domainN[j], fqdn, pos) == 0) break;
                    }
                    if (j == dhcpFlowP->domainNCnt) {
                        char *domainP = malloc(pos+1);
                        memcpy(domainP, fqdn, pos);
                        domainP[pos] = '\0';
                        dhcpFlowP->domainN[dhcpFlowP->domainNCnt] = domainP;
                        dhcpFlowP->domainNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->domainrep[j]++;
#endif
                }
                break;
            default:
                t2buf_skip_n(&t2buf, optlen);
                break;
        }
    }

    // TODO link flows
    if (sPktFile) fprintf(sPktFile, "%"PRIu8"\t\t0x%08"B2T_PRIX32"\t\t", msgT, transID);
}
#endif // IPV6_ACTIVATE > 0
