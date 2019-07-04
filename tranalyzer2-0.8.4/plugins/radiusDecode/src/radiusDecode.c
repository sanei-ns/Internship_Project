/*
 * radiusDecode.c
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

#include "radiusDecode.h"


// Global variables

radius_flow_t *radius_flows;


// Static variables

static uint64_t num_radius, num_radius0;
static uint64_t num_axs, num_axs0;
static uint64_t num_axs_acc, num_axs_acc0;
static uint64_t num_axs_rej, num_axs_rej0;
static uint64_t num_acc, num_acc0;


// Tranalyzer functions

T2_PLUGIN_INIT("radiusDecode", "0.8.4", 0, 8);


void initialize() {
    // allocate struct for all flows and initialise to 0
    if (UNLIKELY(!(radius_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*radius_flows))))) {
        T2_PERR("radiusDecode", "failed to allocate memory for radius_flows");
        exit(-1);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("RADIUS status", "radiusStat", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Access-Request/Accept/Reject/Challenge", "radiusAxsReq_Acc_Rej_Chal", 0, 4, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting-Request/Response", "radiusAccReq_Resp", 0, 2, bt_uint_16, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Start/Stop", "radiusAccStart_Stop", 0, 2, bt_uint_16, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS username", "radiusUser", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS service type", "radiusServiceTyp", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS login-service", "radiusLoginService", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS vendor ID (SMI)", "radiusVendor", 0, 1, bt_uint_32));
#if RADIUS_NAS == 1
    bv = bv_append_bv(bv, bv_new_bv("RADIUS NAS Identifier", "radiusNasId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS NAS IP address", "radiusNasIp", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS NAS IP port", "radiusNasPort", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS NAS port type", "radiusNasPortTyp", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS NAS port Id", "radiusNasPortId", 0, 1, bt_string));
#endif // RADIUS_NAS == 1
#if RADIUS_FRAMED == 1
    bv = bv_append_bv(bv, bv_new_bv("RADIUS framed IP address", "radiusFramedIp", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS framed IP netmask", "radiusFramedMask", 0, 1, bt_ip4_addr));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS framed protocol", "radiusFramedProto", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS framed compression", "radiusFramedComp", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS framed MTU", "radiusFramedMtu", 0, 1, bt_uint_32));
#endif // RADIUS_FRAMED == 1
#if RADIUS_TUNNEL == 1
    // TODO tag_tunnelType_tunnelMedium tag_tunnelCli tag_tunnelSrv
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel type and medium type", "radiusTunnel_Medium", 0, 2, bt_uint_32, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel client endpoint", "radiusTunnelCli", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel server endpoint", "radiusTunnelSrv", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel client authentication Id", "radiusTunnelCliAId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel server authentication Id", "radiusTunnelSrvAId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS tunnel preference", "radiusTunnelPref", 0, 1, bt_uint_32));
#endif // RADIUS_TUNNEL == 1
#if RADIUS_ACCT == 1
    //bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Event Timestamp", "radiusAcctEvtTs", 0, 1, bt_timestamp));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Session Id", "radiusAcctSessId", 0, 1, bt_string));
    //repeating?
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Session Time (seconds)", "radiusAcctSessTime", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Status Type", "radiusAcctStatTyp", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Terminate Cause", "radiusAcctTerm", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Input/Output Octets", "radiusAccInOct_OutOct", 0, 2, bt_uint_32, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Input/Output Packets", "radiusAccInPkt_OutPkt", 0, 2, bt_uint_32, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Accounting Input/Output Gigawords", "radiusAccInGw_OutGw", 0, 2, bt_uint_32, bt_uint_32));
#endif // RADIUS_ACCT == 1
    bv = bv_append_bv(bv, bv_new_bv("RADIUS user connection info", "radiusConnInfo", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS filter Identifier", "radiusFilterId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Called Station Identifier", "radiusCalledId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS Calling Station Identifier", "radiusCallingId", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("RADIUS reply message", "radiusReplyMsg", 0, 1, bt_string));
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    radius_flow_t * const radiusFlowP = &radius_flows[flowIndex];
    memset(radiusFlowP, '\0', sizeof(*radiusFlowP)); // set everything to 0

    if (flowP->layer4Protocol == L3_UDP) {
        const uint_fast16_t src_port = flowP->srcPort;
        const uint_fast16_t dst_port = flowP->dstPort;
        if ((src_port == RADIUS_AUTH_PORT     && dst_port > 1024) ||
            (dst_port == RADIUS_AUTH_PORT     && src_port > 1024) ||
            (src_port == RADIUS_ACC_PORT      && dst_port > 1024) ||
            (dst_port == RADIUS_ACC_PORT      && src_port > 1024) ||
            (src_port == RADIUS_AUTH_OLD_PORT && dst_port > 1024) ||
            (dst_port == RADIUS_AUTH_OLD_PORT && src_port > 1024) ||
            (src_port == RADIUS_ACC_OLD_PORT  && dst_port > 1024) ||
            (dst_port == RADIUS_ACC_OLD_PORT  && src_port > 1024))
        {
            radiusFlowP->stat |= RADIUS_STAT_RADIUS;
        }
    }
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {

    radius_flow_t * const radiusFlowP = &radius_flows[flowIndex];
    if (radiusFlowP->stat == 0x00) return; // not a RADIUS packet

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    num_radius++;

    uint16_t snaplen = packet->snapL7Length;
    if (snaplen < sizeof(radius_t)) return;

    uint8_t *pktptr = (uint8_t*)packet->layer7Header;
    const radius_t * const radius = (radius_t*)pktptr;
    pktptr += sizeof(radius_t);
    snaplen -= sizeof(radius_t);

    uint16_t len = ntohs(radius->len);
    if (UNLIKELY(len < RADIUS_LEN_MIN || len > RADIUS_LEN_MAX)) {
        radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
    }

    const unsigned long revFlowIndex = flows[flowIndex].oppositeFlowIndex;

    switch (radius->code) {
        case RADIUS_C_AXS_REQ:
            num_axs++;
            radiusFlowP->num_axs[0]++;
            radiusFlowP->stat |= RADIUS_STAT_AXS;
            break;
        case RADIUS_C_AXS_ACC:
            num_axs++;
            num_axs_acc++;
            radiusFlowP->num_axs[1]++;
            radiusFlowP->stat |= (RADIUS_STAT_CONN_SUCC | RADIUS_STAT_AXS);
            if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                radius_flow_t * const revFlowP = &radius_flows[revFlowIndex];
                revFlowP->stat |= RADIUS_STAT_CONN_SUCC;
            }
            break;
        case RADIUS_C_AXS_REJ:
            num_axs++;
            num_axs_rej++;
            radiusFlowP->num_axs[2]++;
            radiusFlowP->stat |= (RADIUS_STAT_CONN_FAIL | RADIUS_STAT_AXS);
            if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                radius_flow_t * const revFlowP = &radius_flows[revFlowIndex];
                revFlowP->stat |= RADIUS_STAT_CONN_FAIL;
            }
            break;
        case RADIUS_C_AXS_CHAL:
            num_axs++;
            radiusFlowP->num_axs[3]++;
            radiusFlowP->stat |= RADIUS_STAT_AXS;
            break;
        case RADIUS_C_ACC_REQ:
            num_acc++;
            radiusFlowP->num_acc[0]++;
            radiusFlowP->stat |= RADIUS_STAT_ACC;
            break;
        case RADIUS_C_ACC_RESP:
            num_acc++;
            radiusFlowP->num_acc[1]++;
            radiusFlowP->stat |= RADIUS_STAT_ACC;
            break;
        default:
            break;
    }

    const uint16_t STRMAX = 1024;
    char str[STRMAX+1];
    str[STRMAX] = '\0';
    uint8_t *avppptr;
    uint16_t len2;
    uint32_t u32;
    radius_avp_t *avp;
    while (snaplen > sizeof(radius_avp_t)) {
        avp = (radius_avp_t*)(pktptr);
        len = avp->len;
        avppptr = pktptr + sizeof(radius_avp_t);
        if (UNLIKELY(len < sizeof(radius_avp_t))) {
            radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
            break;
        }
        if (snaplen < len) break;
        switch (avp->type) {
            case 1:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->user, (char*)avppptr, len2);
                //printf("User-Name(1): %s\n", radiusFlowP->user);
                break;
            case 2:
                if (UNLIKELY(len < 18 || len > 130)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("User-Password(2): %s\n", str);
                break;
            case 3:
                if (UNLIKELY(len != 19)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                //RADIUS_DBG("CHAP-Password(3): %s\n", str);
                break;
            case 4:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->nasip = *(uint32_t*)avppptr;
                //RADIUS_DBG("NAS-IP-Address(4): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 5:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->nasport = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("NAS-IP-Port(5): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 6:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->serviceType = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Service-Type(6): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 7:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->fproto = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Framed-Protocol(7): %d\n", radiusFlowP->fproto);
                break;
            case 8:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->fip = *(uint32_t*)avppptr;
                //RADIUS_DBG("Framed-IP-Address(8): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 9:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->fmask = *(uint32_t*)avppptr;
                //RADIUS_DBG("Framed-IP-Netmask(9): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 10:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Framed-Routing(10): %d\n", ntohl(*(uint32_t*)avppptr));
                // 0 None
                // 1 Send routing packets
                // 2 Listen for routing packets
                // 3 Send and Listen
                break;
            case 11:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->filter, (char*)avppptr, len2);
                //RADIUS_DBG("Filter-Id(11): %s\n", radiusFlowP->filter);
                break;
            case 12:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 64-65535
                radiusFlowP->fmtu = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Framed-MTU(12): %d\n", radiusFlowP->fmtu);
                break;
            case 13:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->fcomp = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Framed-Compression(13): %d\n", radiusFlowP->fcomp);
                break;
            case 14:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Login-IP-Host(14): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 15:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->logSer = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Login-Service(15): %d\n",  radiusFlowP->logSer);
                break;
            case 16:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // MAX 65535
                RADIUS_DBG("Login-TCP-Port(16): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 18:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->replymsg, (char*)avppptr, len2);
                //RADIUS_DBG("Reply-Message(18): %s\n", radiusFlowP->replymsg);
                break;
            case 19:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Callback-Number(19): %s\n", str);
                break;
            case 20:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Callback-Id(20): %s\n", str);
                break;
            case 22:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Framed-Route(22): %s\n", str);
                break;
            case 23:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Framed-IPX-Network(22): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 24:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("State(24): %s\n", str);
                break;
            case 25:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                // not always human readable
                //RADIUS_DBG("Class(25): %s\n", str);
                break;
            case 26:
                if (UNLIKELY(len < 7)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // vendor id (SMI)
                radiusFlowP->vendor = ntohl(*(uint32_t*)avppptr);
                // https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
                avppptr += sizeof(uint32_t);
                // string (vendor type, length, attribute)
                len2 = MIN(len - sizeof(radius_avp_t) - sizeof(uint32_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                //RADIUS_DBG("Vendor-Specific(26): %d %s\n", radiusFlowP->vendor, str);
                break;
            case 27:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Session-Timeout(27): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 28:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Idle-Timeout(28): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 29:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Termination-Action(29): %d\n",  ntohl(*(uint32_t*)avppptr));
                // 0 Default
                // 1 RADIUS-Request
                break;
            case 30:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->calledid, (char*)avppptr, len2);
                //RADIUS_DBG("Called-Station-Id(30): %s\n", radiusFlowP->calledid);
                break;
            case 31:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->callingid, (char*)avppptr, len2);
                //RADIUS_DBG("Calling-Station-Id(31): %s\n", radiusFlowP->callingid);
                break;
            case 32:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->nasid, (char*)avppptr, len2);
                //RADIUS_DBG("NAS-Identifier(32): %s\n", radiusFlowP->nasid);
                break;
            case 33:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Proxy-State(33): %s\n", str);
                break;
            case 34:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Login-LAT-Service(34): %s\n", str);
                break;
            case 35:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Login-LAT-Node(35): %s\n", str);
                break;
            case 36:
                if (UNLIKELY(len != 34)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Login-LAT-Group(36): %s\n", str);
                break;
            case 37:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 0:65535
                RADIUS_DBG("Framed-AppleTalk-Link(37): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 38:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 0:65535
                RADIUS_DBG("Framed-AppleTalk-Network(38): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 39:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Framed-AppleTalk-Zone(39): %s\n", str);
                break;
            case 40:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                u32 = ntohl(*(uint32_t*)avppptr);
                radiusFlowP->acctStatTyp = u32;
                //RADIUS_DBG("Acct-Status-Type(40): %d\n", u32);
                switch (u32) {
                    case 1: // start
                        radiusFlowP->num_acc_start++;
                        break;
                    case 2: // stop
                        radiusFlowP->num_acc_stop++;
                        break;
                    default:
                        break;
                }
                //  1 Start
                //  2 Stop
                //  3 Interim-Update
                //  7 Accounting-On
                //  8 Accounting-Off
                //  9 Tunnel-Start
                // 10 Tunnel-Stop
                // 11 Tunnel-Reject
                // 12 Tunnel-Link-Start
                // 13 Tunnel-Link-Stop
                // 14 Tunnel-Link-Reject
                // 15 Failed
                break;
            case 41:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Delay-Time(41): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 42:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->in_oct = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Input-Octets(42): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 43:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->out_oct = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Output-Octets(43): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 44:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->acctSessId, (char*)avppptr, len2);
                //RADIUS_DBG("Acct-Session-Id(44): %s\n", radiusFlowP->acctSessId);
                break;
            case 45:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Authentic(45): %d\n", ntohl(*(uint32_t*)avppptr));
                // 1 RADIUS
                // 2 Local
                // 3 Remote
                // 4 Diameter
                break;
            case 46:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //TODO: repeating?
                radiusFlowP->sessTime = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Session-Time(46): %d\n", radiusFlowP->sessTime);
                break;
            case 47:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->in_pkt = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Input-Packets(47): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 48:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->out_pkt = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Output-Packets(48): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 49:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->acctTerm = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Terminate-Cause(49): %d\n", radiusFlowP->acctTerm);
                break;
            case 50:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Acct-Multi-Session-Id(50): %s\n", str);
                break;
            case 51:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Link-Count(51): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 52:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->in_gw = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Input-Gigawords(52): %d\n", radiusFlowP->in_gw);
                break;
            case 53:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->out_gw = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Acct-Output-Gigawords(53): %d\n", radiusFlowP->out_gw);
                break;
            case 55:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //radiusFlowP->acct_evt_ts = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Event-Timestamp(55): %d\n", radiusFlowP->acct_evt_ts);
                break;
            case 60:
                if (UNLIKELY(len < 7)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("CHAP-Challenge(60): %s\n", str);
                break;
            case 61:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->nasporttyp = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("NAS-Port-Type(61): %d\n", radiusFlowP->nasporttyp);
                //  0 Async
                //  1 Sync
                //  2 ISDN Sync
                //  3 ISDN Async V.120
                //  4 ISDN Async V.110
                //  5 Virtual
                //  6 PIAFS
                //  7 HDLC Clear Channel
                //  8 X.25
                //  9 X.75
                // 10 G.3 Fax
                // 11 SDSL - Symmetric DSL
                // 12 ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation
                // 13 ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone
                // 14 IDSL - ISDN Digital Subscriber Line
                // 15 Ethernet
                // 16 xDSL - Digital Subscriber Line of unknown type
                // 17 Cable
                // 18 Wireless - Other
                // 19 Wireless - IEEE 802.11
                break;
            case 62:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Port-Limit(62): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 63:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Login-LAT-Port(63): %s\n", str);
                break;
            case 64:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->tunnel = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                //radiusFlowP->tunnel[u32] = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //RADIUS_DBG("Tunnel-Type(64): %d\n", radiusFlowP->tunnel);
                break;
            case 65:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->tunnel_med = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                //radiusFlowP->tunnel_med[u32] = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //RADIUS_DBG("Tunnel-Medium-Type(65): %d\n", radiusFlowP->tunnel_med);
                break;
            case 66:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(radiusFlowP->tunnelCli, (char*)avppptr, len2);
                //RADIUS_DBG("Tunnel-Client-Endpoint(66): %s\n", radiusFlowP->tunnelCli);
                break;
            case 67:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(radiusFlowP->tunnelSrv, (char*)avppptr, len2);
                //RADIUS_DBG("Tunnel-Server-Endpoint(66): %s\n", radiusFlowP->tunnelSrv);
                break;
            case 68:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                // not always human readable, implementation dependent
                //RADIUS_DBG("Acct-Tunnel-Connection(68): %s\n", str);
                break;
            case 69:
                if (UNLIKELY(len < 5)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                avppptr += sizeof(uint8_t); // skip tag
                avppptr += sizeof(uint16_t); // skip salt
                len2 = MIN(len - sizeof(radius_avp_t) - sizeof(uint8_t) - sizeof(uint16_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                //RADIUS_DBG("Tunnel-Password(69): %s\n", str);
                break;
            case 77:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->connInfo, (char*)avppptr, len2);
                //RADIUS_DBG("Connect-Info(77): %s\n", radiusFlowP->connInfo);
                break;
            case 79:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("EAP-Message(79): %s\n", str);
                break;
            case 80:
                if (UNLIKELY(len != 18)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Message-Authenticator(80): %s\n", str);
                break;
            case 81:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                RADIUS_DBG("Tunnel-Private-Group-ID(81): %s\n", str);
                break;
            case 82:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(str, (char*)avppptr, len2);
                str[len2] = '\0';
                // not always human readable
                //RADIUS_DBG("Tunnel-Assignment-ID(82): %s\n", str);
                break;
            case 83:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                radiusFlowP->tunnelPref = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //RADIUS_DBG("Tunnel-Preference(83): %d -> %d\n", u32, radiusFlowP->tunnelPref);
                break;
            case 85:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Interim-Interval(85): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 86:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Tunnel-Packets-Lost(86): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 87:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), STRMAX);
                strncpy(radiusFlowP->nasportid, (char*)avppptr, len2);
                //RADIUS_DBG("NAS-Port-Id(87): %s\n", radiusFlowP->nasportid);
                break;
            case 90:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(radiusFlowP->tunnelCliAId, (char*)avppptr, len2);
                //RADIUS_DBG("Tunnel-Client-Auth-ID(90): %s\n", radiusFlowP->tunnelCliAId);
                break;
            case 91:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len2, STRMAX);
                strncpy(radiusFlowP->tunnelSrvAId, (char*)avppptr, len2);
                //RADIUS_DBG("Tunnel-Server-Auth-ID(91): %s\n", radiusFlowP->tunnelSrvAId);
                break;
            default:
                T2_PDBG("radiusDecode", "Unhandled attribute type %d\n", avp->type);
                RADIUS_DBG("Unhandled attribute type %d\n", avp->type);
                break;
        }
        pktptr += len;
        if (snaplen > len) snaplen -= len;
        else snaplen = 0; // TODO set bit
    }

#if FORCE_MODE == 1
    if (packet->layer4Type == L3_UDP && (radiusFlowP->num_axs[1] || radiusFlowP->num_axs[2])) {
        flow_t * const flowP = &flows[flowIndex];
        T2_RM_FLOW(flowP);
    }
#endif
}


void onFlowTerminate(unsigned long flowIndex) {
    radius_flow_t *radiusFlowP = &radius_flows[flowIndex];

#if BLOCK_BUF == 0
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->stat, sizeof(uint8_t));
    uint8_t i;
    for (i = 0; i < 4; i++) {
        outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->num_axs[i], sizeof(uint16_t));
    }
    for (i = 0; i < 2; i++) {
        outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->num_acc[i], sizeof(uint16_t));
    }
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->num_acc_start, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->num_acc_stop, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, radiusFlowP->user, strlen(radiusFlowP->user)+1);
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->serviceType, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->logSer, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->vendor, sizeof(uint32_t));
#if RADIUS_NAS == 1
    outputBuffer_append(main_output_buffer, radiusFlowP->nasid, strlen(radiusFlowP->nasid)+1);
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->nasip, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->nasport, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->nasporttyp, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, radiusFlowP->nasportid, strlen(radiusFlowP->nasportid)+1);
#endif // RADIUS_NAS == 1
#if RADIUS_FRAMED == 1
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->fip, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->fmask, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->fproto, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->fcomp, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->fmtu, sizeof(uint32_t));
#endif // RADIUS_FRAMED == 1
#if RADIUS_TUNNEL == 1
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->tunnel, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->tunnel_med, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, radiusFlowP->tunnelCli, strlen(radiusFlowP->tunnelCli)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->tunnelSrv, strlen(radiusFlowP->tunnelSrv)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->tunnelCliAId, strlen(radiusFlowP->tunnelCliAId)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->tunnelSrvAId, strlen(radiusFlowP->tunnelSrvAId)+1);
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->tunnelPref, sizeof(uint32_t));
#endif // RADIUS_TUNNEL == 1
#if RADIUS_ACCT == 1
    //time_t ts = radiusFlowP->acct_evt_ts;
    //outputBuffer_append(main_output_buffer, (char*) &ts, sizeof(time_t));
    outputBuffer_append(main_output_buffer, radiusFlowP->acctSessId, strlen(radiusFlowP->acctSessId)+1);
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->sessTime, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->acctStatTyp, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->acctTerm, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->in_oct, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->out_oct, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->in_pkt, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->out_pkt, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->in_gw, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*) &radiusFlowP->out_gw, sizeof(uint32_t));
#endif // RADIUS_ACCT == 1
    outputBuffer_append(main_output_buffer, radiusFlowP->connInfo, strlen(radiusFlowP->connInfo)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->filter, strlen(radiusFlowP->filter)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->calledid, strlen(radiusFlowP->calledid)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->callingid, strlen(radiusFlowP->callingid)+1);
    outputBuffer_append(main_output_buffer, radiusFlowP->replymsg, strlen(radiusFlowP->replymsg)+1);
#endif // BLOCK_BUF == 0
}


static void radius_pluginReport(FILE *stream) {
    if (num_radius > 0) {
        T2_FPLOG_DIFFNUMP0(stream, "radiusDecode", "Number of RADIUS packets", num_radius, numPackets);
        T2_FPLOG_DIFFNUMP(stream, "radiusDecode", "Number of RADIUS Access packets", num_axs, num_radius);
        T2_FPLOG_DIFFNUMP(stream, "radiusDecode", "Number of RADIUS Access-Accept packets", num_axs_acc, num_radius);
        T2_FPLOG_DIFFNUMP(stream, "radiusDecode", "Number of RADIUS Access-Reject packets", num_axs_rej, num_radius);
        T2_FPLOG_DIFFNUMP(stream, "radiusDecode", "Number of RADIUS Accounting packets", num_acc, num_radius);
    }
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_radius0 = 0;
    num_axs0 = 0;
    num_axs_acc0 = 0;
    num_axs_rej0 = 0;
    num_acc0 = 0;
#endif // DIFF_REPORT == 1
    radius_pluginReport(stream);
}


void monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("radiusPkts\tradiusAxsPkts\tradiusAxsAccPkts\tradiusAxsRejPkts\tradiusAccPkts\t", stream); // Note the trailing tab (\t)
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream, "%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t", // Note the trailing tab (\t)
                num_radius - num_radius0, num_axs - num_axs0, num_axs_acc - num_axs_acc0,
                num_axs_rej - num_axs_rej0, num_acc - num_acc0);
            break;

        case T2_MON_PRI_REPORT:
            radius_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }

#if DIFF_REPORT == 1
    num_radius0 = num_radius;
    num_axs0 = num_axs;
    num_axs_acc0 = num_axs_acc;
    num_axs_rej0 = num_axs_rej;
    num_acc0 = num_acc;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
    free(radius_flows);
}
