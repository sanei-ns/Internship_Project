/*
 * stunDecode.c
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

#include "stunDecode.h"


#define NAT_OB_APPEND_OPT_STR(s) OUTBUF_APPEND_OPTSTR(main_output_buffer, s)

#define NAT_OB_APPEND_OPT_ADDR_PORT(a, p) \
    if (!a) { \
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); \
    } else { \
        OUTBUF_APPEND_NUMREP(main_output_buffer, ONE); \
        OUTBUF_APPEND_U32(main_output_buffer, a); \
        (p) = ntohs(p), \
        OUTBUF_APPEND_U16(main_output_buffer, p); \
    }

// Store mapped address and port into provided 'a' and 'p'
#define NAT_MA_DECODE(a, p) \
    mapped_addr = (stun_mapped_addr_t*)(STUN_ATTR_DATA(rp)); \
    (p) = mapped_addr->port; \
    if (mapped_addr->family == STUN_MA_FAMILY_IP4) { \
        (a) = mapped_addr->addr4; \
    } else if (mapped_addr->family == STUN_MA_FAMILY_IP6) { \
        /* TODO IPv6 */ \
    }
// Store decoded mapped address and port into provided 'a' and 'p'
#define NAT_XMA_DECODE(a, p) \
    mapped_addr = (stun_mapped_addr_t*)(STUN_ATTR_DATA(rp)); \
    (p) = STUN_XMA_PORT(mapped_addr->port); \
    if (mapped_addr->family == STUN_MA_FAMILY_IP4) { \
        (a) = STUN_XMA_ADDR4(mapped_addr->addr4); \
    } else if (mapped_addr->family == STUN_MA_FAMILY_IP6) { \
        /* TODO IPv6 */ \
    }


// Global variables

nat_flow_t *nat_flows;


// Static variables

static uint64_t num_stun;
static uint64_t num_natpmp;


// Tranalyzer functions

T2_PLUGIN_INIT("stunDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(nat_flows = calloc(mainHashMap->hashChainTableSize, sizeof(nat_flow_t))))) {
        T2_PERR("stunDecode", "failed to allocate memory for nat_flows");
        exit(-1);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H32(bv, "natStat", "NAT status");
    BV_APPEND_H32(bv, "natErr" , "NAT error code");
    BV_APPEND(bv, "natMCReq_Ind_Succ_Err", "NAT message class (REQ, INDIC, SUCC RESP, ERR RESP) (STUN)",
            STUN_MT_CLASS_N, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_R(bv, "natAddr_Port"     , "NAT mapped address and port (STUN)"          , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natXAddr_Port"    , "NAT xor mapped address and port (STUN)"      , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natPeerAddr_Port" , "NAT xor peer address and port (TURN)"        , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natOrigAddr_Port" , "NAT response origin address and port (STUN)" , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natRelayAddr_Port", "NAT relayed address and port (TURN)"         , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natDstAddr_Port"  , "NAT destination address and port (TURN)"     , 2, bt_ip4_addr, bt_uint_16);
    //BV_APPEND_R(bv, "natAltAddrPort"   , "NAT alternate server address and port (STUN)", 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natOtherAddr_Port" , "NAT other address and port (STUN)"           , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_U32(bv, "natLifetime"    , "NAT binding lifetime [seconds] (STUN)");
    //BV_APPEND(bv, "natBWSenmin_SenMax_RcvMin_RcvMax", "NAT bandwidth reservation amount (min/max send, min/max received) (MS-TURN)",
    //      TURN_BW_N, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32));
    BV_APPEND_STR_R(bv, "natUser"    , "NAT username (STUN)");
    BV_APPEND_STR_R(bv, "natPass"    , "NAT password (STUN)");
    BV_APPEND_STR_R(bv, "natRealm"   , "NAT realm (STUN)");
    BV_APPEND_STR_R(bv, "natSoftware", "NAT software (STUN)");
#if NAT_PMP == 1
    BV_APPEND(bv, "natPMPReqEA_MU_MT" , "NAT-PMP number of requests (External Address, Map UDP, Map TCP)" , 3, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND(bv, "natPMPRespEA_MU_MT", "NAT-PMP number of responses (External Address, Map UDP, Map TCP)", 3, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_U32(bv, "natPMPSSSOE", "NAT-PMP seconds since start of epoch");
#endif // NAT_PMP == 1
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    nat_flow_t * const nat_flow = &nat_flows[flowIndex];
    memset(nat_flow, '\0', sizeof(nat_flow_t));
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    const uint_fast8_t proto = packet->layer4Type;
    if (proto != L3_UDP && proto != L3_TCP) return;

    const flow_t * const flow = &flows[flowIndex];
    nat_flow_t * const nat_flow = &nat_flows[flowIndex];

    uint16_t snaplen = packet->snapL7Length;
    uint8_t *rp = (uint8_t*)packet->layer7Header;

    // NAT PMP
    if (proto == L3_UDP && (flow->srcPort == NATPMP_PORT || flow->dstPort == NATPMP_PORT)) {
        const nat_pmp_t * const pmp_hdr = (nat_pmp_t*)rp;
        num_natpmp++;
        if (snaplen < sizeof(nat_pmp_t)) return;
        const uint8_t op = pmp_hdr->opcode;
        switch (op) {
            case NATPMP_OP_EXTADDR_REQ:
                // No more data
                return;
            case NATPMP_OP_EXTADDR_RESP: {
                const nat_pmp_resp_t * const resp = (nat_pmp_resp_t*)rp;
                if (snaplen < sizeof(nat_pmp_resp_t)) return;
                nat_flow->natpmp_start = resp->start;
                if (resp->result == 0) nat_flow->mapped_addr = resp->ext_ip;
                else nat_flow->err |= (1 << resp->result); // See NAT-PMP result codes (NATPMP_R_*)
                break;
            }
            case NATPMP_OP_MAP_UDP_REQ:
            case NATPMP_OP_MAP_TCP_REQ: {
               //nat_pmp_map_req_t *req = (nat_pmp_map_req_t*)rp;
               break;
            }
            case NATPMP_OP_MAP_UDP_RESP:
            case NATPMP_OP_MAP_TCP_RESP: {
               //nat_pmp_map_resp_t *resp = (nat_pmp_map_resp_t*)rp;
               break;
            }
            default:
               // unknown opcode
               nat_flow->stat |= NAT_STAT_MALFORMED;
               break;
        }
        // Count the number of NAT-PMP messages
        if (op <= NATPMP_OP_MAP_TCP_REQ) {
            nat_flow->num_natpmp_op[op]++;
            return;
        } else if (op >= NATPMP_OP_EXTADDR_RESP && op <= NATPMP_OP_MAP_TCP_RESP) {
            nat_flow->num_natpmp_op[op-125]++;
            return;
        }
        // opcode was unknown... try to decode the message as STUN
    }

    const stun_header_t * const stun_hdr = (stun_header_t*)rp;
    if (snaplen < sizeof(stun_header_t)) return;

    // No magic cookie, no STUN!
    if (stun_hdr->magic_cookie != STUN_MAGIC_COOKIE) return;
    else if (!STUN_LEN_IS_VALID(stun_hdr->len)) return;
    else if (stun_hdr->zero != 0) return;

    if (flow->srcPort != STUN_PORT || flow->srcPort != STUNS_PORT ||
        flow->dstPort != STUN_PORT || flow->dstPort != STUNS_PORT)
    {
        nat_flow->stat |= NAT_STAT_STUN_OVER_NSP;
    }

    nat_flow->num_mt_class[STUN_MT_CLASS_TO_INT(STUN_MT_CLASS(stun_hdr->type))]++;
    const uint16_t meth = STUN_MT_METH(stun_hdr->type);
    if (meth >= STUN_M_ALLOC && meth <= STUN_M_CONNECT_ATTEMPT)
        nat_flow->stat |= NAT_STAT_TURN;

    snaplen -= sizeof(stun_header_t);
    rp += sizeof(stun_header_t);

    uint16_t len = ntohs(stun_hdr->len);

    uint16_t padding, alen = 0;
    size_t str_len;
    uint8_t *tmp_str;
    stun_attr_t *attr;
    stun_error_t *err;
    stun_mapped_addr_t *mapped_addr;
    turn_bw_rsv_amount_t *bw_amount;

    while (len >= sizeof(stun_attr_t) && snaplen >= sizeof(stun_attr_t)) {
        attr = (stun_attr_t*)rp;
        alen = ntohs(attr->len);
        if (len < alen) {
            nat_flow->stat |= NAT_STAT_MALFORMED;
            // TODO report the type of the faulty record
            return;
        }
        if (snaplen < alen) {
            nat_flow->stat |= NAT_STAT_SNAPLEN;
            return;
        }
        switch (ntohs(attr->type)) {

            // Address/port
            case STUN_AT_MAPPED_ADDR:
                NAT_MA_DECODE(nat_flow->mapped_addr, nat_flow->mapped_port);
                break;
            case STUN_AT_ALT_SERVER: // FIXME not tested
                NAT_MA_DECODE(nat_flow->alt_server_addr, nat_flow->alt_server_port);
                break;
            case STUN_AT_RESPONSE_ORIGIN:
                NAT_MA_DECODE(nat_flow->resp_orig_addr, nat_flow->resp_orig_port);
                break;
            case STUN_AT_DEST_ADDR:
                NAT_MA_DECODE(nat_flow->dest_addr, nat_flow->dest_port);
                nat_flow->stat |= NAT_STAT_TURN;
                break;
            case STUN_AT_OTHER_ADDRESS: // FIXME not tested
                NAT_MA_DECODE(nat_flow->other_addr, nat_flow->other_port);
                break;

            // XOR address/port
            case STUN_AT_XOR_MAPPED_ADDR:
                NAT_XMA_DECODE(nat_flow->xor_mapped_addr, nat_flow->xor_mapped_port);
                break;
            case STUN_AT_XOR_PEER_ADDR:
                // TODO it seems there can be more than one...
                NAT_XMA_DECODE(nat_flow->xor_peer_addr, nat_flow->xor_peer_port);
                nat_flow->stat |= NAT_STAT_TURN;
                break;
            case STUN_AT_XOR_RELAYED_ADDR:
                NAT_XMA_DECODE(nat_flow->relayed_addr, nat_flow->relayed_port);
                nat_flow->stat |= NAT_STAT_TURN;
                break;

            // Error
            case STUN_AT_ERR_CODE:
                err = (stun_error_t*)(STUN_ATTR_DATA(rp));
                STUN_ERR_TO_BF(STUN_ERR_CODE(err->res_cl_num), nat_flow);
                break;

            // Strings
            case STUN_AT_USERNAME:
                str_len = MIN(alen, STUN_USERNAME_MAXLEN-1);
                if ((tmp_str = memchr(STUN_ATTR_DATA(rp), ':', alen))) {
                    str_len -= (++tmp_str - (STUN_ATTR_DATA(rp)));
                    memcpy(&nat_flow->password, tmp_str, str_len);
                    nat_flow->password[str_len+1] = '\0';
                    str_len = tmp_str - (STUN_ATTR_DATA(rp)) - 1; // ignore ':'
                    memcpy(&nat_flow->username, STUN_ATTR_DATA(rp), str_len);
                    nat_flow->username[str_len+1] = '\0';
                } else {
                    memcpy(&nat_flow->username, STUN_ATTR_DATA(rp), str_len);
                    nat_flow->username[str_len+1] = '\0';
                }
                break;
            case STUN_AT_PASSWORD: // deprecated
                nat_flow->stat |= NAT_STAT_DEPRECATED;
                str_len = MIN(alen, STUN_USERNAME_MAXLEN-1);
                memcpy(&nat_flow->password, STUN_ATTR_DATA(rp), str_len);
                nat_flow->password[str_len+1] = '\0';
                break;
            case STUN_AT_REALM:
                str_len = MIN(alen, STUN_ATTR_STR_MAXLEN-1);
                memcpy(&nat_flow->realm, STUN_ATTR_DATA(rp), str_len);
                nat_flow->realm[str_len+1] = '\0';
                break;
            case STUN_AT_SOFTWARE:
                str_len = MIN(alen, STUN_ATTR_STR_MAXLEN-1);
                memcpy(&nat_flow->software, STUN_ATTR_DATA(rp), str_len);
                nat_flow->software[str_len+1] = '\0';
                break;

            // Flag
            case STUN_AT_DONT_FRAGMENT:
                nat_flow->stat |= NAT_STAT_TURN;
                nat_flow->stat |= NAT_STAT_DF;
                break;
            case STUN_AT_NONCE: // TODO store nonce? (older version had NONCE and REALM swapped...)
                nat_flow->stat |= NAT_STAT_NONCE;
                break;

            // Uint32
            case STUN_AT_LIFETIME:
                nat_flow->stat |= NAT_STAT_TURN;
                nat_flow->lifetime = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;
            case STUN_AT_BANDWIDTH:
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_DEPRECATED);
                nat_flow->bandwidth = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;
            case STUN_AT_PRIORITY:
                nat_flow->stat |= NAT_STAT_ICE;
                nat_flow->priority = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;

            // Uint16
            case STUN_AT_CHANNEL_NUMBER: // FIXME not tested
                nat_flow->stat |= NAT_STAT_TURN;
                nat_flow->channel = ntohs(*(uint16_t*)(STUN_ATTR_DATA(rp)));
                break;

            // Uint8
            case STUN_AT_REQ_TRANSPORT:
                nat_flow->stat |= NAT_STAT_TURN;
                nat_flow->req_proto = *(STUN_ATTR_DATA(rp));
                break;
            case STUN_AT_REQ_ADDR_FAMILY:
                nat_flow->stat |= NAT_STAT_TURN;
                nat_flow->req_family = *(STUN_ATTR_DATA(rp));
                break;

            // TURN
            case STUN_AT_EVEN_PORT: // FIXME not tested
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_EVEN_PORT);
                if (*(STUN_ATTR_DATA(rp)) & 0x1) nat_flow->stat |= NAT_STAT_RES_NEXT_PORT;
                break;
            case STUN_AT_TIMER_VAL:
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_DEPRECATED);
                break;
            case STUN_AT_MAGIC_COOKIE:
                nat_flow->stat |= NAT_STAT_TURN;
                if (*(uint32_t*)(STUN_ATTR_DATA(rp)) != TURN_MAGIC_COOKIE) nat_flow->stat |= NAT_STAT_MALFORMED;
                break;

            case STUN_AT_DATA:
            case STUN_AT_RESERVATION_TOKEN:
                nat_flow->stat |= NAT_STAT_TURN;
                break;

            // ICE
            case STUN_AT_USE_CANDIDATE:
            case STUN_AT_ICE_CONTROLLED:
            case STUN_AT_ICE_CONTROLLING:
                nat_flow->stat |= NAT_STAT_ICE;
                break;

            // MS-TURN
            case STUN_AT_MS_VERSION:
            case STUN_AT_MS_XOR_MAPPED_ADDR:
            case STUN_AT_MS_SEQ_NUM:
            case STUN_AT_MS_SERVICE_QUALITY:
            case STUN_AT_MS_ALT_MAPPED_ADDR:
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                break;

            // MS-TURNBW
            case STUN_AT_BANDWIDTH_RSV_AMOUNT:
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                bw_amount = (turn_bw_rsv_amount_t*)(STUN_ATTR_DATA(rp));
                nat_flow->ms_bandwidth[TURN_BW_MIN_SEND] = ntohl(bw_amount->min_send);
                nat_flow->ms_bandwidth[TURN_BW_MAX_SEND] = ntohl(bw_amount->max_send);
                nat_flow->ms_bandwidth[TURN_BW_MIN_RCV] = ntohl(bw_amount->min_rcv);
                nat_flow->ms_bandwidth[TURN_BW_MAX_RCV] = ntohl(bw_amount->max_rcv);
                break;
            case STUN_AT_SIP_DIALOG_ID:
            case STUN_AT_SIP_CALL_ID:
                nat_flow->stat |= NAT_STAT_SIP;
                /* FALLTHRU */
            case STUN_AT_BANDWIDTH_ACM:
            case STUN_AT_BANDWIDTH_RSV_ID:
            case STUN_AT_REMOTE_SITE_ADDR:
            case STUN_AT_REMOTE_RELAY_SITE:
            case STUN_AT_LOCAL_SITE_ADDR:
            case STUN_AT_LOCAL_RELAY_SITE:
            case STUN_AT_REMOTE_SITE_ADDR_RP:
            case STUN_AT_REMOTE_RELAY_SITE_RP:
            case STUN_AT_LOCAL_SITE_ADDR_RP:
            case STUN_AT_LOCAL_RELAY_SITE_RP:
            case STUN_AT_LOCATION_PROFILE:
                nat_flow->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                break;

            // MS-ICE
            case STUN_AT_CANDIDATE_ID:
            case STUN_AT_IMPLEM_VER:
                nat_flow->stat |= (NAT_STAT_ICE | NAT_STAT_MS);
                break;

            // deprecated
            case STUN_AT_RESP_ADDR:
            case STUN_AT_CHANGE_ADDR:
            case STUN_AT_SOURCE_ADDR:
            case STUN_AT_CHANGED_ADDR:
            case STUN_AT_REFLECTED_FROM:
                nat_flow->stat |= NAT_STAT_DEPRECATED;
                break;

            // do nothing
            case STUN_AT_MSG_INTEGRITY:
            case STUN_AT_FINGERPRINT:
                break;

            default:
                T2_PDBG("stunDecode", "Unhandled attribute %#04x", ntohs(attr->type));
                break;
        }

        padding = alen % 4;
        if (padding > 0) padding = 4 - padding;
        alen += STUN_ATTR_HDR_LEN + padding;
        if (alen > len) { // Bogus length
            nat_flow->stat |= NAT_STAT_MALFORMED;
            break;
        }

        len -= alen;
        snaplen -= alen;
        rp += alen;
    }

    nat_flow->stat |= NAT_STAT_STUN;
    num_stun++;
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    nat_flow_t * const nat_flow = &nat_flows[flowIndex];
    OUTBUF_APPEND_U32(main_output_buffer, nat_flow->stat);
    OUTBUF_APPEND_U32(main_output_buffer, nat_flow->err);
    uint_fast32_t i;
    for (i = 0; i < STUN_MT_CLASS_N; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, nat_flow->num_mt_class[i]);
    }
    // Addr_Port
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->mapped_addr, nat_flow->mapped_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->xor_mapped_addr, nat_flow->xor_mapped_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->xor_peer_addr, nat_flow->xor_peer_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->resp_orig_addr, nat_flow->resp_orig_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->relayed_addr, nat_flow->relayed_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->dest_addr, nat_flow->dest_port);
    //NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->alt_server_addr, nat_flow->alt_server_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(nat_flow->other_addr, nat_flow->other_port);
    OUTBUF_APPEND_U32(main_output_buffer, nat_flow->lifetime);
    //for (i = 0; i < TURN_BW_N; i++) {
    //    OUTBUF_APPEND_U32(main_output_buffer, nat_flow->ms_bandwidth[i]);
    //}
    // Str
    NAT_OB_APPEND_OPT_STR(nat_flow->username);
    NAT_OB_APPEND_OPT_STR(nat_flow->password);
    NAT_OB_APPEND_OPT_STR(nat_flow->realm);
    NAT_OB_APPEND_OPT_STR(nat_flow->software);
#if NAT_PMP == 1
    for (i = 0; i < 6; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, nat_flow->num_natpmp_op[i]);
    }
    OUTBUF_APPEND_U32(main_output_buffer, nat_flow->natpmp_start);
#endif // NAT_PMP == 1
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "stunDecode", "Number of NAT-PMP packets", num_natpmp, numPackets);
    T2_FPLOG_NUMP(stream, "stunDecode", "Number of STUN packets", num_stun, numPackets);
}


void onApplicationTerminate() {
    free(nat_flows);
}
