/*
 * lldpDecode.c
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

#include "lldpDecode.h"
#include "t2buf.h"


// Global variables

lldp_flow_t *lldp_flows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t num_lldp_pkts, num_lldp_pkts0;


#define LLDP_READ_HEX(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, maxlen/2); \
    if (read != (size_t)len) { \
        lldp_flow->stat |= LLDP_STAT_STR; \
    } \
    if (t2buf_hexdecode(t2buf, read, dest, 0) != read) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    } \
    dest[2*read] = '\0'; \
    if (read != (size_t)len) t2buf_skip_n(t2buf, len - read); \
}

#define LLDP_READ_STR(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, maxlen); \
    if (read != (size_t)len) { \
        lldp_flow->stat |= LLDP_STAT_STR; \
    } \
    if (!t2buf_read_n(t2buf, (uint8_t*)dest, read)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    } \
    dest[read] = '\0'; \
    if (read != (size_t)len) t2buf_skip_n(t2buf, len - read); \
}

#define LLDP_READ_N(t2buf, dest, n) \
    if (!t2buf_read_n(t2buf, dest, n)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    }

#define LLDP_READ_U8(t2buf, dest) \
    if (!t2buf_read_u8(t2buf, dest)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    }

#define LLDP_READ_U16(t2buf, dest) \
    if (!t2buf_read_u16(t2buf, dest)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    }

#define LLDP_READ_U32(t2buf, dest) \
    if (!t2buf_read_u32(t2buf, dest)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    }

#define LLDP_READ_LE_U32(t2buf, dest) \
    if (!t2buf_read_le_u32(t2buf, dest)) { \
        lldp_flow->stat |= LLDP_STAT_SNAP; \
        return; \
    }

#define LLDP_CHECK_MIN_LEN(len, min) \
    if (len < min) { \
        lldp_flow->stat |= LLDP_STAT_LEN; \
        return; \
    }

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("lldpDecode", "0.8.4", 0, 8);


void initialize() {
#if ETH_ACTIVATE == 0
    T2_PWRN("lldpDecode", "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    if (UNLIKELY(!(lldp_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*lldp_flows))))) {
        T2_PERR("lldpDecode", "failed to allocate memory for lldp_flows");
        exit(-1);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv,   "lldpStat"   , "LLDP status");
    // TODO: could there be more than one time a given TLV? For TTL yes.
    // Mandatory TLVs
    BV_APPEND_STRC(bv,  "lldpChassis", "LLDP chassis ID");
    BV_APPEND_STR(bv,   "lldpPort"   , "LLDP port ID");
    BV_APPEND_U16_R(bv, "lldpTTL"    , "LLDP Time To Live (sec)");
#if LLDP_OPT_TLV == 1
    // Optional TLVs
    BV_APPEND_STR(bv, "lldpPortDesc", "LLDP port description");
    BV_APPEND_STR(bv, "lldpSysName" , "LLDP system name");
    BV_APPEND_STR(bv, "lldpSysDesc" , "LLDP system description");
    BV_APPEND(bv, "lldpCaps_Enabled", "LLDP supported and enabled capabilities", 2, bt_hex_16, bt_hex_16);
    BV_APPEND_STRC(bv, "lldpMngmtAddr", "LLDP management address"); // TODO There could be more than 1
#endif // LLDP_OPT_TLV == 1
    return bv;
}


void onFlowGenerated(packet_t *packet, uint64_t flowIndex) {
    lldp_flow_t * const lldp_flow = &lldp_flows[flowIndex];
    memset(lldp_flow, '\0', sizeof(*lldp_flow));

    if (!(packet->status & L2_LLDP)) return;

    lldp_flow->stat |= LLDP_STAT_LLDP;
}


void claimLayer2Information(packet_t *packet, uint64_t flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    lldp_flow_t * const lldp_flow = &lldp_flows[flowIndex];
    if (!(packet->status & L2_LLDP)) return;

    num_lldp_pkts++;

    const uint16_t snaplen = packet->snapL7Length;
    const uint8_t * const l7hdr = packet->layer7Header;
    t2buf_t t2buf = t2buf_create(l7hdr, snaplen);

    uint8_t mandatory = 0;
    uint8_t type = UINT8_MAX;

    while (t2buf_left(&t2buf) > 1 && type != LLDP_TLV_END) {

        /* TLV type and length */
        uint16_t type_len;
        LLDP_READ_U16(&t2buf, &type_len);
        type = LLDP_TYPE(type_len);
        const uint16_t len = LLDP_LEN(type_len);

        if (type < LLDP_TLV_PORT_DESC) {
            mandatory |= (1 << type);
        } else if (type <= LLDP_TLV_MNGMT_ADDR) {
            lldp_flow->stat |= LLDP_STAT_OPT;
        }

        switch (type) {

            // Mandatory TLVs

            /* Chassis Id */
            case LLDP_TLV_CHASSIS_ID: {

                /* Chassis Id subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);

                switch (subtype) {

                    case LLDP_CID_CHASSIS_COMP: /* Chassis component */
                    case LLDP_CID_IF_ALIAS:     /* Interface alias   */
                    case LLDP_CID_IF_NAME:      /* Interface name    */
                    case LLDP_CID_LOCAL: {      /* Locally assigned  */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_STR(&t2buf, lldp_flow->chassis, len-1, LLDP_STRLEN);
                        break;
                    }

                    case LLDP_CID_PORT_COMP: {  /* Port component */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_HEX(&t2buf, lldp_flow->chassis, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* MAC address */
                    case LLDP_CID_MAC_ADDR: {
                        LLDP_CHECK_MIN_LEN(len, 2);
                        uint8_t mac[len];
                        LLDP_READ_STR(&t2buf, mac, len-1, LLDP_STRLEN);
                        size_t dsize = 2*(len-1)+6;
                        if (dsize > sizeof(lldp_flow->chassis)) {
                            lldp_flow->stat |= LLDP_STAT_STR;
                            dsize = sizeof(lldp_flow->chassis);
                        }
                        // TODO use t2_mac_to_str
                        snprintf(lldp_flow->chassis, dsize,
                                "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                                "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                                mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
                                mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
                        break;
                    }

                    /* Network address */
                    case LLDP_CID_NET_ADDR: {
                        uint8_t family;
                        LLDP_READ_U8(&t2buf, &family);
                        if (family == 1) { // IPv4
                            uint32_t ip;
                            LLDP_READ_LE_U32(&t2buf, &ip);
                            inet_ntop(AF_INET, &ip, lldp_flow->chassis, INET_ADDRSTRLEN);
                        } else if (family == 2) { // IPv6
                            uint8_t ip[16];
                            LLDP_READ_N(&t2buf, ip, 16);
                            inet_ntop(AF_INET6, ip, lldp_flow->chassis, INET6_ADDRSTRLEN);
                        } else {
#if DEBUG > 0
                            T2_PERR("lldpDecode", "Network address family %u not implemented", family);
#endif // DEBUG > 0
                            LLDP_CHECK_MIN_LEN(len, 3);
                            LLDP_READ_HEX(&t2buf, lldp_flow->chassis, len-2, LLDP_STRLEN);
                            // 0: reserved
                            // 4: HDLC (8-bit multidrop)
                        }
                        break;
                    }

                    default:
#if DEBUG > 0
                        T2_PERR("lldpDecode", "Chassis subtype %u not implemented (reserved)", subtype);
#endif // DEBUG > 0
                        lldp_flow->stat |= LLDP_STAT_RSVD;
                        LLDP_CHECK_MIN_LEN(len, 1);
                        t2buf_skip_n(&t2buf, len-1);
                        break;
                }
                break;
            } // LLDP_TLV_CHASSIS_ID

            /* Port Id */
            case LLDP_TLV_PORT_ID: {

                /* Port Id subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);

                switch (subtype) {

                    case LLDP_PID_IF_ALIAS: /* Interface alias  */
                    case LLDP_PID_IF_NAME:  /* Interface name   */
                    case LLDP_PID_LOCAL: {  /* Locally assigned */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_STR(&t2buf, lldp_flow->port_id, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* Port component */
                    case LLDP_PID_PORT_COMP: {
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_HEX(&t2buf, lldp_flow->port_id, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* MAC address */
                    case LLDP_PID_MAC_ADDR: {
                        LLDP_CHECK_MIN_LEN(len, 2);
                        uint8_t mac[len];
                        LLDP_READ_STR(&t2buf, mac, len-1, LLDP_STRLEN);
                        size_t dsize = 2*(len-1)+6;
                        if (dsize > sizeof(lldp_flow->port_id)) {
                            lldp_flow->stat |= LLDP_STAT_STR;
                            dsize = sizeof(lldp_flow->port_id);
                        }
                        // TODO use t2_mac_to_str
                        snprintf(lldp_flow->port_id, dsize,
                                "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                                "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                                mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
                                mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
                        break;
                    }

                    /* Network address */
                    case LLDP_PID_NET_ADDR: {
                        uint8_t family;
                        LLDP_READ_U8(&t2buf, &family);
                        if (family == 1) { // IPv4
                            uint32_t ip;
                            LLDP_READ_LE_U32(&t2buf, &ip);
                            inet_ntop(AF_INET, &ip, lldp_flow->port_id, INET_ADDRSTRLEN);
                        } else if (family == 2) { // IPv6
                            uint8_t ip[16];
                            LLDP_READ_N(&t2buf, ip, 16);
                            inet_ntop(AF_INET6, ip, lldp_flow->port_id, INET6_ADDRSTRLEN);
                        } else {
#if DEBUG > 0
                            T2_PERR("lldpDecode", "Network address family %u not implemented", family);
#endif // DEBUG > 0
                            LLDP_CHECK_MIN_LEN(len, 3);
                            LLDP_READ_HEX(&t2buf, lldp_flow->port_id, len-2, LLDP_STRLEN);
                        }
                        break;
                    }

                    /* Agent Circuit Id */
                    case LLDP_PID_CIRC_ID: // TODO
#if DEBUG > 0
                        T2_PERR("lldpDecode", "Port subtype Agent Circuit ID not implemented");
#endif // DEBUG > 0
                        LLDP_CHECK_MIN_LEN(len, 2);
                        t2buf_skip_n(&t2buf, len-1);
                        break;

                    default:
#if DEBUG > 0
                        T2_PERR("lldpDecode", "Port subtype %u not implemented (reserved)", subtype);
#endif // DEBUG > 0
                        lldp_flow->stat |= LLDP_STAT_RSVD;
                        LLDP_CHECK_MIN_LEN(len, 1);
                        t2buf_skip_n(&t2buf, len-1);
                        break;
                }
                break;
            }

            /* Time To Live */
            case LLDP_TLV_TTL: {
                uint16_t ttl;
                LLDP_READ_U16(&t2buf, &ttl);
#if LLDP_TTL_AGGR == 1
                uint_fast32_t i;
                for (i = 0; i < lldp_flow->num_ttl; i++) {
                    if (ttl == lldp_flow->ttl[i]) break;
                }
                if (i != lldp_flow->num_ttl) break;
#endif // LLDP_TTL_AGGR == 1
                if (lldp_flow->num_ttl < LLDP_NUM_TTL) {
                    lldp_flow->ttl[lldp_flow->num_ttl++] = ttl;
                } else {
                    lldp_flow->stat |= LLDP_STAT_TTL;
                }
                break;
            }

            /* End of LLDPDU */
            case LLDP_TLV_END:
                break;

            // Optional TLVs

#if LLDP_OPT_TLV == 1
            /* Port Description */
            case LLDP_TLV_PORT_DESC: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldp_flow->portdesc, len, LLDP_STRLEN);
                break;
            }

            /* System Name */
            case LLDP_TLV_SYS_NAME: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldp_flow->sysname, len, LLDP_STRLEN);
                break;
            }

            /* System Description */
            case LLDP_TLV_SYS_DESC: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldp_flow->sysdesc, len, LLDP_STRLEN);
                break;
            }

            /* System Capabilities */
            case LLDP_TLV_SYS_CAPS: {
                /* Supported capabilities */
                uint16_t caps;
                LLDP_READ_U16(&t2buf, &caps);
                lldp_flow->caps |= caps;
                /* Enabled capabilities */
                uint16_t enabled;
                LLDP_READ_U16(&t2buf, &enabled);
                lldp_flow->enabled_caps |= enabled;
                break;
            }

            /* Management address */
            case LLDP_TLV_MNGMT_ADDR: {
                /* Management address string length */
                uint8_t addr_len;
                LLDP_READ_U8(&t2buf, &addr_len);
                /* Management address subtype */
                uint8_t family;
                LLDP_READ_U8(&t2buf, &family);
                /* Management address */
                if (family == 1) {
                    uint32_t ip;
                    LLDP_READ_LE_U32(&t2buf, &ip);
                    inet_ntop(AF_INET, &ip, lldp_flow->mngmt_addr, INET_ADDRSTRLEN);
                } else if (family == 2) { // IPv6
                    uint8_t ip[16];
                    LLDP_READ_N(&t2buf, ip, 16);
                    inet_ntop(AF_INET6, ip, lldp_flow->mngmt_addr, INET6_ADDRSTRLEN);
                } else {
#if DEBUG > 0
                    T2_PERR("lldpDecode", "Network address family %u not implemented", family);
#endif // DEBUG > 0
                    LLDP_CHECK_MIN_LEN(addr_len, 2);
                    LLDP_READ_HEX(&t2buf, lldp_flow->mngmt_addr, addr_len-1, LLDP_STRLEN);
                }
                /* Interface numbering subtype address */
                uint8_t iface_type;
                LLDP_READ_U8(&t2buf, &iface_type);
                /* Interface number */
                uint32_t iface;
                LLDP_READ_U32(&t2buf, &iface);
                /* OID string length */
                uint8_t oid_len;
                LLDP_READ_U8(&t2buf, &oid_len);
                if (oid_len > 1) {
                    /* Object identifier */
                    char oid[2*oid_len+1];
                    LLDP_READ_HEX(&t2buf, oid, oid_len, 2*oid_len);
                }
                //if (family == 1) {
                //    T2_WRN("Management Address: %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
                //} else {
                //    T2_WRN("Management Address: %s", addr);
                //}
                break;
            }

            /* Organization specific */
            case LLDP_TLV_ORG_SPEC: {
//#if DEBUG > 0
//                T2_PERR("lldpDecode", "Organization specific TLV not implemented");
//#endif // DEBUG > 0
                lldp_flow->stat |= LLDP_STAT_SPEC;
                /* Organization Unique Code (OUI) */
                char oui[7]; // 2*3 + 1
                LLDP_READ_HEX(&t2buf, oui, 3, 6);
                /* Subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);
                // TODO
                LLDP_CHECK_MIN_LEN(len, 4);
                t2buf_skip_n(&t2buf, len - 4);
                break;
            }
#endif // LLDP_OPT_TLV == 1

            default:
                if (type > LLDP_TLV_MNGMT_ADDR && type < LLDP_TLV_ORG_SPEC) {
                    lldp_flow->stat |= LLDP_STAT_RSVD;
                } else if (type > LLDP_TLV_ORG_SPEC) {
                    lldp_flow->stat |= LLDP_STAT_UNK;
#if DEBUG > 0
                    T2_PERR("lldpDecode", "Unhandled TLV type %u", type);
#endif // DEBUG > 0
                }
                t2buf_skip_n(&t2buf, len);
                break;
        }
    }

    if (mandatory != 0x0f) lldp_flow->stat |= LLDP_STAT_MAND;
}


#if BLOCK_BUF == 0
void onFlowTerminate(uint64_t flowIndex) {
    const lldp_flow_t * const lldp_flow = &lldp_flows[flowIndex];
    OUTBUF_APPEND_U16(main_output_buffer, lldp_flow->stat);
    // Mandatory TLVs
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->chassis);
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->port_id);
    OUTBUF_APPEND_NUMREP(main_output_buffer, lldp_flow->num_ttl);
    for (uint_fast32_t i = 0; i < lldp_flow->num_ttl; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, lldp_flow->ttl);
    }
#if LLDP_OPT_TLV == 1
    // LLDP port description
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->portdesc);
    // LLDP system name
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->sysname);
    // LLDP system description
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->sysdesc);
    // LLDP supported and enabled capabilities
    OUTBUF_APPEND_U16(main_output_buffer, lldp_flow->caps);
    OUTBUF_APPEND_U16(main_output_buffer, lldp_flow->enabled_caps);
    // LLDP management address
    OUTBUF_APPEND_STR(main_output_buffer, lldp_flow->mngmt_addr);
#endif // LLDP_OPT_TLV == 1
}
#endif // BLOCK_BUF == 0


static void lldp_pluginReport(FILE *stream) {
    T2_FPLOG_DIFFNUMP(stream, "lldpDecode", "Number of LLDP packets", num_lldp_pkts, numPackets);
}


void monitoring(FILE *stream, uint8_t state) {
    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("lldpPkts\t", stream); // Note the trailing tab (\t)
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream, "%"PRIu64"\t", num_lldp_pkts - num_lldp_pkts0); // Note the trailing tab (\t)
            break;

        case T2_MON_PRI_REPORT:
            lldp_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }

#if DIFF_REPORT == 1
    num_lldp_pkts0 = num_lldp_pkts;
#endif // DIFF_REPORT == 1
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_lldp_pkts0 = 0;
#endif // DIFF_REPORT == 1
    lldp_pluginReport(stream);
}


void onApplicationTerminate() {
    free(lldp_flows);
}

#endif // ETH_ACTIVATE > 0
