/*
 * cdpDecode.c
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

#include "cdpDecode.h"
#include "t2buf.h"


// plugin variables

cdp_flow_t *cdp_flows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t num_cdp_pkts, num_cdp_pkts0;


#define CDP_READ_STR(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, maxlen); \
    if (read != len) { \
        cdp_flow->stat |= CDP_STAT_STR; \
    } \
    if (!t2buf_read_n(t2buf, (uint8_t*)dest, read)) { \
        cdp_flow->stat |= CDP_STAT_SNAP; \
        return; \
    } \
    dest[read] = '\0'; \
    if (read != len) t2buf_skip_n(t2buf, len - read); \
}

#define CDP_CHECK_MIN_LEN(len, min) \
    if (len < min) { \
        cdp_flow->stat |= CDP_STAT_LEN; \
        return; \
    }

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("cdpDecode", "0.8.4", 0, 8);


void initialize() {
#if ETH_ACTIVATE == 0
    T2_PWRN("cdpDecode", "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    if (UNLIKELY(!(cdp_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*cdp_flows))))) {
        T2_PERR("cdpDecode", "failed to allocate memory for cdp_flows");
        exit(-1);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv,   "cdpStat"          , "CDP status");
    BV_APPEND_U8(bv,   "cdpVersion"       , "CDP version");
    BV_APPEND_U8(bv,   "cdpTTL"           , "CDP Time To Live (sec)");
    BV_APPEND_H32(bv,  "cdpTLVTypes"      , "CDP TLV types");
    BV_APPEND_STRC(bv, "cdpDevice"        , "CDP device ID");
    BV_APPEND_STR(bv,  "cdpPlatform"      , "CDP platform");
    BV_APPEND_STRC(bv, "cdpPort"          , "CDP port ID");
    BV_APPEND_H32(bv,  "cdpCaps"          , "CDP capabilities");
    BV_APPEND_H8(bv,   "cdpDuplex"        , "CDP duplex");
    BV_APPEND_U16(bv,  "cdpNVLAN"         , "CDP native VLAN");
    BV_APPEND_STRC(bv, "cdpVTPMngmtDomain", "CDP VTP management domain");
    //BV_APPEND_STRC(bv, "cdpMngmtAddr", "CDP management address");
    return bv;
}


void onFlowGenerated(packet_t *packet, uint64_t flowIndex) {
    cdp_flow_t * const cdp_flow = &cdp_flows[flowIndex];
    memset(cdp_flow, '\0', sizeof(*cdp_flow));

    if (packet->layer2Type != ETHERTYPE_CDP) return;

    cdp_flow->stat |= CDP_STAT_CDP;
}


void claimLayer2Information(packet_t *packet, uint64_t flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    cdp_flow_t * const cdp_flow = &cdp_flows[flowIndex];
    if (packet->layer2Type != ETHERTYPE_CDP) return;

    num_cdp_pkts++;

    const uint16_t snaplen = packet->snapL7Length;
    const uint8_t * const l7hdr = packet->layer7Header;
    t2buf_t t2buf = t2buf_create(l7hdr, snaplen);

    /* Version */
    t2buf_read_u8(&t2buf, &cdp_flow->version);

    /* TTL */
    t2buf_read_u8(&t2buf, &cdp_flow->ttl);

    /* Checksum */
    t2buf_skip_u16(&t2buf);

    while (t2buf_left(&t2buf) > 3) {

        /* TLV type */
        uint16_t type;
        t2buf_read_u16(&t2buf, &type);

        /* TLV length */
        uint16_t len;
        t2buf_read_u16(&t2buf, &len);

        CDP_CHECK_MIN_LEN(len, 4);

        len -= 4; // length include type and length fields (4 bytes)

        if (type < 31) {
            cdp_flow->tlv_types |= (1U << type);
        } else {
            cdp_flow->tlv_types |= (1U << 31);
        }

        switch (type) {

            /* Device ID */
            case CDP_TLV_DEVICE_ID:
                CDP_READ_STR(&t2buf, cdp_flow->device, len, CDP_STRLEN);
                break;

            /* Addresses */
            //case CDP_TLV_ADDRESSES: {
            //    /* Number of addresses */
            //    uint32_t naddr;
            //    t2buf_read_u32(&t2buf, &naddr);
            //    for (uint_fast32_t i = 0; i < naddr; i++) {
            //        /* Protocol type */
            //        uint8_t ptype;
            //        t2buf_read_u8(&t2buf, &ptype);
            //        /* Protocol length */
            //        uint8_t plen;
            //        t2buf_read_u8(&t2buf, &plen);
            //        /* Protocol */
            //        uint8_t proto;
            //        t2buf_read_u8(&t2buf, &proto);
            //        /* Address length */
            //        uint16_t alen;
            //        t2buf_read_u16(&t2buf, &alen);
            //        /* Address */
            //        t2buf_skip_n(&t2buf, alen);
            //    }
            //    break;
            //}

            /* Port ID */
            case CDP_TLV_PORT_ID:
                CDP_READ_STR(&t2buf, cdp_flow->port, len, CDP_STRLEN);
                break;

            /* Capabilities */
            case CDP_TLV_CAPS: {
                uint32_t caps;
                t2buf_read_u32(&t2buf, &caps);
                cdp_flow->caps |= caps;
                break;
            }

            /* Software Version */
            //case CDP_TLV_SW_VERSION: {
            //    char version[len+1];
            //    CDP_READ_STR(&t2buf, version, len, CDP_STRLEN);
            //    break;
            //}

            /* Platform */
            case CDP_TLV_PLATFORM:
                CDP_READ_STR(&t2buf, cdp_flow->platform, len, CDP_STRLEN);
                break;

            /* IP Prefix/Gateway (used for ODR) */
            //case CDP_TLV_IP_PREFIXES:
            //    while (t2buf_left(&t2buf) > 4 && len != 0) {
            //        uint32_t ip;
            //        t2buf_read_u32(&t2buf, &ip);
            //        uint8_t cidr;
            //        t2buf_read_u8(&t2buf, &cidr);
            //        CDP_CHECK_MIN_LEN(len, 5);
            //        len -= 5;
            //    }
            //    break;

            /* Protocol Hello */
            //case CDP_TLV_PROTO_HELLO: {
            //    /* OUI */
            //    uint8_t oui[3];
            //    t2buf_read_n(&t2buf, oui, 3);
            //    /* Protocol ID */
            //    uint16_t protoid;
            //    t2buf_read_u16(&t2buf, &protoid);
            //    // TODO (proto dependent)
            //    CDP_CHECK_MIN_LEN(len, 5);
            //    t2buf_skip_n(&t2buf, len-5);
            //    break;
            //}

            /* VTP Management Domain */
            case CDP_TLV_VTP_MNGMT:
                CDP_READ_STR(&t2buf, cdp_flow->vtpdom, len, CDP_STRLEN);
                break;

            /* Native VLAN */
            case CDP_TLV_NATIVE_VLAN:
                t2buf_read_u16(&t2buf, &cdp_flow->vlan);
                break;

            /* Duplex */
            case CDP_TLV_DUPLEX: {
                uint8_t duplex;
                t2buf_read_u8(&t2buf, &duplex);
                cdp_flow->duplex |= (1 << duplex);
                break;
            }

            /* VoIP VLAN Query */
            //case CDP_TLV_VOIP_VLAN_Q: {
            //    /* Data */
            //    uint8_t data;
            //    t2buf_read_u8(&t2buf, &data);
            //    /* Voice VLAN */
            //    uint16_t vlan;
            //    t2buf_read_u16(&t2buf, &vlan);
            //    // XXX WTF is this byte for?
            //    t2buf_skip_u8(&t2buf);
            //    break;
            //}

            /* Power Consumption (mW) */
            //case CDP_TLV_POWER_CONS: {
            //    uint16_t pwcons;
            //    t2buf_read_u16(&t2buf, &pwcons);
            //    break;
            //}

            /* Trust Bitmap */
            //case CDP_TLV_TRUST_BMAP: {
            //    uint8_t bmap;
            //    t2buf_read_u8(&t2buf, &bmap);
            //    break;
            //}

            /* Untrusted port CoS */
            //case CDP_TLV_UNTRUST_PORT: {
            //    uint8_t cos;
            //    t2buf_read_u8(&t2buf, &cos);
            //    break;
            //}

            /* Management Addresses */
            //case CDP_TLV_MNGMT_ADDR: {
            //    /* Number of addresses */
            //    uint32_t naddr;
            //    t2buf_read_u32(&t2buf, &naddr);
            //    for (uint_fast32_t i = 0; i < naddr; i++) {
            //        /* Protocol type */
            //        uint8_t ptype;
            //        t2buf_read_u8(&t2buf, &ptype);
            //        /* Protocol length */
            //        uint8_t plen;
            //        t2buf_read_u8(&t2buf, &plen);
            //        /* Protocol */
            //        uint8_t proto;
            //        t2buf_read_u8(&t2buf, &proto);
            //        /* Address length */
            //        uint16_t alen;
            //        t2buf_read_u16(&t2buf, &alen);
            //        /* Address */
            //        t2buf_skip_n(&t2buf, alen);
            //    }
            //    break;
            //}

            /* Power Requested (mW) */
            //case CDP_TLV_POWER_REQ: {
            //    /* Request-ID */
            //    uint16_t reqid;
            //    t2buf_read_u16(&t2buf, &reqid);
            //    /* Management-ID */
            //    uint16_t mngmtid;
            //    t2buf_read_u16(&t2buf, &mngmtid);
            //    /* Power Requested */
            //    uint16_t pwreq;
            //    t2buf_read_u16(&t2buf, &pwreq);
            //    break;
            //}

            /* Power Available (mW) */
            //case CDP_TLV_POWER_AVAIL: {
            //    /* Request-ID */
            //    uint16_t reqid;
            //    t2buf_read_u16(&t2buf, &reqid);
            //    /* Management-ID */
            //    uint16_t mngmtid;
            //    t2buf_read_u16(&t2buf, &mngmtid);
            //    // TODO check whether the two values are really min/max
            //    /* Power Available */
            //    uint32_t pwmin;
            //    t2buf_read_u32(&t2buf, &pwmin);
            //    /* Power Available */
            //    uint32_t pwmax;
            //    t2buf_read_u32(&t2buf, &pwmax);
            //    break;
            //}

            // Those are implemented above, but not used
            case CDP_TLV_ADDRESSES:
            case CDP_TLV_SW_VERSION:
            case CDP_TLV_IP_PREFIXES:
            case CDP_TLV_PROTO_HELLO:
            case CDP_TLV_VOIP_VLAN_Q:
            case CDP_TLV_POWER_CONS:
            case CDP_TLV_UNTRUST_PORT:
            case CDP_TLV_TRUST_BMAP:
            case CDP_TLV_MNGMT_ADDR:
            case CDP_TLV_POWER_REQ:
            case CDP_TLV_POWER_AVAIL:
                t2buf_skip_n(&t2buf, len);
                break;

            default:
#if DEBUG > 0
                T2_PWRN("cdpDecode", "%"PRIu64" Unhandled TLV type 0x%04"B2T_PRIX16, numPackets, type);
#endif // DEBUG > 0
                t2buf_skip_n(&t2buf, len);
                break;
        }
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(uint64_t flowIndex) {
    const cdp_flow_t * const cdp_flow = &cdp_flows[flowIndex];
    OUTBUF_APPEND_U8(main_output_buffer, cdp_flow->stat);
    OUTBUF_APPEND_U8(main_output_buffer, cdp_flow->version);
    OUTBUF_APPEND_U8(main_output_buffer, cdp_flow->ttl);
    OUTBUF_APPEND_U32(main_output_buffer, cdp_flow->tlv_types);
    OUTBUF_APPEND_STR(main_output_buffer, cdp_flow->device);
    OUTBUF_APPEND_STR(main_output_buffer, cdp_flow->platform);
    OUTBUF_APPEND_STR(main_output_buffer, cdp_flow->port);
    OUTBUF_APPEND_U32(main_output_buffer, cdp_flow->caps);
    OUTBUF_APPEND_U8(main_output_buffer, cdp_flow->duplex);
    OUTBUF_APPEND_U16(main_output_buffer, cdp_flow->vlan);
    OUTBUF_APPEND_STR(main_output_buffer, cdp_flow->vtpdom);
}
#endif // BLOCK_BUF == 0


static void cdp_pluginReport(FILE *stream) {
    T2_FPLOG_DIFFNUMP(stream, "cdpDecode", "Number of CDP packets", num_cdp_pkts, numPackets);
}


void monitoring(FILE *stream, uint8_t state) {
    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("cdpPkts\t", stream); // Note the trailing tab (\t)
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream, "%"PRIu64"\t", num_cdp_pkts - num_cdp_pkts0); // Note the trailing tab (\t)
            break;

        case T2_MON_PRI_REPORT:
            cdp_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }

#if DIFF_REPORT == 1
    num_cdp_pkts0 = num_cdp_pkts;
#endif // DIFF_REPORT == 1
}


void pluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_cdp_pkts0 = 0;
#endif // DIFF_REPORT == 1
    cdp_pluginReport(stream);
}


void onApplicationTerminate() {
    free(cdp_flows);
}

#endif // ETH_ACTIVATE > 0
