/*
 * vrrpDecode.c
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

#include "vrrpDecode.h"
#include "chksum.h"


// Global variables

vrrp_flow_t *vrrp_flows;


// Static variables

static uint64_t num_vrrp2;
static uint64_t num_vrrp3;

#if VRRP_RT == 1
static FILE *vrrpFile;
#endif // VRRP_RT


// Tranalyzer functions

T2_PLUGIN_INIT("vrrpDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(vrrp_flows = calloc(mainHashMap->hashChainTableSize, sizeof(*vrrp_flows))))) {
        T2_PERR("vrrpDecode", "failed to allocate memory for vrrp_flows");
        exit(-1);
    }

#if VRRP_RT == 1
    vrrpFile = t2_open_file(baseFileName, VRRP_SUFFIX, "w");
    if (UNLIKELY(!vrrpFile)) {
        free(vrrp_flows);
        exit(-1);
    }
    fprintf(vrrpFile, "VirtualRtrID\tPriority\tSkewTime[s]\tMasterDownInterval[s]\tAddrCount\tAddresses\tVersion\tType\tAdverInt[s]\tAuthType\tAuthString\tChecksum\tCalcChecksum\tflowIndex\n");
#endif // VRRP_RT
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv,    "vrrpStat",      "VRRP status");
    BV_APPEND_H8(bv,     "vrrpVer",       "VRRP version");
    BV_APPEND_H8(bv,     "vrrpType",      "VRRP type");
    BV_APPEND_U32(bv,    "vrrpVRIDCnt",   "VRRP virtual router ID count");
    BV_APPEND_U8_R(bv,   "vrrpVRID",      "VRRP virtual router ID");
    BV_APPEND_U8(bv,     "vrrpMinPri",    "VRRP minimum priority");
    BV_APPEND_U8(bv,     "vrrpMaxPri",    "VRRP maximum priority");
    BV_APPEND_U8(bv,     "vrrpMinAdvInt", "VRRP minimum advertisement interval [s]");
    BV_APPEND_U8(bv,     "vrrpMaxAdvInt", "VRRP maximum advertisement interval [s]");
    BV_APPEND_H8(bv,     "vrrpAuthType",  "VRRP authentication type");
    BV_APPEND_STRC(bv,   "vrrpAuth",      "VRRP authentication string");
    BV_APPEND_U32(bv,    "vrrpIPCnt",     "VRRP IP address count");
#if VRRP_NUM_IP > 0
    BV_APPEND_TYPE_R(bv, "vrrpIP",        "VRRP IP addresses", VRRP_IP_TYPE);
#endif // VRRP_NUM_IP > 0
    return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
    vrrp_flow_t * const vrrp_flow = &vrrp_flows[flowIndex];
    memset(vrrp_flow, '\0', sizeof(*vrrp_flow));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    if (flowP->layer4Protocol == L3_VRRP) {
        vrrp_flow->stat |= VRRP_STAT_VRRP;
        // TODO check src MAC address == 00:00:5e:00:01:VRID
        if (!PACKET_IS_IPV6(packet)) {
            ipHeader_t *ipHeaderP = (ipHeader_t*)packet->layer3Header;
            if (ipHeaderP->ip_dst.s_addr != VRRP_MCAST_4ADDR) {
                vrrp_flow->stat |= VRRP_STAT_DEST_IP;
            }
        }
    }

    vrrp_flow->minadvint = 0xff;
    vrrp_flow->minpri = 0xff;
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    vrrp_flow_t * const vrrp_flow = &vrrp_flows[flowIndex];
    if (!vrrp_flow->stat) return; // not a vrrp packet

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    if (PACKET_IS_IPV6(packet)) {
        const ip6Header_t *ip6HeaderP = (ip6Header_t*)packet->layer3Header;
        if (ip6HeaderP->ip_ttl != VRRP_TTL) vrrp_flow->stat |= VRRP_STAT_TTL;
    } else {
        const ipHeader_t *ipHeaderP = (ipHeader_t*)packet->layer3Header;
        if (ipHeaderP->ip_ttl != VRRP_TTL) vrrp_flow->stat |= VRRP_STAT_TTL;
    }

    const uint_fast16_t snaplen = packet->snapL7Length;
    if (snaplen < sizeof(vrrp_t)) {
        vrrp_flow->stat |= VRRP_STAT_SNAP;
        return;
    }

    const vrrp_t * const v = (vrrp_t*)packet->layer4Header;

    if (v->type != VRRP_TYPE_ADV) vrrp_flow->stat |= VRRP_STAT_TYPE;

    switch (v->version) {
        case 2:
            num_vrrp2++;
            break;
        case 3:
            num_vrrp3++;
            // Reserved MUST be 0
            if ((v->maxadvint & 0x00f0) != 0) vrrp_flow->stat |= VRRP_STAT_MALFORMED;
            break;
        default:
            vrrp_flow->stat |= VRRP_STAT_VER;
            break;
    }

    vrrp_flow->version |= 1 << v->version;
    vrrp_flow->type |= v->type;

    uint32_t i, imax = MIN(vrrp_flow->vrid_cnt, VRRP_NUM_VRID);

    // Virtual Router ID
    for (i = 0; i < imax; i++) {
        if (vrrp_flow->vrid[i] == v->vrid) goto after_vrid;
    }
    if (vrrp_flow->vrid_cnt < VRRP_NUM_VRID) {
        vrrp_flow->vrid[vrrp_flow->vrid_cnt] = v->vrid;
    } else {
        vrrp_flow->stat |= VRRP_STAT_TRUNC_VRID;
    }
    vrrp_flow->vrid_cnt++;

after_vrid:

    if (v->pri < vrrp_flow->minpri) vrrp_flow->minpri = v->pri;
    if (v->pri > vrrp_flow->maxpri) vrrp_flow->maxpri = v->pri;

    uint8_t advint;
    if (v->version == 2) {
        vrrp_flow->atype |= 1 << v->atype;
        advint = v->advint;
    } else {
        advint = (ntohs(v->maxadvint) & 0x0fff) / 100.0;
    }

    if (advint < vrrp_flow->minadvint) vrrp_flow->minadvint = advint;
    if (advint > vrrp_flow->maxadvint) vrrp_flow->maxadvint = advint;

    uint16_t calc_chksum;

    if (PACKET_IS_IPV6(packet)) {
        // TODO IPv6 checksum
        calc_chksum = 0;
    } else {
        calc_chksum = ~Checksum((uint16_t*)packet->layer4Header, 0, packet->snapL4Length, 3);
        if (v->version == 3) calc_chksum = 0; // TODO checksum for v3
        else if (v->chksum != calc_chksum) vrrp_flow->stat |= VRRP_STAT_CHKSUM;
    }

#if VRRP_RT == 1
    float mai;
    float skew = (256 - v->pri) / 256.0;
    if (v->version == 2) {
        mai = (3 * v->advint + skew);
    } else {
        skew *= ntohs(v->maxadvint) & 0x0fff;
        mai = (3 * (ntohs(v->maxadvint) & 0x0fff)) + skew;
    }
    fprintf(vrrpFile, "%d\t%d\t%lf\t%lf\t%d\t", v->vrid, v->pri, skew, mai, v->ip_cnt);
#endif // VRRP_RT

    uint32_t *ptr = (uint32_t*)((uint8_t*)v + sizeof(*v));
    uint32_t j, n = v->ip_cnt;

    if (PACKET_IS_IPV6(packet)) {
#if VRRP_RT == 1
        char str[INET6_ADDRSTRLEN];
#endif // VRRP_RT == 1
        //imax = MIN(vrrp_flow->sip_cnt, VRRP_NUM_IP);
        for (i = 0; i < n; i++) {
#if VRRP_RT == 1
            inet_ntop(AF_INET6, (struct in6_addr*)ptr, str, INET6_ADDRSTRLEN);
            fprintf(vrrpFile, "%s", str);
            if (i+1 < n) fputc(';', vrrpFile);
#endif // VRRP_RT == 1
            // TODO uniq for IPv6
            if (vrrp_flow->sip_cnt < VRRP_NUM_IP) {
                for (j = 0; j < 4; j++) {
                    vrrp_flow->ip[vrrp_flow->sip_cnt][j] = *ptr;
                    ptr++;
                }
                vrrp_flow->sip_cnt++;
            } else {
                vrrp_flow->stat |= VRRP_STAT_TRUNC_IP;
                ptr += 4;
            }
        }
    } else { // IPv4
        uint32_t ip;
        imax = MIN(vrrp_flow->sip_cnt, VRRP_NUM_IP);
        for (i = 0; i < n; i++) {
            ip = *ptr;
            ptr++;
#if VRRP_RT == 1
            fprintf(vrrpFile, "%s", inet_ntoa(*(struct in_addr*)&ip));
            if (i+1 < n) fputc(';', vrrpFile);
#endif // VRRP_RT == 1
            for (j = 0; j < imax; j++) {
                if (vrrp_flow->ip[j][0] == ip) {
                    j = UINT32_MAX;
                    break;
                }
            }
            if (j != UINT32_MAX) {
                if (vrrp_flow->sip_cnt >= VRRP_NUM_IP) {
                    vrrp_flow->stat |= VRRP_STAT_TRUNC_IP;
                } else {
                    vrrp_flow->ip[vrrp_flow->sip_cnt][0] = ip;
                }
                vrrp_flow->sip_cnt++;
            }
        }
    }

#if VRRP_RT == 1
    fprintf(vrrpFile, "\t%d\t%d\t%d\t%d\t", v->version, v->type,
            v->version == 2 ? v->advint : (ntohs(v->maxadvint) & 0x0fff) / 100, v->atype);
#endif // VRRP_RT == 1

    if (v->atype == VRRP_AUTH_SIMPLE) {
        strncpy(vrrp_flow->auth, (char*)ptr, VRRP_AUTH_MAX);
#if VRRP_RT == 1
        fprintf(vrrpFile, "%s", vrrp_flow->auth);
#endif // VRRP_RT == 1
    } else if (v->version == 2 && *(uint64_t*)ptr != 0)
        vrrp_flow->stat |= VRRP_STAT_MALFORMED;

#if VRRP_RT == 1
    const flow_t * const flowP = &flows[flowIndex];
    fprintf(vrrpFile, "\t0x%04"B2T_PRIX16"\t0x%04"B2T_PRIX16"\t%"PRIu64"\n", ntohs(v->chksum), ntohs(calc_chksum), flowP->findex);
#endif // VRRP_RT == 1
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    vrrp_flow_t *vrrp_flow = &vrrp_flows[flowIndex];

    OUTBUF_APPEND_U16(main_output_buffer, vrrp_flow->stat);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->version);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->type);
    OUTBUF_APPEND_U32(main_output_buffer, vrrp_flow->vrid_cnt);

    uint32_t i, imax = vrrp_flow->vrid_cnt < VRRP_NUM_VRID ? vrrp_flow->vrid_cnt : VRRP_NUM_VRID;
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->vrid[i]);
    }

    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->minpri);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->maxpri);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->minadvint);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->maxadvint);
    OUTBUF_APPEND_U8(main_output_buffer, vrrp_flow->atype);
    OUTBUF_APPEND_STR(main_output_buffer, vrrp_flow->auth);
    OUTBUF_APPEND_U32(main_output_buffer, vrrp_flow->sip_cnt);

    imax = vrrp_flow->sip_cnt < VRRP_NUM_IP ? vrrp_flow->sip_cnt : VRRP_NUM_IP;
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
#if IPV6_ACTIVATE == 2
    const flow_t * const flowP = &flows[flowIndex];
    const uint8_t version = (flowP->status & L2_IPV6) ? 6 : 4;
#endif // IPV6_ACTIVATE == 2
    for (i = 0; i < imax; i++) {
#if IPV6_ACTIVATE == 2
        OUTBUF_APPEND_U8(main_output_buffer, version);
        if (version == 4) {
            OUTBUF_APPEND_U32(main_output_buffer, vrrp_flow->ip[i]);
        } else {
            OUTBUF_APPEND(main_output_buffer, vrrp_flow->ip[i], 4 * sizeof(uint32_t));
        }
#else // IPV6_ACTIVATE != 2
        OUTBUF_APPEND(main_output_buffer, vrrp_flow->ip[i], VRRP_IP_SIZE);
#endif // IPV6_ACTIVATE != 2
    }
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "vrrpDecode", "Number of VRRPv2 packets", num_vrrp2, numPackets);
    T2_FPLOG_NUMP(stream, "vrrpDecode", "Number of VRRPv3 packets", num_vrrp3, numPackets);
}


void onApplicationTerminate() {
#if VRRP_RT == 1
    fclose(vrrpFile);
#endif // VRRP_RT == 1

    free(vrrp_flows);
}
