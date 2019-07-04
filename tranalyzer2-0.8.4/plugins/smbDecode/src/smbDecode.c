/*
 * smbDecode.c
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

#include "smbDecode.h"
#include "fsutils.h"


#define SMB_WIN_TICK         10000000.0 // 100ns
#define SMB_WIN_UNIX_DIFF 11644473600LL // number of secs between windows and unix first epoch
#define SMB_WIN_TIME_TO_UNIX(t) ((t) / SMB_WIN_TICK - SMB_WIN_UNIX_DIFF);


// Global variables

smb_flow_t *smb_flows;


// Static variables

static uint64_t num_smb[3];
#if SMB_SAVE_DATA == 1
static FILE *guidMapF;
#endif // SMB_SAVE_DATA == 1
#if SMB_SAVE_AUTH == 1
static uint32_t smbNumAuth;
static FILE *smbAuthFile;
#endif // SMB_SAVE_AUTH == 1
#if SMB_SECBLOB == 1
static const char *ntlmssp = "NTLMSSP";
#endif // SMB_SECBLOB == 1

#if SMB_USE_FILTER > 0
static const char *smb_fmt[] = { SMB_SAVE_FMT , NULL };
static inline int str_has_suffix(const char *str, const char *suffix);
#endif // SMB_USE_FILTER


// Functions prototypes

static void smbDecodeClean();


// Tranalyzer functions

T2_PLUGIN_INIT("smbDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(smb_flows = calloc(mainHashMap->hashChainTableSize, sizeof(smb_flow_t))))) {
        T2_PERR("smbDecode", "failed to allocate memory for smb_flows");
        exit(-1);
    }

#if SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1
    size_t len;
    char name[SMB_FNAME_LEN];
#endif // SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1

#if SMB_SAVE_DATA == 1
#if SMB_RM_DATADIR == 1
    if (!rmrf(SMB_SAVE_DIR)) {
        T2_PERR("smbDecode", "Failed to remove directory '%s': %s", SMB_SAVE_DIR, strerror(errno));
        smbDecodeClean();
        exit(-1);
    }
#endif // SMB_RM_DATADIR
    if (!mkpath(SMB_SAVE_DIR, S_IRWXU)) {
        T2_PERR("smbDecode", "Failed to create directory '%s': %s", SMB_SAVE_DIR, strerror(errno));
        smbDecodeClean();
        exit(-1);
    }

    len = sizeof(SMB_SAVE_DIR) + sizeof(SMB_MAP_FILE);
    if (len > SMB_FNAME_LEN) {
        T2_PERR("smbDecode", "Path to '%s' is too long. Increase SMB_FNAME_LEN.", SMB_MAP_FILE);
        smbDecodeClean();
        exit(1);
    }
    snprintf(name, len, "%s%s", SMB_SAVE_DIR, SMB_MAP_FILE);

    guidMapF = fopen(name, "w");
    if (UNLIKELY(!guidMapF)) {
        T2_PERR("smbDecode", "Failed to open file '%s' for writing: %s", name, strerror(errno));
        smbDecodeClean();
        exit(-1);
    }
#endif // SMB_SAVE_DATA

#if SMB_SAVE_AUTH == 1
    len = baseFileName_len + 1 + sizeof(SMB_AUTH_FILE);
    if (len > SMB_FNAME_LEN) {
        T2_PERR("smbDecode", "Path to '%s' is too long. Increase SMB_FNAME_LEN.", SMB_AUTH_FILE);
        smbDecodeClean();
        exit(1);
    }
    snprintf(name, len, "%s_%s", baseFileName, SMB_AUTH_FILE);

    smbAuthFile = fopen(name, "w");
    if (UNLIKELY(!smbAuthFile)) {
        T2_PERR("smbDecode", "Failed to open file '%s' for writing: %s", name, strerror(errno));
        smbDecodeClean();
        exit(-1);
    }
#endif // SMB_SAVE_AUTH == 1
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("SMB status", "smbStat", 0, 1, bt_hex_16));
#if SMB1_NUM_DIALECT > 0
    bv = bv_append_bv(bv, bv_new_bv("SMB1 number of requested dialects", "smb1NDialects", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB1 requested dialects", "smb1Dialects", 1, 1, bt_string));
#endif // SMB1_NUM_DIALECT > 0
#if SMB2_NUM_DIALECT > 0
    bv = bv_append_bv(bv, bv_new_bv("SMB2 number of dialects", "smb2NDialects", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB2 dialect revision", "smb2Dialects", 1, 1, bt_hex_16));
#endif // SMB2_NUM_DIALECT > 0
#if SMB2_NUM_STAT > 0
    bv = bv_append_bv(bv, bv_new_bv("SMB2 number of unique SMB2 header status values", "smbNHdrStat", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB2 list of unique header status", "smbHdrStat", 1, 1, bt_hex_32));
#endif // SMB2_NUM_STAT > 0
    bv = bv_append_bv(bv, bv_new_bv("SMB opcodes ", "smbOpcodes", 0, 1, bt_hex_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB number of opcodes", "smbNOpcodes", 0, SMB2_OP_N,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB previous session ID", "smbPrevSessId", 0, 1, bt_hex_64));
    bv = bv_append_bv(bv, bv_new_bv("SMB native OS", "smbNativeOS", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB native LAN Manager", "smbNativeLanMan", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB primary domain", "smbPrimDom", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB target name", "smbTargName", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB domain name", "smbDomName", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB user name", "smbUserName", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB host name", "smbHostName", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB NTLM server challenge", "smbNTLMServChallenge", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB NT proof string", "smbNTProofStr", 0, 1, bt_string));
#if SMB_SAVE_AUTH == 1
    //bv = bv_append_bv(bv, bv_new_bv("SMB NTLM client challenge", "smbNTLMCliChallenge", 0, 1, bt_string));
#endif // SMB_SAVE_AUTH == 1
    bv = bv_append_bv(bv, bv_new_bv("SMB session key", "smbSessionKey", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB client/server GUID", "smbGUID", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB session flags, security mode and capabilities", "smbSFlags_secM_caps", 0, 3, bt_hex_16, bt_hex_8, bt_hex_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB server start time", "smbBootT", 0, 1, bt_timestamp));
    bv = bv_append_bv(bv, bv_new_bv("SMB max transaction/read/write size", "smbMaxSizeT_R_W", 0, 3, bt_uint_32, bt_uint_32, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB full share path name", "smbPath", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("SMB type of share being accessed", "smbShareT", 0, 1, bt_hex_8));
    bv = bv_append_bv(bv, bv_new_bv("SMB share flags, capabilities and access mask", "smbShareF_caps_acc", 0, 3, bt_hex_32, bt_hex_32, bt_hex_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB number of accessed files", "smbNFiles", 0, 1, bt_uint_32));
    bv = bv_append_bv(bv, bv_new_bv("SMB accessed files", "smbFiles", 1, 1, bt_string));
    return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
    smb_flow_t * const smb_flow = &smb_flows[flowIndex];
    memset(smb_flow, '\0', sizeof(smb_flow_t));
    const flow_t * const flow = &flows[flowIndex];
    const uint_fast8_t proto = packet->layer4Type;
    const uint_fast16_t sp = flow->srcPort;
    const uint_fast16_t dp = flow->dstPort;
    if (proto == L3_TCP &&
            (sp == NB_SESSION_PORT || sp == SMB_DIRECT_PORT ||
             dp == NB_SESSION_PORT || dp == SMB_DIRECT_PORT))
    {
        smb_flow->stat |= SMB_STAT_SMB;
    }
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {

    const flow_t * const flow = &flows[flowIndex];

    smb_flow_t * const smb_flow = &smb_flows[flowIndex];
    if (!smb_flow->stat) return;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    //smb_flow->numPkts++;

    const uint32_t tcpseq = ntohl(((tcpHeader_t*)packet->layer4Header)->seq);
    if (smb_flow->hdrstat > 0 && tcpseq > smb_flow->tcpseq) {
        // packet out of order, reset state
        //printf("MISSING SEGMENT: findex: %ld, pkt: %"PRIu32", %"PRIu32" > %"PRIu32" = %"PRIu32"\n", flow->findex, smb_flow->numPkts, tcpseq, smb_flow->tcpseq, tcpseq-smb_flow->tcpseq);
        smb_flow->hdrstat = 0;
    }
    smb_flow->tcpseq = tcpseq + packet->packetL7Length;

    uint32_t version;
    uint32_t tmp;

#if SMB2_SAVE_DATA == 1
    uint32_t processed = 0;
#endif // SMB2_SAVE_DATA == 1

#if SMB1_DECODE == 1
    smb1_header_t *smb1 = NULL;
#endif // SMB1_DECODE == 1
    smb2_header_t *smb2 = NULL;
    uint32_t remaining = packet->snapL7Length;
    uint8_t *ptr = (uint8_t*)packet->layer7Header;

//#if SMB_SECBLOB == 1
    const uint8_t * const l7end = ptr + remaining;
//#endif // SMB_SECBLOB == 1

    while (remaining && l7end - ptr) {

#if SMB1_SAVE_DATA == 1
        if (smb_flow->hdrstat == SMB1_HDRSTAT_DATA) {
            goto smb1_write_data;
        } else if (smb_flow->hdrstat == SMB1_HDRSTAT_WRITE) {
            goto smb1_write_hdr;
        } else
#endif // SMB1_SAVE_DATA == 1
#if SMB1_DECODE == 1
        if (smb_flow->hdrstat == SMB1_HDRSTAT_SMB1) {
            tmp = sizeof(smb1_header_t) - smb_flow->hdroff;
            if (remaining < tmp) {
                smb_flow->hdrstat = 0;
                smb_flow->hdroff = 0;
                return;
            }
            memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            smb1 = (smb1_header_t*)smb_flow->hdr;
            version = smb1->proto_id;
            goto smb_version;
        } else
#endif // SMB1_DECODE == 1
#if SMB2_SAVE_DATA == 1
        if (smb_flow->hdrstat == SMB2_HDRSTAT_DATA) {
            goto write_data;
        } else if (smb_flow->hdrstat == SMB2_HDRSTAT_RDATA) {
            smb_flow->hdrstat = 0;
            goto smb2_read;
        } else if (smb_flow->hdrstat == SMB2_HDRSTAT_WRITE) {
            goto write_hdr;
        } else if (smb_flow->hdrstat == SMB2_HDRSTAT_READ) {
            goto read_hdr;
        } else
#endif // SMB2_SAVE_DATA == 1
        if (smb_flow->hdrstat == SMB2_HDRSTAT_SMB2) {
            tmp = sizeof(smb2_header_t) - smb_flow->hdroff;
            if (remaining < tmp) {
                smb_flow->hdrstat = 0;
                smb_flow->hdroff = 0;
                return;
            }
            memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            smb2 = (smb2_header_t*)smb_flow->hdr;
            version = smb2->proto_id;
            goto smb_version;
        } else if (smb_flow->hdrstat == SMB_HDRSTAT_SMB) {
            tmp = sizeof(smb1_header_t) - smb_flow->hdroff;
            if (remaining < tmp) {
                smb_flow->hdrstat = 0;
                smb_flow->hdroff = 0;
                return;
            }
            memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            version = ((smb_flow->hdr[0] << 24) | (smb_flow->hdr[1] << 16) |
                       (smb_flow->hdr[2] << 8)  | (smb_flow->hdr[3]));
            switch (version) {
                case SMB1_MAGIC_HDR:
#if SMB1_DECODE == 1
                    smb_flow->hdrstat = SMB1_HDRSTAT_SMB1;
                    smb1 = (smb1_header_t*)smb_flow->hdr;
#endif // SMB1_DECODE == 1
                    break;
                case SMB2_MAGIC_HDR:
                    smb_flow->hdrstat = SMB2_HDRSTAT_SMB2;
                    smb2 = (smb2_header_t*)smb_flow->hdr;
                    break;
                case SMB3_MAGIC_HDR:
                    // TODO not implemented yet
                default:
                    smb_flow->hdrstat = 0;
                    smb_flow->hdroff = 0;
                    return;
            }
            goto smb_version;
        }

        // Netbios Session Header
        if (remaining <= NB_SS_HDR_LEN) {
            if (flow->status & SNAPLENGTH) return;
            if (remaining >= 1 && *ptr != 0) return;
            smb_flow->hdrstat = SMB_HDRSTAT_NB;
            smb_flow->hdroff = remaining;
            return;
        }

        if (smb_flow->hdrstat == SMB_HDRSTAT_NB && smb_flow->hdroff != 0) {
            smb_flow->hdrstat = 0;
            tmp = NB_SS_HDR_LEN - smb_flow->hdroff;
            if (remaining < tmp) {
                smb_flow->hdroff = 0;
                return;
            }
            //printf("rebuilding NB header %d %d\n", tmp, remaining);
            ptr += tmp;
            remaining -= tmp;
            smb_flow->hdroff = 0;
        } else {
            // zero(8),smb message length(24)
            if (*ptr != 0) return;

            ptr += NB_SS_HDR_LEN;
            remaining -= NB_SS_HDR_LEN;
        }

        if (remaining < sizeof(uint32_t)) {
            if (flow->status & SNAPLENGTH) return;
            //printf("remaining < uint32_t(version)\n");
            smb_flow->hdrstat = SMB_HDRSTAT_SMB; // SMB, version unknown
            if (remaining) {
                memcpy(smb_flow->hdr, ptr, remaining);
                smb_flow->hdroff = remaining;
            }
            return;
        }

        version = *(uint32_t*)ptr;

smb_version:
        switch (version) { // SMB protocol id

            case SMB1_MAGIC_HDR: {
                num_smb[0]++;
#if SMB1_DECODE == 1
                if (smb_flow->hdrstat != SMB1_HDRSTAT_SMB1) {
                    // SMB1 header
                    if (remaining < sizeof(smb1_header_t)) {
                        if (flow->status & SNAPLENGTH) return;
                        smb_flow->hdrstat = SMB1_HDRSTAT_SMB1;
                        if (remaining) {
                            memcpy(smb_flow->hdr, ptr, remaining);
                            smb_flow->hdroff = remaining;
                        }
                        return;
                    }

                    smb1 = (smb1_header_t*) ptr;
                    if (smb_flow->hdrstat == SMB1_HDRSTAT_DATA) {
                        smb_flow->hdrstat = 0;
                    }

                    ptr += sizeof(smb1_header_t);
                    remaining -= sizeof(smb1_header_t);
                } else {
                    smb_flow->hdrstat = 0;
                    smb_flow->hdroff = 0;
                }

                if (smb1->cmd == SMB1_CMD_CREATE_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        const smb1_create_andx_req_t * const c = (smb1_create_andx_req_t*)ptr;
                        if (remaining <= sizeof(*c)) return;
                        ptr += sizeof(*c);
                        remaining -= sizeof(*c);
                        uint8_t *x = ptr;
                        uint16_t i, len;
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            strncpy(smb_flow->fname, (char*)x, SMB_NATIVE_NAME_LEN);
                        } else {
                            len = MIN(c->NameLength / 2, SMB_FNAME_LEN);
                            if (remaining < 2*len) return;
                            if (len < c->NameLength / 2) smb_flow->stat |= SMB_STAT_NAMETRUNC;
                            uint16_t tmp;
                            for (i = 0; i < len; i++) {
                                tmp = *(uint16_t*)x;
                                if (tmp < 128 && *x != '\\') {
                                    smb_flow->fname[i] = *x;
                                } else {
                                    smb_flow->fname[i] = '_';
                                }
                                x += 2;
                            }
                            smb_flow->fname[i] = '\0';
                        }
                        if (remaining < c->NameLength) return;
                        ptr += c->NameLength;
                        remaining -= c->NameLength;
                        len = strlen(smb_flow->fname);
                        if (len == 0 || remaining < len) return;
                        for (i = 0; i < MIN(smb_flow->numSFile, SMB_NUM_FNAME); i++) {
                            if (memcmp(smb_flow->sname[i], smb_flow->fname, len) == 0) return;
                        }
                        if (smb_flow->numSFile < SMB_NUM_FNAME) {
                            memcpy(smb_flow->sname[smb_flow->numSFile], smb_flow->fname, len);
                        } else smb_flow->stat |= SMB_STAT_FNAMEL;
                        smb_flow->numSFile++;
                    } else { // RESPONSE
#if SMB1_SAVE_DATA == 1
                        const smb1_create_andx_resp_t * const c = (smb1_create_andx_resp_t*)ptr;
                        if (remaining <= sizeof(*c)) return;
                        ptr += sizeof(*c);
                        remaining -= sizeof(*c);
                        const unsigned long ofidx = flow->oppositeFlowIndex;
                        if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                            const smb_flow_t * const revflow = &smb_flows[ofidx];
                            if (revflow && strlen(revflow->fname) > 0) {
                                fprintf(guidMapF, "%s%04x_%"PRIu64"\t%s\n",
                                    SMB_FILE_ID, c->fid, flow->findex, revflow->fname);
                            }
                        }
#endif // SMB1_SAVE_DATA == 1
                    }
                } else
#if SMB1_SAVE_DATA == 1
                if (smb1->cmd == SMB1_CMD_WRITE_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        smb1_write_andx_req_t *w = (smb1_write_andx_req_t*)ptr;
                        if (smb_flow->hdrstat == SMB1_HDRSTAT_WRITE) {
smb1_write_hdr:
                            memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, sizeof(*w) - smb_flow->hdroff);
                            if (remaining < (sizeof(*w) - smb_flow->hdroff)) return;
                            ptr += sizeof(*w) - smb_flow->hdroff;
                            remaining -= (sizeof(*w) - smb_flow->hdroff);
                            w = (smb1_write_andx_req_t*)smb_flow->hdr;
                            smb_flow->hdrstat = 0;
                        } else {
                            ptr += sizeof(*w);
                            if (remaining <= sizeof(*w)) {
                                smb_flow->hdrstat = SMB1_HDRSTAT_WRITE;
                                if (remaining) {
                                    memcpy(smb_flow->hdr, ptr, remaining);
                                    smb_flow->hdroff = remaining;
                                }
                                return;
                            }
                            remaining -= sizeof(*w);
                        }
                        // skip named pipes
                        if (w->bc == 0 || w->wmode & SMB1_WM_MSG_START) return;
                        smb_flow->left = w->bc - 1;
                        smb_flow->off = 0;
                        //printf("%#04x: off: %d, rem: %d, len: %d, bc: %d\n", w->fid, w->offset, w->remaining, w->dlen, w->bc);
                        snprintf(smb_flow->fname, 7, "%04x", w->fid);

smb1_write_data:;
                        char name[SMB_FNAME_LEN];
                        size_t fnamelen = sizeof(SMB_SAVE_DIR) + sizeof(SMB_FILE_ID) + strlen(smb_flow->fname) + 20;
                        if (fnamelen >= SMB_FNAME_LEN) {
                            smb_flow->stat |= SMB_STAT_NAMETRUNC;
                            fnamelen = SMB_FNAME_LEN;
                        }
                        snprintf(name, fnamelen, "%s%s%s_%"PRIu64, SMB_SAVE_DIR, SMB_FILE_ID, smb_flow->fname, flow->findex);
                        const size_t len = remaining;
                        if (len == 0) return;
                        FILE *f = fopen(name, "a");
                        if (f) fclose(f);
                        f = fopen(name, "r+");
                        if (UNLIKELY(!f)) return;
                        fseek(f, smb_flow->off, SEEK_SET);
                        fwrite(ptr, 1, len, f);
                        fclose(f);
                        smb_flow->left -= len;
                        smb_flow->off += len;
                        if (smb_flow->left > 0) {
                            smb_flow->hdrstat = SMB1_HDRSTAT_DATA;
                        } else {
                            smb_flow->hdrstat = 0;
                            smb_flow->off = 0;
                        }
                    } else {
                        // TODO response
                    }
                    return;
                } else
#endif // SMB1_SAVE_DATA
                if (smb1->cmd == SMB1_CMD_SESSION_SETUP_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        const smb1_session_setup_andx_req12_t * const s = (smb1_session_setup_andx_req12_t*) ptr;
                        if (s->wc != 12) return; // TODO s->wc==13
                        if (sizeof(*s)+s->secbloblen >= remaining) return;
                        remaining -= (sizeof(*s) + s->secbloblen);
                        ptr += sizeof(*s) + s->secbloblen;
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            uint16_t bc = s->bc - s->secbloblen;
                            strncpy(smb_flow->nativeos, (char*)ptr, SMB_NATIVE_NAME_LEN);
                            size_t tmp = strlen(smb_flow->nativeos)+1;
                            if (tmp > bc || remaining < tmp) return;
                            ptr += tmp;
                            bc -= tmp;
                            strncpy(smb_flow->nativelanman, (char*)ptr, SMB_NATIVE_NAME_LEN);
                            tmp = strlen(smb_flow->nativelanman)+1;
                            if (tmp > bc || remaining < tmp) return;
                            ptr += tmp;
                            bc -= tmp;
                            if (bc > 0) {
                                strncpy(smb_flow->primarydomain, (char*)ptr, SMB_NATIVE_NAME_LEN);
                                tmp = strlen(smb_flow->primarydomain)+1;
                                if (tmp > bc || remaining < tmp) return;
                                ptr += tmp;
                                bc -= tmp;
                            }
                        } else {
                            if (remaining && ((sizeof(*s)+s->secbloblen) & 0x1) != 0) ptr++; // padding
                            uint32_t i = 0;
                            uint16_t tmp;
                            uint16_t bc = s->bc - s->secbloblen;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smb_flow->nativeos[i] = *ptr;
                                else smb_flow->nativeos[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smb_flow->nativeos[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            ptr += 2;
                            bc -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smb_flow->nativelanman[i] = *ptr;
                                else smb_flow->nativelanman[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smb_flow->nativelanman[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            ptr += 2;
                            bc -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smb_flow->primarydomain[i] = *ptr;
                                else smb_flow->primarydomain[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smb_flow->primarydomain[i] = '\0';
                        }
#if SMB_SECBLOB == 1
                        if (s->secbloblen > 0) {
                            ptr = (uint8_t*)s + sizeof(*s);
                            if (l7end - ptr <= 0) return;
                            const void * const vtmp = memmem(ptr, /*s->secbloblen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                            if (!vtmp) return;
                            ptr += ((uint8_t*)vtmp - ptr);
                            remaining -= ((uint8_t*)vtmp - ptr);

                            const ntlmssp_auth_t * const a = (ntlmssp_auth_t*)ptr;
                            if (remaining < sizeof(*a)) return;
                            if (a->type != NTLMSSP_MT_AUTH) return;

                            uint32_t i, off;
                            uint8_t *tmp;

                            if (a->nt_resp_len >= 16) {
                                // NTProofStr
                                off = 0;
                                tmp = ptr + a->nt_resp_off;
                                if (remaining < sizeof(*a) + a->nt_resp_off + 16) return;
                                for (i = 0; i < 16; i++) {
                                    snprintf(&(smb_flow->ntproof[off]), 3, "%02"B2T_PRIX8, *tmp);
                                    off += 2;
                                    tmp++;
                                }
                                smb_flow->ntproof[off] = '\0';

                                // NTLMv2 response *TODO: check length
                                off = 0;
                                const uint16_t len = a->nt_resp_len - 16;
                                if (remaining < sizeof(*a) + a->nt_resp_off + 16 + len) return;
                                for (i = 0; i < len; i++) {
                                    snprintf(&(smb_flow->ntlmclientchallenge[off]), 3, "%02"B2T_PRIX8, *tmp);
                                    off += 2;
                                    tmp++;
                                }
                                smb_flow->ntlmclientchallenge[off] = '\0';
                            }

                            tmp = ptr + a->dom_off;
                            if (remaining < sizeof(*a) + a->dom_off + a->dom_len) return;
                            //SMB_READ_U16_STR(smb_flow->host_name, tmp, a->host_len/2);
                            for (i = 0; i < a->dom_len/2; i++) {
                                smb_flow->domain_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->user_off;
                            //SMB_READ_U16_STR(smb_flow->user_name, tmp, a->user_len/2);
                            if (remaining < sizeof(*a) + a->user_off + a->user_len) return;
                            for (i = 0; i < a->user_len/2; i++) {
                                smb_flow->user_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->host_off;
                            //SMB_READ_U16_STR(smb_flow->host_name, tmp, a->host_len/2);
                            if (remaining < sizeof(*a) + a->host_off + a->host_len) return;
                            for (i = 0; i < a->host_len/2; i++) {
                                smb_flow->host_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->session_off;
                            off = 0;
                            if (remaining < sizeof(*a) + a->session_off + a->session_len) return;
                            for (i = 0; i < a->session_len; i++) {
                                snprintf(&(smb_flow->sessionkey[off]), 3, "%02"B2T_PRIX8, *tmp);
                                off += 2;
                                tmp++;
                            }
                            smb_flow->sessionkey[off] = '\0';
                            // TODO Version
                        }
#endif // SMB_SECBLOB == 1
                    } else { // RESPONSE
                        const smb1_session_setup_andx_resp_t * const s = (smb1_session_setup_andx_resp_t*) ptr;
                        if (s->wc == 0) return;
                        uint16_t bc = s->bc;
                        ptr += sizeof(*s);
                        if (s->wc == 4) {
#if SMB_SECBLOB == 1
                            if (l7end - ptr <= 0) return;
                            const void * const tmp = memmem(ptr, /*s->bc*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                            if (!tmp) return;
                            const ntlmssp_challenge_t * const c = (ntlmssp_challenge_t*)tmp;
                            if (c->type != NTLMSSP_MT_CHALLENGE) return;

                            // NTLM Server challenge
                            uint32_t i, off = 0;
                            for (i = 0; i < 8; i++) {
                                snprintf(&(smb_flow->ntlmserverchallenge[off]), 3, "%02"B2T_PRIX8, c->nonce[i]);
                                off += 2;
                            }
                            smb_flow->ntlmserverchallenge[off] = '\0';
#endif // SMB_SECBLOB == 1
                            bc = *(uint16_t*)ptr;
                            if (remaining < (uint32_t)(2 + s->bc)) return;
                            ptr += 2 + s->bc; // skip security blob
                            remaining -= (2 + s->bc);
                        }
                        if (remaining < sizeof(*s)) return;
                        remaining -= sizeof(*s);
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            strncpy(smb_flow->nativeos, (char*)ptr, SMB_NATIVE_NAME_LEN);
                            size_t tmp = strlen(smb_flow->nativeos)+1;
                            if (tmp >= bc || remaining < tmp) return;
                            ptr += tmp;
                            remaining -= tmp;
                            bc -= tmp;
                            strncpy(smb_flow->nativelanman, (char*)ptr, SMB_NATIVE_NAME_LEN);
                            tmp = strlen(smb_flow->nativelanman)+1;
                            if (tmp >= bc || remaining < tmp) return;
                            ptr += tmp;
                            remaining -= tmp;
                            bc -= tmp;
                            if (bc > 1 && remaining > 1) {
                                strncpy(smb_flow->primarydomain, (char*)ptr, SMB_NATIVE_NAME_LEN);
                                tmp = strlen(smb_flow->primarydomain)+1;
                                if (remaining < tmp) return;
                                ptr += tmp;
                                remaining -= tmp;
                            }
                        } else {
                            if (((sizeof(*s)+((s->wc==4) ? (2+s->bc) : 0)) & 0x1) != 0) {
                                if (bc < 1 || remaining < 1) return;
                                ptr++; // padding
                                remaining--;
                                bc--;
                            }
                            uint32_t i = 0;
                            uint16_t tmp;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smb_flow->nativeos[i] = *ptr;
                                else smb_flow->nativeos[i] = '_';
                                ptr += 2;
                                remaining -= 2;
                                bc -= 2;
                                i++;
                            }
                            smb_flow->nativeos[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            bc -= 2;
                            ptr += 2;
                            remaining -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smb_flow->nativelanman[i] = *ptr;
                                else smb_flow->nativelanman[i] = '_';
                                ptr += 2;
                                remaining -= 2;
                                bc -= 2;
                                i++;
                            }
                            smb_flow->nativelanman[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            bc -= 2;
                            ptr += 2;
                            remaining -= 2;
                            if (bc > 2) {
                                i = 0;
                                while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && (l7end - ptr) != 0 && *(uint16_t*)ptr != 0) {
                                    tmp = *(uint16_t*)ptr;
                                    if (tmp < 128) smb_flow->primarydomain[i] = *ptr;
                                    else smb_flow->primarydomain[i] = '_';
                                    ptr += 2;
                                    remaining -= 2;
                                    bc -= 2;
                                    i++;
                                }
                                smb_flow->primarydomain[i] = '\0';
                            }
                        }
                    }
                }
#endif // SMB1_DECODE
#if SMB1_NUM_DIALECT > 0
                if (smb1->cmd != SMB1_CMD_NEGOTIATE) return;
                if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                    const smb1_negotiate_req_t * const n = (smb1_negotiate_req_t*)ptr;
                    if (remaining < sizeof(*n)) return;
                    remaining -= sizeof(*n);
                    ptr += sizeof(*n);
                    size_t len, maxlen;
                    uint32_t ndialect1 = 0;
                    const uint8_t diff = (smb_flow->ndialect1 == 0) ? 0 : 1;
                    while (remaining > 1) {
                        ptr++; // skip buffer format
                        len = strlen((char*)ptr);
                        maxlen = MIN(len, SMB1_DIAL_MAXLEN);
                        if (remaining < maxlen) return;
                        if (maxlen < len) smb_flow->stat |= SMB_STAT_DIALNAME;
                        if (diff == 0) {
                            if (smb_flow->ndialect1 < SMB1_NUM_DIALECT) {
                                strncpy(smb_flow->dialect1[smb_flow->ndialect1], (char*)ptr, maxlen);
                                smb_flow->dialect1[smb_flow->ndialect1][maxlen] = '\0';
                            } else {
                                smb_flow->stat |= SMB_STAT_DIAL1L;
                            }
                            smb_flow->ndialect1++;
                        } else {
                            if (strncmp(smb_flow->dialect1[ndialect1], (char*)ptr, maxlen) != 0) smb_flow->stat |= SMB_STAT_MALFORMED;
                            ndialect1++;
                        }
                        len++; // include '\0'
                        if (len+1 <= remaining) remaining -= (len + 1); // skip buffer format and dialect
                        else remaining = 0;
                        ptr += len;
                    }

                } else { // RESPONSE
                    const unsigned long ofidx = flow->oppositeFlowIndex;
                    if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                        const smb1_negotiate_resp_t * const n = (smb1_negotiate_resp_t*)ptr;
                        if (remaining < sizeof(*n)) return;
                        const smb_flow_t * const revflow = &smb_flows[ofidx];
                        const uint16_t sdi = n->sdi;
                        if (n->wc > 0 && sdi < revflow->ndialect1) {
                            if (sdi < SMB1_NUM_DIALECT) {
                                smb_flow->ndialect1 = 1;
                                strncpy(smb_flow->dialect1[0], revflow->dialect1[sdi], strlen(revflow->dialect1[sdi])+1);
                            } else {
                                smb_flow->stat |= SMB_STAT_DIAL_OOB;
                            }
                        } else {
                            smb_flow->stat |= SMB_STAT_INV_DIAL;
                        }
                    }
                }
#endif // SMB1_NUM_DIALECT > 0
                return;
            }

            case SMB2_MAGIC_HDR: {
                num_smb[1]++;
                if (smb_flow->hdrstat != SMB2_HDRSTAT_SMB2) {
                    // SMB2 header
                    if (remaining < sizeof(smb2_header_t)) {
                        if (flow->status & SNAPLENGTH) return;
                        smb_flow->hdrstat = SMB2_HDRSTAT_SMB2;
                        if (remaining) {
                            memcpy(smb_flow->hdr, ptr, remaining);
                            smb_flow->hdroff = remaining;
                        }
                        return;
                    }

                    smb2 = (smb2_header_t*) ptr;
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_DATA) {
                        smb_flow->hdrstat = 0;
                    }

                    ptr += sizeof(smb2_header_t);
                    remaining -= sizeof(smb2_header_t);
                } else {
                    smb_flow->hdrstat = 0;
                    smb_flow->hdroff = 0;
                }
                smb_flow->msg_id = smb2->msg_id;
                break;
            }

            // Ignore SMB3 for now...
            case SMB3_MAGIC_HDR: num_smb[2]++; return;
            default:                           return;
        }

        // length
        if (smb2->len != SMB2_HDR_LEN) {
            smb_flow->stat |= SMB_STAT_MALFORMED;
            return;
        }

#if SMB2_NUM_STAT > 0
        // status
        if (!SMB2_IS_REQUEST(smb2)) { // RESPONSE
            uint32_t i, found = 0;
            uint32_t imax = MIN(smb_flow->numstat, SMB2_NUM_STAT);
            for (i = 0; i < imax && !found; i++) {
                if (smb_flow->smbstat[i] == smb2->status) found = 1;
            }
            if (!found) {
                if (smb_flow->numstat < SMB2_NUM_STAT)
                    smb_flow->smbstat[smb_flow->numstat] = smb2->status;
                else smb_flow->stat |= SMB_STAT_SMB2STAT;
                smb_flow->numstat++;
            }
        }
#endif // SMB2_NUM_STAT > 0

        // opcode
        if (smb2->opcode >= SMB2_OP_N) {
            smb_flow->stat |= SMB_STAT_MALFORMED;
            return;
        }
        smb_flow->opcodes |= (1 << smb2->opcode);
        smb_flow->nopcode[smb2->opcode]++;

        switch (smb2->opcode) {

            case SMB2_OP_CREATE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_create_req_t * const c = (smb2_create_req_t*) ptr;
                    uint8_t *x = ((uint8_t*)smb2 + c->fnameoff);
                    remaining -= sizeof(*c);
                    //T2_INF("%d\n", remaining);
                    if (remaining == 0) return;
                    const uint16_t len = MIN(c->fnamelen / 2, SMB_FNAME_LEN);
                    if (len < c->fnamelen / 2) smb_flow->stat |= SMB_STAT_NAMETRUNC;
                    uint16_t i, tmp;
                    for (i = 0; i < len; i++) {
                        tmp = *(uint16_t*)x;
                        if (tmp < 128 && *x != '\\') {
                            smb_flow->fname[i] = *x;
                        } else {
                            smb_flow->fname[i] = '_';
                        }
                        x += 2;
                    }
                    smb_flow->fname[i] = '\0';
                    for (i = 0; i < MIN(smb_flow->numSFile, SMB_NUM_FNAME); i++) {
                        if (memcmp(smb_flow->sname[i], smb_flow->fname, len) == 0) return;
                    }
                    if (smb_flow->numSFile < SMB_NUM_FNAME) {
                        memcpy(smb_flow->sname[smb_flow->numSFile], smb_flow->fname, len);
                        smb_flow->sname[smb_flow->numSFile][len] = '\0';
                    } else smb_flow->stat |= SMB_STAT_FNAMEL;
                    smb_flow->numSFile++;
                } else { // SMB2 RESPONSE
#if SMB2_SAVE_DATA == 1
                    const smb2_create_resp_t * const c = (smb2_create_resp_t*) ptr;
                    const unsigned long ofidx = flow->oppositeFlowIndex;
                    if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                        const smb_flow_t * const revflow = &smb_flows[ofidx];
                        if (revflow && strlen(revflow->fname) > 0) {
                            fprintf(guidMapF, "File_Id_%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x_%"PRIu64"\t%s\n",
                                c->fid.d1, c->fid.d2, c->fid.d3,
                                c->fid.d4[0], c->fid.d4[1], c->fid.d4[2], c->fid.d4[3],
                                c->fid.d4[4], c->fid.d4[5], c->fid.d4[6], c->fid.d4[7],
                                flow->findex, revflow->fname);
                        }
                    }
#endif // SMB2_SAVE_DATA
                }
                return;
            }

            case SMB2_OP_CLOSE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    //smb2_close_req_t *c = (smb2_close_req_t*) ptr;
                } else { // RESPONSE
                    //smb2_close_resp_t *c = (smb2_close_resp_t*) ptr;
                }
                return;
            }

#if SMB2_SAVE_DATA == 1
            case SMB2_OP_WRITE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    smb2_write_t *w = (smb2_write_t*) ptr;
                    static const uint16_t wsize = 48;
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_WRITE) {
write_hdr:
                        memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, wsize - smb_flow->hdroff);
                        ptr += wsize - smb_flow->hdroff;
                        w = (smb2_write_t*)smb_flow->hdr;
                    }
                    if (remaining < wsize) {
                        smb_flow->hdrstat = SMB2_HDRSTAT_WRITE;
                        if (remaining) {
                            memcpy(smb_flow->hdr, ptr, remaining);
                            smb_flow->hdroff = remaining;
                        }
                        return;
                    }
                    smb_flow->left = w->datalen;
                    smb_flow->off = w->fileoff;
                    remaining -= wsize;
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_WRITE) {
                        smb_flow->hdrstat = 0;
                        remaining += smb_flow->hdroff;
                        smb_flow->hdroff = 0;
                    }
                    ptr += (w->dataoff - sizeof(smb2_header_t));

                    // use file id as name
                    snprintf(smb_flow->fname, 37,
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        w->fid.d1, w->fid.d2, w->fid.d3,
                        w->fid.d4[0], w->fid.d4[1], w->fid.d4[2], w->fid.d4[3],
                        w->fid.d4[4], w->fid.d4[5], w->fid.d4[6], w->fid.d4[7]);

write_data:;
                    const uint32_t len = smb_flow->left < remaining ? smb_flow->left : remaining;
                    //T2_PDBG("smbDecode", "%s:%d:writing %d at %ld finishing at %ld", smb_flow->fname, smb_flow->numPkts, len, smb_flow->off, smb_flow->off + len);

#if SMB_USE_FILTER > 0
#if SMB_USE_FILTER == 1
                    uint8_t found = 0;
#endif // SMB_USE_FILTER == 1
                    int i;
                    for (i = 0; smb_fmt[i]; i++) {
                        if (str_has_suffix(smb_flow->fname, smb_fmt[i])) {
#if SMB_USE_FILTER == 1
                            found = 1;
                            break;
#elif SMB_USE_FILTER == 2
                            return;
#endif // SMB_USE_FILTER
                        }
                    }
#if SMB_USE_FILTER == 1
                    if (!found) return;
#endif // SMB_USE_FILTER == 1
#endif // SMB_USE_FILTER

                    char name[SMB_FNAME_LEN];
                    size_t fnamelen = sizeof(SMB_SAVE_DIR) + sizeof(SMB_FILE_ID) + strlen(smb_flow->fname) + 20;
                    if (fnamelen >= SMB_FNAME_LEN) {
                        smb_flow->stat |= SMB_STAT_NAMETRUNC;
                        fnamelen = SMB_FNAME_LEN;
                    }
                    snprintf(name, fnamelen, "%s%s%s_%"PRIu64, SMB_SAVE_DIR, SMB_FILE_ID, smb_flow->fname, flow->findex);
                    FILE *f = fopen(name, "a");
                    if (f) fclose(f);
                    f = fopen(name, "r+");
                    if (UNLIKELY(!f)) return;
                    fseek(f, smb_flow->off, SEEK_SET);
                    fwrite(ptr, 1, len, f);
                    fclose(f);

                    smb_flow->off += len;
                    if (smb_flow->left <= remaining) {
                        ptr += smb_flow->left;
                        processed += smb_flow->left;
                        smb_flow->left = remaining - smb_flow->left;
                        smb_flow->hdrstat = 0;
                    } else {
                        smb_flow->left -= len;
                        if (smb_flow->left > 0) smb_flow->hdrstat = SMB2_HDRSTAT_DATA;
                        else smb_flow->hdrstat = 0;
                    }
                    remaining -= len;
                } else { // SMB2 RESPONSE
                    // TODO
                    return;
                }
                break;
            }
#endif // SMB2_SAVE_DATA == 1

#if SMB2_SAVE_DATA == 1
            case SMB2_OP_READ: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_read_req_t * const r = (smb2_read_req_t*) ptr;
                    snprintf(smb_flow->rname, sizeof(smb_flow->rname),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        r->fid.d1, r->fid.d2, r->fid.d3,
                        r->fid.d4[0], r->fid.d4[1], r->fid.d4[2], r->fid.d4[3],
                        r->fid.d4[4], r->fid.d4[5], r->fid.d4[6], r->fid.d4[7]);
                    smb_flow->roff = r->off;
                } else { // SMB2 RESPONSE
                    // TODO not all read records are counted...
                    smb2_read_resp_t *r = (smb2_read_resp_t*) ptr;
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_READ) {
read_hdr:
                        memcpy(smb_flow->hdr + smb_flow->hdroff, ptr, 17 - smb_flow->hdroff);
                        ptr += 17 - smb_flow->hdroff;
                        r = (smb2_read_resp_t*)smb_flow->hdr;
                    }
                    // TODO check SMB header status if not success, abort
                    if (r->dlen == 0) return;
                    if (remaining < sizeof(*r)) {
                        smb_flow->hdrstat = SMB2_HDRSTAT_READ;
                        if (remaining) {
                            memcpy(smb_flow->hdr, ptr, remaining);
                            smb_flow->hdroff = remaining;
                        }
                        return;
                    }
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_READ) {
                        smb_flow->hdrstat = 0;
                        remaining -= (17 - smb_flow->hdroff);
                        smb_flow->hdroff = 0;
                    } else {
                        ptr += sizeof(*r);
                        remaining -= sizeof(*r);
                    }
smb2_read:;
                    const unsigned long ofidx = flow->oppositeFlowIndex;
                    if (ofidx == HASHTABLE_ENTRY_NOT_FOUND) return; // request not seen
                    const smb_flow_t * const revflow = &smb_flows[ofidx];
                    if (revflow->msg_id != smb_flow->msg_id) return; // msg id do not match

                    const uint32_t len = remaining;
                    if (smb_flow->rleft == 0) {
                        smb_flow->rleft = r->dlen; // TODO fix warning
                        smb_flow->roff = revflow->roff;
                    }
                    if (smb_flow->rleft > len) smb_flow->hdrstat = SMB2_HDRSTAT_RDATA;
                    smb_flow->rleft -= len;
                    char name[SMB_FNAME_LEN];
                    size_t fnamelen = sizeof(SMB_SAVE_DIR) + sizeof(SMB_FILE_ID) + strlen(revflow->rname) + 20;
                    if (fnamelen >= SMB_FNAME_LEN) {
                        smb_flow->stat |= SMB_STAT_NAMETRUNC;
                        fnamelen = SMB_FNAME_LEN;
                    }
                    snprintf(name, fnamelen, "%s%s%s_%"PRIu64, SMB_SAVE_DIR, SMB_FILE_ID, revflow->rname, flow->findex);//TODO try without findex
                    FILE *f = fopen(name, "a");
                    if (f) fclose(f);
                    f = fopen(name, "r+");
                    if (UNLIKELY(!f)) return;
                    fseek(f, smb_flow->roff, SEEK_SET);
                    fwrite(ptr, 1, len, f);
                    fclose(f);
                    if (smb_flow->hdrstat == SMB2_HDRSTAT_RDATA) {
                        smb_flow->roff += len;
                        return;
                    }
                    if (smb_flow->rleft == 0) {
                        smb_flow->roff = 0;
                    }
                }
                return;
            }
#endif // SMB2_SAVE_DATA == 1

            case SMB2_OP_QUERY_INFO: {
                if (SMB2_IS_REQUEST(smb2)) {

                } else { // SMB2 RESPONSE
                    // TODO get info about file
                }
                return;
            }

            case SMB2_OP_QUERY_DIR: {
                // TODO [MS-FSCC], section 2.4
                if (SMB2_IS_REQUEST(smb2)) {

                } else { // SMB2 RESPONSE
                    // TODO get directory listing
                }
                return;
            }

            case SMB2_OP_TREE_CONNECT: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_tree_connect_req_t * const t = (smb2_tree_connect_req_t*) ptr;
                    uint8_t *x = ((uint8_t*)smb2 + t->pathoff);
                    const uint16_t len = MIN(t->pathlen / 2, SMB_FNAME_LEN);
                    if (len < t->pathlen / 2) smb_flow->stat |= SMB_STAT_NAMETRUNC;
                    uint16_t i, tmp;
                    for (i = 0; i < len; i++) {
                        tmp = *(uint16_t*)x;
                        if (tmp < 128) {
                            smb_flow->path[i] = *x;
                        } else {
                            smb_flow->path[i] = '_';
                        }
                        x += 2;
                    }
                    smb_flow->path[i] = '\0';
                } else { // SMB2 RESPONSE
                    const smb2_tree_connect_resp_t * const t = (smb2_tree_connect_resp_t*) ptr;
                    smb_flow->sharetype = t->sharetype;
                    smb_flow->shareflags = t->shareflags;
                    smb_flow->sharecaps = t->caps;
                    smb_flow->shareaccess = t->maxacc;
                }
                return;
            }

            case SMB2_OP_NEGOTIATE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_negotiate_req_t * const n = (smb2_negotiate_req_t*) ptr;
                    smb_flow->caps = n->caps;
                    smb_flow->secmod = n->secmod;
#if SMB2_NUM_DIALECT > 0
                    smb_flow->ndialect = (remaining - 36) / sizeof(uint16_t);
                    const uint8_t imax = MIN(smb_flow->ndialect, SMB2_NUM_DIALECT);
                    if (imax < smb_flow->ndialect) smb_flow->stat |= SMB_STAT_DIAL2L;
                    uint16_t *tmp = (uint16_t*)(ptr+36);
                    for (uint_fast8_t i = 0; i < imax; i++) {
                        smb_flow->dialect[i] = *tmp;
                        tmp++;
                    }
#endif // SMB2_NUM_DIALECT > 0
                    snprintf(smb_flow->guid, sizeof(smb_flow->guid),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        n->guid.d1, n->guid.d2, n->guid.d3,
                        n->guid.d4[0], n->guid.d4[1], n->guid.d4[2], n->guid.d4[3],
                        n->guid.d4[4], n->guid.d4[5], n->guid.d4[6], n->guid.d4[7]);
                } else { // SMB2 RESPONSE
                    const smb2_negotiate_resp_t * const n = (smb2_negotiate_resp_t*) ptr;
#if SMB2_NUM_DIALECT > 0
                    smb_flow->ndialect = 1;
                    smb_flow->dialect[0] = n->drev;
#endif // SMB2_NUM_DIALECT > 0
                    smb_flow->secmod = n->secmod;
                    smb_flow->caps = n->caps;
                    smb_flow->maxTSize = n->maxTSize;
                    smb_flow->maxRSize = n->maxRSize;
                    smb_flow->maxWSize = n->maxWSize;
                    smb_flow->bootTime = SMB_WIN_TIME_TO_UNIX(n->srvStartT);
                    snprintf(smb_flow->guid, sizeof(smb_flow->guid),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        n->guid.d1, n->guid.d2, n->guid.d3,
                        n->guid.d4[0], n->guid.d4[1], n->guid.d4[2], n->guid.d4[3],
                        n->guid.d4[4], n->guid.d4[5], n->guid.d4[6], n->guid.d4[7]);
#if SMB_SECBLOB == 1
                    if (n->secbuflen > 0) {
                        ptr += (n->secbufoff - SMB2_HDR_LEN);
                        const gssapi_t * const gss = (gssapi_t*)ptr;
                        ptr += sizeof(*gss);
                        if (gss->atag != 0x60) return;
                        if (gss->otag == 0x06) {
                            switch (*(uint64_t*)(ptr-2)) {
                                case SPNEGO_OID:
                                    // TODO list supported
                                    break;
                                default:
                                    //T2_PDBG("smbDecode", "Unhandled OID");
                                    break;
                            }
                        }
                    }
#endif // SMB_SECBLOB == 1
                }
                return;
            }

            case SMB2_OP_SESSION_SETUP: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_session_setup_req_t * const s = (smb2_session_setup_req_t*) ptr;
                    smb_flow->prevsessid = s->prevsessid;
#if SMB_SECBLOB == 1
                    if (s->secbuflen > 0) {
                        ptr += (s->secbufoff - SMB2_HDR_LEN);
                        if (l7end - ptr <= 0) return;
                        const void * const vtmp = memmem(ptr, /*s->secbuflen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                        if (!vtmp) return;
                        ptr += ((uint8_t*)vtmp - ptr);
                        remaining -= ((uint8_t*)vtmp - ptr);
                        ntlmssp_auth_t *a = (ntlmssp_auth_t*)ptr;
                        if (remaining < sizeof(*a)) return;
                        if (a->type != NTLMSSP_MT_AUTH) return;
                        uint32_t i;
                        uint8_t *tmp = ptr + a->dom_off;
                        //SMB_READ_U16_STR(smb_flow->domain_name, tmp, a->dom_len/2);
                        if (remaining < sizeof(*a) + a->dom_off + a->dom_len) return;
                        for (i = 0; i < a->dom_len/2; i++) {
                            smb_flow->domain_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->user_off;
                        //SMB_READ_U16_STR(smb_flow->user_name, tmp, a->user_len/2);
                        if (remaining < sizeof(*a) + a->user_off + a->user_len) return;
                        for (i = 0; i < a->user_len/2; i++) {
                            smb_flow->user_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->host_off;
                        //SMB_READ_U16_STR(smb_flow->host_name, tmp, a->host_len/2);
                        if (remaining < sizeof(*a) + a->host_off + a->host_len) return;
                        for (i = 0; i < a->host_len/2; i++) {
                            smb_flow->host_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->session_off;
                        uint32_t off = 0;
                        if (remaining < sizeof(*a) + a->session_off + a->session_len) return;
                        for (i = 0; i < a->session_len; i++) {
                            snprintf(&(smb_flow->sessionkey[off]), 3, "%02"B2T_PRIX8, *tmp);
                            off += 2;
                            tmp++;
                        }
                        smb_flow->sessionkey[off] = '\0';
                        // TODO Version
                    }
#endif // SMB_SECBLOB == 1
                    ptr += sizeof(*s);
                } else { // SMB2 RESPONSE
                    const smb2_session_setup_resp_t * const s = (smb2_session_setup_resp_t*) ptr;
                    smb_flow->sflags = s->sflags;
#if SMB_SECBLOB == 1
                    if (s->secbuflen > 0) {
                        if (s->secbufoff < SMB2_HDR_LEN) return;
                        if (remaining < (uint32_t)(s->secbufoff-SMB2_HDR_LEN)) return; // TODO fix warning
                        remaining -= (s->secbufoff-SMB2_HDR_LEN);
                        ptr += (s->secbufoff - SMB2_HDR_LEN);
                        if (l7end - ptr <= 0) return;
                        const void * const vtmp = memmem(ptr, /*s->secbuflen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                        if (!vtmp) return;
                        ptr += ((uint8_t*)vtmp - ptr);
                        remaining -= ((uint8_t*)vtmp - ptr);
                        const ntlmssp_challenge_t * const c = (ntlmssp_challenge_t*)ptr;
                        if (remaining < sizeof(*c)) return;
                        if (c->type != NTLMSSP_MT_CHALLENGE) return;
                        uint8_t *tmp = ptr + c->domoff;
                        uint32_t i;
                        //SMB_READ_U16_STR(smb_flow->target_name, ptr, c->domlen/2);
                        if (remaining < sizeof(*c) + c->domoff + c->domlen) return;
                        for (i = 0; i < c->domlen/2; i++) {
                            smb_flow->target_name[i] = *tmp;
                            tmp += 2;
                        }
                        smb_flow->target_name[i] = '\0';

                        // NTLM Server challenge
                        if (remaining < sizeof(*c) + 16) return;
                        uint32_t off = 0;
                        for (i = 0; i < 8; i++) {
                            snprintf(&(smb_flow->ntlmserverchallenge[off]), 3, "%02"B2T_PRIX8, c->nonce[i]);
                            off += 2;
                        }
                        smb_flow->ntlmserverchallenge[off] = '\0';
                        // TODO list supported
                    }
#endif // SMB_SECBLOB == 1
                }
                return;
            }

            default:
                T2_PDBG("smbDecode", "Unhandled SMB2 opcode %#02x", smb2->opcode);
                return;
        }
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    smb_flow_t * const smb_flow = &smb_flows[flowIndex];
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->stat, sizeof(uint16_t));
    uint32_t i, imax;
#if SMB1_NUM_DIALECT > 0
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->ndialect1, sizeof(uint32_t));
    imax = MIN(smb_flow->ndialect1, SMB1_NUM_DIALECT);
    outputBuffer_append(main_output_buffer, (char*)&imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, smb_flow->dialect1[i], strlen(smb_flow->dialect1[i])+1);
    }
#endif // SMB1_NUM_DIALECT > 0
#if SMB2_NUM_DIALECT > 0
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->ndialect, sizeof(uint32_t));
    imax = MIN(smb_flow->ndialect, SMB2_NUM_DIALECT);
    outputBuffer_append(main_output_buffer, (char*)&imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, (char*)&smb_flow->dialect[i], sizeof(uint16_t));
    }
#endif // SMB2_NUM_DIALECT > 0
#if SMB2_NUM_STAT > 0
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->numstat, sizeof(uint32_t));
    imax = MIN(smb_flow->numstat, SMB2_NUM_STAT);
    outputBuffer_append(main_output_buffer, (char*)&imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, (char*)&smb_flow->smbstat[i], sizeof(uint32_t));
    }
#endif // SMB2_NUM_STAT > 0
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->opcodes, sizeof(uint32_t));
    for (i = 0; i < SMB2_OP_N; i++) {
        outputBuffer_append(main_output_buffer, (char*)&smb_flow->nopcode[i], sizeof(uint32_t));
    }
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->prevsessid, sizeof(uint64_t));
    outputBuffer_append(main_output_buffer, smb_flow->nativeos, strlen(smb_flow->nativeos)+1);
    outputBuffer_append(main_output_buffer, smb_flow->nativelanman, strlen(smb_flow->nativelanman)+1);
    outputBuffer_append(main_output_buffer, smb_flow->primarydomain, strlen(smb_flow->primarydomain)+1);
    outputBuffer_append(main_output_buffer, smb_flow->target_name, strlen(smb_flow->target_name)+1);
    outputBuffer_append(main_output_buffer, smb_flow->domain_name, strlen(smb_flow->domain_name)+1);
    outputBuffer_append(main_output_buffer, smb_flow->user_name, strlen(smb_flow->user_name)+1);
    outputBuffer_append(main_output_buffer, smb_flow->host_name, strlen(smb_flow->host_name)+1);
    outputBuffer_append(main_output_buffer, smb_flow->ntlmserverchallenge, strlen(smb_flow->ntlmserverchallenge)+1);
    outputBuffer_append(main_output_buffer, smb_flow->ntproof, strlen(smb_flow->ntproof)+1);
#if SMB_SAVE_AUTH == 1
    //outputBuffer_append(main_output_buffer, smb_flow->ntlmclientchallenge, strlen(smb_flow->ntlmclientchallenge)+1);
#endif // SMB_SAVE_AUTH == 1
    outputBuffer_append(main_output_buffer, smb_flow->sessionkey, strlen(smb_flow->sessionkey)+1);
    outputBuffer_append(main_output_buffer, smb_flow->guid, strlen(smb_flow->guid)+1);
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->sflags, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->secmod, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->caps, sizeof(uint32_t));
    const uint64_t secs = smb_flow->bootTime;
    static const uint32_t zero = 0;
    outputBuffer_append(main_output_buffer, (char*)&secs, sizeof(uint64_t));
    outputBuffer_append(main_output_buffer, (char*)&zero, sizeof(uint32_t)); // nsec
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->maxTSize, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->maxRSize, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->maxWSize, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, smb_flow->path, strlen(smb_flow->path)+1);
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->sharetype, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->shareflags, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->sharecaps, sizeof(uint32_t));
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->shareaccess, sizeof(uint32_t));
    // accessed files
    outputBuffer_append(main_output_buffer, (char*)&smb_flow->numSFile, sizeof(uint32_t));
    imax = MIN(smb_flow->numSFile, SMB_NUM_FNAME);
    outputBuffer_append(main_output_buffer, (char*)&imax, sizeof(uint32_t));
    for (i = 0; i < imax; i++) {
        outputBuffer_append(main_output_buffer, smb_flow->sname[i], strlen(smb_flow->sname[i])+1);
    }

#if SMB_SAVE_AUTH == 1
    const flow_t * const flow = &flows[flowIndex];
    const unsigned long reverseFlowIndex = flow->oppositeFlowIndex;
    if (!(flow->status & L3FLOWINVERT) && reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        smb_flow_t * const reverseFlow = &smb_flows[reverseFlowIndex];
        if (strlen(smb_flow->user_name) && strlen(smb_flow->domain_name) &&
            strlen(reverseFlow->ntlmserverchallenge) && strlen(smb_flow->ntproof) &&
            strlen(smb_flow->ntlmclientchallenge))
        {
            smbNumAuth++;
            smb_flow->stat |= SMB_STAT_AUTH;
            reverseFlow->stat |= SMB_STAT_AUTH;
            fprintf(smbAuthFile, "# %"PRIu64"\n%s::%s:%s:%s:%s\n", flow->findex,
                    smb_flow->user_name, smb_flow->domain_name,
                    reverseFlow->ntlmserverchallenge, smb_flow->ntproof,
                    smb_flow->ntlmclientchallenge);
        }
    }
#endif // SMB_SAVE_AUTH == 1
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    T2_FPLOG_NUM(stream, "smbDecode", "Number of SMBv1 records", num_smb[0]);
    T2_FPLOG_NUM(stream, "smbDecode", "Number of SMBv2 records", num_smb[1]);
    T2_FPLOG_NUM(stream, "smbDecode", "Number of SMBv3 records", num_smb[2]);

#if SMB_SAVE_AUTH == 1
    T2_FPLOG_NUM(stream, "smbDecode", "Number of NetNTLMv2 hashes extracted", smbNumAuth);
#endif // SMB_SAVE_AUTH == 1
}


void onApplicationTerminate() {
    smbDecodeClean();
}


static void smbDecodeClean() {
#if SMB_SAVE_DATA == 1
    if (guidMapF) fclose(guidMapF);
#endif /// SMB_SAVE_DATA

#if SMB_SAVE_AUTH == 1
    if (smbAuthFile) fclose(smbAuthFile);
#endif /// SMB_SAVE_AUTH

    free(smb_flows);
}


#if SMB_USE_FILTER > 0
static inline int str_has_suffix(const char *str, const char *suffix) {
    if (!str || !suffix) return 0;
    const size_t str_len = strlen(str);
    const size_t suffix_len = strlen(suffix);
    if (str_len < suffix_len) return 0;
    return (strcmp(str + str_len - suffix_len, suffix) == 0);
}
#endif // SMB_USE_FILTER
