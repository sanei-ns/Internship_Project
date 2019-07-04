/*
 * sshDecode.c
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

#include "sshDecode.h"
#include "t2buf.h"


#if SSH_DEBUG == 1
#define SSH_DBG(format, args...) printf("sshDecode:pkt %"PRIu64": " format "\n", numPackets, ##args)
#else // SSH_DEBUG == 0
#define SSH_DBG(format, args...)
#endif // SSH_DEBUG == 0


// plugin variables

sshFlow_t *sshFlows;


// Static variables

#if SSH_DECODE == 1
// Message digest
static EVP_MD_CTX *mdctx;
static const EVP_MD *md;
#endif

static uint64_t numSSH;


// Tranalyzer functions

T2_PLUGIN_INIT("sshDecode", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(sshFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*sshFlows))))) {
        T2_PERR("sshDecode", "failed to allocate memory for sshFlows");
        exit(-1);
    }

#if SSH_DECODE == 1
    mdctx = EVP_MD_CTX_create();
    if (UNLIKELY(!mdctx)) {
        T2_PERR("sshDecode", "Failed to create digest context");
        free(sshFlows);
        return;
    }

    md = EVP_md5();
    if (UNLIKELY(!md)) {
        T2_PERR("sshDecode", "Failed to create message digest");
        EVP_MD_CTX_destroy(mdctx);
        free(sshFlows);
        return;
    }
#endif // SSH_DECODE == 1
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "sshStat", "SSH status");
    BV_APPEND_STR_R(bv, "sshVersion", "SSH version and software");
#if SSH_DECODE == 1
    BV_APPEND_STR_R(bv, "sshFingerprint", "SSH public key fingerprint");
    BV_APPEND_STR_R(bv, "sshCookie", "SSH cookie");
    BV_APPEND_STR_R(bv, "sshKEX", "SSH KEX Algorithms");
    BV_APPEND_STR_R(bv, "sshSrvHostKeyAlgo", "SSH server host key algorithms");
    BV_APPEND_STR_R(bv, "sshEncCS", "SSH encryption algorithms client to server");
    BV_APPEND_STR_R(bv, "sshEncSC", "SSH encryption algorithms server to client");
    BV_APPEND_STR_R(bv, "sshMacCS", "SSH MAC algorithms client to server");
    BV_APPEND_STR_R(bv, "sshMacSC", "SSH MAC algorithms server to client");
    BV_APPEND_STR_R(bv, "sshCompCS", "SSH compression algorithms client to server");
    BV_APPEND_STR_R(bv, "sshCompSC", "SSH compression algorithms server to client");
    BV_APPEND_STR_R(bv, "sshLangCS", "SSH languages client to server");
    BV_APPEND_STR_R(bv, "sshLangSC", "SSH languages server to client");
#endif // SSH_DECODE == 1
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__ ((unused)), unsigned long flowIndex) {
    sshFlow_t * const sshFlowP = &sshFlows[flowIndex];
    memset(sshFlowP, '\0', sizeof(sshFlow_t));
#if SSH_USE_PORT == 1
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->dstPort == SSH_PORT || flowP->srcPort == SSH_PORT) {
        sshFlowP->stat |= SSH_STAT_SSH;
    }
#endif
}


#if SSH_DECODE == 1
static void md5_hash_mem(t2buf_t *t2buf, uint32_t len, char *dst, uint32_t dst_len) {
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        T2_PERR("sshDecode", "Failed to initialize digest context");
        return;
    }

    if (!EVP_DigestUpdate(mdctx, t2buf->buffer+t2buf_tell(t2buf), len)) {
        T2_PERR("sshDecode", "Failed to update digest");
        return;
    }

    unsigned int dlen;
    unsigned char digest_value[EVP_MAX_MD_SIZE+1];
    if (!EVP_DigestFinal_ex(mdctx, digest_value, &dlen)) {
        T2_PERR("sshDecode", "Failed to finalize digest");
        return;
    }

    if (dst_len < 3 * dlen) {
        T2_PERR("sshDecode", "Destination buffer for message digest too small... increase to %u", 2 * dlen + 1);
        return;
    }

    t2buf_t tmp = t2buf_create(digest_value, dlen);
    t2buf_hexdecode(&tmp, dlen, dst, ':');
}


static inline void ssh_read_str(t2buf_t *t2buf, char *dst, uint32_t dst_len, const char *dbg
#if SSH_DEBUG == 0
        __attribute__((unused))
#endif
    )
{
    uint32_t len;
    t2buf_read_u32(t2buf, &len);

    t2buf_readnstr(t2buf, (uint8_t*)dst, dst_len, len, T2BUF_UTF8, true);

    SSH_DBG("%s: %s", dbg, dst);
}


static inline void ssh_read_hexstr(t2buf_t *t2buf, char *dst, uint32_t dlen, const char *dbg
#if SSH_DEBUG == 0
        __attribute__((unused))
#endif
    )
{
    t2buf_hexdecode(t2buf, dlen, dst, 0);
    SSH_DBG("%s: %s", dbg, dst);
}


static inline void ssh_read_mpint(t2buf_t *t2buf, const char *dbg
#if SSH_DEBUG == 0
        __attribute__((unused))
#endif
    )
{
    uint32_t len;
    t2buf_read_u32(t2buf, &len);

    char dst[2*len+1];
    ssh_read_hexstr(t2buf, dst, len, dbg);
}
#endif // SSH_DECODE == 1


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];

    const uint8_t proto = flowP->layer4Protocol;
    if (proto != L3_TCP) return;

    // Only first frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint32_t remaining = packet->snapL7Length;
    if (remaining == 0) return; // No payload

    const uint8_t * const ptr = packet->layer7Header;
    t2buf_t t2buf = t2buf_create(ptr, remaining);

    sshFlow_t * const sshFlowP = &sshFlows[flowIndex];

    // SSH protocol version exchange
    uint32_t magic;
    if (t2buf_peek_u32(&t2buf, &magic) && magic == SSH_MAGIC) {
        if (flowP->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND ||
            !(sshFlows[flowP->oppositeFlowIndex].stat & SSH_STAT_VER_FIRST))
        {
            // keep track of who sent the ssh version first
            sshFlowP->stat |= SSH_STAT_VER_FIRST;
        }
        sshFlowP->stat |= SSH_STAT_SSH;

        long len = t2buf_readline(&t2buf, (uint8_t *)sshFlowP->version, SSH_BUFSIZE, false);
        if (len > 0) { // len is at least 4 bytes because peek_u32 succeeded
            if (sshFlowP->version[len-2] == '\r') len--;
            else sshFlowP->stat |= SSH_STAT_MALFORMED; // backward compatibility
            sshFlowP->version[len-1] = '\0';
        } else if (len == T2BUF_DST_FULL) {
            sshFlowP->stat |= SSH_STAT_VER_TRUNC;
            sshFlowP->version[SSH_BUFSIZE] = '\0';
        } else if (len == T2BUF_NULL) {
            sshFlowP->stat |= SSH_STAT_MALFORMED; // NULL byte in banner
        }
        return;
    }

#if SSH_DECODE == 1
    if (!sshFlowP->stat) return;

    while (t2buf_left(&t2buf) > 5) {
        /* Packet length (min: 16, max: 32768) */
        uint32_t pkt_len;
        t2buf_read_u32(&t2buf, &pkt_len);

        /* Padding length (min: 4, max: 255) */
        uint8_t padlen;
        t2buf_read_u8(&t2buf, &padlen);

        if (pkt_len > 1 && (t2buf_left(&t2buf) < pkt_len - 1 || padlen >= pkt_len-1)) {
            // encrypted packet, tcp segment or snapped
            SSH_DBG("New encrypted or snapped record or TCP segment (length: %u, padding: %u)", pkt_len, padlen);
            return;
        }

        /* Message code */
        uint8_t msg_type;
        if (!t2buf_read_u8(&t2buf, &msg_type)) return;

        SSH_DBG("New Record (type: %u, length: %u, padding: %u)", msg_type, pkt_len, padlen);

        switch (msg_type) {
            case SSH_MSG_KEXINIT:
                SSH_DBG("Key Exchange Init");
                // cookie
                ssh_read_hexstr(&t2buf, sshFlowP->cookie, SSH_COOKIE_SIZE, "cookie");
                // kex algorithms
                ssh_read_str(&t2buf, sshFlowP->kex_algo, SSH_BUFSIZE, "kex_algo");
                // server host key algorithms
                ssh_read_str(&t2buf, sshFlowP->srv_host_key_algo, SSH_BUFSIZE, "srv_host_key_algo");
                // encryption algorithm client to server
                ssh_read_str(&t2buf, sshFlowP->enc_cs, SSH_BUFSIZE, "enc_cs");
                // encryption algorithm server to client
                ssh_read_str(&t2buf, sshFlowP->enc_sc, SSH_BUFSIZE, "enc_sc");
                // mac algorithm client to server
                ssh_read_str(&t2buf, sshFlowP->mac_cs, SSH_BUFSIZE, "mac_cs");
                // mac algorithm server to client
                ssh_read_str(&t2buf, sshFlowP->mac_sc, SSH_BUFSIZE, "mac_sc");
                // compression algorithm client to server
                ssh_read_str(&t2buf, sshFlowP->comp_cs, SSH_BUFSIZE, "comp_cs");
                // compression algorithm server to client
                ssh_read_str(&t2buf, sshFlowP->comp_sc, SSH_BUFSIZE, "comp_sc");
                // languages client to server
                ssh_read_str(&t2buf, sshFlowP->lang_cs, SSH_BUFSIZE, "lang_cs");
                // languages server to client
                ssh_read_str(&t2buf, sshFlowP->lang_sc, SSH_BUFSIZE, "lang_sc");
                // KEX first packet follows
                t2buf_skip_u8(&t2buf);
                // reserved
                t2buf_skip_u32(&t2buf);
                break;

            case SSH_MSG_NEWKEYS:
                SSH_DBG("New Keys");
                break;

            case 30: /* diffie-hellman key exchange init */
                SSH_DBG("Diffie-Hellman Key Exchange Init");
                sshFlowP->dh_key_exchange_init++;
                // DH client e
                ssh_read_mpint(&t2buf, "dh-client-e");
                break;

            case 31: { /* Diffie-Hellman Key Exchange Reply or
                          Diffie-Hellman Group Exchange Group */
                if (sshFlowP->dh_key_exchange_init) {
                    SSH_DBG("Diffie-Hellman Key Exchange Reply");
                    // host key length
                    uint32_t hklen;
                    t2buf_read_u32(&t2buf, &hklen);
                    const long start = t2buf_tell(&t2buf);
                    // host key type length
                    uint32_t hktlen;
                    t2buf_read_u32(&t2buf, &hktlen);
                    // host key type
                    t2buf_readnstr(&t2buf, (uint8_t*)sshFlowP->host_key_type, sizeof(sshFlowP->host_key_type), hktlen, T2BUF_UTF8, true);
                    if (memcmp(sshFlowP->host_key_type, "ssh-rsa", 7) == 0) {
                        // host key
                        // rsa public exponent
                        ssh_read_mpint(&t2buf, "rsa-public-exponent");
                        // rsa modulus (N)
                        ssh_read_mpint(&t2buf, "rsa-modulus-n");
                        const long end = t2buf_tell(&t2buf);
                        // Compute the fingerprint
                        t2buf_seek(&t2buf, start, SEEK_SET);
                        if (hklen > 4) {
                            md5_hash_mem(&t2buf, hklen-4, sshFlowP->fingerprint, sizeof(sshFlowP->fingerprint));
                        }
                        t2buf_seek(&t2buf, end, SEEK_SET);
                    } else if (memcmp(sshFlowP->host_key_type, "ssh-dss", 7) == 0) {
                        // dsa p
                        ssh_read_mpint(&t2buf, "dsa-p");
                        // dsa q
                        ssh_read_mpint(&t2buf, "dsa-q");
                        // dsa g
                        ssh_read_mpint(&t2buf, "dsa-g");
                        // dsa y
                        ssh_read_mpint(&t2buf, "dsa-y");
                    } /*else if (memcmp(sshFlowP->host_key_type, "ecdsa-sha2-", 11) == 0) {
                        char dst[255];
                        ssh_read_str(&t2buf, dst, SSH_BUFSIZE, "ecdsa-curve-id");
                        ssh_read_str(&t2buf, dst, SSH_BUFSIZE, "ecdsa-q");
                    }*/ else {
                        // TODO
                        // t2buf_skip_n(&t2buf, hklen);
                        return;
                    }
                    // DH server f
                    ssh_read_mpint(&t2buf, "dh-server-f");
                    // KEX DH H signature
                    uint32_t hlen;
                    t2buf_read_u32(&t2buf, &hlen);
                    char dst[2*hlen+1];
                    ssh_read_hexstr(&t2buf, dst, hlen, "kex_dh_h_sig");
                } else {
                    /* diffie-hellman group exchange group */
                    SSH_DBG("Diffie-Hellman Group Exchange Group");
                    // DH modulus (P)
                    ssh_read_mpint(&t2buf, "dh-modulus-p");
                    // DH base (G)
                    ssh_read_mpint(&t2buf, "dh-base-g");
                }
                break;
            }

            case 32: /* diffie-hellman group exchange init */
                SSH_DBG("Diffie-Hellman Group Exchange Init");
                // DH client e
                ssh_read_mpint(&t2buf, "dhclient-e");
                break;

            case 33: { /* diffie-hellman group exchange reply */
                SSH_DBG("Diffie-Hellman Group Exchange Reply");
                // KEX DH Host key
                uint32_t hklen;
                t2buf_read_u32(&t2buf, &hklen);
                const long start = t2buf_tell(&t2buf);
                char dst[2*hklen+1];
                ssh_read_hexstr(&t2buf, dst, hklen, "kex_dh_h_sig");
                const long end = t2buf_tell(&t2buf);
                // Compute the fingerprint
                t2buf_seek(&t2buf, start, SEEK_SET);
                md5_hash_mem(&t2buf, hklen, sshFlowP->fingerprint, sizeof(sshFlowP->fingerprint));
                t2buf_seek(&t2buf, end, SEEK_SET);
                // DH server f
                ssh_read_mpint(&t2buf, "dh-server-f");
                // KEX DH signature
                t2buf_read_u32(&t2buf, &hklen);
                char sig[2*hklen+1];
                ssh_read_hexstr(&t2buf, sig, hklen, "kex-dh-h-sig");
                break;
            }

            case 34: /* diffie-hellman group exchange request */
                SSH_DBG("Diffie-Hellman Group Exchange Request");
                // DH GEX Min
                t2buf_skip_u32(&t2buf);
                // DH GEX Number of Bits
                t2buf_skip_u32(&t2buf);
                // DH GEX Max
                t2buf_skip_u32(&t2buf);
                break;

            default:
                T2_PERR("sshDecode", "pkt %"PRIu64": Unhandled message type %u", numPackets, msg_type);
                return;
        }

        /* Padding */
        t2buf_skip_n(&t2buf, padlen);

        // TODO mac length?
    }
#endif // SSH_DECODE == 1
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    const sshFlow_t * const sshFlowP = &sshFlows[flowIndex];

    // Count the number of SSH flows
    if (sshFlowP->stat & SSH_STAT_SSH) numSSH++;

    // SSH status
    OUTBUF_APPEND_U8(main_output_buffer, sshFlowP->stat);

    // SSH version
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->version);

#if SSH_DECODE == 1
    // SSH public key fingerprint
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->fingerprint);

    // SSH cookie
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->cookie);

    // SSH KEX algorithms
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->kex_algo);

    // SSH Server Host Key algorithms
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->srv_host_key_algo);

    // SSH encryption algorithms client to server
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->enc_cs);

    // SSH encryption algorithms server to client
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->enc_sc);

    // SSH MAC algorithms client to server
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->mac_cs);

    // SSH MAC algorithms server to client
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->mac_sc);

    // SSH compression algorithms client to server
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->comp_cs);

    // SSH compression algorithms server to client
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->comp_sc);

    // SSH languages client to server
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->lang_cs);

    // SSH languages server to client
    OUTBUF_APPEND_OPTSTR(main_output_buffer, sshFlowP->lang_sc);
#endif // SSH_DECODE == 1
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "sshDecode", "Number of SSH flows", numSSH, totalFlows);
}


void onApplicationTerminate() {
    free(sshFlows);

#if SSH_DECODE == 1
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup();
#endif
}
