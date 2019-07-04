/*
 * sslDecode.c
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

#include "sslCipher.h"
#include "sslDecode.h"
#include "proto/capwap.h"
#include "t2buf.h"

#if SSL_ANALYZE_CERT == 1
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#if SSL_SAVE_CERT == 1
#include <openssl/pem.h>
#endif

#if SSL_JA3 == 1
#include <openssl/md5.h>
#endif

#if SSL_BLIST == 1 || SSL_JA3 == 1
#include "sslBlist.h"
#else
#include "global.h"
#endif

#if SSL_BLIST == 1
static ssl_blist_t *sslbl;
static uint32_t numBlistCerts;
#endif

#if SSL_JA3 == 1
static ssl_blist_t *sslja3;
static uint32_t numJA3;
#endif


// plugin variables
sslFlow_t *sslFlow;

#if SSL_ANALYZE_OVPN == 1
static uint32_t numOVPN;
#endif
static uint32_t numSSL2;
static uint32_t numSSL3[5];
static uint32_t numDTLS[3];

#if SSL_SAVE_CERT == 1
static uint32_t numSavedCerts;
#endif

static uint16_t sslProto;


// Static inline functions prototypes

#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_is_openvpn(t2buf_t *t2buf, packet_t *packet, sslFlow_t *sslFlowP);
static inline bool ssl_process_openvpn(t2buf_t *t2buf, sslFlow_t *sslFlowP);
#endif
static inline void ssl_process_sslv2(t2buf_t *t2buf, sslFlow_t *sslFlowP);
static inline bool ssl_process_alpn(t2buf_t *t2buf, uint16_t ext_len, sslFlow_t *sslFlowP);
static inline bool ssl_process_hello_extension(t2buf_t *t2buf, sslFlow_t *sslFlowP);
static inline bool ssl_read_tls_record_header(t2buf_t *t2buf, sslFlow_t *sslFlowP, sslRecordHeader_t *rec);
#if SSL_ANALYZE_CERT == 1
#if SSL_CERT_VALIDITY == 1
static inline bool ssl_asn1_convert(const ASN1_TIME *t, struct tm *dst);
#endif
static inline bool ssl_process_ht_cert(t2buf_t *t2buf, sslFlow_t *sslFlowP);
#endif // SSL_ANALYZE_CERT == 1
#if SSL_JA3 == 1
static inline void ssl_compute_ja3(uint8_t handshake_type, sslFlow_t *sslFlowP);
#endif


// helper functions

#define SSL_OUTBUF_APPEND_STR(str) OUTBUF_APPEND_OPTSTR(main_output_buffer, str)


#if SSL_CERT_VALIDITY == 1
static inline bool ssl_asn1_convert(const ASN1_TIME *t, struct tm *dst) {
    if (t->type == V_ASN1_UTCTIME && t->length == 13 && t->data[12] == 'Z') {
        if (!strptime((const char *)t->data, "%y%m%d%H%M%SZ", dst)) {
            return false;
        }
    } else if (t->type == V_ASN1_GENERALIZEDTIME && t->length == 15 && t->data[14] == 'Z') {
        if (!strptime((const char *)t->data, "%Y%m%d%H%M%SZ", dst)) {
            return false;
        }
    } else {
        /* Invalid ASN.1 time */
        return false;
    }
    return true;
}
#endif // SSL_CERT_VALIDITY


static inline bool ssl_read_tls_record_header(t2buf_t *t2buf, sslFlow_t *sslFlowP, sslRecordHeader_t *rec) {

    // record header:
    //   type(8), version(16: major(8), minor(8))
    //   if type==DTLS: epoch(16), seqnum(48)
    //   len(16)

    // Record Type
    if (!t2buf_read_u8(t2buf, &rec->type)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (!SSL_RT_IS_VALID(rec->type)) {
        // If type is invalid, it could still be SSLv2...
        t2buf->pos--; // Unread the record type
        ssl_process_sslv2(t2buf, sslFlowP);
        return false;
    }

    // Record Version
    if (!t2buf_read_u16(t2buf, &rec->version)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (rec->version == SSLv3) {
        sslFlowP->vuln |= SSL_VULN_BEAST;
        sslFlowP->vuln |= SSL_VULN_POODLE;
        sslFlowP->stat |= SSL_STAT_WEAK_PROTO;
    } else if (SSL_V_IS_DTLS(rec->version)) {
        t2buf_skip_u16(t2buf); // epoch
        t2buf_skip_u48(t2buf); // seqnum
    } else if (!SSL_V_IS_SSL(rec->version)) {
        // invalid version... probably not ssl
        return false;
    }

    if (rec->type != SSL_HT_CLIENT_HELLO && sslFlowP->version != 0 && sslFlowP->version != rec->version) {
        sslFlowP->flags |= SSL_FLAG_VER;
        // TODO check that version matches between A and B flow
        sslFlowP->stat |= SSL_STAT_VERSION_MISMATCH;
    }

    // Record Length
    if (!t2buf_read_u16(t2buf, &rec->len)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    return true;
}


// Tranalyzer functions

T2_PLUGIN_INIT("sslDecode", "0.8.4", 0, 8);


void initialize() {
#if SSL_SAVE_CERT == 1
#if SSL_RM_CERTDIR == 1
    if (!rmrf(SSL_CERT_PATH)) {
        T2_PERR("sslDecode", "Failed to remove directory '%s': %s", SSL_CERT_PATH, strerror(errno));
        exit(-1);
    }
#endif // SSL_RM_CERTDIR
    if (mkdir(SSL_CERT_PATH, S_IRWXU) != 0 && errno != EEXIST) {
        T2_PERR("sslDecode", "Failed to create directory '%s': %s", SSL_CERT_PATH, strerror(errno));
        exit(-1);
    }
#endif // SSL_SAVE_CERT

    if (UNLIKELY(!(sslFlow = calloc(mainHashMap->hashChainTableSize, sizeof(sslFlow_t))))) {
        T2_PERR("sslDecode", "failed to allocate memory for sslFlow");
        exit(-1);
    }

#if SSL_BLIST == 1 || SSL_JA3 == 1
    const size_t plen = pluginFolder_len;
    char filename[pluginFolder_len + MAX(sizeof(SSL_BLIST_NAME), sizeof(SSL_JA3_NAME)) + 1];
    strncpy(filename, pluginFolder, plen+1);
#endif

#if SSL_BLIST == 1
    strncpy(filename+plen, SSL_BLIST_NAME, sizeof(SSL_BLIST_NAME)+1);
    sslbl = ssl_blist_load(filename, 40, SSL_BLIST_LEN);
    T2_PINF("sslDecode", "%"PRIu32" blacklisted certificates fingerprints", sslbl->count);
#endif

#if SSL_JA3 == 1
    strncpy(filename+plen, SSL_JA3_NAME, sizeof(SSL_JA3_NAME)+1);
    sslja3 = ssl_blist_load(filename, 32, SSL_JA3_DLEN);
    T2_PINF("sslDecode", "%"PRIu32" JA3 fingerprints loaded", sslja3->count);
#endif
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "sslStat", "SSL status");
    BV_APPEND_H16(bv, "sslProto", "SSL proto");

#if SSL_ANALYZE_OVPN == 1
    BV_APPEND_H16(bv, "ovpnType", "OpenVPN message types");
    BV_APPEND_U64(bv, "ovpnSessionID", "OpenVPN session ID");
#endif

    BV_APPEND_H8(bv, "sslFlags", "SSL flags");
    BV_APPEND_H16(bv, "sslVersion", "SSL version");
    BV_APPEND_H8(bv, "sslVuln", "SSL vulnerabilities");
    BV_APPEND_H32(bv, "sslAlert", "SSL alert");
    BV_APPEND_H16(bv, "sslCipher", "SSL preferred (Client) / negotiated (Server) cipher");

#if SSL_EXT_LIST == 1
    BV_APPEND_U16(bv, "sslNumExt", "SSL number of extensions");
    BV_APPEND_H16_R(bv, "sslExtList", "SSL list of extensions");
#endif

#if SSL_EC == 1
    BV_APPEND_U16(bv, "sslNumECPt", "SSL number of EC points");
    BV_APPEND_H16_R(bv, "sslECPt", "SSL list of EC points");
#endif

#if SSL_EC_FORMATS == 1
    BV_APPEND_U8(bv, "sslNumECFormats", "SSL number of EC point formats");
    BV_APPEND_H8_R(bv, "sslECFormats", "SSL list of EC point formats");
#endif

#if SSL_PROTO_LIST == 1
    BV_APPEND_U16(bv, "sslNumProto", "SSL number of protocols");
    BV_APPEND_STR_R(bv, "sslProtoList", "SSL list of protocols");
#endif

#if SSL_CIPHER_LIST == 1
    BV_APPEND_U16(bv, "sslNumCipher", "SSL number of supported ciphers");
    BV_APPEND_H16_R(bv, "sslCipherList", "SSL list of supported cipher");
#endif

    BV_APPEND(bv, "sslNumCC_A_H_AD_HB", "SSL number of change_cipher, alert, handshake, application data, heartbeat records", 5, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_64, bt_uint_64);
    BV_APPEND_U8(bv, "sslSessIdLen", "SSL Session ID length");
    BV_APPEND_TIMESTAMP_R(bv, "sslGMTTime", "SSL GMT Unix Time");
    BV_APPEND_STR_R(bv, "sslServerName", "SSL server name");

#if SSL_ANALYZE_CERT == 1
    BV_APPEND_U8_R(bv, "sslCertVersion", "SSL certificate version");
#if SSL_CERT_SERIAL == 1
    BV_APPEND_STRC_R(bv, "sslCertSerial", "SSL certificate serial number");
#endif
#if SSL_CERT_FINGPRINT == 2
    BV_APPEND_STRC_R(bv, "sslCertMd5FP", "SSL certificate MD5 fingerprint");
#elif SSL_CERT_FINGPRINT == 1
    BV_APPEND_STRC_R(bv, "sslCertSha1FP", "SSL certificate SHA1 fingerprint");
#endif
#if SSL_CERT_VALIDITY == 1
    BV_APPEND_R(bv, "sslCNotValidBefore_after_lifetime", "SSL certificate validity period (not valid before/after, lifetime (seconds))", 3, bt_timestamp, bt_timestamp, bt_uint_64);
#endif
#if SSL_CERT_SIG_ALG == 1
    BV_APPEND_STR_R(bv, "sslCSigAlg", "SSL certificate signature algorithm");
#endif
#if SSL_CERT_PUBKEY_ALG == 1
    BV_APPEND_STR_R(bv, "sslCKeyAlg", "SSL certificate public key algorithm");
#endif
#if SSL_CERT_PUBKEY_TS == 1
    BV_APPEND_R(bv, "sslCPKeyType_Size", "SSL certificate public key type, size (bits)", 2, bt_string_class, bt_uint_16);
#endif

    // Certificate Subject
#if SSL_CERT_SUBJECT == 1
    BV_APPEND_STR_R(bv, "sslCSubject", "SSL certificate subject");
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
    BV_APPEND_STR_R(bv, "sslCSubjectCommonName", "SSL certificate subject common name");
#endif
#if SSL_CERT_ORGANIZATION == 1
    BV_APPEND_STR_R(bv, "sslCSubjectOrgName", "SSL certificate subject organization name");
#endif
#if SSL_CERT_ORG_UNIT == 1
    BV_APPEND_STR_R(bv, "sslCSubjectOrgUnit", "SSL certificate subject organizational unit name");
#endif
#if SSL_CERT_LOCALITY == 1
    BV_APPEND_STR_R(bv, "sslCSubjectLocality", "SSL certificate subject locality name");
#endif
#if SSL_CERT_STATE == 1
    BV_APPEND_STR_R(bv, "sslCSubjectState", "SSL certificate subject state or province name");
#endif
#if SSL_CERT_COUNTRY == 1
    BV_APPEND_STRC_R(bv, "sslCSubjectCountry", "SSL certificate subject country name");
#endif
#endif // SSL_CERT_SUBJECT

    // Certificate Issuer
#if SSL_CERT_ISSUER == 1
    BV_APPEND_STR_R(bv, "sslCIssuer", "SSL certificate issuer");
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
    BV_APPEND_STR_R(bv, "sslCIssuerCommonName", "SSL certificate issuer common name");
#endif
#if SSL_CERT_ORGANIZATION == 1
    BV_APPEND_STR_R(bv, "sslCIssuerOrgName", "SSL certificate issuer organization name");
#endif
#if SSL_CERT_ORG_UNIT == 1
    BV_APPEND_STR_R(bv, "sslCIssuerOrgUnit", "SSL certificate issuer organizational unit name");
#endif
#if SSL_CERT_LOCALITY == 1
    BV_APPEND_STR_R(bv, "sslCIssuerLocality", "SSL certificate issuer locality name");
#endif
#if SSL_CERT_STATE == 1
    BV_APPEND_STR_R(bv, "sslCIssuerState", "SSL certificate issuer state or province name");
#endif
#if SSL_CERT_COUNTRY == 1
    BV_APPEND_STRC_R(bv, "sslCIssuerCountry", "SSL certificate issuer country name");
#endif
#endif // SSL_CERT_ISSUER

#if SSL_BLIST == 1
    BV_APPEND_STR_R(bv, "sslBlistCat", "SSL blacklisted certificate category");
#endif

#if SSL_JA3 == 1
    BV_APPEND_STRC_R(bv, "sslJA3Hash", "SSL JA3 fingerprint");
    BV_APPEND_STR_R(bv, "sslJA3Desc", "SSL JA3 description");
#if SSL_JA3_STR == 1
    BV_APPEND_STR_R(bv, "sslJA3Str", "SSL JA3 string");
#endif
#endif // SSL_JA3 == 1

#endif // SSL_ANALYZE_CERT

    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__ ((unused)), unsigned long flowIndex) {
    sslFlow_t * const sslFlowP = &sslFlow[flowIndex];
    memset(sslFlowP, '\0', sizeof(sslFlow_t));
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    const uint16_t snaplen = packet->snapL7Length;
    if (snaplen == 0) return; // No payload

    const flow_t * const flowP = &flows[flowIndex];
    const uint8_t proto = flowP->layer4Protocol;
    if (proto != L3_TCP && proto != L3_UDP && proto != L3_SCTP) return;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint8_t * const ptr = packet->layer7Header;
    t2buf_t t2buf = t2buf_create(ptr, snaplen);

    sslFlow_t *sslFlowP = &sslFlow[flowIndex];

#if SSL_ANALYZE_OVPN == 1
    if (ssl_is_openvpn(&t2buf, packet, sslFlowP)) {
        if (!ssl_process_openvpn(&t2buf, sslFlowP)) {
            return;
        }
    }
#endif

    if (packet->status & L3_CAPWAP) {
        // FIXME only works if CAPWAP was the last header...
        // TODO if (!t2buf_peek_u48(t2buf, &type) || type != 1) return;
        capwap_header_t *capwap = (capwap_header_t*)(t2buf.buffer + t2buf.pos);
        if (capwap->type != 1) return;
        t2buf_skip_u32(&t2buf); // CAPWAP header
        // DTLS
    }

    // SSL Record
    sslRecordHeader_t rec;

    while (t2buf_left(&t2buf) >= SSL_RT_HDR_LEN) {

        if (!ssl_read_tls_record_header(&t2buf, sslFlowP, &rec)) return;

        if (rec.len > SSL_RT_MAX_LEN) {
            // invalid length
            sslFlowP->stat |= SSL_STAT_REC_TOO_LONG;
            return;
        }

        sslFlowP->version = rec.version;

        const long recStart = t2buf_tell(&t2buf);

        switch (rec.type) {

            case SSL_RT_APPLICATION_DATA:  // encrypted
                sslFlowP->num_app_data++;
                break;

            case SSL_RT_CHANGE_CIPHER_SPEC: {
                // message consists of a single byte of value 1
                uint8_t one;
                if (!t2buf_read_u8(&t2buf, &one)) {
                    //sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }
                if (one != 1) sslFlowP->stat |= SSL_STAT_MALFORMED;
                sslFlowP->num_change_cipher++;
                break;
            }

            case SSL_RT_ALERT: {
                sslFlowP->num_alert++;

                uint8_t level, descr;
                if (!t2buf_read_u8(&t2buf, &level) ||
                    !t2buf_read_u8(&t2buf, &descr))
                {
                    //sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }

                if (level != SSL_AL_WARN && level != SSL_AL_FATAL) {
                    // encrypted or malformed
                    break;
                }

                if (level == SSL_AL_FATAL) {
                    sslFlowP->stat |= SSL_STAT_AL_FATAL;
                }

                SSL_SET_AD_BF(sslFlowP, descr);
                break;
            }

            case SSL_RT_HANDSHAKE: {
                sslFlowP->num_handshake++;
                if (!rec.len) break;

                // there can be multiple handshake messages
                while (t2buf_left(&t2buf) != 0 && rec.len > (t2buf_tell(&t2buf) - recStart)) {
                    const long hsStart = t2buf_tell(&t2buf);

                    uint8_t handshake_type;
                    uint32_t handshake_len;
                    if (!t2buf_read_u8(&t2buf, &handshake_type) ||
                        !t2buf_read_u24(&t2buf, &handshake_len))
                    {
                        //sslFlowP->stat |= SSL_STAT_SNAP;
                        return;
                    }

                    if (SSL_V_IS_DTLS(sslFlowP->version)) {
                        t2buf_skip_u16(&t2buf); // message_seq
                        t2buf_skip_u24(&t2buf); // fragment_offset
                        t2buf_skip_u24(&t2buf); // fragment_length
                    }

                    switch (handshake_type) {

                        case SSL_HT_HELLO_REQUEST:
                            sslFlowP->num_hello_req++;
                            break;

                        case SSL_HT_SERVER_HELLO:
                            /* FALLTHRU */
                        case SSL_HT_CLIENT_HELLO: {
                            if (!t2buf_read_u16(&t2buf, &sslFlowP->version)) {
                                //sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            if (!SSL_V_IS_VALID(sslFlowP->version)) {
                                // invalid version... message probably encrypted
                                sslFlowP->version = rec.version;
                                t2buf_skip_n(&t2buf, handshake_len);
                                break;
                            }

                            // GMT time is part of Random
                            uint32_t gmt;
                            if (!t2buf_peek_u32(&t2buf, &gmt)) {
                                //sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }
                            sslFlowP->gmt_time = gmt;

                            if  (sslFlowP->gmt_time < SSL_TS_1YEAR) {
                                sslFlowP->flags |= SSL_FLAG_STIME;
                            } else if (sslFlowP->gmt_time > ((uint32_t)packet->pcapHeader->ts.tv_sec + SSL_TS_5YEARS)) {
                                sslFlowP->flags |= SSL_FLAG_RTIME;
                            }

                            // peek into Random...
                            uint64_t rp1, rp2, rp3;
                            uint32_t rp4;
                            if (!t2buf_peek_u64(&t2buf, &rp1) ||
                                !t2buf_peek_u64(&t2buf, &rp2) ||
                                !t2buf_peek_u64(&t2buf, &rp3) ||
                                !t2buf_peek_u32(&t2buf, &rp4))
                            {
                                //sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            // make sure Random is random...
                            if ((rp1 == 0 && rp2 == 0 && rp3 == 0 && rp4 == 0) ||
                                (rp1 == UINT64_MAX && rp2 == UINT64_MAX &&
                                 rp3 == UINT64_MAX && rp4 == UINT32_MAX))
                            {
                                // Only 0s or only 1s
                                sslFlowP->flags |= SSL_FLAG_RAND;
                            }

                            // Skip Random
                            t2buf_skip_n(&t2buf, SSL_HELLO_RANDOM_LEN);

                            if (!t2buf_read_u8(&t2buf, &sslFlowP->session_len)) {
                                //sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            t2buf_skip_n(&t2buf, sslFlowP->session_len); // skip session_id
                            // if (id == 0) session not resumable
                            // else if (id != client_id) new session
                            // else resumed session

                            if (handshake_type == SSL_HT_CLIENT_HELLO) {
                                // TODO do we also have this on the ServerHello?
                                if (sslFlowP->session_len != 0) {
                                    sslFlowP->stat |= SSL_STAT_RENEGOTIATION;
                                }

                                // TODO do we also have this on the ServerHello?
                                if (SSL_V_IS_DTLS(sslFlowP->version)) {
                                    // TODO cookie MUST be 0 if message is not a reply to a hello_verify_request
                                    uint8_t cookie_len;
                                    if (!t2buf_read_u8(&t2buf, &cookie_len)) { // cookie length
                                        //sslFlowP->stat |= SSL_STAT_SNAP;
                                        return;
                                    }
                                    t2buf_skip_n(&t2buf, cookie_len); // cookie
                                }
                            }

                            uint16_t num_cipher;
                            if (handshake_type == SSL_HT_SERVER_HELLO) {
                                num_cipher = 1;
                            } else {
                                uint16_t cipher_len;
                                if (!t2buf_read_u16(&t2buf, &cipher_len)) {
                                    //sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                num_cipher = cipher_len / sizeof(uint16_t);
                            }

#if SSL_CIPHER_LIST == 1
                            sslFlowP->num_cipher = num_cipher;
#endif

                            uint16_t cipher;
                            for (uint_fast16_t i = 0; i < num_cipher; i++) {
                                if (!t2buf_read_u16(&t2buf, &cipher)) {
                                    //sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                SSL_FLAG_WEAK_CIPHER(sslFlowP, cipher);

                                if (i == 0) {
                                    // Preferred/Selected cipher
                                    sslFlowP->cipher = cipher;
                                }
#if SSL_CIPHER_LIST == 1
                                if (i < SSL_MAX_CIPHER) {
                                    sslFlowP->cipher_list[i] = cipher;
                                } else {
                                    sslFlowP->stat |= SSL_STAT_CIPHERL_TRUNC;
                                }
#endif
                            }

                            uint8_t comp_len;
                            if (handshake_type == SSL_HT_SERVER_HELLO) {
                                comp_len = 1;
                            } else {
                                if (!t2buf_read_u8(&t2buf, &comp_len)) {
                                    //sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }
                            }

                            // Compression methods
                            for (uint_fast8_t i = 0; i < comp_len; i++) {
                                uint8_t compr;
                                if (!t2buf_read_u8(&t2buf, &compr)) {
                                    //sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                if (compr == SSL_COMPRESSION_DEFLATE) {
                                    sslFlowP->flags |= SSL_FLAG_COMPR;
                                    sslFlowP->vuln |= SSL_VULN_BREACH;
                                    sslFlowP->vuln |= SSL_VULN_CRIME;
                                }
                            }

                            // Hello extensions (optional for TLS < 1.3)
                            const long pos = t2buf_tell(&t2buf);
                            if (rec.len       > (pos - recStart) &&  // Record not fully parsed yet
                                handshake_len > (pos - hsStart))     // Handshake not fully parsed yet (XXX redundant?)
                            {
                                // Ignore size of extensions
                                t2buf_skip_u16(&t2buf);

                                while (handshake_len > (t2buf_tell(&t2buf) - hsStart)) { /// XXX rec.len > (pos - recStart)?
                                    if (!ssl_process_hello_extension(&t2buf, sslFlowP)) return;
                                }
                            }
#if SSL_JA3 == 1
                            ssl_compute_ja3(handshake_type, sslFlowP);
#endif
                            break;
                        }

                        case SSL_HT_HELLO_VERIFY_REQUEST:
                            if (!t2buf_read_u16(&t2buf, &sslFlowP->version)) {
                                //sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            if (!SSL_V_IS_VALID(sslFlowP->version)) {
                                // invalid version... message probably encrypted
                                sslFlowP->version = rec.version;
                                t2buf_skip_n(&t2buf, handshake_len);
                                break;
                            }

                            t2buf_skip_u32(&t2buf); // cookie
                            break;

                        case SSL_HT_CERTIFICATE:
#if SSL_ANALYZE_CERT == 1
                            // only process first certificate
                            if (sslFlowP->cert_version != 0) {
#endif
                                t2buf_skip_n(&t2buf, rec.len - (t2buf_tell(&t2buf) - recStart));
#if SSL_ANALYZE_CERT == 1
                            } else if (!ssl_process_ht_cert(&t2buf, sslFlowP)) {
                                return;
                            }
#endif
                            break;

                        case SSL_HT_SERVER_HELLO_DONE:
                            // no payload
                            sslFlowP->num_server_hello_done++;
                            break;

                        case SSL_HT_CLIENT_KEY_EXCHANGE:
                        case SSL_HT_SERVER_KEY_EXCHANGE:
                        case SSL_HT_CERTIFICATE_REQUEST:
                        case SSL_HT_CERTIFICATE_VERIFY:
                        case SSL_HT_FINISHED:
                            if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);
                            // XXX else ???
                            break;

                        default:
                            // unknown handshake type... encrypted or not ssl
                            //if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);
                            t2buf_skip_n(&t2buf, rec.len - (t2buf_tell(&t2buf) - recStart));
                            break;
                    } // switch handshake_type

                    //if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);

                    if (rec.len == (t2buf_tell(&t2buf) - recStart)) break; // end of record
                    //if (rec.len - handshake_len - 4 == 0) break;

                    const size_t shift = handshake_len - (t2buf_tell(&t2buf) - hsStart) + 4;
                    if (shift > 0) /*handshake_len <= rec.len && shift)*/ t2buf_skip_n(&t2buf, shift);
                }
                break;
            }

            case SSL_RT_HEARTBEAT: {
                sslFlowP->num_heartbeat++;

                uint8_t type;
                uint16_t len;
                if (!t2buf_read_u8(&t2buf, &type) ||
                    !t2buf_read_u16(&t2buf, &len))
                {
                    //sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }

                if (type != SSL_HB_REQ && type != SSL_HB_RESP) {
                    sslFlowP->stat |= SSL_STAT_MALFORMED;
                }

                if (len > rec.len) {
                    sslFlowP->vuln |= SSL_VULN_HEART;
                    return;
                }

                t2buf_skip_n(&t2buf, len); // skip payload

                const uint16_t padding = (rec.len - len - SIZEOF_SSL_HEARTBEAT);
                if (padding < SSL_HB_MIN_PAD_LEN) {
                    sslFlowP->stat |= SSL_STAT_MALFORMED;
                }

                t2buf_skip_n(&t2buf, padding); // skip padding

                break;
            }

            default:
                // unknown record type... encrypted or not ssl
                break;
        }

        // next record?
        const size_t shift = rec.len - (t2buf_tell(&t2buf) - recStart);
        if (shift) t2buf_skip_n(&t2buf, shift);
    }
}


#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_is_openvpn(t2buf_t *t2buf, packet_t *packet, sslFlow_t *sslFlowP) {
    uint16_t length;
    return sslFlowP->proto & SSL_STAT_PROTO_OVPN || (
                t2buf_left(t2buf) >= 16          &&
                t2buf_peek_u16(t2buf, &length)   &&
                length == packet->packetL7Length-2);
}
#endif


#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_process_openvpn(t2buf_t *t2buf, sslFlow_t *sslFlowP) {
    t2buf_skip_u16(t2buf);  // skip packet length

    // opcode(5)/key_id(3)
    uint8_t opcode;
    if (!t2buf_read_u8(t2buf, &opcode)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    opcode = (opcode & 0xf8) >> 3;
    if (!SSL_OVPN_OPCODE_IS_VALID(opcode)) {
        // Invalid opcode
        return false;
    }
    sslFlowP->ovpnType |= (1 << opcode);

    if (!(sslFlowP->proto & SSL_STAT_PROTO_OVPN)) {
        sslFlowP->proto |= SSL_STAT_PROTO_OVPN;
        numOVPN++;
    }

    if (opcode == SSL_OVPN_DATA_V1 || opcode == SSL_OVPN_DATA_V2) {
        // No more processing required
        return false;
    }

    if (sslFlowP->ovpnSessID == 0) {
        if (!t2buf_read_u64(t2buf, &sslFlowP->ovpnSessID)) {
            //sslFlowP->stat |= SSL_STAT_SNAP;
            return false;
        }
    } else {
        // TODO test whether the session IDs match
        t2buf_skip_u64(t2buf);
    }

    // TODO only if tls_auth is used (heuristic)
//#if SSL_OVPN_TLS_AUTH == 1
//    // HMAC
//    t2buf_skip_n(t2buf, hmac_size);
//    if (t2buf_left(t2buf) >= 8) {
//        // PID
//        t2buf_skip_u32(t2buf);
//        // Net Time
//        t2buf_skip_u32(t2buf);
//    }
//#endif // SSL_OVPN_TLS_AUTH == 1

    if (opcode != SSL_OVPN_CTRL_V1) {
        // No more processing required
        return false;
    }

    // Message Packet-ID Array Length
    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    // Message Packet-ID Array
    if (len > 0) {
        t2buf_skip_n(t2buf, len * sizeof(uint32_t));
    }

    // Remote Session ID
    // Not present in first message
    // TODO check it matches opposite flow session id
    uint16_t rsid;
    if (!t2buf_peek_u16(t2buf, &rsid)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (rsid != 0) {
        t2buf_skip_u64(t2buf);
    }

    // Message Packet-ID
    t2buf_skip_u32(t2buf);

    // XXX do we really have to continue?
    return true;
}
#endif


static inline void ssl_process_sslv2(t2buf_t *t2buf, sslFlow_t *sslFlowP) {
    if (t2buf_left(t2buf) < SIZEOF_SSLV2) return;

    uint16_t len;
    uint8_t type;
    uint8_t v_major, v_minor;
    if (!t2buf_read_u16(t2buf, &len)    ||
        !t2buf_read_u8(t2buf, &type)    ||
        !t2buf_read_u8(t2buf, &v_major) ||
        !t2buf_read_u8(t2buf, &v_minor))
    {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return;
    }

    if (!SSL2_MT_IS_VALID(type)) return;  // Invalid message type, probably not SSL

    if (len & 0x8000) {
        // no padding, record header is 2 bytes
        len = (len & 0x7fff) + 2;
    } else {
        // padding, record header is 3 bytes
        len = (len & 0x3fff) + 3;
    }

    if (len - SIZEOF_SSLV2 > t2buf_left(t2buf)) {
        return; // Not enough data available... snapped or not SSL
    }

    const uint16_t version = v_major << 8 | v_minor;
    if (sslFlowP->version != SSLv2 && (version == SSLv2 || !SSL_V_IS_SSL(version))) {
        return; // ... probably not SSL
    }

    sslFlowP->version = version; // can be SSLv3 or TLSv1*
    if (version == SSLv2) {
        sslFlowP->stat |= SSL_STAT_WEAK_PROTO;
        sslFlowP->flags |= SSL_FLAG_V2;
    }

    // TODO keep on decoding...
}


static inline bool ssl_process_alpn(t2buf_t *t2buf, uint16_t ext_len, sslFlow_t *sslFlowP) {
    uint8_t proto_len;
    while (ext_len != 0) {
        if (!t2buf_read_u8(t2buf, &proto_len) ||
            proto_len > t2buf_left(t2buf))
        {
            //sslFlowP->stat |= SSL_STAT_SNAP;
            return false;
        }

        if (proto_len == 0) break;

        uint16_t proto16 = 0;

        if (proto_len >= sizeof(uint16_t)) {
            // If t2buf_peek_u16 fails, proto16 will still be 0
            t2buf_peek_u16(t2buf, &proto16);
            //if (!t2buf_peek_u16(t2buf, &proto16)) {
            //    //sslFlowP->stat |= SSL_STAT_SNAP;
            //    return false;
            //}
        }

        switch (proto16) {
            // TODO also flag h2c?
            case SSL_PROTO_HTTP2: sslFlowP->proto |= SSL_STAT_PROTO_HTTP2; break;
            case SSL_PROTO_HTTP3: sslFlowP->proto |= SSL_STAT_PROTO_HTTP3; break;
            default: {
                uint32_t proto32 = 0;
                if (proto_len >= sizeof(uint32_t)) {
                    // If t2buf_peek_u32 fails, proto32 will still be 0
                    t2buf_peek_u32(t2buf, &proto32);
                    //if (!t2buf_peek_u32(t2buf, &proto32)) {
                    //    //sslFlowP->stat |= SSL_STAT_SNAP;
                    //    return false;
                    //}
                }
                switch (proto32) {
                    // TODO also flag http/0.9, http/1.0 and http/1.1?
                    case SSL_PROTO_HTTP: sslFlowP->proto |= SSL_STAT_PROTO_HTTP; break;
                    // TODO also flag spdy/2 and spdy/3?
                    case SSL_PROTO_SPDY: sslFlowP->proto |= SSL_STAT_PROTO_SPDY; break;
                    case SSL_PROTO_IMAP: sslFlowP->proto |= SSL_STAT_PROTO_IMAP; break;
                    case SSL_PROTO_POP3: sslFlowP->proto |= SSL_STAT_PROTO_POP3; break;
                    case SSL_PROTO_XMPP: sslFlowP->proto |= SSL_STAT_PROTO_XMPP; break;
                    case SSL_PROTO_STUN: sslFlowP->proto |= SSL_STAT_PROTO_STUN; break;
                    case SSL_PROTO_APNS: sslFlowP->proto |= SSL_STAT_PROTO_APNS; break;
                    case SSL_PROTO_COAP: sslFlowP->proto |= SSL_STAT_PROTO_COAP; break;
                    default: {
                        uint32_t proto24 = 0;
                        if (proto_len >= 3) {
                            // If t2buf_peek_u24 fails, proto24 will still be 0
                            t2buf_peek_u24(t2buf, &proto24);
                            //if (!t2buf_peek_u24(t2buf, &proto24)) {
                            //    //sslFlowP->stat |= SSL_STAT_SNAP;
                            //    return false;
                            //}
                        }
                        switch (proto24) {
                            case SSL_PROTO_FTP: sslFlowP->proto |= SSL_STAT_PROTO_FTP; break;
                            default: {
                                uint64_t proto48 = 0;
                                if (proto_len >= 6) {
                                    // If t2buf_peek_u48 fails, proto24 will still be 0
                                    t2buf_peek_u48(t2buf, &proto48);
                                    //if (!t2buf_peek_u48(t2buf, &proto48)) {
                                    //    //sslFlowP->stat |= SSL_STAT_SNAP;
                                    //    return false;
                                    //}
                                }
                                switch (proto48) {
                                    case SSL_PROTO_WEBRTC: sslFlowP->proto |= SSL_STAT_PROTO_WEBRTC; break;
                                    default:
                                        // TODO also flag c-webrtc?
                                        if (proto_len >= sizeof(SSL_PROTO_MANSIEVE) &&
                                            strnstr((char*)(t2buf->buffer + t2buf->pos), SSL_PROTO_MANSIEVE, proto_len))
                                        {
                                            sslFlowP->proto |= SSL_STAT_PROTO_MANSIEVE;
                                        } else {
                                            sslFlowP->proto |= SSL_STAT_PROTO_UNKNOWN;
                                        }
                                        break;
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }

#if SSL_PROTO_LIST == 1
        const uint8_t idx = sslFlowP->num_proto;
        if (idx >= SSL_MAX_PROTO) {
            sslFlowP->stat |= SSL_STAT_PROTOL_TRUNC;
        } else {
            const uint8_t plen = MIN(SSL_PROTO_LEN, proto_len);
            if (plen < proto_len) sslFlowP->stat |= SSL_STAT_PROTON_TRUNC;
            // TODO t2buf_peek_str
            memcpy(sslFlowP->proto_list[idx], t2buf->buffer + t2buf->pos, plen);
            sslFlowP->proto_list[idx][plen] = '\0';
        }
        sslFlowP->num_proto++;
#endif

        t2buf_skip_n(t2buf, proto_len);
        ext_len -= (proto_len + 1);
    }

    return true;
}


static inline bool ssl_process_hello_extension(t2buf_t *t2buf, sslFlow_t *sslFlowP) {
    uint16_t ext_len, ext_type;
    if (!t2buf_read_u16(t2buf, &ext_type) ||
        !t2buf_read_u16(t2buf, &ext_len))
    {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

#if SSL_EXT_LIST == 1
    if (sslFlowP->num_ext < SSL_MAX_EXT) {
        sslFlowP->ext_list[sslFlowP->num_ext] = ext_type;
    } else {
        sslFlowP->stat |= SSL_STAT_EXTL_TRUNC;
    }
    sslFlowP->num_ext++;
#endif

    switch (ext_type) {

        case SSL_HT_HELLO_EXT_SERVER_NAME: {
            if (ext_len == 0) break;

            t2buf_skip_u16(t2buf); // skip server name list length

            uint8_t type;
            if (!t2buf_read_u8(t2buf, &type)) {
                //sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            if (type) { // skip type (only HOST_NAME (0) is valid)
                sslFlowP->stat |= SSL_STAT_MALFORMED;
                break;
            }

            uint16_t sNameLen;
            if (!t2buf_read_u16(t2buf, &sNameLen)) {
                //sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            // TODO t2buf_peek_str
            //long ret = t2buf_read_str(t2buf, sslFlowP->server_name, SSL_SNI_MAX_LEN, T2BUF_UTF8, true);
            //if (ret == T2BUF_DST_FULL) {
            //    t2buf_skip_n(t2buf, sNameLen - SSL_SNI_MAX_LEN);
            //} else if (ret == T2BUF_EMPTY) {
            //    // XXX TODO FIXME add a return code, for no more data to read
            //    //sslFlowP->stat |= SSL_STAT_SNAP;
            //    return false;
            //}
            memcpy(sslFlowP->server_name, t2buf->buffer + t2buf->pos, MIN(sNameLen, SSL_SNI_MAX_LEN));
            t2buf_skip_n(t2buf, sNameLen);
            break;
        }

        case SSL_HT_HELLO_EXT_USE_SRTP:
            sslFlowP->proto |= SSL_STAT_PROTO_RTP;
            t2buf_skip_n(t2buf, ext_len);
            break;

        case SSL_HT_HELLO_EXT_HEARTBEAT: {
            uint8_t flag;
            if (!t2buf_peek_u8(t2buf, &flag)) {
                //sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            if (flag == SSL_HB_EXT_NOT_ALLOWED) {
                sslFlowP->stat |= SSL_STAT_NO_HEARTBEAT;
            } else if (flag != SSL_HB_EXT_ALLOWED) {
                sslFlowP->stat |= SSL_STAT_MALFORMED;
            }

            t2buf_skip_n(t2buf, ext_len);
            break;
        }

        // ALPN/NPN
        case SSL_HT_HELLO_EXT_ALPN:
            if (!t2buf_read_u16(t2buf, &ext_len)) {  // ALPN extension length
                //sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }
            /* FALLTHRU */
        case SSL_HT_HELLO_EXT_NPN:
            if (!ssl_process_alpn(t2buf, ext_len, sslFlowP)) return false;
            break;

        case SSL_HT_HELLO_EXT_RENEG_INFO:
            sslFlowP->stat |= SSL_STAT_RENEGOTIATION;
            t2buf_skip_n(t2buf, ext_len);
            break;

#if SSL_EC == 1
        case SSL_HT_HELLO_EXT_ELLIPTIC_CURVES:
            if (ext_len == 0) break;
            t2buf_skip_u16(t2buf); // skip EC points length
            ext_len -= 2;
            // TODO what if ext_len is odd, e.g., 3..
            while (ext_len != 0) {
                if (sslFlowP->num_ec < SSL_MAX_EC) {
                    if (!t2buf_read_u16(t2buf, &sslFlowP->ec[sslFlowP->num_ec])) {
                        //sslFlowP->stat |= SSL_STAT_SNAP;
                        return false;
                    }
                } else {
                    t2buf_skip_u16(t2buf);
                    sslFlowP->stat |= SSL_STAT_EC_TRUNC;
                }
                sslFlowP->num_ec++;
                ext_len -=2;
            }
            break;
#endif // SSL_EC == 1

#if SSL_EC_FORMATS == 1
        case SSL_HT_HELLO_EXT_EC_POINT_FORMATS:
            if (ext_len == 0) break;
            t2buf_skip_u8(t2buf); // skip EC point formats length
            ext_len--;
            while (ext_len != 0) {
                if (sslFlowP->num_ec_formats < SSL_MAX_EC_FORMATS) {
                    if (!t2buf_read_u8(t2buf, &sslFlowP->ec_formats[sslFlowP->num_ec_formats])) {
                        //sslFlowP->stat |= SSL_STAT_SNAP;
                        return false;
                    }
                } else {
                    t2buf_skip_u8(t2buf);
                    sslFlowP->stat |= SSL_STAT_EC_TRUNC;
                }
                sslFlowP->num_ec_formats++;
                ext_len--;
            }
            break;
#endif // SSL_EC_FORMATS == 1

        default:
            t2buf_skip_n(t2buf, ext_len);
            break;
    } // switch ext_type

    return true;
}


#if SSL_ANALYZE_CERT == 1
static inline bool ssl_process_ht_cert(t2buf_t *t2buf, sslFlow_t *sslFlowP) {

#if (SSL_CERT_SUBJECT > 0 || SSL_CERT_ISSUER > 0)
    X509_NAME *cert_name;
#endif

    // read the length of all certificates
    uint32_t total_cert_len;
    if (!t2buf_read_u24(t2buf, &total_cert_len)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (total_cert_len == 0) return true;

    uint32_t cert_len;
    if (!t2buf_read_u24(t2buf, &cert_len)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (cert_len == 0) return true;

    const uint8_t *rp = t2buf->buffer + t2buf->pos;
    X509 * const cert = d2i_X509(NULL, (const unsigned char**)&rp, MIN(cert_len, t2buf_left(t2buf)));
    t2buf_skip_n(t2buf, cert_len);
    if (!cert) {
        //sslFlowP->stat |= SSL_STAT_CERT;
        return true;
    }

    sslFlowP->cert_version = ((uint8_t) X509_get_version(cert)) + 1;

#if SSL_CERT_SUBJECT > 0
    cert_name = X509_get_subject_name(cert);
#endif

    // Certificate Subject
#if SSL_CERT_SUBJECT == 1
    X509_NAME_print_ex();
    // TODO replaced function with X509_NAME_print_ex() and XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB
    sslFlowP->cert_subject = X509_NAME_oneline(cert_name, NULL, 0);
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, sslFlowP->cert_sCommon, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORGANIZATION == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationName, sslFlowP->cert_sOrg, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORG_UNIT == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationalUnitName, sslFlowP->cert_sOrgUnit, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_LOCALITY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_localityName, sslFlowP->cert_sLoc, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_STATE == 1
    X509_NAME_get_text_by_NID(cert_name, NID_stateOrProvinceName, sslFlowP->cert_sState, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_COUNTRY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_countryName, sslFlowP->cert_sCountry, SSL_CERT_COUNTRY_LEN+1);
#endif
#endif // SSL_CERT_SUBJECT

    // Certificate Issuer
#if SSL_CERT_ISSUER > 0
    cert_name = X509_get_issuer_name(cert);
#endif
#if SSL_CERT_ISSUER == 1
    sslFlowP->cert_issuer  = X509_NAME_oneline(cert_name, NULL, 0);
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, sslFlowP->cert_iCommon, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORGANIZATION == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationName, sslFlowP->cert_iOrg, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORG_UNIT == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationalUnitName, sslFlowP->cert_iOrgUnit, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_LOCALITY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_localityName, sslFlowP->cert_iLoc, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_STATE == 1
    X509_NAME_get_text_by_NID(cert_name, NID_stateOrProvinceName, sslFlowP->cert_iState, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_COUNTRY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_countryName, sslFlowP->cert_iCountry, SSL_CERT_COUNTRY_LEN+1);
#endif
#endif // SSL_CERT_ISSUER

#if SSL_CERT_SIG_ALG == 1
    // signature algorithm
    sslFlowP->sig_type = X509_get_signature_nid(cert);
#endif // SSL_CERT_SIG_ALG

    // Public Key
    EVP_PKEY * const key = X509_get_pubkey(cert);
    if (key) {
        sslFlowP->pkey_size = EVP_PKEY_bits(key);
        if (sslFlowP->pkey_size > 0 && sslFlowP->pkey_size < 1024) {
            sslFlowP->stat |= SSL_STAT_WEAK_KEY;
        }

#if SSL_CERT_PUBKEY_TS == 1 || SSL_CERT_PUBKEY_ALG == 1
        sslFlowP->pkey_type = EVP_PKEY_base_id(key);
#endif

        EVP_PKEY_free(key);
    }

#if SSL_CERT_SERIAL == 1
    const ASN1_INTEGER * const  serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bnserial = ASN1_INTEGER_to_BN(serial, NULL);
        if (bnserial) {
            sslFlowP->cert_serial = BN_bn2hex(bnserial);
            BN_free(bnserial);
        }
    }
#endif

#if SSL_CERT_VALIDITY == 1
    const ASN1_TIME * const not_before = X509_get_notBefore(cert);
    const ASN1_TIME * const not_after = X509_get_notAfter(cert);

    if (!ssl_asn1_convert(not_before, &sslFlowP->cert_not_before) ||
        !ssl_asn1_convert(not_after, &sslFlowP->cert_not_after))
    {
        // XXX what to do if conversion failed?
    }

    // TODO check certificate validity
    //sslFlowP->stat |= SSL_STAT_CERT_EXPIRED;
#endif

    // TODO to save 'all' certificates, we need to reassemble packets...
#if (SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT > 0)
    const EVP_MD *digest;
#if SSL_CERT_FINGPRINT == 2
    digest = EVP_md5();
#else
    digest = EVP_sha1();
#endif

    unsigned int n;
    unsigned char hash[SSL_CERT_SHA1_LEN];
    if (!X509_digest(cert, digest, hash, &n)) {
        X509_free(cert);
        return true;
    }

    for (unsigned int j = 0; j < n; j++) {
        sprintf(&sslFlowP->cert_fingerprint[2*j], "%02"B2T_PRIX8, hash[j]);
    }

#if SSL_BLIST == 1
    const char *blist_cat;
    if ((blist_cat = ssl_blist_lookup(sslbl, sslFlowP->cert_fingerprint))) {
        memcpy(sslFlowP->blist_cat, blist_cat, MIN(strlen(blist_cat)+1, SSL_BLIST_LEN-1));
        sslFlowP->stat |= SSL_STAT_BLIST;
        numBlistCerts++;
    }
#endif

#if SSL_SAVE_CERT == 1
    size_t name_len = sizeof(SSL_CERT_PATH) + strlen(sslFlowP->cert_fingerprint) + sizeof(SSL_CERT_EXT) + 1;
#if SSL_CERT_NAME_FINDEX == 1
    name_len += 26 /* UINT64 */ + 1 /* _ */;
#endif
    char name[name_len];
    strcpy(name, SSL_CERT_PATH);
#if SSL_CERT_NAME_FINDEX == 1
    snprintf(&name[strlen(name)], 28, "%"PRIu64"_", flowP->findex);
#endif
    strncat(name, sslFlowP->cert_fingerprint, strlen(sslFlowP->cert_fingerprint));
    strncat(name, SSL_CERT_EXT, sizeof(SSL_CERT_EXT));

    // only save/count certificates once
    if (access(name, F_OK) != 0) {
        FILE *f = fopen(name, "wb");
        if (!f) {
            T2_PERR("sslDecode", "failed to open file '%s': %s", name, strerror(errno));
            X509_free(cert);
            return true;
        }
        PEM_write_X509(f, cert);
        fclose(f);
        numSavedCerts++;
    }
#endif // SSL_SAVE_CERT == 1
#endif // SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT

    X509_free(cert);

    return true;
}
#endif // SSL_ANALYZE_CERT == 1


#if SSL_JA3 == 1
/*
 * Fingerprints
 * ============
 *
 * ja3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 *     md5(769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0)
 *     md5(769,4-5-10-9-100-98-3-6-19-18-99,,,)
 *
 * ja3s = SSLVersion,Cipher,SSLExtension
 *     md5(769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11)
 *     md5(769,4-5-10-9-100-98-3-6-19-18-99,)
 *
 * TODO handle Google GREASE
 */
static inline void ssl_compute_ja3(uint8_t handshake_type, sslFlow_t *sslFlowP) {
    if ((sslFlowP->stat & SSL_STAT_JA3_TRUNC) != 0 ||
        strlen(sslFlowP->ja3_hash) != 0)
    {
        // Do not try to fingerprint truncated entries
        // Only fingerprint the first Client/Server Hello
        return;
    }

    size_t pos = 0;
    char fingerprint[SSL_JA3_STR_LEN];

    // SSLVersion
    pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu16",", sslFlowP->version);
    if (pos >= SSL_JA3_STR_LEN) {
        //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
        return;
    }

    // Cipher
    if (handshake_type == SSL_HT_SERVER_HELLO) {
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu16, sslFlowP->cipher);
        if (pos >= SSL_JA3_STR_LEN) {
            //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }
#if SSL_CIPHER_LIST == 1
    } else {
        const uint_fast32_t num_cipher = sslFlowP->num_cipher;
        for (uint_fast32_t i = 0; i < num_cipher; i++) {
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu16"%s",
                    sslFlowP->cipher_list[i], i < num_cipher-1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }
#endif
    }
    pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, ",");
    if (pos >= SSL_JA3_STR_LEN) {
        //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
        return;
    }

#if SSL_EXT_LIST == 1
    // SSLExtension
    const uint_fast32_t num_ext = sslFlowP->num_ext;
    for (uint_fast32_t i = 0; i < num_ext; i++) {
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu16"%s",
                sslFlowP->ext_list[i], i < num_ext-1 ? "-" : "");
        if (pos >= SSL_JA3_STR_LEN) {
            //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }
    }
#endif

    if (handshake_type == SSL_HT_CLIENT_HELLO) {
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, ",");
        if (pos >= SSL_JA3_STR_LEN) {
            //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }

#if SSL_EC == 1
        // EllipticCurve
        const uint_fast32_t num_ec = sslFlowP->num_ec;
        for (uint_fast32_t i = 0; i < num_ec; i++) {
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu16"%s",
                    sslFlowP->ec[i], i < num_ec-1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }
#endif
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, ",");
        if (pos >= SSL_JA3_STR_LEN) {
            //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }

#if SSL_EC_FORMATS == 1
        // EllipticCurvePointFormat
        const uint_fast32_t num_ec_formats = sslFlowP->num_ec_formats;
        for (uint_fast32_t i = 0; i < num_ec_formats; i++) {
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN-pos, "%"PRIu8"%s",
                    sslFlowP->ec_formats[i], i < num_ec_formats-1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                //sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }
#endif
    }

#if SSL_JA3_STR == 1
    memcpy(sslFlowP->ja3_str, fingerprint, strlen(fingerprint)+1);
#endif

    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, fingerprint, strlen(fingerprint));
    unsigned char digest[16];
    MD5_Final(digest, &md5);

    for (uint_fast32_t i = 0; i < 16; i++) {
        snprintf(&(sslFlowP->ja3_hash[2*i]), 16*2, "%02"B2T_PRIX8, (uint8_t)digest[i]);
    }

    const char *ja3_desc;
    if ((ja3_desc = ssl_blist_lookup(sslja3, sslFlowP->ja3_hash))) {
        numJA3++;
        memcpy(sslFlowP->ja3_desc, ja3_desc, MIN(strlen(ja3_desc)+1, SSL_JA3_DLEN-1));
    }
}
#endif // SSL_JA3 == 1


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    sslFlow_t *sslFlowP = &sslFlow[flowIndex];
    const uint16_t version = sslFlowP->version;
    const uint8_t ssl_v_is_valid = (version == 0) ? 0 : 1;

    // SSL stat
    if (!sslFlowP->proto && !ssl_v_is_valid) sslFlowP->stat = 0; // fix erroneous early detection
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->stat);

    // SSL proto
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->proto);
    sslProto |= sslFlowP->proto;

#if SSL_ANALYZE_OVPN == 1
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->ovpnType);
    OUTBUF_APPEND_U64(main_output_buffer, sslFlowP->ovpnSessID);
#endif

    // SSL flags
    OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->flags);

    // SSL/TLS version
    if (SSL_V_IS_SSL(version)) numSSL3[SSL_V_MINOR(version)]++;
    else if (version == SSLv2) numSSL2++;
    else if (SSL_V_IS_DTLS(version)) numDTLS[(version == DTLSv10 ? 0 : version == DTLSv12 ? 1 : 2)]++;
    OUTBUF_APPEND_U16(main_output_buffer, version);

    // vuln
    if (!ssl_v_is_valid) sslFlowP->vuln = 0; // fix erroneous early detection
    OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->vuln);

    // alert
    OUTBUF_APPEND_U32(main_output_buffer, sslFlowP->alert);

    // cipher
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->cipher);

#if SSL_EXT_LIST == 1 || SSL_PROTO_LIST == 1 || SSL_CIPHER_LIST == 1 || SSL_EC == 1 || SSL_EC_FORMATS == 1
    uint_fast32_t i, imax;
#endif

#if SSL_EXT_LIST == 1
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_ext);
    imax = MIN(sslFlowP->num_ext, SSL_MAX_EXT);
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->ext_list[i]);
    }
#endif

#if SSL_EC == 1
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_ec);
    imax = MIN(sslFlowP->num_ec, SSL_MAX_EC);
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->ec[i]);
    }
#endif

#if SSL_EC_FORMATS == 1
    OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->num_ec_formats);
    imax = MIN(sslFlowP->num_ec_formats, SSL_MAX_EC_FORMATS);
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->ec_formats[i]);
    }
#endif

#if SSL_PROTO_LIST == 1
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_proto);
    imax = MIN(sslFlowP->num_proto, SSL_MAX_PROTO);
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_STR(main_output_buffer, sslFlowP->proto_list[i]);
    }
#endif

#if SSL_CIPHER_LIST == 1
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_cipher);
    imax = MIN(sslFlowP->num_cipher, SSL_MAX_CIPHER);
    OUTBUF_APPEND_NUMREP(main_output_buffer, imax);
    for (i = 0; i < imax; i++) {
        OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->cipher_list[i]);
    }
#endif

    // number of data records (change_cipher, alert, handshake, application_data)
    if (!ssl_v_is_valid) { // fix erroneous early detection
        sslFlowP->num_change_cipher = 0;
        sslFlowP->num_alert = 0;
        sslFlowP->num_handshake = 0;
        sslFlowP->num_app_data = 0;
        sslFlowP->num_heartbeat = 0;
    }
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_change_cipher);
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_alert);
    OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->num_handshake);
    OUTBUF_APPEND_U64(main_output_buffer, sslFlowP->num_app_data);
    OUTBUF_APPEND_U64(main_output_buffer, sslFlowP->num_heartbeat);
    OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->session_len);

    if (!ssl_v_is_valid) {
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // GMT Unix Time
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // server_name

#if SSL_ANALYZE_CERT == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert version

#if SSL_CERT_SERIAL == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert serial number
#endif

#if SSL_CERT_FINGPRINT > 0
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert fingerprint
#endif

#if SSL_CERT_VALIDITY == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert validity
#endif

#if SSL_CERT_SIG_ALG == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert signature algorithm
#endif

#if SSL_CERT_PUBKEY_ALG == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert public key algorithm
#endif

#if SSL_CERT_PUBKEY_TS == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert public key type, size
#endif

        // Cert subject
#if SSL_CERT_SUBJECT == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject common name
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject organization
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject organizational unit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject locality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject state
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert subject country
#endif
#endif // SSL_CERT_SUBJECT

        // Cert issuer
#if SSL_CERT_ISSUER == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer common name
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer organization
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer organizational unit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer locality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer state
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO); // Cert issuer country
#endif
#endif // SSL_CERT_ISSUER

#endif // SSL_ANALYZE_CERT == 1
    } else {

        if (sslFlowP->gmt_time == 0) {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ONE);
            OUTBUF_APPEND_TIME(main_output_buffer, sslFlowP->gmt_time, ZERO);
        }

        if (sslFlowP->server_name[0] == '\0' && flows[flowIndex].oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            SSL_OUTBUF_APPEND_STR(sslFlow[flows[flowIndex].oppositeFlowIndex].server_name);
        } else {
            SSL_OUTBUF_APPEND_STR(sslFlowP->server_name);
        }

#if SSL_ANALYZE_CERT == 1

        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ONE);
            OUTBUF_APPEND_U8(main_output_buffer, sslFlowP->cert_version);
        }

#if SSL_CERT_SERIAL == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_serial);
        OPENSSL_free(sslFlowP->cert_serial);
#endif

#if SSL_CERT_FINGPRINT > 0
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_fingerprint);
#endif

#if SSL_CERT_VALIDITY == 1
        // Cert validity: before, after, lifetime
        if (sslFlowP->cert_not_before.tm_mday == 0 || sslFlowP->cert_not_after.tm_mday == 0) { // mday starts at one
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
            // time was given as UTC. Ignore daylight saving time.
            sslFlowP->cert_not_before.tm_isdst = -1;
            sslFlowP->cert_not_after.tm_isdst = -1;
            OUTBUF_APPEND_NUMREP(main_output_buffer, ONE);
            const uint64_t t1 = mktime(&sslFlowP->cert_not_before);
            OUTBUF_APPEND_TIME(main_output_buffer, t1, ZERO);
            const uint64_t t2 = mktime(&sslFlowP->cert_not_after);
            OUTBUF_APPEND_TIME(main_output_buffer, t2, ZERO);
            const uint64_t d = t2 - t1;
            OUTBUF_APPEND_U64(main_output_buffer, d);
        }
#endif

#if SSL_CERT_SIG_ALG == 1
        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
#if SSL_CERT_ALG_NAME_LONG == 0
            const char *sig_alg = OBJ_nid2sn(sslFlowP->sig_type);
#else // SSL_CERT_ALG_NAME_LONG == 1
            const char *sig_alg = OBJ_nid2ln(sslFlowP->sig_type);
#endif // SSL_CERT_ALG_NAME_LONG
            SSL_OUTBUF_APPEND_STR(sig_alg);
        }
#endif // SSL_CERT_SIG_ALG == 1

#if SSL_CERT_PUBKEY_ALG == 1
        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
#if SSL_CERT_ALG_NAME_LONG == 0
            const char *pkey_alg = OBJ_nid2sn(sslFlowP->pkey_type);
#else // SSL_CERT_ALG_NAME_LONG == 1
            const char *pkey_alg = OBJ_nid2ln(sslFlowP->pkey_type);
#endif // SSL_CERT_ALG_NAME_LONG
            SSL_OUTBUF_APPEND_STR(pkey_alg);
        }
#endif // SSL_CERT_PUBKEY_ALG == 1

#if SSL_CERT_PUBKEY_TS == 1
        if (sslFlowP->pkey_type == 0 && sslFlowP->pkey_size == 0) {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ZERO);
        } else {
            OUTBUF_APPEND_NUMREP(main_output_buffer, ONE);
            char *pkey_type;
            switch (sslFlowP->pkey_type) {
                case EVP_PKEY_RSA : pkey_type = "RSA"  ; break;
                case EVP_PKEY_DSA : pkey_type = "DSA"  ; break;
                case EVP_PKEY_EC  : pkey_type = "ECDSA"; break;
                default: /*Unkown*/ pkey_type = "UNDEF"; break;
            }
            OUTBUF_APPEND_STR(main_output_buffer, pkey_type);
            OUTBUF_APPEND_U16(main_output_buffer, sslFlowP->pkey_size);
        }
#endif

        // Certificate Subject
#if SSL_CERT_SUBJECT == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_subject);
        OPENSSL_free(sslFlowP->cert_subject);
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sCommon);
#endif
#if SSL_CERT_ORGANIZATION == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sOrg);
#endif
#if SSL_CERT_ORG_UNIT == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sOrgUnit);
#endif
#if SSL_CERT_LOCALITY == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sLoc);
#endif
#if SSL_CERT_STATE == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sState);
#endif
#if SSL_CERT_COUNTRY == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_sCountry);
#endif
#endif // SSL_CERT_SUBJECT

        // Certificate Issuer
#if SSL_CERT_ISSUER == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_issuer);
        OPENSSL_free(sslFlowP->cert_issuer);
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iCommon);
#endif
#if SSL_CERT_ORGANIZATION == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iOrg);
#endif
#if SSL_CERT_ORG_UNIT == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iOrgUnit);
#endif
#if SSL_CERT_LOCALITY == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iLoc);
#endif
#if SSL_CERT_STATE == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iState);
#endif
#if SSL_CERT_COUNTRY == 1
        SSL_OUTBUF_APPEND_STR(sslFlowP->cert_iCountry);
#endif
#endif // SSL_CERT_ISSUER

#endif // SSL_ANALYZE_CERT
    }

#if SSL_BLIST == 1
    SSL_OUTBUF_APPEND_STR(sslFlowP->blist_cat);
#endif

#if SSL_JA3 == 1
    SSL_OUTBUF_APPEND_STR(sslFlowP->ja3_hash);
    SSL_OUTBUF_APPEND_STR(sslFlowP->ja3_desc);
#if SSL_JA3_STR == 1
    SSL_OUTBUF_APPEND_STR(sslFlowP->ja3_str);
#endif
#endif // SSL_JA3 == 1
}
#endif // BLOCK_BUF


void pluginReport(FILE *stream) {
#if SSL_ANALYZE_OVPN == 1
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of OpenVPN flows", numOVPN, totalFlows);
#endif
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of SSL 2.0 flows", numSSL2, totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of SSL 3.0 flows", numSSL3[0], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of TLS 1.0 flows", numSSL3[1], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of TLS 1.1 flows", numSSL3[2], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of TLS 1.2 flows", numSSL3[3], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of TLS 1.3 flows", numSSL3[4], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of DTLS 1.0 (OpenSSL pre 0.9.8f) flows", numDTLS[2], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of DTLS 1.0 flows", numDTLS[0], totalFlows);
    T2_FPLOG_NUMP(stream, "sslDecode", "Number of DTLS 1.2 flows", numDTLS[1], totalFlows);
    if (sslProto) {
        T2_FPLOG(stream, "sslDecode", "Aggregated protocols: 0x%04"B2T_PRIX16, sslProto);
    }
#if SSL_SAVE_CERT == 1
    T2_FPLOG_NUM(stream, "sslDecode", "Number of certificates saved", numSavedCerts);
#endif
#if SSL_BLIST == 1
    T2_FPLOG_NUM(stream, "sslDecode", "Number of blacklisted certificates", numBlistCerts);
#endif
#if SSL_JA3 == 1
    T2_FPLOG_NUM(stream, "sslDecode", "Number of JA3 signatures matched", numJA3);
#endif
}


void onApplicationTerminate() {
    free(sslFlow);

#if SSL_BLIST == 1
    ssl_blist_free(sslbl);
#endif

#if SSL_JA3 == 1
    ssl_blist_free(sslja3);
#endif
}
