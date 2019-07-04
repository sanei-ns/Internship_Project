/*
 * sslDecode.h
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

/*
 * References:
 *   SSL 2.0 [https://tools.ietf.org/html/draft-hickman-netscape-ssl-00]
 *   SSL 3.0 [RFC 6101]
 *
 *   TLS 1.0 [RFC 2246]
 *   TLS 1.1 [RFC 4346]
 *   TLS 1.2 [RFC 5246]
 *
 *   DTLS 1.0 [RFC 4347]
 *   DTLS 1.2 [RFC 6347]
 *
 *   DTLS for DCCP [RFC 5238]
 *   DTLS for SRTP [RFC 5764]
 *   DTLS for SCTP [RFC 6083]
 *
 *   Attacks on TLS/DTLS [RFC 7457]
 *
 *   SSL Blacklist: https://sslbl.abuse.ch/
 */

#ifndef __SSLDECODE_H__
#define __SSLDECODE_H__

// local includes
#include <stdint.h>
#include <time.h>

// user defines

// OpenVPN
#define SSL_ANALYZE_OVPN       0 // whether or not to analyze OpenVPN (Experimental)

// SSL/TLS
#define SSL_EXT_LIST           1 // whether or not to output the list and number of extensions
#if SSL_EXT_LIST == 1
#define SSL_MAX_EXT            8 // maximum number of extensions to store
#endif // SSL_EXT_LIST

#define SSL_EC                 1 // whether or not to output the list and number of Elliptic Curve
#if SSL_EC == 1
#define SSL_MAX_EC             6 // maximum number of EC to store
#endif // SSL_EC

#define SSL_EC_FORMATS         1 // whether or not to output the list and number of Elliptic Curve point formats
#if SSL_EC_FORMATS == 1
#define SSL_MAX_EC_FORMATS     6 // maximum number of EC formats to store
#endif // SSL_EC_FORMATS

#define SSL_PROTO_LIST         1 // whether or not to output the list and number of protocols
#if SSL_PROTO_LIST == 1
#define SSL_MAX_PROTO          6 // maximum number of protocols to store
#define SSL_PROTO_LEN         16 // maximum number of characters per protocols
#endif // SSL_PROTO_LIST

#define SSL_CIPHER_LIST        1 // whether or not to output the list and number of supported ciphers
#if SSL_CIPHER_LIST == 1
#define SSL_MAX_CIPHER         30 // maximum number of ciphers to store
#endif // SSL_CIPHER_LIST

#define SSL_ANALYZE_CERT       1 // whether or not to analyze certificates

#if (SSL_ANALYZE_CERT == 1)

#define SSL_CERT_SERIAL        1 // whether or not to print the certificate serial number
#define SSL_CERT_FINGPRINT     1 // 0: no certificate fingerprint, 1: SHA1, 2: MD5
#define SSL_CERT_VALIDITY      1 // whether or not to print the certificate validity (Valid from/to)
#define SSL_CERT_SIG_ALG       1 // whether or not to print the certificate signature algorithm
#define SSL_CERT_PUBKEY_ALG    1 // whether or not to print the certificate public key algorithm
#define SSL_CERT_ALG_NAME_LONG 0 // whether to use short (0) or long (1) names for algorithms
#define SSL_CERT_PUBKEY_TS     1 // whether or not to print the certificate public key type and size

#define SSL_CERT_SUBJECT       2 // 0: no information about the certificate subject,
                                 // 1: print the whole subject as one string,
                                 // 2: print selected fields only
#define SSL_CERT_ISSUER        2 // 0: no information about the certificate issuer,
                                 // 1: print the whole issuer as one string,
                                 // 2: print selected fields only

#if ((SSL_CERT_SUBJECT == 2) || (SSL_CERT_ISSUER == 2))
#define SSL_CERT_COMMON_NAME   1 // whether or not to print the common name of the issuer/subject
#define SSL_CERT_ORGANIZATION  1 // whether or not to print the organization name of the issuer/subject
#define SSL_CERT_ORG_UNIT      1 // whether or not to print the organizational unit name of the issuer/subject
#define SSL_CERT_LOCALITY      1 // whether or not to print the locality name of the issuer/subject
#define SSL_CERT_STATE         1 // whether or not to print the state or province of the issuer/subject
#define SSL_CERT_COUNTRY       1 // whether or not to print the country of the issuer/subject
#endif // SSL_CERT_SUBJECT || SSL_CERT_ISSUER

#if ((SSL_CERT_VALIDITY) == 1 && (SSL_CERT_PUBKEY_TS) == 1 && (((SSL_CERT_SUBJECT) == 1 && (SSL_CERT_ISSUER) == 1)) || \
    ((SSL_CERT_SUBJECT) == 2 && (SSL_CERT_ISSUER) == 2 && (SSL_CERT_COMMON_NAME == 1) && (SSL_CERT_ORGANIZATION) == 1))
#endif // SSL_CERT_VALIDITY && SSL_CERT_PUBKEY_TS && SSL_CERT_SUBJECT && SSL_CERT_ISSUER ...

// TODO in order to analyze ALL certificates, we need to reassemble packets...
#define SSL_RM_CERTDIR       1 // whether or not to remove SSL_CERT_PATH before starting
#define SSL_SAVE_CERT        0 // whether or not to save certificates
#define SSL_CERT_NAME_FINDEX 0 // whether or not to prepend the flowIndex to the certificate name

#if SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT == 1
#define SSL_BLIST          0 // Search for blacklisted certificates
#define SSL_BLIST_LEN     41 // Max length for blacklist descriptions
#define SSL_JA3            1 // Output JA3 fingerprint (hash and description)
#define SSL_JA3_STR        0 // Also output JA3 fingerprint before hashing
#define SSL_JA3_DLEN     512 // Max length for JA3 descriptions
#define SSL_JA3_STR_LEN 1024 // Max length for uncompressed JA3 signatures (ja3_str)
#endif // SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT == 1

#define SSL_CERT_PATH "/tmp/TranCerts/" // folder for saved certificates
#define SSL_CERT_EXT  ".pem"            // extension for saved certificates

#endif // SSL_ANALYZE_CERT

// plugin defines

#define SSL_RT_HDR_LEN           5 // type(1), version(2), length(2)
#define SSL_RT_MAX_LEN       16384
#define SSL_SESSION_ID_LEN      32
#define SSL_HELLO_RANDOM_LEN    32 // time (4 bytes), random (28 bytes)
#define SSL_HB_MIN_PAD_LEN      16 // mininum padding length for heartbeat messages

#define SSL_CERT_COUNTRY_LEN     2
#define SSL_CERT_SHA1_LEN       40
#define SSL_CERT_NAME_MAXLEN    64 // CN, O, OU, SN, email
#define SSL_CERT_LOC_MAXLEN    128 // L, ST
#define SSL_SNI_MAX_LEN        255

// Protocol version
// SSL
#define SSLv2   0x0002
#define SSLv3   0x0300
// TLS
#define TLSv10  0x0301
#define TLSv11  0x0302
#define TLSv12  0x0303
#define TLSv13  0x0304
// DTLS
#define DTLSv10_OLD 0x0100 // pre standard version of DTLSv1.0 (OpenSSL pre 0.9.8f)
#define DTLSv10     0xfeff
// DTLSv11 does not exist
#define DTLSv12     0xfefd

#define SSL_V_MAJOR(v) ((v) >> 8)
#define SSL_V_MINOR(v) ((v) & 0x00ff)

#define SSL_V_IS_DTLS(v) (((v) == DTLSv10) || ((v) == DTLSv12) || ((v) == DTLSv10_OLD))
#define SSL_V_IS_SSL(v) (((v) >= SSLv3) && ((v) <= TLSv13))
#define SSL_V_IS_VALID(v) (SSL_V_IS_SSL((v)) || SSL_V_IS_DTLS((v)))

// ALPN Protocols (network order)
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
#define SSL_PROTO_HTTP3    0x6833         // h3
#define SSL_PROTO_HTTP2    0x6832         // h2
//#define SSL_PROTO_HTTP2_C  0x683263       // h2c
#define SSL_PROTO_FTP      0x667470       // ftp
#define SSL_PROTO_HTTP     0x68747470     // http
#define SSL_PROTO_SPDY     0x73706479     // spdy
#define SSL_PROTO_IMAP     0x696d6170     // imap
#define SSL_PROTO_POP3     0x706f7033     // pop3
#define SSL_PROTO_XMPP     0x786d7070     // xmpp
#define SSL_PROTO_STUN     0x7374756e     // stun
#define SSL_PROTO_APNS     0x61706e73     // apns
#define SSL_PROTO_COAP     0x636f6170     // coap
#define SSL_PROTO_WEBRTC   0x776562727463 // webrtc
#define SSL_PROTO_MANSIEVE "managesieve"
//#define SSL_PROTO_MANSIEVE 0x65766569736567616e616d // managesieve

// Record types
#define SSL_RT_CHANGE_CIPHER_SPEC 0x14
#define SSL_RT_ALERT              0x15
#define SSL_RT_HANDSHAKE          0x16
#define SSL_RT_APPLICATION_DATA   0x17
#define SSL_RT_HEARTBEAT          0x18

// If record type is not valid, then it is probably not TLS
#define SSL_RT_IS_VALID(t) (((t) >= SSL_RT_CHANGE_CIPHER_SPEC) && ((t) <= SSL_RT_HEARTBEAT))

// SSL2 message types
#define SSL2_MT_ERROR               0x00
#define SSL2_MT_CLIENT_HELLO        0x01
#define SSL2_MT_CLIENT_MASTER_KEY   0x02
#define SSL2_MT_CLIENT_FINISHED     0x03
#define SSL2_MT_SERVER_HELLO        0x04
#define SSL2_MT_SERVER_VERIFY       0x05
#define SSL2_MT_SERVER_FINISHED     0x06
#define SSL2_MT_REQUEST_CERTIFICATE 0x07
#define SSL2_MT_CLIENT_CERTIFICATE  0x08

// If record type is not valid, then it is probably not SSLv2
#define SSL2_MT_IS_VALID(t) ((t) <= SSL2_MT_CLIENT_CERTIFICATE)

// Handshake types
#define SSL_HT_HELLO_REQUEST        0x00
#define SSL_HT_CLIENT_HELLO         0x01
#define SSL_HT_SERVER_HELLO         0x02
#define SSL_HT_HELLO_VERIFY_REQUEST 0x03 // RFC6347, DTLS only
#define SSL_HT_NEW_SESSION_TICKET   0x04 // RFC5077
#define SSL_HT_CERTIFICATE          0x0B
#define SSL_HT_SERVER_KEY_EXCHANGE  0x0C
#define SSL_HT_CERTIFICATE_REQUEST  0x0D
#define SSL_HT_SERVER_HELLO_DONE    0x0E
#define SSL_HT_CERTIFICATE_VERIFY   0x0F
#define SSL_HT_CLIENT_KEY_EXCHANGE  0x10
#define SSL_HT_FINISHED             0x14
#define SSL_HT_CERTIFICATE_URL      0x15 // RFC3546
#define SSL_HT_CERTIFICATE_STATUS   0x16 // RFC3546
#define SSL_HT_SUPPLEMENTAL_DATA    0x17 // RFC4680
//#define SSL_HT_NEXT_PROTOCOL 0x43 // https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html

// Hello extensions
#define SSL_HT_HELLO_EXT_SERVER_NAME            0x0000
#define SSL_HT_HELLO_EXT_MAX_FRAGMENT_LENGTH    0x0001
#define SSL_HT_HELLO_EXT_CLIENT_CERT_URL        0x0002
#define SSL_HT_HELLO_EXT_TRUSTED_CA_KEYS        0x0003
#define SSL_HT_HELLO_EXT_TRUNCATED_HMAC         0x0004
#define SSL_HT_HELLO_EXT_STATUS_REQUEST         0x0005
#define SSL_HT_HELLO_EXT_USER_MAPPING           0x0006
#define SSL_HT_HELLO_EXT_CLIENT_AUTH            0x0007
#define SSL_HT_HELLO_EXT_SERVER_AUTH            0x0008
#define SSL_HT_HELLO_EXT_CERT_TYPE              0x0009
#define SSL_HT_HELLO_EXT_ELLIPTIC_CURVES        0x000a
#define SSL_HT_HELLO_EXT_EC_POINT_FORMATS       0x000b
#define SSL_HT_HELLO_EXT_SRP                    0x000c
#define SSL_HT_HELLO_EXT_SIG_HASH_ALGS          0x000d
#define SSL_HT_HELLO_EXT_USE_SRTP               0x000e
#define SSL_HT_HELLO_EXT_HEARTBEAT              0x000f
#define SSL_HT_HELLO_EXT_ALPN                   0x0010
#define SSL_HT_HELLO_EXT_STATUS_REQUEST_V2      0x0011
#define SSL_HT_HELLO_EXT_SIGNED_CERT_TIMESTAMP  0x0012
#define SSL_HT_HELLO_EXT_CLIENT_CERT_TYPE       0x0013
#define SSL_HT_HELLO_EXT_SERVER_CERT_TYPE       0x0014
#define SSL_HT_HELLO_EXT_PADDING                0x0015
#define SSL_HT_HELLO_EXT_ENCRYPT_THEN_MAC       0x0016
#define SSL_HT_HELLO_EXT_EXT_MASTER_SECRET_TYPE 0x0017
#define SSL_HT_HELLO_EXT_SESSION_TICKET         0x0023
#define SSL_HT_HELLO_EXT_EXTENDED_RANDOM        0x0028
#define SSL_HT_HELLO_EXT_NPN                    0x3374
#define SSL_HT_HELLO_EXT_ORIGIN_BOUND_CERT      0x3377
#define SSL_HT_HELLO_EXT_ENCRYPTED_CLIENT_CERT  0x337c
#define SSL_HT_HELLO_EXT_CHANNEL_ID_OLD         0x754f
#define SSL_HT_HELLO_EXT_CHANNEL_ID             0x7550
#define SSL_HT_HELLO_EXT_RENEG_INFO             0xff01

// Compression methods
#define SSL_COMPRESSION_NULL     0
#define SSL_COMPRESSION_DEFLATE  1
#define SSL_COMPRESSION_LZS     64

// Alert level
#define SSL_AL_WARN  1
#define SSL_AL_FATAL 2

// Alert description
#define SSL_AD_CLOSE_NOTIFY            0x00
#define SSL_AD_UNEXPECTED_MSG          0x0a /* fatal */
#define SSL_AD_BAD_RECORD_MAC          0x14 /* fatal */
#define SSL_AD_DECRYPTION_FAIL         0x15 /* fatal */
#define SSL_AD_RECORD_OVERFLOW         0x16 /* fatal */
#define SSL_AD_DECOMPRESSION_FAIL      0x1e /* fatal */
#define SSL_AD_HANDSHAKE_FAIL          0x28 /* fatal */
#define SSL_AD_NO_CERT                 0x29
#define SSL_AD_BAD_CERT                0x2a
#define SSL_AD_UNSUPPORTED_CERT        0x2b
#define SSL_AD_CERT_REVOKED            0x2c
#define SSL_AD_CERT_EXPIRED            0x2d
#define SSL_AD_CERT_UNKNOWN            0x2e
#define SSL_AD_ILLEGAL_PARAM           0x2f /* fatal */
#define SSL_AD_UNKNOWN_CA              0x30 /* fatal */
#define SSL_AD_ACCESS_DENIED           0x31 /* fatal */
#define SSL_AD_DECODE_ERROR            0x32 /* fatal */
#define SSL_AD_DECRYPT_ERROR           0x33
#define SSL_AD_EXPORT_RESTRICTION      0x3c /* fatal */
#define SSL_AD_PROTOCOL_VERSION        0x46 /* fatal */
#define SSL_AD_INSUFFICIENT_SECURITY   0x47 /* fatal */
#define SSL_AD_INTERNAL_ERROR          0x50 /* fatal */
#define SSL_AD_INAPPROPRIATE_FALLBACK  0x56 /* fatal */
#define SSL_AD_USER_CANCELED           0x5a /* fatal */
#define SSL_AD_NO_RENEGOTIATION        0x64 /* warn  */
// 0x6e-0x73 - [RFC3546]
#define SSL_AD_UNSUPPORTED_EXTENSION   0x6e /* warn  */
#define SSL_AD_CERT_UNOBTAINABLE       0x6f /* warn  */
#define SSL_AD_UNRECOGNIZED_NAME       0x70
#define SSL_AD_BAD_CERT_STATUS_RESP    0x71 /* fatal */
#define SSL_AD_BAD_CERT_HASH_VALUE     0x72 /* fatal */
#define SSL_AD_UNKNOWN_PSK_IDENTITY    0x73 /* fatal */
#define SSL_AD_NO_APPLICATION_PROTOCOL 0x78 /* fatal */

// Heartbeat request/response
#define SSL_HB_REQ  0x1
#define SSL_HB_RESP 0x2

// Hello extension heartbeat
#define SSL_HB_EXT_ALLOWED     0x01 // peer allowed to send
#define SSL_HB_EXT_NOT_ALLOWED 0x02 // peer not allowed to send

#define SSL_STAT_VERSION_MISMATCH  0x0001
#define SSL_STAT_REC_TOO_LONG      0x0002 // record length > SSL_RT_MAX_LEN
#define SSL_STAT_MALFORMED         0x0004
#define SSL_STAT_CERT_EXPIRED      0x0008
#define SSL_STAT_AL_FATAL          0x0010 // connection closed due to fatal alert
#define SSL_STAT_RENEGOTIATION     0x0020
#define SSL_STAT_NO_HEARTBEAT      0x0040 // peer not allowed to send heartbeat requests

#define SSL_STAT_CIPHERL_TRUNC     0x0080 // cipher list truncated... increase SSL_MAX_CIPHER
#define SSL_STAT_EXTL_TRUNC        0x0100 // extension list truncated... increase SSL_MAX_EXT
#define SSL_STAT_PROTOL_TRUNC      0x0200 // protocol list truncated... increase SSL_MAX_PROTO
#define SSL_STAT_PROTON_TRUNC      0x0400 // protocol list truncated... increase SSL_PROTO_LEN
#define SSL_STAT_EC_TRUNC          0x0800 // EC or EC formats list truncated... increase SSL_MAX_EC or SSL_MAX_EC_FORMATS

#define SSL_STAT_BLIST             0x1000 // Cert. is blacklisted
// Weak configuration
// http://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_%28OTG-CRYPST-001%29
#define SSL_STAT_WEAK_CIPHER       0x2000 // Null, DES, RC4 (RFC7465), Anon-DH, 40/56 bits
#define SSL_STAT_WEAK_PROTO        0x4000 // SSLv2.0, SSLv3.0 // (TLSv1.0?)
#define SSL_STAT_WEAK_KEY          0x8000

// Proto
#define SSL_STAT_PROTO_HTTP     0x0001 // HTTP (HTTP/0.9, HTTP/1.0, HTTP/1.1)
#define SSL_STAT_PROTO_HTTP2    0x0002 // HTTP/2
#define SSL_STAT_PROTO_HTTP3    0x0004 // HTTP/3
#define SSL_STAT_PROTO_SPDY     0x0008 // SPDY
#define SSL_STAT_PROTO_IMAP     0x0010 // IMAP
#define SSL_STAT_PROTO_POP3     0x0020 // POP3
#define SSL_STAT_PROTO_FTP      0x0040 // FTP
#define SSL_STAT_PROTO_XMPP     0x0080 // XMPP jabber
#define SSL_STAT_PROTO_STUN     0x0100 // STUN/TURN
#define SSL_STAT_PROTO_APNS     0x0200 // Apple Push Notification Service
#define SSL_STAT_PROTO_WEBRTC   0x0400 // WebRTC Media and Data
#define SSL_STAT_PROTO_COAP     0x0800 // CoAP
#define SSL_STAT_PROTO_MANSIEVE 0x1000 // ManageSieve
#define SSL_STAT_PROTO_RTP      0x2000 // RTP or RTCP (guessed by the presence of the use_srtp extension)
#define SSL_STAT_PROTO_OVPN     0x4000 // OpenVPN (guessed by being able to decode the protocol)
#define SSL_STAT_PROTO_UNKNOWN  0x8000 // ALPN matches none of the above

// Vulnerabilities
#define SSL_VULN_BEAST       0x01 // Vulnerable to BEAST (SSLv3.0, TLSv1.0, CBC cipher)
#define SSL_VULN_BREACH      0x02 // Vulnerable to BREACH
#define SSL_VULN_CRIME       0x04 // Vulnerable to CRIME
#define SSL_VULN_FREAK       0x08 // Vulnerable to FREAK
#define SSL_VULN_POODLE      0x10 // Vulnerable to POODLE
#define SSL_VULN_HEART       0x20 // HEARTBLEED attack attempted
//#define SSL_VULN_HEART_SUCC  0x40 // HEARTBLEED attack successful (TODO: check response in reverse flow)

// Flags (see https://idea.popcount.org/2012-06-17-ssl-fingerprinting-for-p0f)
#define SSL_FLAG_V2    0x01 // request is SSLv2
#define SSL_FLAG_VER   0x02 // SSL version on 'request' layer different than on 'record' layer
#define SSL_FLAG_STIME 0x04 // gmt_unix_time small (less than 1 year since epoch)
#define SSL_FLAG_RTIME 0x08 // gmt_unix_time more than 5 years in the future
#define SSL_FLAG_RAND  0x10 // random data (28 bytes) not random
#define SSL_FLAG_COMPR 0x20 // compression (deflate) is enabled

#define SSL_TS_1YEAR   31556926 // number of seconds in one year
#define SSL_TS_5YEARS 157784630 // number of seconds in five year

// OpenVPN
#define SSL_OVPN_CTRL_HARD_RST_CLI_V1 1 // P_CONTROL_HARD_RESET_CLIENT_V1
#define SSL_OVPN_CTRL_HARD_RST_SRV_V1 2 // P_CONTROL_HARD_RESET_SERVER_V1
#define SSL_OVPN_CTRL_SOFT_RST_V1     3 // P_CONTROL_SOFT_RESET_V1
#define SSL_OVPN_CTRL_V1              4 // P_CONTROL_V1
#define SSL_OVPN_ACK_V1               5 // P_ACK_V1
#define SSL_OVPN_DATA_V1              6 // P_DATA_V1
#define SSL_OVPN_CTRL_HARD_RST_CLI_V2 7 // P_CONTROL_HARD_RESET_CLIENT_V2
#define SSL_OVPN_CTRL_HARD_RST_SRV_V2 8 // P_CONTROL_HARD_RESET_SERVER_V2
#define SSL_OVPN_DATA_V2              9 // P_DATA_V2

#define SSL_OVPN_OPCODE_IS_VALID(opcode) \
    ((opcode) >= SSL_OVPN_CTRL_HARD_RST_CLI_V1 && \
     (opcode) <= SSL_OVPN_DATA_V2)

// JA3 uses the list of Cipher, Extensions and EllipticCurves
// If one of those is truncated, there is no point in computing the fingerprint
#define SSL_STAT_JA3_TRUNC ( \
    SSL_STAT_EC_TRUNC      | \
    SSL_STAT_EXTL_TRUNC    | \
    SSL_STAT_CIPHERL_TRUNC)

#if SSL_JA3 == 1
#if SSL_CIPHER_LIST != 1
#error SSL_JA3 requires SSL_CIPHER_LIST=1
#endif // SSL_CIPHER_LIST != 1
#if SSL_EXT_LIST != 1
#error SSL_JA3 requires SSL_EXT_LIST=1
#endif // SSL_EXT_LIST != 1
#if SSL_EC != 1
#error SSL_JA3 requires SSL_EC=1
#endif // SSL_EC != 1
#if SSL_EC_FORMATS != 1
#error SSL_JA3 requires SSL_EC_FORMATS=1
#endif // SSL_EC_FORMATS != 1
#endif // SSL_JA3 == 1

// Debug
#define SSL_PRI_REC_HDR(r) (printf("[SSL_REC] type: %#02x, version: %#04x, len: %d\n", r.type, r.version, r.len))
#define SSL_PRI_ALERT(a) (printf("\t[SSL_AL] level: %d, descr: %#02x\n", a.level, a.descr))

// Alert description bitfield
#define SSL_SET_AD_BF(ssl, a) \
    switch ((a)) { \
        case SSL_AD_CLOSE_NOTIFY:            ssl->alert |= 0x00000001; break; \
        case SSL_AD_UNEXPECTED_MSG:          ssl->alert |= 0x00000002; break; \
        case SSL_AD_BAD_RECORD_MAC:          ssl->alert |= 0x00000004; break; \
        case SSL_AD_DECRYPTION_FAIL:         ssl->alert |= 0x00000008; break; \
        case SSL_AD_RECORD_OVERFLOW:         ssl->alert |= 0x00000010; break; \
        case SSL_AD_DECOMPRESSION_FAIL:      ssl->alert |= 0x00000020; break; \
        case SSL_AD_HANDSHAKE_FAIL:          ssl->alert |= 0x00000040; break; \
        case SSL_AD_NO_CERT:                 ssl->alert |= 0x00000080; break; \
        case SSL_AD_BAD_CERT:                ssl->alert |= 0x00000100; break; \
        case SSL_AD_UNSUPPORTED_CERT:        ssl->alert |= 0x00000200; break; \
        case SSL_AD_CERT_REVOKED:            ssl->alert |= 0x00000400; break; \
        case SSL_AD_CERT_EXPIRED:            ssl->alert |= 0x00000800; \
                                             ssl->stat |= SSL_STAT_CERT_EXPIRED; \
                                                                       break; \
        case SSL_AD_CERT_UNKNOWN:            ssl->alert |= 0x00001000; break; \
        case SSL_AD_ILLEGAL_PARAM:           ssl->alert |= 0x00002000; break; \
        case SSL_AD_UNKNOWN_CA:              ssl->alert |= 0x00004000; break; \
        case SSL_AD_ACCESS_DENIED:           ssl->alert |= 0x00008000; break; \
        case SSL_AD_DECODE_ERROR:            ssl->alert |= 0x00010000; break; \
        case SSL_AD_DECRYPT_ERROR:           ssl->alert |= 0x00020000; break; \
        case SSL_AD_EXPORT_RESTRICTION:      ssl->alert |= 0x00040000; break; \
        case SSL_AD_PROTOCOL_VERSION:        ssl->alert |= 0x00080000; break; \
        case SSL_AD_INSUFFICIENT_SECURITY:   ssl->alert |= 0x00100000; break; \
        case SSL_AD_INTERNAL_ERROR:          ssl->alert |= 0x00200000; break; \
        case SSL_AD_USER_CANCELED:           ssl->alert |= 0x00400000; break; \
        case SSL_AD_NO_RENEGOTIATION:        ssl->alert |= 0x00800000; break; \
        case SSL_AD_UNSUPPORTED_EXTENSION:   ssl->alert |= 0x01000000; break; \
        case SSL_AD_INAPPROPRIATE_FALLBACK:  ssl->alert |= 0x02000000; break; \
        case SSL_AD_CERT_UNOBTAINABLE:       ssl->alert |= 0x04000000; break; \
        case SSL_AD_UNRECOGNIZED_NAME:       ssl->alert |= 0x08000000; break; \
        case SSL_AD_BAD_CERT_STATUS_RESP:    ssl->alert |= 0x10000000; break; \
        case SSL_AD_BAD_CERT_HASH_VALUE:     ssl->alert |= 0x20000000; break; \
        case SSL_AD_UNKNOWN_PSK_IDENTITY:    ssl->alert |= 0x40000000; break; \
        case SSL_AD_NO_APPLICATION_PROTOCOL: ssl->alert |= 0x80000000; break; \
        default: break; \
    }

// plugin structs

#define SIZEOF_SSLV2 5
typedef struct {
    uint16_t len;
    uint8_t type;
    uint8_t version_major;
    uint8_t version_minor;
} ssl2Header_t;

typedef struct {
    uint8_t type;     // record type (SSL_RT_*)
    uint16_t version; // major(8), minor(8)
    uint16_t len;     // length of data in the record (excluding the header)
                      // (MUST NOT exceed 16384)
} sslRecordHeader_t;

typedef struct {
    uint32_t type:8;
    uint32_t len:24; // message length
} sslHandshake_t;

#define SIZEOF_SSL_ALERT 2
typedef struct {
    uint8_t level; // SSL_AL_WARN(1), SSL_AL_FATAL(2)
    uint8_t descr; // SSL_AD_*
} sslAlert_t;

#define SIZEOF_SSL_HEARTBEAT 3
typedef struct {
    uint8_t  type;
    uint16_t len;
    // len bytes of payload
    // at least 16 bytes of padding
} sslHeartbeat_t;

typedef struct {
    uint16_t version;

    // bitfield
    uint16_t stat;

    uint32_t alert;

#if SSL_EXT_LIST == 1
    uint16_t num_ext;
    uint16_t ext_list[SSL_MAX_EXT]; // extensions list
#endif // SSL_EXT_LIST

#if SSL_EC == 1
    uint8_t num_ec;
    uint16_t ec[SSL_MAX_EC]; // Elliptic Curve points
#endif // SSL_EC

#if SSL_EC_FORMATS == 1
    uint8_t num_ec_formats;
    uint8_t ec_formats[SSL_MAX_EC_FORMATS]; // EC formats list
#endif // SSL_EC_FORMATS

#if SSL_PROTO_LIST == 1
    uint16_t num_proto;
    char proto_list[SSL_MAX_PROTO][SSL_PROTO_LEN]; // protocol list
#endif // SSL_PROTO_LIST

    // cipher
    uint16_t cipher;    // preferred (client) / negotiated (server) cipher (see sslCipher.h)

#if SSL_CIPHER_LIST == 1
    uint16_t num_cipher;
    uint16_t cipher_list[SSL_MAX_CIPHER]; // cipher list (see sslCipher.h)
#endif // SSL_CIPHER_LIST

    uint16_t proto;
    uint8_t flags;

    // Statistics
    uint8_t num_server_hello_done; // 1: handshake successful
    uint8_t num_hello_req;

    // Record type statistics
    uint16_t num_change_cipher;
    uint16_t num_alert;
    uint16_t num_handshake;
    uint64_t num_app_data;
    uint64_t num_heartbeat;

    uint8_t vuln; // bitfield for vulnerabilities
    uint8_t compr;
    uint8_t session_len; // session id length

#if SSL_ANALYZE_OVPN == 1
    uint16_t ovpnType;
    uint64_t ovpnSessID;
#endif // SSL_ANALYZE_OVPN == 1

    char server_name[SSL_SNI_MAX_LEN+1];  // hello extension
    //char session_id[SSL_SESSION_ID_LEN+1];

    uint64_t gmt_time;

    // Certificate
#if SSL_ANALYZE_CERT == 1
    uint8_t cert_version;

#if SSL_CERT_SERIAL == 1
    char *cert_serial;
#endif // SSL_CERT_SERIAL == 1

#if (SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT > 0)
    char cert_fingerprint[SSL_CERT_SHA1_LEN+1];
#if SSL_BLIST == 1
    char blist_cat[SSL_BLIST_LEN];
#endif // SSL_BLIST == 1
#if SSL_JA3 == 1
    //char ja3_fingerprint[1024];
    char ja3_desc[SSL_JA3_DLEN];
    char ja3_hash[33]; // md5
#if SSL_JA3_STR == 1
    char ja3_str[SSL_JA3_STR_LEN];
#endif
#endif // SSL_JA3 == 1
#endif // (SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT > 0)

#if SSL_CERT_SIG_ALG == 1
    int sig_type; // signature algorithm
#endif // SSL_CERT_SIG_ALG

    uint16_t pkey_size; // public key size (bits)
#if SSL_CERT_PUBKEY_TS == 1 || SSL_CERT_PUBKEY_ALG == 1
    int pkey_type;   // public key type (EVP_PKEY_RSA, EVP_PKEY_DSA, EV_PKEY_EC, ...)
#endif // SSL_CERT_PUBKEY_TS == 1 || SSL_CERT_PUBKEY_ALG == 1

    // Certificate Subject
#if SSL_CERT_SUBJECT == 1
    char *cert_subject;
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
    char cert_sCommon[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_COMMON_NAME
#if SSL_CERT_ORGANIZATION == 1
    char cert_sOrg[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_ORGANIZATION
#if SSL_CERT_ORG_UNIT == 1
    char cert_sOrgUnit[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_ORG_UNIT
#if SSL_CERT_LOCALITY == 1
    char cert_sLoc[SSL_CERT_LOC_MAXLEN+1];
#endif // SSL_CERT_LOCALITY
#if SSL_CERT_STATE == 1
    char cert_sState[SSL_CERT_LOC_MAXLEN+1];
#endif // SSL_CERT_STATE
#if SSL_CERT_COUNTRY == 1
    char cert_sCountry[SSL_CERT_COUNTRY_LEN+1]; // ISO3166 two character country code
#endif // SSL_CERT_COUNTRY
#endif // SSL_CERT_SUBJECT

    // Certificate Issuer
#if SSL_CERT_ISSUER == 1
    char *cert_issuer;
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
    char cert_iCommon[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_COMMON_NAME
#if SSL_CERT_ORGANIZATION == 1
    char cert_iOrg[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_ORGANIZATION
#if SSL_CERT_ORG_UNIT == 1
    char cert_iOrgUnit[SSL_CERT_NAME_MAXLEN+1];
#endif // SSL_CERT_ORG_UNIT
#if SSL_CERT_LOCALITY == 1
    char cert_iLoc[SSL_CERT_LOC_MAXLEN+1];
#endif // SSL_CERT_LOCALITY
#if SSL_CERT_STATE == 1
    char cert_iState[SSL_CERT_LOC_MAXLEN+1];
#endif // SSL_CERT_STATE
#if SSL_CERT_COUNTRY == 1
    char cert_iCountry[SSL_CERT_COUNTRY_LEN+1]; // ISO3166 two character country code
#endif // SSL_CERT_COUNTRY
#endif // SSL_CERT_ISSUER

#if SSL_CERT_VALIDITY == 1
    struct tm cert_not_before; // TODO validity period should be <= 39 (if nb > 1 Apr. 2015) (60) months
    struct tm cert_not_after;
#endif // SSL_CERT_VALIDITY

#endif // SSL_ANALYZE_CERT == 1
} sslFlow_t;

extern sslFlow_t *sslFlow;

#endif // __SSLDECODE_H__
