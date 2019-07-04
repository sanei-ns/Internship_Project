/*
 * pwX.c
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for strcasestr
#endif // _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "pwX.h"
#include "cdecode.h"
#include "global.h"
#include "memdebug.h"

#define PLUGIN_NAME "pwX"

// Global variables

static uint32_t pwx_count;         // number of extracted passwords
#if PWX_STATUS != 0
static uint32_t pwx_success_count; // number of extracted passwords with successful login
static uint32_t pwx_fail_count;    // number of extracted passwords with failed login
#endif // PWX_STATUS != 0

// macros to print messages only in message debug mode
#if (DEBUG | PWX_DEBUG) != 0
#define debug_print(format, args...) T2_PINF(PLUGIN_NAME, format, ##args)
#else // DEBUG == 0 && PWX_DEBUG == 0
#define debug_print(format, args...)
#endif // (DEBUG | PWX_DEBUG) != 0


/**
 * @brief  Read one line from src and store it in dst
 *
 * The result stored in dst does not contain the line return but it is
 * counted in the returned value.
 *
 * @param  src pointer to the beginning of the line that we want to read
 * @param  dst pointer to the destination buffer where to store the line
 * @param  end pointer to byte after the payload
 * @param  dst_size size of the destination buffer
 * @return number of read bytes
 */
static int read_line(const char *src, char *dst, const char *end, uint16_t dst_size) {
    const char * const original_src = src;
    uint16_t written = 0;
    while (src < end && *src != '\0') {
        if (src < end-1 && *src == '\r' && src[1] == '\n') {
            src += 2;
            break;
        } else if (*src == '\n') {
            src++;
            break;
        } else {
           if (written >= dst_size - 1) {
               break;
           }
           *dst++ = *src++;
           written++;
        }
    }
    *dst = '\0';
    return src - original_src;
}

/**
 * This function assumes that dst is as big as src
 */
#if (PWX_SMTP | PWX_HTTP_BASIC | PWX_HTTP_PROXY) != 0
static int unbase64(const char *src, char *dst) {
    // initialize base64 decoder state
    base64_decodestate s;
    base64_init_decodestate(&s);
    // decode base64 string
    return base64_decode_block(src, strlen(src), dst, &s);
}

/**
 * This function assumes that dst is as big as src
 */
#if PWX_SMTP != 0
static int unbase64_str(const char *src, char *dst) {
    const int cnt = unbase64(src, dst);
    dst[cnt] = '\0';
    return cnt;
}
#endif // PWX_SMTP != 0
#endif // (PWX_SMTP | PWX_HTTP_BASIC | PWX_HTTP_PROXY) != 0

/**
 * @brief  Extract username and password from SMTP AUTH PLAIN format
 *
 * This function assumes that user_dst and pass_dst are at least as long as src.
 *
 * @param  src pointer to the SMTP AUTH PLAIN login string
 * @param  user_dst pointer to the buffer where to store the decoded username
 * @param  pass_dst pointer to the buffer where to store the decoded password
 * @retval -1 if something went wrong
 */
#if PWX_SMTP != 0
static int decode_plain_auth(const char *src, char *user_dst, char *pass_dst) {
#if (DEBUG | PWX_DEBUG) != 0
    const char * const origin_user = user_dst;
    const char * const origin_pass = pass_dst;
#endif // (DEBUG | PWX_DEBUG) != 0
    // temporary buffer to receive decoded base64
    char buffer[PE_BUFFER_SIZE];
    // decode login
    const int cnt = unbase64(src, buffer);
    const char *ptr = buffer;
    const char * const end = ptr + cnt;
    // skip authorization id part
    while (ptr < end && *ptr != '\0') {
        ptr++;
    }
    ptr++; // skip the separating '\0'
    // store the username
    while (ptr < end && *ptr != '\0') {
        *user_dst++ = *ptr++;
    }
    *user_dst = '\0'; // add the terminating '\0'
    ptr++; // skip the separating '\0'
    // store the password
    while (ptr < end && *ptr != '\0') {
        *pass_dst++ = *ptr++;
    }
    *pass_dst = '\0'; // add the terminating '\0'
    debug_print("plain auth: %s -> %s : %s", src, origin_user, origin_pass);
    return 0;
}
#endif // PWX_SMTP != 0

/**
 * @brief  Extract username and password from HTTP basic format
 *
 * This function assumes that user_dst and pass_dst are at least as long as src.
 *
 * @param  src pointer to the HTTP basic login string
 * @param  user_dst pointer to the buffer where to store the decoded username
 * @param  pass_dst pointer to the buffer where to store the decoded password
 * @retval -1 if something went wrong
 */
#if (PWX_HTTP_BASIC | PWX_HTTP_PROXY) != 0
static int decode_basic_auth(const char *src, char *user_dst, char *pass_dst) {
#if (DEBUG | PWX_DEBUG) != 0
    const char * const origin_user = user_dst;
    const char * const origin_pass = pass_dst;
#endif // (DEBUG | PWX_DEBUG) != 0
    // temporary buffer to receive decoded base64
    char buffer[PE_BUFFER_SIZE];
    // decode login
    const int cnt = unbase64(src, buffer);
    const char *ptr = buffer;
    const char * const end = ptr + cnt;
    // store the username
    while (ptr < end && *ptr != ':') {
        *user_dst++ = *ptr++;
    }
    *user_dst = '\0'; // add the terminating '\0'
    ptr++; // skip the separating ':'
    // store the password
    while (ptr < end && *ptr != '\0') {
        *pass_dst++ = *ptr++;
    }
    *pass_dst = '\0'; // add the terminating '\0'
    debug_print("basic auth: %s -> %s : %s", src, origin_user, origin_pass);
    return 0;
}
#endif // (PWX_HTTP_BASIC | PWX_HTTP_PROXY) != 0

/**
 * @brief  Extract username and password from IMAP login
 *
 * This function assumes that user_dst and pass_dst are at least as long as src.
 *
 * @param  src pointer to the IMAP login string
 * @param  user_dst pointer to the buffer where to store the decoded username
 * @param  pass_dst pointer to the buffer where to store the decoded password
 * @retval -1 if something went wrong
 */
#if PWX_IMAP != 0
static int decode_imap_auth(const char *src, char *user_dst, char *pass_dst) {
#if (DEBUG | PWX_DEBUG) != 0
    const char * const origin_user = user_dst;
    const char * const origin_pass = pass_dst;
#endif // (DEBUG | PWX_DEBUG) != 0
    // check if username and password are quoted
    bool quoted = false;
    if (*src == '"') {
        quoted = true;
        ++src;
    }
    // store the username
    while (*src != '\0' && ((quoted && (*src != '"' || src[-1] == '\\')) || (!quoted && *src != ' '))) {
        *user_dst++ = *src++;
    }
    *user_dst = '\0'; // add the terminating '\0'
    if (quoted) {
        ++src; // skip closing quote
    }
    ++src; // skip the separating ' '
    quoted = false;
    if (*src == '"') {
        quoted = true;
        ++src;
    }
    // store the password
    while (*src != '\0') {
        *pass_dst++ = *src++;
    }
    if (quoted) {
        --pass_dst;
    }
    *pass_dst = '\0'; // add the terminating '\0'
    debug_print("imap auth: %s : %s", origin_user, origin_pass);
    return 0;
}
#endif // PWX_IMAP != 0

/**
 * @brief  Extract username and password from url-encoded HTTP GET/POST
 *
 * This function assumes that user_dst and pass_dst are at least as long as src.
 *
 * @param  src pointer to the url-encoded login string
 * @param  user_dst pointer to the buffer where to store the decoded username
 * @param  pass_dst pointer to the buffer where to store the decoded password
 * @retval -1 if something went wrong
 * @retval 0 if username and password where not found
 * @retval 1 if username and password where found
 */
#if (PWX_HTTP_GET | PWX_HTTP_POST) != 0
static int decode_http_auth(const char *src, char *user_dst, char *pass_dst) {
#if (DEBUG | PWX_DEBUG) != 0
    const char * const origin_src  = src;
#endif // (DEBUG | PWX_DEBUG) != 0
    const char * const origin_user = user_dst;
    const char * const origin_pass = pass_dst;
    // temporary buffer to store key
    char buffer[PE_BUFFER_SIZE];
    bool found_user = false;
    bool found_pass = false;
    while (*src != '\0' && *src != ' ' && !(found_pass && found_user)) {
        // read key
        char *ptr = buffer;
        while (*src != '\0' && *src != ' ' && *src != '=') {
            *ptr++ = *src++;
        }
        if (*src != '=') {
            break;
        }
        ++src; // skip '='
        *ptr = '\0'; // null terminate key in buffer
        // check if key is username
        if (!found_user && ((strcasestr(buffer, "user")) || strcasestr(buffer, "login"))) {
            // store username
            while (*src != '\0' && *src != ' ' && *src != '&') {
                *user_dst++ = *src++;
            }
            *user_dst = '\0'; // add the terminating '\0'
            found_user = true;
        } else if (!found_pass && (strcasestr(buffer, "pass") || strcasestr(buffer, "pwd"))) {
            // store password
            while (*src != '\0' && *src != ' ' && *src != '&') {
                *pass_dst++ = *src++;
            }
            *pass_dst = '\0'; // add the terminating '\0'
            found_pass = true;
        }
        if (*src == '&') {
            ++src; // skip '&'
        }
    }
    if (found_user && found_pass && strlen(origin_user) > 0 && strlen(origin_pass) > 0) {
        debug_print("http auth: %s -> %s : %s", origin_src, origin_user, origin_pass);
        return 1;
    }
    return 0;
}
#endif // (PWX_HTTP_GET | PWX_HTTP_POST) != 0

/*
 * Notify opposite flow that the status of the login should be checked on next packet.
 */
#if PWX_STATUS == 0
static void set_check_status(unsigned long flowIndex __attribute__ ((unused)),
        PasswordProtocol proto __attribute__ ((unused))) {
#else // PWX_STATUS != 0
static void set_check_status(unsigned long flowIndex, PasswordProtocol proto) {
    const unsigned long oppositeFlowIndex = flows[flowIndex].oppositeFlowIndex;
    if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        pwX_flows[oppositeFlowIndex].proto = proto;
    }
#endif // PWX_STATUS != 0
}

/*
 * Set auth status in opposite flow and mark this flow as extracted.
 */
#if PWX_STATUS != 0
static void set_auth_status(unsigned long flowIndex, AuthStatus status) {
    const unsigned long oppositeFlowIndex = flows[flowIndex].oppositeFlowIndex;
    // should always be true
    if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        pwX_flows[oppositeFlowIndex].status = status;
    }
    pwX_flows[flowIndex].proto = ALREADY_EXTRACTED;
    // update global success/fail counts
    if (status == SUCCESS) {
        ++pwx_success_count;
    } else if (status == FAILED) {
        ++pwx_fail_count;
    }
}
#endif // PWX_STATUS != 0

/**
 * Make a copy of username and password buffers and store them in the password flow strucutre.
 * Set the correct authentication type and mark flow as already extracted
 */
static int copy_and_store(const char * const user, const char * const pass,
        pwX_flow_t * const pwx_flow, AuthType auth_type) {
    // make a copy of the username and store it in the flow structure
    pwx_flow->username = strdup(user);
    // make a copy of the username and store it in the flow structure
    pwx_flow->password = strdup(pass);
    // set the authentication type as auth_type
    pwx_flow->auth_type = auth_type;
    pwx_flow->proto = ALREADY_EXTRACTED;
    return 0;
}

/**
 * FTP like login extraction (used by FTP, POP3 and IRC)
 * 1st packet: USER username
 * 2nd packet: PASS password
 */
#if (PWX_FTP | PWX_POP3 | PWX_IRC) != 0
static int ftp_login_extract(pwX_flow_t * const pwx_flow, const char * const payload,
        const char * const payload_end, char *buffer, AuthType auth_type) {
    if (!pwx_flow->username && strncmp(payload, "USER ", 5) == 0) {
        // read the username
        read_line(payload + 5, buffer, payload_end, PE_BUFFER_SIZE);
    #if PWX_IRC != 0
        // IRC USER command is slightly different: username is followed by other parameters
        if (auth_type == IRC_AUTH) {
            for (size_t i = 0; i < strlen(buffer); ++i) {
                if (buffer[i] == ' ') {
                    buffer[i] = '\0';
                    break;
                }
            }
        }
    #endif // PWX_IRC
        // make a copy of the buffer
        pwx_flow->username = strdup(buffer);
        // set the authentication type as auth_type
        pwx_flow->auth_type = auth_type;
    } else if (!pwx_flow->password && strncmp(payload, "PASS ", 5) == 0) {
        // read the username
        read_line(payload + 5, buffer, payload_end, PE_BUFFER_SIZE);
        // make a copy of the buffer
        pwx_flow->password = strdup(buffer);
        // set the authentication type as auth_type
        pwx_flow->auth_type = auth_type;
    }
    if (pwx_flow->password && pwx_flow->username) {
        pwx_flow->proto = ALREADY_EXTRACTED;
        return 1;
    }
    return 0;
}
#endif // (PWX_FTP | PWX_POP3 | PWX_IRC) != 0

#if PWX_TELNET != 0
static int extract_telnet(char **buffer, const char *src, const char * const end) {
    // create username / password buffer on first call
    if (!*buffer) {
        *buffer = malloc(PE_BUFFER_SIZE);
        memset(*buffer, 0, PE_BUFFER_SIZE);
    }
    // special case for strange telnet client
    // sends "\r\0" in single packet instead of ending string with "\r\n"
    if (end - src == 2 && src[0] == '\r' && src[1] == '\0') {
        return 1;
    }

    // parse payload
    size_t len = strlen(*buffer);
    while (src < end && *src != '\0' && *src != -1) {
        // conditions to stop filling the buffer
        if (len >= PE_BUFFER_SIZE - 1 || *src == '\n') {
            if (len > 0 && (*buffer)[len-1] == '\r') {
                (*buffer)[len-1] = '\0';
            }
            return 1;
        }
        // some clients end lines with only '\r'
        if (src == end - 1 && *src == '\r') {
            return 1;
        }
        if (*src == 8) { // backspace
            if (len > 0) {
                (*buffer)[--len] = '\0';
            }
            ++src;
        } else {
            (*buffer)[len++] = *src++;
        }
    }
    return 0;
}
#endif // PWX_TELNET != 0

/**
 * DER decoding of LDAP bind request
 */
#if PWX_LDAP != 0
static int extract_ldap(const char* payload, const char * const end, pwX_flow_t * const pwx_flow) {
    if ((*payload++ & 0x1f) != 0x10) {
        return 0; // not a DER sequence
    }
    uint8_t len = *payload++;
    if (payload + len > end) {
        return 0; // invalid DER or cut payload
    }
    if ((*payload++ & 0x1f) != 0x02 || *payload++ != 1) {
        return 0; // invalid message ID type
    }
    ++payload; // skip message ID
    if (*payload++ != 0x60) {
        return 0; // this is not a bind request
    }
    ++payload; // skip unknown byte
    if ((*payload++ & 0x1f) != 0x02 || *payload++ != 1) {
        return 0; // invalid version type
    }
    ++payload; // skip version
    // extract username
    if ((*payload++ & 0x1f) != 0x04) {
        return 0; // invalid name type
    }
    len = *payload++;
    if (payload + len > end) {
        return 0; // invalid DER or cut payload
    }
    pwx_flow->username = strndup(payload, len);
    payload += len;
    // already mark flow as extracted in case of error / not simple auth
    pwx_flow->auth_type = LDAP_AUTH;
    pwx_flow->proto = ALREADY_EXTRACTED;
    // extract password
    if (*payload++ != -128) { // -128 is encoded as 0x80
        return 0; // not using simple auth type => cannot extract password
    }
    len = *payload++;
    if (payload + len > end) {
        return 0; // invalid DER or cut payload
    }
    pwx_flow->password = strndup(payload, len);
    // don't output anonymous bind requests
    if (strlen(pwx_flow->username) == 0 && strlen(pwx_flow->password) == 0) {
        pwx_flow->auth_type = NO_AUTH;
    }
    return 1;
}

#if PWX_STATUS != 0
static AuthStatus extract_ldap_status(const char* payload, const char * const end) {
    if ((*payload++ & 0x1f) != 0x10) {
        return UNKNOWN; // not a DER sequence
    }
    uint8_t len = *payload++;
    if (len != 0x84 && payload + len > end) {
        return UNKNOWN; // invalid DER or cut payload
    }
    if (len == 0x84) {
        payload += 4;
    }
    if ((*payload++ & 0x1f) != 0x02 || *payload++ != 1) {
        return UNKNOWN; // invalid message ID type
    }
    ++payload; // skip message ID
    if (*payload++ != 0x61) {
        return UNKNOWN; // this is not a bind response
    }
    len = *payload++;
    if (len != 0x84 && payload + len > end) {
        return UNKNOWN; // invalid DER or cut payload
    }
    if (len == 0x84) {
        payload += 4;
    }
    if ((*payload++ & 0x1f) != 0x0a) {
        return UNKNOWN; // not an enumerated type
    }
    if (*payload++ != 1) {
        return UNKNOWN; // not a 1 byte result code
    }

    uint8_t code = *payload;
    if (code == 0) {
        return SUCCESS;
    } else if (code == 1) {
        return FAILED;
    } else {
        return UNKNOWN;
    }
}
#endif // PWX_STATUS != 0
#endif // PWX_LDAP != 0

#if PWX_PAP != 0
static bool pap_extract(pwX_flow_t * const pwx_flow, const uint8_t *pap_hdr, size_t pap_len) {
    if (pap_len < 8 || pap_hdr[0] != 1) {
        return false;
    }

    size_t user_len = (size_t)pap_hdr[4];
    if (user_len + 5 > pap_len) {
        return false;
    }

    // mark flow as extracted
    pwx_flow->auth_type = PAP_AUTH;
    pwx_flow->proto = ALREADY_EXTRACTED;

    // copy username
    if (!(pwx_flow->username = malloc(user_len + 1))) {
        return false;
    }
    memcpy(pwx_flow->username, &pap_hdr[5], user_len);
    pwx_flow->username[user_len] = '\0';

    // check if packet is not snapped at password
    if (user_len + 5 >= pap_len) {
        return false;
    }
    size_t pass_len = (size_t)pap_hdr[user_len + 5];
    if (pass_len + user_len + 6 > pap_len) {
        return false;
    }

    // copy password
    if (!(pwx_flow->password = malloc(pass_len + 1))) {
        return false;
    }
    memcpy(pwx_flow->password, &pap_hdr[6 + user_len], pass_len);
    pwx_flow->password[pass_len] = '\0';

    debug_print("PAP auth: %s:%s", pwx_flow->username, pwx_flow->password);
    return true;
}
#endif // PWX_PAP != 0

/**
 * Classify protocol based on destination port
 */
static PasswordProtocol proto_from_port(uint16_t dstPort, uint16_t srcPort
#if PWX_TELNET == 0
__attribute__ ((unused))
#endif // PWX_TELNET == 0
) {
#if PWX_HTTP != 0
    if (dstPort == 80 || dstPort == 8080) {
        return HTTP;
    }
#endif // PWX_HTTP != 0
#if PWX_FTP != 0
    if (dstPort == 21) {
        return FTP;
    }
#endif // PWX_FTP != 0
#if PWX_POP3 != 0
    if (dstPort == 110) {
        return POP3;
    }
#endif // PWX_POP3 != 0
#if PWX_IMAP != 0
    if (dstPort == 143) {
        return IMAP;
    }
#endif // PWX_IMAP != 0
#if PWX_SMTP != 0
    if (dstPort == 25 || dstPort == 587) {
        return SMTP;
    }
#endif // PWX_SMTP != 0
#if PWX_IRC != 0
    if ((dstPort >= 6667 && dstPort <= 6669) || dstPort == 194) {
        return IRC;
    }
#endif // PWX_IRC != 0
#if PWX_TELNET != 0
    if (dstPort == 23) {
        return TELNET;
    } else if (srcPort == 23) {
        return TELNET_B;
    }
#endif // PWX_TELNET != 0
#if PWX_LDAP != 0
    if (dstPort == 389) {
        return LDAP;
    }
#endif // PWX_LDAP != 0
    return NOT_EXTRACTABLE;
}


// Tranalyzer functions

T2_PLUGIN_INIT(PLUGIN_NAME, "0.8.4", 0, 8);


void initialize() {
    // allocate memory for plugin structures for each flow
    pwX_flows = calloc(mainHashMap->hashChainTableSize, sizeof(pwX_flow_t));
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;

    // authentication type column
    bv = bv_append_bv(bv, bv_new_bv("Authentication type of the extracted username/password",
                "pwxType", 0, 1, bt_uint_8));
#if PWX_USERNAME != 0
    // username column
    bv = bv_append_bv(bv, bv_new_bv("Extracted username", "pwxUser", 0, 1, bt_string));
#endif // PWX_USERNAME != 0
#if PWX_PASSWORD != 0
    // password column
    bv = bv_append_bv(bv, bv_new_bv("Extracted password", "pwxPass", 0, 1, bt_string));
#endif // PWX_PASSWORD != 0
#if PWX_STATUS != 0
    // authentication status column
    bv = bv_append_bv(bv, bv_new_bv("Authentication status", "pwxStatus", 0, 1, bt_uint_8));
#endif // PWX_STATUS != 0

    return bv;
}

void onFlowGenerated(packet_t* packet __attribute__ ((unused)), unsigned long flowIndex) {
    pwX_flow_t *pwX_P = &pwX_flows[flowIndex];
    memset(pwX_P, 0, sizeof(pwX_flow_t)); // set everything to 0
}


#if PWX_PAP != 0 && ETH_ACTIVATE > 0
void claimLayer2Information(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    pwX_flow_t *passExtractP = &pwX_flows[flowIndex];

    // nothing to do if protocol doesn't contain extractable passwords
    if (passExtractP->proto == NOT_EXTRACTABLE || passExtractP->proto == ALREADY_EXTRACTED) {
        return;
    }

    // if protocol is not defined yet, try to guess it
    if (passExtractP->proto == UNDEFINED) {
        // check for PAP over PPP or PPPoES
        if ((packet->status & L2_PPPoE_S) && (packet->pppoEHdr != NULL) &&
                (packet->pppoEHdr->pppProt == PPP_PAPn)) {
            // check that packet is not snapped before PAP header
            uint8_t *pap_hdr = (uint8_t *)packet->pppoEHdr + sizeof(pppoEH_t);
            if (pap_hdr - (uint8_t *)packet->layer2Header < packet->snapL2Length) {
                size_t pap_len = packet->snapL2Length - (pap_hdr - (uint8_t *)packet->layer2Header);
                if (pap_extract(passExtractP, pap_hdr, pap_len)) {
                    set_check_status(flowIndex, CHECK_PAP);
                }
            }
        }
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_PAP) {
        // check for PAP over PPP or PPPoES
        if ((packet->status & L2_PPPoE_S) && (packet->pppoEHdr != NULL) &&
                (packet->pppoEHdr->pppProt == PPP_PAPn)) {
            // check that packet is not snapped before PAP header
            uint8_t *pap_hdr = (uint8_t *)packet->pppoEHdr + sizeof(pppoEH_t);
            if (pap_hdr - (uint8_t *)packet->layer2Header < packet->snapL2Length) {
                if (pap_hdr[0] == 2) {
                    set_auth_status(flowIndex, SUCCESS);
                } else if (pap_hdr[0] == 3) {
                    set_auth_status(flowIndex, FAILED);
                } else {
                    set_auth_status(flowIndex, UNKNOWN);
                }
            }
        }
    #endif // PWX_STATUS != 0
    }
}
#endif // PWX_PAP != 0 && ETH_ACTIVATE > 0


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    flow_t *flowP = &flows[flowIndex];

    pwX_flow_t *passExtractP = &pwX_flows[flowIndex];

    // nothing to do if protocol doesn't contain extractable passwords
    if (passExtractP->proto == NOT_EXTRACTABLE || passExtractP->proto == ALREADY_EXTRACTED) {
        return;
    }

    // if protocol is not defined yet, try to guess it
    if (passExtractP->proto == UNDEFINED) {
    #if PWX_PAP != 0
        // check for PAP over PPP over GRE
        if ((packet->status & L2_PPP) && (packet->status & L2_GRE) &&
                (packet->pppHdr != NULL) && (packet->pppHdr->pppHdru.prot == PPP_PAPn)) {
            // check that packet is not snapped before PAP header
            uint8_t *pap_hdr = (uint8_t *)packet->pppHdr + sizeof(pppHdr_t);
            if (pap_hdr - (uint8_t *)packet->layer2Header < packet->snapL2Length) {
                size_t pap_len = packet->snapL2Length - (pap_hdr - (uint8_t *)packet->layer2Header);
                if (pap_extract(passExtractP, pap_hdr, pap_len)) {
                    // INFO: opposite flow might not exist yet: no check will be done
                    set_check_status(flowIndex, CHECK_PAP);
                }
            }
        }
    #endif // PWX_PAP != 0

        // currently all protocol we analyze are using TCP
        if (packet->layer4Type != L3_TCP) {
            passExtractP->proto = NOT_EXTRACTABLE;
            return;
        }
        // define protocol based on destination port
        passExtractP->proto = proto_from_port(flowP->dstPort, flowP->srcPort);
        if (passExtractP->proto == NOT_EXTRACTABLE) {
            return;
        }
    }

    #if PWX_PAP != 0 && PWX_STATUS != 0
    if (passExtractP->proto == CHECK_PAP) {
        // check for PAP over PPP or PPPoES
        if ((packet->status & L2_PPP) && (packet->status & L2_GRE) &&
                (packet->pppHdr != NULL) && (packet->pppHdr->pppHdru.prot == PPP_PAPn)) {
            // check that packet is not snapped before PAP header
            uint8_t *pap_hdr = (uint8_t *)packet->pppHdr + sizeof(pppHdr_t);
            if (pap_hdr - (uint8_t *)packet->layer2Header < packet->snapL2Length) {
                if (pap_hdr[0] == 2) {
                    set_auth_status(flowIndex, SUCCESS);
                } else if (pap_hdr[0] == 3) {
                    set_auth_status(flowIndex, FAILED);
                } else {
                    set_auth_status(flowIndex, UNKNOWN);
                }
            }
        }
    }
    #endif // PWX_PAP != 0 && PWX_STATUS != 0

    // L7 payload
    const char * payload = (const char * const) packet->layer7Header;
    const char * const payload_end = payload + packet->snapL7Length;
    // temporary buffers
    char buffer[PE_BUFFER_SIZE];
#if (PWX_SMTP | PWX_IMAP | PWX_HTTP | PWX_IRC) != 0
    char user_buffer[PE_BUFFER_SIZE];
    char pass_buffer[PE_BUFFER_SIZE];
#endif // (PWX_SMTP | PWX_IMAP | PWX_HTTP | PWX_IRC) != 0

    int count;
    const uint32_t seq = ntohl(packet->layer4Header->tcpHeader.seq);

#if PWX_FTP != 0
    // FTP authentication extraction
    if (passExtractP->proto == FTP && packet->snapL7Length > 5) {
        if (ftp_login_extract(passExtractP, payload, payload_end, buffer, FTP_AUTH)) {
            set_check_status(flowIndex, CHECK_FTP);
        }
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_FTP && packet->snapL7Length >= 3) {
        if (strncmp(payload, "230", 3) == 0) {
            set_auth_status(flowIndex, SUCCESS);
        } else {
            set_auth_status(flowIndex, FAILED);
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_FTP != 0

#if PWX_POP3 != 0
    // POP3 authentication extraction
    if (passExtractP->proto == POP3 && packet->snapL7Length > 5) {
        if (ftp_login_extract(passExtractP, payload, payload_end, buffer, POP3_AUTH)) {
            set_check_status(flowIndex, CHECK_POP3);
        }
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_POP3 && packet->snapL7Length >= 3) {
        if (strncmp(payload, "+OK", 3) == 0) {
            set_auth_status(flowIndex, SUCCESS);
        } else {
            set_auth_status(flowIndex, FAILED);
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_POP3 != 0

#if PWX_IRC != 0
    // IRC authentication extraction
    if (passExtractP->proto == IRC && packet->snapL7Length > 5) {
        // users can log in using PASS and USER messages similar to FTP and POP3
        if (ftp_login_extract(passExtractP, payload, payload_end, buffer, IRC_AUTH)) {
            // TODO: find traffic or IRC server supporting USER/PASS login to see response
            //set_check_status(flowIndex, CHECK_IRC_PASS);
        }
        count = read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
        // on some servers, users can also log in using the /NS IDENTIFY command
        if (strncasecmp(buffer, "ns identify ", 12) == 0) {
            passExtractP->password = strdup(buffer + 12);
            passExtractP->auth_type = IRC_AUTH;
            // TODO: find traffic or IRC server supporting NS IDENTIFY login to see response
            //set_check_status(flowIndex, CHECK_IRC_NS);
        } else if (strncasecmp(buffer, "privmsg nickserv :identify ", 27) == 0) { // freenode specific
            debug_print("irc freenode auth found: %s", buffer);
            passExtractP->password = strdup(buffer + 27);
            passExtractP->auth_type = IRC_AUTH;
            set_check_status(flowIndex, CHECK_IRC_FREENODE);
        } else if (strncasecmp(buffer, "nick ", 5) == 0) {
            passExtractP->username = strdup(buffer + 5);
            passExtractP->auth_type = IRC_AUTH;
        }

        // if both username and password have already been extracted, don't check next packages
        if (passExtractP->username && passExtractP->password) {
            passExtractP->proto = ALREADY_EXTRACTED;
        }
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_IRC_FREENODE && packet->snapL7Length > 40) {
        count = read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
        if (strcasestr(buffer, "invalid password") != NULL) {
            set_auth_status(flowIndex, FAILED);
        } else if (strcasestr(buffer, "identified for") != NULL) {
            set_auth_status(flowIndex, SUCCESS);
        } else {
            set_auth_status(flowIndex, UNKNOWN);
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_IRC != 0

#if PWX_SMTP != 0
    // SMTP authentication extraction
    if (passExtractP->proto == SMTP) {
        // start of AUTH LOGIN
        if (packet->snapL7Length >= 10 && strncmp(payload, "AUTH LOGIN", 10) == 0) {
            passExtractP->smtp_login_state = 1; // next packet is username
            passExtractP->next_seq = seq + packet->packetL7Length;
        } else if (packet->snapL7Length >= 10 && strncmp(payload, "AUTH PLAIN", 10) == 0) {
            // check if authentication was sent on the same line
            count = read_line(payload + 11, buffer, payload_end, PE_BUFFER_SIZE);
            if (count <= 0) {
                passExtractP->smtp_plain_state = 1; // next packet is username/password
                passExtractP->next_seq = seq + packet->packetL7Length;
            } else {
                decode_plain_auth(buffer, user_buffer, pass_buffer);
                // store username and password in flow and set auth as SMTP
                copy_and_store(user_buffer, pass_buffer, passExtractP, SMTP_AUTH);
                set_check_status(flowIndex, CHECK_SMTP);
            }
        } else if (packet->snapL7Length >= 3 && passExtractP->smtp_login_state == 1 &&
                seq == passExtractP->next_seq) {
            read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
            unbase64_str(buffer, user_buffer);
            // make a copy of the username and store it in the flow structure
            passExtractP->username = strdup(user_buffer);
            passExtractP->smtp_login_state = 2;
            passExtractP->next_seq = seq + packet->packetL7Length;
            // set the authentication type as SMTP
            passExtractP->auth_type = SMTP_AUTH;
        } else if (packet->snapL7Length >= 3 && passExtractP->smtp_login_state == 2 &&
                seq == passExtractP->next_seq) {
            read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
            unbase64_str(buffer, pass_buffer);
            // make a copy of the password and store it in the flow structure
            passExtractP->password = strdup(pass_buffer);
            // set the authentication type as SMTP
            passExtractP->auth_type = SMTP_AUTH;
            passExtractP->proto = ALREADY_EXTRACTED;
            set_check_status(flowIndex, CHECK_SMTP);
        } else if (packet->snapL7Length >= 3 && passExtractP->smtp_plain_state == 1 &&
                seq == passExtractP->next_seq) {
            read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
            decode_plain_auth(buffer, user_buffer, pass_buffer);
            // store username and password in flow and set auth as SMTP
            copy_and_store(user_buffer, pass_buffer, passExtractP, SMTP_AUTH);
            set_check_status(flowIndex, CHECK_SMTP);
        }
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_SMTP && packet->snapL7Length >= 3) {
        if (strncmp(payload, "235", 3) == 0) {
            set_auth_status(flowIndex, SUCCESS);
        } else {
            set_auth_status(flowIndex, FAILED);
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_SMTP != 0

#if PWX_IMAP != 0
    // IMAP authentication extraction
    if (passExtractP->proto == IMAP && packet->snapL7Length >= 10) {
        count = read_line(payload, buffer, payload_end, PE_BUFFER_SIZE);
        // check that the line is long enough to contain a login
        if (count < 10) {
            return;
        }
        const char * const login = strstr(buffer, " LOGIN ");
        // check that the LOGIN string is present and correctly positionned
        if (!login || login - buffer > 2) {
            return;
        }
        debug_print("IMAP auth found: %s", buffer);
        decode_imap_auth(login + 7, user_buffer, pass_buffer);
        // store username and password in flow and set auth as IMAP
        copy_and_store(user_buffer, pass_buffer, passExtractP, IMAP_AUTH);
        set_check_status(flowIndex, CHECK_IMAP);
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_IMAP && packet->snapL7Length > 5) {
        const char * const space = strnstr(payload, " ", packet->snapL7Length);
        if (space && space + 2 < payload_end) {
            if (strncasecmp(space + 1, "OK", 2) == 0) {
                set_auth_status(flowIndex, SUCCESS);
            } else {
                set_auth_status(flowIndex, FAILED);
            }
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_IMAP != 0

#if PWX_HTTP != 0
    // HTTP authentication extraction
    if (passExtractP->proto == HTTP) {
    #if PWX_HTTP_POST != 0
        bool post_form = false;
    #endif // PWX_HTTP_POST != 0
        // for now, just extract HTTP basic authentication
        size_t cursor = 0;
        while (payload + cursor + 21 < payload_end) {
            count = read_line(payload + cursor, buffer, payload_end, PE_BUFFER_SIZE);
            cursor += count;
            if (count < 3) {
                break; // we reached the end of the HTTP header
            }
        #if PWX_HTTP_BASIC != 0
            // basic authorization header
            if (strncmp(buffer, "Authorization: Basic ", 21) == 0) {
                decode_basic_auth(buffer + 21, user_buffer, pass_buffer);
                // store username and password in flow and set auth as HTTP basic
                copy_and_store(user_buffer, pass_buffer, passExtractP, HTTP_BASIC_AUTH);
                set_check_status(flowIndex, CHECK_HTTP);
                return;
            }
        #endif // PWX_HTTP_BASIC != 0
        #if PWX_HTTP_PROXY != 0
            if (strncmp(buffer, "Proxy-Authorization: Basic ", 27) == 0) {
                decode_basic_auth(buffer + 27, user_buffer, pass_buffer);
                // store username and password in flow and set auth as HTTP proxy
                copy_and_store(user_buffer, pass_buffer, passExtractP, HTTP_PROXY_AUTH);
                set_check_status(flowIndex, CHECK_HTTP);
                return;
            }
        #endif // PWX_HTTP_PROXY != 0
        #if PWX_HTTP_POST != 0
            if (strncmp(buffer, "Content-Type: application/x-www-form-urlencoded", 47) == 0) {
                post_form = true;
            }
        #endif // PWX_HTTP_POST != 0
        #if PWX_HTTP_GET != 0
            if (strncmp(buffer, "GET ", 4) == 0) {
                int i = 4;
                // skip start of request until GET parameters
                while (buffer[i] != '\0' && buffer[i] != '?') {
                    ++i;
                }
                // if no GET parameters, continue parsing HTTP header
                if (buffer[i] != '?') {
                    continue;
                }
                if (decode_http_auth(buffer + i + 1, user_buffer, pass_buffer) == 1) {
                    copy_and_store(user_buffer, pass_buffer, passExtractP, HTTP_GET_AUTH);
                    // TODO: find reliable way to check status
                    return;
                }
            }
        #endif // PWX_HTTP_GET != 0
        }
    #if PWX_HTTP_POST != 0
        // extract authentication from posted HTTP form
        if (post_form) {
            read_line(payload + cursor, buffer, payload_end, PE_BUFFER_SIZE);
            if (decode_http_auth(buffer, user_buffer, pass_buffer) == 1) {
                copy_and_store(user_buffer, pass_buffer, passExtractP, HTTP_POST_AUTH);
                // TODO: find reliable way to check status
            }
        }
    #endif // PWX_HTTP_POST != 0
        return;
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_HTTP && packet->snapL7Length >= 12) {
        if (strncmp(payload + 8, " 403", 4) == 0) {
            set_auth_status(flowIndex, FAILED);
        } else {
            set_auth_status(flowIndex, SUCCESS);
        }
    #endif // PWX_STATUS != 0
    }
#endif // PWX_HTTP != 0

#if PWX_TELNET != 0
    if (passExtractP->proto == TELNET_B) {
        const uint32_t ack = ntohl(packet->layer4Header->tcpHeader.ack_seq);
        // special case for strange server which happen some '\r\0' in front of login string
        while (payload_end - payload > 2 && payload[0] == '\r' && payload[1] == '\0') {
            payload += 2;
        }
        if (strncasestr(payload, "login:", payload_end - payload) ||
                strncasestr(payload, "username:", payload_end - payload)) {
            const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
            if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                pwX_flow_t *opposite_pwX_P = &pwX_flows[oppositeFlowIndex];
                opposite_pwX_P->telnet_state = 1;
                opposite_pwX_P->next_seq = ack;
            } else {
                passExtractP->proto = NOT_EXTRACTABLE;
            }
        } else if (strncasestr(payload, "password:", payload_end - payload)) {
            const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
            if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                pwX_flow_t *opposite_pwX_P = &pwX_flows[oppositeFlowIndex];
                opposite_pwX_P->telnet_state = 2;
                opposite_pwX_P->next_seq = ack;
            } else {
                passExtractP->proto = NOT_EXTRACTABLE;
            }
        }
        return;
    }
    if (passExtractP->proto == TELNET) {
        if (passExtractP->telnet_state == 1 && passExtractP->next_seq == seq) {
            if (extract_telnet(&passExtractP->username, payload, payload_end)) {
                passExtractP->telnet_state = 2;
                passExtractP->next_seq = seq + packet->packetL7Length;
                passExtractP->auth_type = TELNET_AUTH;
            } else {
                // username can be split among several packets
                passExtractP->next_seq += packet->packetL7Length;
            }
        } else if (passExtractP->telnet_state == 2 && passExtractP->next_seq == seq) {
            if (extract_telnet(&passExtractP->password, payload, payload_end)) {
                passExtractP->auth_type = TELNET_AUTH;
                passExtractP->proto = ALREADY_EXTRACTED;
                set_check_status(flowIndex, CHECK_TELNET);
            } else {
                // password can be split among several packets
                passExtractP->next_seq += packet->packetL7Length;
            }
        }
        return;
    }
#endif // PWX_TELNET != 0

#if PWX_LDAP != 0
    if (passExtractP->proto == LDAP && packet->snapL7Length > 5) {
        // extract username and password from bindRequest messages
        // content is in DER encoded ASN.1 format
        // should be replaced when we have a LDAP plugin
        if (extract_ldap(payload, payload_end, passExtractP)) {
            set_check_status(flowIndex, CHECK_LDAP);
        }
    #if PWX_STATUS != 0
    } else if (passExtractP->proto == CHECK_LDAP && packet->snapL7Length >= 5) {
        set_auth_status(flowIndex, extract_ldap_status(payload, payload_end));
    #endif // PWX_STATUS != 0
    }
#endif // PWX_LDAP != 0
}

void onFlowTerminate(unsigned long flowIndex) {
    pwX_flow_t *passExtractP = &pwX_flows[flowIndex];

    // output authentication type
    outputBuffer_append(main_output_buffer, (char *)&passExtractP->auth_type, sizeof(uint8_t));
    if (passExtractP->auth_type != NO_AUTH) ++pwx_count;

    // output username
    const char * const user = passExtractP->username;
#if PWX_USERNAME != 0
    if (user) {
        outputBuffer_append(main_output_buffer, user, strlen(user)+1);
    } else {
        outputBuffer_append(main_output_buffer, "\0", 1);
    }
#endif // PWX_USERNAME != 0
    if (user) {
        free(passExtractP->username);
    }

    // output password
    const char * const pass = passExtractP->password;
#if PWX_PASSWORD != 0
    if (pass) {
        outputBuffer_append(main_output_buffer, pass, strlen(pass)+1);
    } else {
        outputBuffer_append(main_output_buffer, "\0", 1);
    }
#endif // PWX_PASSWORD != 0

#if PWX_STATUS != 0
    // authentication status (unknown, success, failure)
    outputBuffer_append(main_output_buffer, (char *)&passExtractP->status, sizeof(uint8_t));
#endif // PWX_STATUS != 0

    if (pass) {
        free(passExtractP->password);
    }
}

void pluginReport(FILE *stream) {
    if (pwx_count) {
#if PWX_STATUS != 0
        T2_FPLOG(stream, PLUGIN_NAME, "Number of passwords with successful/failed/unknown login: %"PRIu32"/%"PRIu32"/%"PRIu32,
                pwx_success_count, pwx_fail_count, pwx_count - (pwx_success_count + pwx_fail_count));
#else // PWX_STATUS == 0
        T2_FPLOG_NUM(stream, PLUGIN_NAME, "Number of passwords extracted", pwx_count);
#endif // PWX_STATUS != 0
    }
}

void onApplicationTerminate() {
    free(pwX_flows);
}
