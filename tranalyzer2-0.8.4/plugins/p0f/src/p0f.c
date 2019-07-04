/*
 * p0f.c
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

#include "p0f.h"

// plugin functions
static int p0f_read_db();

// plugin variables
//const static char *osCl[4] = {"!", "win", "unix", "other"};
//const static char *progCl[17] = {"unknown", "Windows", "Linux", "OpenBSD", "FreeBSD", "Solaris", "MacOSX", "HP-UX", "OpenVMS", "iOS", "BaiduSpider", "Blackberry", "NeXTSTEP", "Nintendo", "NMap", "tp0f", "Tru64"};
//const static char *verCl[48] = {"unknown", "NT", "XP", "7", "8", "10", "10.9 or newer (sometimes iPhone or iPad)", "10.x", "11.x", "2.0", "2.2.x", "2.2.x-3.x", "2.2.x-3.x (barebone)", "2.2.x-3.x (no timestamps)", "2.2.x (loopback)", "2.4-2.6", "2.4.x", "2.4.x-2.6.x", "2.4.x (loopback)", "2.6.x", "2.6.x (Google crawler)", "2.6.x (loopback)", "3.11 and newer", "3.1-3.10", "3DS", "3.x", "3.x (loopback)", "4.x", "4.x-5.x", "5.x", "6", "7 or 8", "7 (Websense crawler)", "7.x", "8", "8.x", "8.x-9.x", "9.x", "9.x or newer", "(Android)", "iPhone or iPad", "NT kernel", "NT kernel 5.x", "NT kernel 6.x", "OS detection", "sendsyn utility", "SYN scan", "Wii", };

p0f_ssl_sig p0f_ssl_sigs[P0F_SSL_NSIG+1];

extern sslFlow_t *sslFlow __attribute__((weak));

// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("p0f", "0.8.4", 0, 8, "sslDecode");


void initialize() {
    if (!p0f_read_db()) {
        exit(-1);
    }
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("p0f SSL fingerprint rule number", "p0fSSLRule", 0, 1, bt_uint_16));
    bv = bv_append_bv(bv, bv_new_bv("p0f SSL OS fingerprint", "p0fSSLOS", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("p0f SSL OS fingerprint (2)", "p0fSSLOS2", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("p0f SSL browser fingerprint", "p0fSSLBrowser", 0, 1, bt_string));
    bv = bv_append_bv(bv, bv_new_bv("p0f SSL fingerprint comment", "p0fSSLComment", 0, 1, bt_string));
    return bv;
}


#if BLOCK_BUF == 0
#if P0F_SSL_CIPHER  == 1 || P0F_SSL_EXT    == 1 || P0F_SSL_VER   == 1 || \
    P0F_SSL_NCIPHER == 1 || P0F_SSL_NUMEXT == 1 || P0F_SSL_FLAGS == 1
void onFlowTerminate(unsigned long flowIndex) {
    sslFlow_t *sslFlowP = &sslFlow[flowIndex];
#else
void onFlowTerminate(unsigned long flowIndex __attribute__((unused))) {
#endif

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
    uint_fast16_t j;
    char str[P0F_SSL_ELEN];
#endif

    uint8_t match;
    p0f_ssl_sig s;
    for (uint_fast16_t i = 0; i < P0F_SSL_NSIG; i++) {
        match = 1;
        s = p0f_ssl_sigs[i];
#if P0F_SSL_VER == 1
        match &= (s.version == sslFlowP->version);
#endif
#if P0F_SSL_NCIPHER == 1
        match &= (s.nciphers == sslFlowP->num_cipher);
#endif
#if P0F_SSL_NUMEXT == 1
        match &= (s.numext == sslFlowP->num_ext);
#endif
#if P0F_SSL_FLAGS == 1
        match &= (s.flags == sslFlowP->flags);
#endif

        if (!match) continue;

#if P0F_SSL_CIPHER == 1
        // ciphers
        for (j = 0; j < s.nciphers; j++) {
            if (strcmp(s.ciphers[j], "*") == 0) continue;
            snprintf(str, P0F_SSL_ELEN, "%x", sslFlowP->cipher_list[j]);
            // XXX for now if '?' is present, it is always the first character
            if (strstr(s.ciphers[j], "?")) {
                if (strlen(s.ciphers[j]) == strlen(str)) {
                    str[0] = '?';
                } else {
                    snprintf(str, P0F_SSL_ELEN, "?%x", sslFlowP->cipher_list[j]);
                }
            }

            if (strcmp(s.ciphers[j], str) != 0) {
                match = 0;
                break;
            }
        }
        if (!match) continue;
#endif // P0F_SSL_CIPHER == 1

#if P0F_SSL_EXT == 1
        // extensions
        for (j = 0; j < s.numext; j++) {
            if (strcmp(s.ext[j], "*") == 0) continue;
            snprintf(str, P0F_SSL_ELEN, "%x", sslFlowP->ext_list[j]);
            // XXX for now if '?' is present, it is always the first character
            if (strstr(s.ext[j], "?")) {
                if (strlen(s.ext[j]) == strlen(str)) {
                    str[0] = '?';
                } else {
                    snprintf(str, P0F_SSL_ELEN, "?%x", sslFlowP->ext_list[j]);
                }
            }

            if (strcmp(s.ext[j], str) != 0) {
                match = 0;
                break;
            }
        }
        if (!match) continue;
#endif // P0F_SSL_EXT == 1

        if (match) {
            outputBuffer_append(main_output_buffer, (char*)&s.rulenum, sizeof(uint16_t));
            outputBuffer_append(main_output_buffer, s.os, strlen(s.os)+1);
            outputBuffer_append(main_output_buffer, s.os2, strlen(s.os2)+1);
            outputBuffer_append(main_output_buffer, s.browser, strlen(s.browser)+1);
            outputBuffer_append(main_output_buffer, s.comment, strlen(s.comment)+1);
            return;
        }
    }

    // no fingerprint match
    static const uint16_t zero = 0;
    static const char *unknown = "";
    outputBuffer_append(main_output_buffer, (char*)&zero, sizeof(uint16_t));
    outputBuffer_append(main_output_buffer, unknown, strlen(unknown)+1);
    outputBuffer_append(main_output_buffer, unknown, strlen(unknown)+1);
    outputBuffer_append(main_output_buffer, unknown, strlen(unknown)+1);
    outputBuffer_append(main_output_buffer, unknown, strlen(unknown)+1);
}
#endif // BLOCK_BUF == 0


static int p0f_read_db() {
    FILE *file = t2_open_file(pluginFolder, P0F_SSL_DB, "r");
    if (UNLIKELY(!file)) return 0;

    char line[P0F_SSL_LLEN];

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
    char *token;
    uint32_t j;
#endif

    uint32_t i = 0;
    p0f_ssl_sig *s;
    char ciphers[SSL_MAX_CIPHER*P0F_SSL_ELEN];
    char exts[SSL_MAX_EXT*P0F_SSL_ELEN];
    uint16_t maxciphers = 0, maxext = 0;
    while (fgets(line, P0F_SSL_LLEN, file) != NULL) {
        if (i > P0F_SSL_NSIG) {
            i++;
            continue;
        }
        // Skip comments and empty lines
        if (UNLIKELY(line[0] == '%' || line[0] == ' ' || line[0] == '\n' || line[0] == '\t')) continue;
        s = &p0f_ssl_sigs[i];
        sscanf(line, "%"SCNu16"\t%"SCNx16"\t%"SCNu16"\t%[^\t]\t%"SCNu16"\t%[^\t]\t%"SCNx8"\t%[^\t]\t%[^\t]\t%[^\t]\t%[^\t\n]", &(s->rulenum), &(s->version), &(s->nciphers), &ciphers[0], &(s->numext), &exts[0], &(s->flags), &(s->os[0]), &(s->os2[0]), &(s->browser[0]), &(s->comment[0]));
        // max number of ciphers/extensions
        if (s->nciphers > maxciphers) maxciphers = s->nciphers;
        if (s->numext > maxext) maxext = s->numext;
        i++;

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
        if (s->nciphers >= SSL_MAX_CIPHER || s->numext >= SSL_MAX_EXT) continue;
#endif

#if P0F_SSL_CIPHER == 1
        // split ciphers by ','
        if (s->nciphers > 0) {
            j = 0;
            token = strtok(ciphers, ",");
            while (token) {
                strncpy(s->ciphers[j], token, strlen(token)+1);
                token = strtok(NULL, ",");
                j++;
            }
        }
#endif // P0F_SSL_CIPHER == 1

#if P0F_SSL_EXT == 1
        // split extensions by ','
        if (s->numext > 0) {
            j = 0;
            token = strtok(exts, ",");
            while (token) {
                strncpy(s->ext[j], token, strlen(token)+1);
                token = strtok(NULL, ",");
                j++;
            }
        }
#endif // P0F_SSL_EXT == 1
    }

    fclose(file);

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
    if (maxciphers >= SSL_MAX_CIPHER || maxext >= SSL_MAX_EXT) {
        T2_PERR("p0f", "Increase SSL_MAX_CIPHER to %"PRIu32" and SSL_MAX_EXT to %"PRIu32" in sslDecode.h", maxciphers+1, maxext+1);
        return 0;
    }
#endif

    if (i > P0F_SSL_NSIG) {
        T2_PERR("p0f", "Increase P0F_SSL_NSIG to %u", i);
        return 0;
    }

    return 1;
}
