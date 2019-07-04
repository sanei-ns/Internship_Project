/*
 * t2utils.c
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

#include "t2utils.h"
#include "bin2txt.h"
#include "t2log.h"
#include "global.h" // for L2_IPV6

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <string.h>


inline void *t2_malloc(size_t size) {
    void *data = malloc(size);
    if (UNLIKELY(!data)) {
        T2_ERR("Failed to allocate memory");
        exit(1);
    }
    return data;
}


inline void *t2_calloc(size_t nmemb, size_t size) {
    void *data = calloc(nmemb, size);
    if (UNLIKELY(!data)) {
        T2_ERR("Failed to allocate memory");
        exit(1);
    }
    return data;
}


inline char *t2_alloc_filename(const char *prefix, const char *suffix) {
    assert(suffix != NULL);

    char path[MAX_FILENAME_LEN];
    t2_build_filename(prefix, suffix, &(path[0]), MAX_FILENAME_LEN);
    return strdup(path);
}


inline void t2_build_filename(const char *prefix, const char *suffix, char *dest, size_t dsize) {
    if (UNLIKELY(!suffix || !dest || !dsize)) {
        // Programming error
        T2_PERR("t2_build_filename", "suffix, dest and dsize > 0 are required");
        exit(1);
    }

    const size_t plen = prefix ? strlen(prefix) : 0;
    const size_t slen = strlen(suffix);
    const size_t len = plen + slen;

    if (UNLIKELY(len+1 >= MIN(dsize, MAX_FILENAME_LEN))) {
        T2_ERR("Path for '%s' is too long", suffix);
        exit(1);
    }

    if (LIKELY(prefix != NULL)) strcpy(dest, prefix);
    strcpy(dest + plen, suffix);
    dest[len] = '\0';
}


inline bool t2_file_exists(const char *prefix, const char *suffix) {
    assert(suffix != NULL);

    char path[MAX_FILENAME_LEN];
    t2_build_filename(prefix, suffix, &(path[0]), MAX_FILENAME_LEN);

    struct stat buf;
    return (stat(path, &buf) == 0);
}


inline FILE *t2_open_file(const char *prefix, const char *suffix, const char *mode) {

    assert(mode != NULL && suffix != NULL);

    char path[MAX_FILENAME_LEN];
    t2_build_filename(prefix, suffix, &(path[0]), MAX_FILENAME_LEN);

    FILE *file;
    if (UNLIKELY(!(file = fopen(path, mode)))) {
        T2_ERR("Failed to open file '%s': %s", path, strerror(errno));
        return NULL;
    }

    return file;
}


inline void t2_conv_readable_num(uint64_t num, char *numstr, size_t size, const char *suffix) {
    if (num < 1024) {
        numstr[0] = '\0';
        return;
    }

    const uint_fast8_t i = MIN(ilogb(num) / 10, 8);
    if (i == 0) {
        numstr[0] = '\0';
        return;
    }

    const char *units = ".KMGTPEZY"; // 8 max
    const double factors[] = { 1, 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24 };
    snprintf(&(numstr[0]), size, " (%.2f %c%s)", num / factors[i], units[i], suffix ? suffix : "");
}


// Return true if packet is a first fragment
inline bool t2_is_first_fragment(const packet_t *packet) {
#if IPV6_ACTIVATE == 2
    if (PACKET_IS_IPV6(packet)) {
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
        const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdr;
        if (ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6ID_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
    } else { // IPv4
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        const ipHeader_t * const ipHeaderP = (ipHeader_t*)packet->layer3Header;
        if (ipHeaderP && (ipHeaderP->ip_off & FRAGID_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    }
#endif // IPV6_ACTIVATE == 2

    return true;
}


// Return true if packet is the last fragment
inline bool t2_is_last_fragment(const packet_t *packet) {
#if IPV6_ACTIVATE == 2
    if (PACKET_IS_IPV6(packet)) {
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
        const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdr;
        if (ip6FragHdrP && (ip6FragHdrP->frag_off & MORE_FRAG6_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
    } else { // IPv4
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        const ipHeader_t * const ipHeaderP = (ipHeader_t*)packet->layer3Header;
        if (ipHeaderP && (ipHeaderP->ip_off & MORE_FRAG_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    }
#endif // IPV6_ACTIVATE == 2

    return true;
}


inline void t2_ipv4_to_str(struct in_addr ip, char *dest, size_t dsize) {
#if IP4_FORMAT == 1
    t2_ipv4_to_uncompressed(ip, dest, dsize);
#elif IP4_FORMAT == 2
    t2_ipv4_to_hex(ip, dest, dsize);
#elif IP4_FORMAT == 3
    t2_ipv4_to_uint(ip, dest, dsize);
#else // IP4_FORMAT == 0
    t2_ipv4_to_compressed(ip, dest, dsize);
#endif // IP4_FORMAT == 0
}


inline void t2_ipv4_to_compressed(struct in_addr ip, char *dest, size_t dsize) {
    inet_ntop(AF_INET, &ip, dest, dsize);
}


inline void t2_ipv4_to_hex(struct in_addr ip, char *dest, size_t dsize) {
    snprintf(dest, dsize, "0x%08"B2T_PRIX32, ntohl(ip.s_addr));
}


inline void t2_ipv4_to_uint(struct in_addr ip, char *dest, size_t dsize) {
    snprintf(dest, dsize, "%"PRIu32, ntohl(ip.s_addr));
}


inline void t2_ipv4_to_uncompressed(struct in_addr ip, char *dest, size_t dsize) {
    const uint8_t addr[] = {
        (ip.s_addr & 0x000000ff),
        (ip.s_addr & 0x0000ff00) >>  8,
        (ip.s_addr & 0x00ff0000) >> 16,
        (ip.s_addr & 0xff000000) >> 24,
    };
    snprintf(dest, dsize, "%03"PRIu8".%03"PRIu8".%03"PRIu8".%03"PRIu8,
            addr[0], addr[1], addr[2], addr[3]);
}


inline void t2_ipv6_to_str(struct in6_addr ip, char *dest, size_t dsize) {
#if IP6_FORMAT == 1 // uncompressed
    t2_ipv6_to_uncompressed(ip, dest, dsize);
#elif IP6_FORMAT == 2 // hex128
    t2_ipv6_to_hex128(ip, dest, dsize);
#elif IP6_FORMAT == 3 // hex64_hex64
    t2_ipv6_to_hex64_hex64(ip, dest, dsize);
#else // IP6_FORMAT == 0
    t2_ipv6_to_compressed(ip, dest, dsize);
#endif // IP6_FORMAT == 0
}


inline void t2_ipv6_to_compressed(struct in6_addr ip, char *dest, size_t dsize) {
    inet_ntop(AF_INET6, &ip, dest, dsize);
}


inline void t2_ipv6_to_uncompressed(struct in6_addr ip, char *dest, size_t dsize) {
#ifdef __APPLE__
    const uint16_t * const val16 = ip.__u6_addr.__u6_addr16;
#else
    const uint16_t * const val16 = ip.__in6_u.__u6_addr16;
#endif
    snprintf(dest, dsize,
            "%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":"
            "%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16,
            ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
            ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]));
}


inline void t2_ipv6_to_hex128(struct in6_addr ip, char *dest, size_t dsize) {
#ifdef __APPLE__
    const uint8_t * const val8 = ip.__u6_addr.__u6_addr8;
#else
    const uint8_t * const val8 = ip.__in6_u.__u6_addr8;
#endif
    snprintf(dest, dsize,
            "0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
              "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
              "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
              "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8,
            val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7],
            val8[8], val8[9], val8[10], val8[11], val8[12], val8[13], val8[14], val8[15]);
}


inline void t2_ipv6_to_hex64_hex64(struct in6_addr ip, char *dest, size_t dsize) {
#ifdef __APPLE__
    const uint8_t * const val8 = ip.__u6_addr.__u6_addr8;
#else
    const uint8_t * const val8 = ip.__in6_u.__u6_addr8;
#endif
    snprintf(dest, dsize,
            "0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
              "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"_"
            "0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
              "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8,
            val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7],
            val8[8], val8[9], val8[10], val8[11], val8[12], val8[13], val8[14], val8[15]);
}


inline void t2_mac_to_str(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
#if MAC_FORMAT == 1
    t2_mac_to_hex(mac, dest, dsize);
#else // MAC_FORMAT == 0
    t2_mac_to_mac(mac, dest, dsize);
#endif // MAC_FORMAT == 0
}


inline void t2_mac_to_mac(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
    snprintf(dest, dsize,
            "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
            "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
            mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
            mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
}


inline void t2_mac_to_hex(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
    snprintf(dest, dsize, "0x%016"B2T_PRIX64,
            ((uint64_t)mac[0] << 40) | ((uint64_t)mac[1] << 32) |
            ((uint64_t)mac[2] << 24) | ((uint64_t)mac[3] << 16) |
            ((uint64_t)mac[4] <<  8) |  (uint64_t)mac[5]);
}


inline uint64_t t2_mac_to_uint64(const uint8_t mac[ETH_ALEN]) {
    uint64_t mac64 = mac[0];
    for (uint_fast8_t i = 1; i < ETH_ALEN; i++) {
        mac64 = (mac64 << 8) | mac[i];
    }
    return mac64;
}


inline void t2_uint64_to_mac(uint64_t mac, uint8_t *dest) {
    for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
        dest[i] = (mac >> 8 * (ETH_ALEN - 1 - i)) & 0xff;
    }
}


inline void t2_discard_trailing_char(FILE *stream, int c) {
    const off_t offset = ftello(stream);
    if (LIKELY(offset > 0)) {
        fseek(stream, -1, SEEK_CUR);
        const int last = fgetc(stream);
        if (last == c) fseek(stream, -1, SEEK_CUR);
    }
}
