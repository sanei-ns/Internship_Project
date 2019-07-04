/*
 * t2utils.h
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

#ifndef __T2UTILS_H__
#define __T2UTILS_H__

#include "networkHeaders.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>


// Hints the compiler that the expression is likely to evaluate to a true value
#define LIKELY(x) __builtin_expect ((x), 1)

// Hints the compiler that the expression is unlikely to evaluate to a true value
#define UNLIKELY(x) __builtin_expect ((x), 0)


// Min/Max for two and three values
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif // MIN

#ifndef MIN3
#define MIN3(a, b, c) ((a) < (b) ? MIN((a),(c)) : MIN((b),(c)))
#endif // MIN3

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif // MAX

#ifndef MAX3
#define MAX3(a, b, c) ((a) > (b) ? MAX((a),(c)) : MAX((b),(c)))
#endif // MAX3


// Stringify macros
#define XSTR(s) #s
#define STR(s) XSTR(s)


#if IPV6_ACTIVATE == 2
#define FLOW_IS_IPV4(f) (((f)->status & L2_IPV4) != 0)
#define FLOW_IS_IPV6(f) (((f)->status & L2_IPV6) != 0)
#define PACKET_IS_IPV4(p) (((p)->status & L2_IPV4) != 0)
#define PACKET_IS_IPV6(p) (((p)->status & L2_IPV6) != 0)
#else // IPV6_ACTIVATE != 2
#define FLOW_IS_IPV4(f) !IPV6_ACTIVATE
#define FLOW_IS_IPV6(f) IPV6_ACTIVATE
#define PACKET_IS_IPV4(p) !IPV6_ACTIVATE
#define PACKET_IS_IPV6(p) IPV6_ACTIVATE
#endif // IPV6_ACTIVATE != 2


// Call t2_ipv6_to_str(ip.IPv6, ...) or t2_ipv4_to_str(ip.IPv4, ...)
// depending on the value of 'version'
#if IPV6_ACTIVATE == 0
#define T2_IP_TO_STR(ip, version, dest, dsize) t2_ipv4_to_str(ip.IPv4, dest, dsize);
#else //  IPV6_ACTIVATE != 0
#define T2_IP_TO_STR(ip, version, dest, dsize) \
    if (version == 6) { \
        t2_ipv6_to_str(ip.IPv6, dest, dsize); \
    } else { \
        t2_ipv4_to_str(ip.IPv4, dest, dsize); \
    }
#endif // IPV6_ACTIVATE != 0


#define T2_CONV_NUM(num, str) \
    t2_conv_readable_num((num), str, sizeof(str), "");


#define T2_MALLOC(dst, size) { \
    dst = malloc(size); \
    if (UNLIKELY(!(dst))) { \
        T2_ERR("Failed to allocate memory"); \
        exit(1); \
    } \
}


#define T2_CALLOC(dst, nmemb, size) { \
    dst = calloc((nmemb), (size)); \
    if (UNLIKELY(!(dst))) { \
        T2_ERR("Failed to allocate memory"); \
        exit(1); \
    } \
}


// Functions

extern void *t2_malloc(size_t size);
extern void *t2_calloc(size_t nmemb, size_t size);

// Build the filename consisting of the concatenation of 'prefix' and 'suffix' (no slash is added)
// (If 'prefix is NULL, the filename is 'suffix' (must not be NULL))
// Return a newly allocated buffer with the filename (MUST be free'd)
extern char* t2_alloc_filename(const char *prefix, const char *suffix);

// Build the filename consisting of the concatenation of 'prefix' and 'suffix' (no slash is added)
// (If 'prefix is NULL, the filename is 'suffix' (must not be NULL))
// The filename is stored in *dest of size 'dsize' (including trailing '\0')
extern void t2_build_filename(const char *prefix, const char *suffix, char *dest, size_t dsize);

// Return true if 'filename' exists, false otherwise
// 'filename' is the concatenation of 'prefix' and 'suffix' (no slash is added)
// (If 'prefix' is NULL, 'filename' is 'suffix' (must not be NULL))
extern bool t2_file_exists(const char *prefix, const char *suffix);

// Open 'filename' in mode 'mode' ('r', 'w', ...).
// 'filename' is the concatenation of 'prefix' and 'suffix' (no slash is added)
// (If 'prefix' is NULL, 'filename' is 'suffix' (must not be NULL))
extern FILE* t2_open_file(const char *prefix, const char *suffix, const char *mode);

// Convert num to human readable format, e.g., 1577658 -> " (1.58 M)"
// Formatted output is stored in numstr (of size size) and guaranteed to be NULL terminated.
// An extra suffix can be provided, e.g., b/s -> " (1.58 Mb/s)
extern void t2_conv_readable_num(uint64_t num, char *numstr, size_t size, const char *suffix);


// Return true if packet is a first fragment
extern bool t2_is_first_fragment(const packet_t *packet);

// Return true if packet is the last fragment
extern bool t2_is_last_fragment(const packet_t *packet);


// Return the string representation of the IPv4 address ip (dependent on IP4_FORMAT)
extern void t2_ipv4_to_str(struct in_addr ip, char *dest, size_t dsize);

// Return the IPv4 compressed string representation of the IPv4 address ip, e.g., 1.2.3.4
extern void t2_ipv4_to_compressed(struct in_addr ip, char *dest, size_t dsize);

// Return the IPv4 uncompressed string representation of the IPv4 address ip, e.g., 001.002.003.004
extern void t2_ipv4_to_uncompressed(struct in_addr ip, char *dest, size_t dsize);

// Return the hexadecimal string representation of the IPv4 address ip, e.g., 0x01020304
extern void t2_ipv4_to_hex(struct in_addr ip, char *dest, size_t dsize);

// Return the unsigned int representation of the IPv4 address ip, e.g., 16909060
extern void t2_ipv4_to_uint(struct in_addr ip, char *dest, size_t dsize);


// Return the string representation of the IPv6 address ip (dependent on IP6_FORMAT)
extern void t2_ipv6_to_str(struct in6_addr ip, char *dest, size_t dsize);

// Return the IPv6 compressed string representation of the IPv6 address ip
extern void t2_ipv6_to_compressed(struct in6_addr ip, char *dest, size_t dsize);

// Return the IPv6 uncompressed string representation of the IPv6 address ip
extern void t2_ipv6_to_uncompressed(struct in6_addr ip, char *dest, size_t dsize);

// Return the hexadecimal string representation of the IPv6 address ip
extern void t2_ipv6_to_hex128(struct in6_addr ip, char *dest, size_t dsize);

// Return the hexadecimal string representation of the IPv6 address ip as
// two 64-bits hex numbers separated by underscore
extern void t2_ipv6_to_hex64_hex64(struct in6_addr ip, char *dest, size_t dsize);


// Return the string representation of the MAC address mac (dependent on MAC_FORMAT and MAC_SEP)
extern void t2_mac_to_str(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize);

// Return the string representation of the MAC address mac, e.g., 00:11:22:33:44:55 (dependent on MAC_SEP)
extern void t2_mac_to_mac(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize);

// Return the hexadecimal string representation of the MAC address mac, e.g., 0x001122334455
extern void t2_mac_to_hex(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize);

// Convert a MAC address (array of uint8_t) to an uint64_t
extern uint64_t t2_mac_to_uint64(const uint8_t mac[ETH_ALEN]);

// Convert a MAC address (uint64_t) as an array of uint8_t
// (Make sure dest can store at least ETH_ALEN (=6) bytes)
extern void t2_uint64_to_mac(uint64_t mac, uint8_t *dest);


// Remove the trailing char 'c' from 'stream'
extern void t2_discard_trailing_char(FILE *stream, int c);

#endif // __T2UTILS_H__
