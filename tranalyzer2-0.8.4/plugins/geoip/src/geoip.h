/*
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
 * This product includes GeoLite/GeoLite2 data created by MaxMind,
 *     available from http://www.maxmind.com
 */

#ifndef __GEOIP_H__
#define __GEOIP_H__

// global includes

// local includes
#include "global.h"

// user defines
#define GEOIP_LEGACY     0 // Whether to use GeoLite2 (0) or the GeoLite legacy database (1)

#define GEOIP_SRC        1 // whether or not to display geo info for the source IP
#define GEOIP_DST        1 // whether or not to display geo info for the destination IP

#define GEOIP_CONTINENT  2 // 0: no continent, 1: name (GeoLite2), 2: two letters code
#define GEOIP_COUNTRY    2 // 0: no country, 1: name, 2: two letters code, 3: three letters code (Legacy)
#define GEOIP_CITY       1 // whether or not to display the city of the IP
#define GEOIP_POSTCODE   1 // whether or not to display the postal code of the IP
#define GEOIP_POSITION   1 // whether or not to display the position (latitude, longitude) of the IP
#define GEOIP_METRO_CODE 0 // whether or not to display the metro (dma) code of the IP (US only)

#if GEOIP_LEGACY == 0
#define GEOIP_ACCURACY   1    // whether or not to display the accuracy (GeoLite2)
#define GEOIP_TIMEZONE   1    // whether or not to display the time zone (GeoLite2)
#define GEOIP_LANG       "en" // Output language: en, de, fr, es, ja, pt-BR, ru, zh-CN, ...
#define GEOIP_BUFSIZE    64   // buffer size
#else // GEOIP_LEGACY == 1
#define GEOIP_REGION     1 // 0: no region,  1: name, 2: code
#define GEOIP_AREA_CODE  0 // whether or not to display the telephone area code of the IP
#define GEOIP_NETMASK    1 // 0: no netmask, 1: netmask as int (cidr),
                           // 2: netmask as hex (IPv4 only), 3: netmask as IP (IPv4 only)
#define GEOIP_DB_CACHE   2 // 0: read DB from file system (slower, least memory)
                           // 1: index cache (cache frequently used index only)
                           // 2: memory cache (faster, more memory)
#endif // GEOIP_LEGACY == 1

#define GEOIP_UNKNOWN    "--" // Representation of unknown locations (GeoIP's default)

// GeoIP Status
#define GEOIP_STAT_TRUNC 0x1 // name was truncated... increase GEOIP_BUFSIZE

// plugin defines
#if GEOIP_LEGACY == 0
#define GEOIP_DB_FILE "GeoLite2-City.mmdb"
#define GEOIP_DB_LEN   sizeof(GEOIP_DB_FILE)
#else // GEOIP_LEGACY == 1
#define GEOIP_DB_FILE  "GeoLiteCity.dat"
#define GEOIP_DB_FILE6 "GeoLiteCityv6.dat"
#define GEOIP_DB_LEN   sizeof(GEOIP_DB_FILE6)
#endif // GEOIP_LEGACY == 0

// Country type
#if GEOIP_COUNTRY == 1
#define GEOIP_COUNTRY_TYPE bt_string
#elif (GEOIP_COUNTRY == 2 || GEOIP_COUNTRY == 3)
#define GEOIP_COUNTRY_TYPE bt_string_class
#endif // (GEOIP_COUNTRY == 2 || GEOIP_COUNTRY == 3)

// Region type
#if GEOIP_REGION == 1
#define GEOIP_REGION_TYPE bt_string
#elif GEOIP_REGION == 2
#define GEOIP_REGION_TYPE bt_string_class
#endif // GEOIP_REGION == 2

// Continent type
#if GEOIP_CONTINENT == 1
#define GEOIP_CONTINENT_TYPE bt_string
#elif GEOIP_CONTINENT == 2
#define GEOIP_CONTINENT_TYPE bt_string_class
#endif // GEOIP_CONTINENT == 2

// Position and metro code type
#if GEOIP_LEGACY == 0
#define GEOIP_POS_TYPE bt_double
#define GEOIP_DMA_TYPE bt_uint_16
#else // GEOIP_LEGACY == 1
#define GEOIP_POS_TYPE bt_float
#define GEOIP_DMA_TYPE bt_int_32
#endif // GEOIP_LEGACY == 1

#if GEOIP_LEGACY == 1

// TODO For now, netmask for IPv6 can only be represented as int
#if IPV6_ACTIVATE > 0 && GEOIP_NETMASK > 1
#error Netmask for IPv6 can only be represented as int (GEOIP_NETMASK=1)
#endif // IPV6_ACTIVATE > 0 && GEOIP_NETMASK > 0

// Netmask type
#if GEOIP_NETMASK == 1
#define GEOIP_NETMASK_TYPE bt_uint_32
#elif GEOIP_NETMASK == 2
#define GEOIP_NETMASK_TYPE bt_hex_32
#elif GEOIP_NETMASK == 3
#define GEOIP_NETMASK_TYPE bt_ip4_addr
#endif // GEOIP_NETMASK == 3

#define GEOIP_CIDR_TO_HEX(m) ((0xffffffff >> (32 - (m))) << (32 - (m)))
#define GEOIP_CIDR_TO_IP(m) ntohl(GEOIP_CIDR_TO_HEX((m)))

// DB cache
#if GEOIP_DB_CACHE == 0
#define GEOIP_DB_CACHE_FLAG GEOIP_STANDARD
#elif GEOIP_DB_CACHE == 1
#define GEOIP_DB_CACHE_FLAG GEOIP_INDEX_CACHE
#else // GEOIP_DB_CACHE == 2
#define GEOIP_DB_CACHE_FLAG GEOIP_MEMORY_CACHE
#endif // GEOIP_DB_CACHE == 2
#endif // GEOIP_LEGACY == 1

#endif // __GEOIP_H__
