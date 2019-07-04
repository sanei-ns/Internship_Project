/*
 * gz2txt.h
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

#ifndef __GZ2TXT_H__
#define __GZ2TXT_H__


#ifndef USE_ZLIB

// User defines

#define USE_ZLIB 2  // 0: no,
                    // 1: yes, no specific version,
                    // 2: yes, min 1.2.9 (for gzfread (only used in tranalyzer-b2t))

#endif // USE_ZLIB

// Local defines

#if USE_ZLIB == 0

// No support for ZLIB requested... use the standard functions => no suffix required
#define GZ2TXT_TEST_ZLIB_VERSION(pluginName)
#define GZ_SUFFIX ""

#else // USE_ZLIB != 0

#include <stdbool.h>
#include <stdio.h>
#include <zlib.h>

#include "binaryValue.h"

#define GZ_SUFFIX ".gz"

#define ZLIB_REQUIRED_VERSION 0x1290 // Minimum version of zlib required (1.2.9, for gzfread)

#if USE_ZLIB == 1
#define GZ2TXT_TEST_ZLIB_VERSION(pluginName)
#else // USE_ZLIB == 2
#define GZ2TXT_TEST_ZLIB_VERSION(pluginName) gz2txt_test_zlib_version(pluginName)
#endif // USE_ZLIB == 2


// Function prototypes

extern void gz2txt_test_zlib_version(const char *pluginName);
extern bool parse_file_gz2txt(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress);
extern bool parse_file_gz2json(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress);

#endif // USE_ZLIB != 0

#endif // __GZ2TXT_H__
