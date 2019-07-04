/*
 * bin2txt.h
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

#ifndef __BIN2TXT_H__
#define __BIN2TXT_H__

// local includes
#include "binaryValue.h"
#include "outputBuffer.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

// User defines

#define IP4_FORMAT             0 // IPv4 addresses representation:
                                 //     0: normal
                                 //     1: normalized (padded with zeros)
                                 //     2: hexadecimal
                                 //     3: uint32

#define IP6_FORMAT             0 // IPv6 addresses representation:
                                 //     0: compressed
                                 //     1: uncompressed
                                 //     2: one 128-bits hex number
                                 //     3: two 64-bits hex numbers

#define MAC_FORMAT             0 // MAC addresses representation:
                                 //     0: normal (edit MAC_SEP to change the separator)
                                 //     1: one 64-bits hex number
#define MAC_SEP ":"              // Separator to use in MAC addresses: 11:22:33:44:55:66

#define HEX_CAPITAL            0 // hex output: 0: lower case; 1: upper case
#define TFS_EXTENDED_HEADER    0 // Extended header in flow file
#define B2T_TIME_IN_MICRO_SECS 1 // Time precision: 0: nanosecs, 1: microsecs
#define TFS_NC_TYPE            1 // Types in header file: 0: numbers, 1: C types
#define TFS_SAN_UTF8           1 // Activates the UTF-8 sanitizer for strings
#define B2T_TIMESTR            0 // Print unix timestamps as human readable dates

#define HDR_CHR "%"  // start characters to label comments
#define SEP_CHR "\t" // column separator in the flow file
                     // ; . _ and " should not be used

// JSON
#define JSON_KEEP_EMPTY 0 // Whether or not to output empty fields
#define JSON_PRETTY     0 // Whether to add spaces to make the output more readable

// local defines

#if HEX_CAPITAL == 0
#define B2T_PRIX8  PRIx8
#define B2T_PRIX16 PRIx16
#define B2T_PRIX32 PRIx32
#define B2T_PRIX64 PRIx64
#define B2T_PRIXFAST8  PRIxFAST8
#define B2T_PRIXFAST16 PRIxFAST16
#define B2T_PRIXFAST32 PRIxFAST32
#define B2T_PRIXFAST64 PRIxFAST64
#else // HEX_CAPITAL == 1
#define B2T_PRIX8  PRIX8
#define B2T_PRIX16 PRIX16
#define B2T_PRIX32 PRIX32
#define B2T_PRIX64 PRIX64
#define B2T_PRIXFAST8  PRIXFAST8
#define B2T_PRIXFAST16 PRIXFAST16
#define B2T_PRIXFAST32 PRIXFAST32
#define B2T_PRIXFAST64 PRIXFAST64
#endif // HEX_CAPITAL

// ISO 8601 time format
// <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
#define B2T_TIMEFRMT "%FT%T"

#if B2T_TIME_IN_MICRO_SECS != 0
#define B2T_TPFRMT "06"PRIu32
#else // B2T_TIME_IN_MICRO_SECS == 0
#define B2T_TPFRMT "09"PRIu32
#endif // B2T_TIME_IN_MICRO_SECS == 0

// Typedefs
typedef int (*fclose_func_t)(void *stream);
typedef int (*fgetc_func_t)(void *stream);
typedef void * (*fopen_func_t)(const char *path, const char *mode);
typedef int (*fprintf_func_t)(void *stream, const char *format, ...);
typedef int (*fputc_func_t)(int c, void *stream);
typedef int (*fputs_func_t)(const char *s, void *stream);
typedef size_t (*fread_func_t)(void *ptr, size_t size, size_t nmemb, void *stream);
typedef int (*fseek_func_t)(void *stream, off_t offset, int whence);
typedef off_t (*ftell_func_t)(void *stream);
typedef void (*rewind_func_t)(void *stream);
typedef int (*ungetc_func_t)(int c, void *stream);

typedef bool (*parse_binary_func_t)(void *input, binary_value_t * const bv, FILE *outfile, bool compress);


// Structs
typedef struct b2t_func_s {
    fclose_func_t  fclose;
    fgetc_func_t   fgetc;
    fopen_func_t   fopen;
    fprintf_func_t fprintf;
    fputc_func_t   fputc;
    fputs_func_t   fputs;
    fread_func_t   fread;
    fseek_func_t   fseek;
    ftell_func_t   ftell;
    rewind_func_t  rewind;
    ungetc_func_t  ungetc;
    bool (*get_val)(void*, void*, size_t, size_t, struct b2t_func_s funcs);
} b2t_func_t;


// Variables
extern const b2t_func_t b2t_funcs;
extern const b2t_func_t b2t_funcs_gz;


// Function prototypes
extern bool get_val_from_input_file(void *input, void *dest, size_t size, size_t n, b2t_func_t funcs);

// Returned value MUST be free'd with bv_header_destroy()
binary_value_t *t2_read_bin_header(void *infile, uint32_t hdrlen, b2t_func_t funcs, uint32_t *offset);

bool parse_binary2text(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs);
bool parse_binary2json(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs);

extern bool parse_file_bin2txt(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress);
extern bool parse_file_bin2json(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress);

extern bool parse_buffer_bin2txt(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs);
extern bool parse_buffer_bin2json(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs);

void parse_binary_header2text(binary_value_t * const bv, void *outfile, b2t_func_t funcs);
void print_values_description(binary_value_t * const bv, void *outfile, b2t_func_t funcs);

#endif // __BIN2TXT_H__
