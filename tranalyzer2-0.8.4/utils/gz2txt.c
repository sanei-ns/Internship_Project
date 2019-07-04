/*
 * gz2txt.c
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

#include "gz2txt.h"
#include "global.h"


#if USE_ZLIB != 0

// Function prototypes
static inline int gzputc_wrapper(int c, gzFile file);
static inline int gzputs_wrapper(const char *s, gzFile file);


const b2t_func_t b2t_funcs_gz = {
    .fclose  = (fclose_func_t)gzclose,
    .fgetc   = (fgetc_func_t)gzgetc,
    .fopen   = (fopen_func_t)gzopen,
    .fprintf = (fprintf_func_t)gzprintf,
    .fputc   = (fputc_func_t)gzputc_wrapper,
    .fputs   = (fputs_func_t)gzputs_wrapper,
#if ZLIB_VERNUM >= ZLIB_REQUIRED_VERSION
    .fread   = (fread_func_t)gzfread,
#else // ZLIB_VERNUM < ZLIB_REQUIRED_VERSION
    .fread   = (fread_func_t)fread, // gzfread does not exist...
#endif // ZLIB_VERNUM < ZLIB_REQUIRED_VERSION
    .fseek   = (fseek_func_t)gzseek,
    .ftell   = (ftell_func_t)gzoffset,
    .rewind  = (rewind_func_t)gzrewind,
    .ungetc  = (ungetc_func_t)gzungetc,
    .get_val = get_val_from_input_file,
};


static inline int gzputc_wrapper(int c, gzFile file) {
    return gzputc(file, c);
}


static inline int gzputs_wrapper(const char *s, gzFile file) {
    return gzputs(file, s);
}


inline void gz2txt_test_zlib_version(const char *pluginName) {
    if (ZLIB_VERNUM < ZLIB_REQUIRED_VERSION) {
        T2_PERR(pluginName, "Cannot compress the output, zlib version 1.2.9 required, found %s", ZLIB_VERSION);
        T2_PINF(pluginName, "Set GZ_COMPRESS=0 in %s.h", pluginName);
        exit(1);
    }
}


inline bool parse_file_gz2txt(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs;
    if (compress) {
        funcs = b2t_funcs_gz;
    } else {
        funcs = b2t_funcs;
        funcs.fread = (fread_func_t)gzfread;
    }
    return parse_binary2text(input, bv, outfile, funcs);
}


inline bool parse_file_gz2json(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs;
    if (compress) {
        funcs = b2t_funcs_gz;
    } else {
        funcs = b2t_funcs;
        funcs.fread = (fread_func_t)gzfread;
    }
    return parse_binary2json(input, bv, outfile, funcs);
}
#endif // USE_ZLIB != 0
