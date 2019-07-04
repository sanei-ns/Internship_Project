/*
 * bin2txt.c
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

#include "gz2txt.h"  // includes bin2txt.h
#include "global.h"

#include <assert.h>
#include <math.h>
#include <string.h>


// Global Variables

#if TFS_NC_TYPE == 1
static const char *type2str[] = {
    "",                                         // bt_compound
    "I8", "I16", "I32", "I64", "I128", "I256",  // bt_int_*
    "U8", "U16", "U32", "U64", "U128", "U256",  // bt_uint_*
    "H8", "H16", "H32", "H64", "H128", "H256",  // bt_hex_*
    "F", "D", "LD",                             // bt_float, bt_double, bt_long_double
    "C", "S", "C",                              // bt_char, bt_string, bt_flow_direction
#if B2T_TIMESTR == 1
    "S",                                        // bt_timestamp
#else // B2T_TIMESTR == 0
    "U64.U32",                                  // bt_timestamp
#endif // B2T_TIMESTR == 0
    "U64.U32", "MAC", "IP4", "IP6", "IPX", "SC" // bt_duration, bt_mac_addr, bt_ip4_addr, bt_ip6_addr, bt_ipx_addr, bt_string_class
};
#endif // TFS_NC_TYPE == 1

const b2t_func_t b2t_funcs = {
    .fclose  = (fclose_func_t)fclose,
    .fgetc   = (fgetc_func_t)fgetc,
    .fopen   = (fopen_func_t)fopen,
    .fprintf = (fprintf_func_t)fprintf,
    .fputc   = (fputc_func_t)fputc,
    .fputs   = (fputs_func_t)fputs,
    .fread   = (fread_func_t)fread,
    .fseek   = (fseek_func_t)fseeko,
    .ftell   = (ftell_func_t)ftello,
    .rewind  = (rewind_func_t)rewind,
    .ungetc  = (ungetc_func_t)ungetc,
    .get_val = get_val_from_input_file,
};

#if USE_ZLIB == 0
// gz2txt.c was not required/compiled or _HAS_GZ2TXT_C was not defined...
// Do not use zlib... use the standard functions
// FIXME is there a way to make this assignment work?!?
//const b2t_func_t b2t_funcs_gz = b2t_funcs;
const b2t_func_t b2t_funcs_gz = {
    .fclose  = (fclose_func_t)fclose,
    .fgetc   = (fgetc_func_t)fgetc,
    .fopen   = (fopen_func_t)fopen,
    .fprintf = (fprintf_func_t)fprintf,
    .fputc   = (fputc_func_t)fputc,
    .fputs   = (fputs_func_t)fputs,
    .fread   = (fread_func_t)fread,
    .fseek   = (fseek_func_t)fseeko,
    .ftell   = (ftell_func_t)ftello,
    .rewind  = (rewind_func_t)rewind,
    .ungetc  = (ungetc_func_t)ungetc,
    .get_val = get_val_from_input_file,
};
#endif // USE_ZLIB == 0


// Global function declarations
static void parse_subheader_type(const binary_subvalue_t * const sv, void *outfile, b2t_func_t funcs);
static bool parse_subval(void *input, const binary_subvalue_t * const sv, void *outfile, b2t_func_t funcs);
static bool parse_binary_value(void *input, uint32_t type, void *outfile, bool json, b2t_func_t funcs);
static bool parse_subval_json(void *input, const binary_subvalue_t *sv, void *outfile, b2t_func_t funcs);
static void json_print_double(void *outfile, long double val, b2t_func_t funcs);
static bool t2_read_bin_header_rec(const uint32_t * const header, uint32_t *hdrpos, binary_subvalue_t *bv);
static inline uint32_t t2_get_bin_header_len(void *infile, b2t_func_t funcs);
#if TFS_SAN_UTF8 == 1
static bool b2t_sanitize_utf8(void *input, void *outfile, b2t_func_t funcs);
#endif


// functions
static inline bool get_val_from_input_buffer(void *input, void *dest, size_t size, size_t n, b2t_func_t funcs __attribute__((unused))) {
    outputBuffer_t *buffer = (outputBuffer_t*)input;
    const size_t sn = size * n;
    if (UNLIKELY(buffer->size < buffer->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buffer->pos + sn;
        T2_PERR("bin2txt", "Buffer overflow: %zu increase MAIN_OUTPUT_BUFFER_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buffer->buffer + buffer->pos, sn);
    buffer->pos += sn;
    return true;
}


inline bool get_val_from_input_file(void *input, void *dest, size_t size, size_t n, b2t_func_t funcs) {
    if (UNLIKELY(funcs.fread(dest, size, n, input) != n)) {
        T2_PERR("bin2txt", "Failed to read value from file");
        return false;
    }
    return true;
}


/*
 * parse the header strings:
 *      long strings with column number, types and repeat, as rows
 */
void print_values_description(binary_value_t * const bv, void *outfile, b2t_func_t funcs) {

    funcs.fputs("# Col No.\tType\tName\tDescription", outfile);

    uint_fast32_t i, j = 1;

    binary_value_t *act_bv = bv;
    while (act_bv) {
        // Column number
        funcs.fprintf(outfile, "\n%"PRIuFAST32"\t", j++);

        // Column type
        for (i = 0; i < act_bv->num_values; i++) {
            if (i != 0) funcs.fputc('_', outfile); // Separator
            if (act_bv->subval[i].type == bt_compound) {
                parse_subheader_type(&(act_bv->subval[i]), outfile, funcs);
            } else {
#if TFS_NC_TYPE == 1
                funcs.fputs(type2str[act_bv->subval[i].type], outfile);
#else // TFS_NC_TYPE == 0
                funcs.fprintf(outfile, "%"PRIu32, act_bv->subval[i].type);
#endif // TFS_NC_TYPE
            }
        }

        // Repetitive flag
        if (act_bv->is_repeating) funcs.fputs(":R", outfile);
        //else funcs.fputs(":N", outfile);

        // Column name and description
        funcs.fprintf(outfile, "\t%s\t%s", act_bv->name, act_bv->desc);

        act_bv = act_bv->next;
    }

    funcs.fputc('\n', outfile);
}


/*
 * parse the header strings:
 *     short strings aggregated in one row with '%' as prefix (default)
 */
void parse_binary_header2text(binary_value_t * const bv, void *outfile, b2t_func_t funcs) {
    binary_value_t *act_bv = bv;

#if TFS_EXTENDED_HEADER == 1
    uint_fast32_t i, j;

    // Count the number of columns
    j = 0;
    while (act_bv) {
        j++;
        act_bv = act_bv->next;
    }

    act_bv = bv;

    // We need 21 placeholders to later insert the number of flows,
    // which can be UINT_64_MAX, which is 20 digits
    funcs.fprintf(outfile, "%s                     \n", HDR_CHR);
    funcs.fprintf(outfile, "%s %"PRIuFAST32"\n", HDR_CHR, j); // print number of bv's

    // Column types
    funcs.fprintf(outfile, "%s ", HDR_CHR);
    while (act_bv) {
        if (act_bv != bv) funcs.fputs(SEP_CHR, outfile);
        for (i = 0; i < act_bv->num_values; i++) {
            if (i != 0) funcs.fputc('_', outfile); // Separator
            if (act_bv->subval[i].type == bt_compound) {
                parse_subheader_type(&(act_bv->subval[i]), outfile, funcs);
            } else {
                funcs.fprintf(outfile, "%"PRIu32, act_bv->subval[i].type);
            }
        }

        // Repetitive flag
        if (act_bv->is_repeating) funcs.fputs(":R", outfile);
        //else fputs(":N", outfile);

        act_bv = act_bv->next;
    }

    funcs.fputc('\n', outfile);
    act_bv = bv;
#endif // TFS_EXTENDED_HEADER == 1

    // Column names
    funcs.fputs(HDR_CHR, outfile);
    while (act_bv) {
        if (act_bv != bv) funcs.fputs(SEP_CHR, outfile);
        funcs.fputs(act_bv->name, outfile);
        act_bv = act_bv->next;
    }

    funcs.fputc('\n', outfile);
}


static void parse_subheader_type(const binary_subvalue_t * const sv, void *outfile, b2t_func_t funcs) {
    funcs.fputc('(', outfile);

    for (uint_fast32_t i = 0; i < sv->num_values; i++) {
        if (i != 0) funcs.fputc('_', outfile); // Separator
        if (sv->subval[i].type == bt_compound) {
            parse_subheader_type(&(sv->subval[i]), outfile, funcs);
        } else {
#if TFS_NC_TYPE == 1
            funcs.fputs(type2str[sv->subval[i].type], outfile);
#else // TFS_NC_TYPE == 0
            funcs.fprintf(outfile, "%"PRIu32, sv->subval[i].type);
#endif // TFS_NC_TYPE == 1
        }
    }

    // Print repetitive flag and closing parenthese
    if (sv->is_repeating) funcs.fputs(":R)", outfile);
    else funcs.fputs(":N)", outfile);
}


static inline void json_print_value_name(binary_value_t *act_bv, binary_value_t *bv, void *outfile, b2t_func_t funcs) {
    if (LIKELY(act_bv != bv)) {
        funcs.fputc(',', outfile);
#if JSON_PRETTY == 1
        funcs.fputc(' ', outfile);
#endif
    }
    // Write object name -> value name short
    funcs.fprintf(outfile, "\"%s\":", act_bv->name);
#if JSON_PRETTY == 1
    funcs.fputc(' ', outfile);
#endif
}


inline bool parse_file_bin2txt(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs = (compress ? b2t_funcs_gz : b2t_funcs);
    return parse_binary2text(input, bv, outfile, funcs);
}


inline bool parse_file_bin2json(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs = (compress ? b2t_funcs_gz : b2t_funcs);
    return parse_binary2json(input, bv, outfile, funcs);
}


inline bool parse_buffer_bin2txt(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs) {
    b2t_func_t funcs = b2t_funcs;
    funcs.get_val = get_val_from_input_buffer;
    // Save and reset buffer position
    const uint32_t bufpos = input->pos;
    input->pos = 0;
    const bool ret = parse_binary2text(input, bv, outfile, funcs);
    // Restore buffer position
    input->pos = bufpos;
    return ret;
}


inline bool parse_buffer_bin2json(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs) {
    b2t_func_t funcs = b2t_funcs;
    funcs.get_val = get_val_from_input_buffer;
    // Save and reset buffer position
    const uint32_t bufpos = input->pos;
    input->pos = 0;
    const bool ret = parse_binary2json(input, bv, outfile, funcs);
    // Restore buffer position
    input->pos = bufpos;
    return ret;
}


bool parse_binary2text(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs) {

    uint32_t num_repeat;
    uint_fast32_t rep, val;

    binary_value_t *act_bv = bv;
    while (act_bv) {
        if (act_bv != bv) funcs.fputs(SEP_CHR, outfile); // Column separator

        // check if output can be repeated
        // If yes, read amount of repeats, if no set num_repeat to 1
        if (!act_bv->is_repeating) {
            num_repeat = 1;
        } else if (UNLIKELY(!funcs.get_val(input, &num_repeat, sizeof(uint32_t), 1, funcs))) {
            return false;
        }

        for (rep = 0; rep < num_repeat; rep++) {
            // for each output val:
            // check type and write it out, if zero then it contains subvals
            for (val = 0; val < act_bv->num_values; val++) {
                if (act_bv->subval[val].type != bt_compound) {
                    if (UNLIKELY(!parse_binary_value(input, act_bv->subval[val].type, outfile, false, funcs))) {
                        return false;
                    }
                } else {
                    if (UNLIKELY(!parse_subval(input, &act_bv->subval[val], outfile, funcs))) {
                        return false;
                    }
                }

                // Compound value separator
                if (val < act_bv->num_values - 1) funcs.fputc('_', outfile);
            }

            // Repeat value separator
            if (rep < num_repeat - 1) funcs.fputc(';', outfile);
        }

        act_bv = act_bv->next;
    }

    funcs.fputc('\n', outfile);

    return true;
}


bool parse_binary2json(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs) {
    uint32_t num_repeat;
    uint_fast32_t rep, val;

    binary_value_t *act_bv = bv;
    funcs.fputc('{', outfile);
    while (act_bv) {
        // check if output can be repeated
        // If yes, read amount of repeats, if no set num_repeat to 1
        if (act_bv->is_repeating) {
            if (UNLIKELY(!funcs.get_val(input, &num_repeat, sizeof(uint32_t), 1, funcs))) {
                return false;
            }
#if JSON_KEEP_EMPTY == 0
            if (num_repeat == 0) {
                act_bv = act_bv->next;
                continue;
            }
#endif // JSON_KEEP_EMPTY == 0
            json_print_value_name(act_bv, bv, outfile, funcs);
            funcs.fputc('[', outfile);
        } else {
            num_repeat = 1;
            json_print_value_name(act_bv, bv, outfile, funcs);
        }
        for (rep = 0; rep < num_repeat; rep++) {
            if (rep > 0) {
                funcs.fputc(',', outfile);
#if JSON_PRETTY == 1
                funcs.fputc(' ', outfile);
#endif
            }

            if (act_bv->num_values > 1) {
                funcs.fputc('[', outfile); // Val has two or more subvalues -> print value array opening bracket
            }

            // for each output val:
            // check type and write it out, if zero then it contains subvals
            for (val = 0; val < act_bv->num_values; val++) {
                if (val > 0) {
                    funcs.fputc(',', outfile);
#if JSON_PRETTY == 1
                    funcs.fputc(' ', outfile);
#endif
                }
                if (act_bv->subval[val].type == bt_compound) {
                    if (UNLIKELY(!parse_subval_json(input, &act_bv->subval[val], outfile, funcs))) {
                        return false;
                    }
                } else {
                    if (UNLIKELY(!parse_binary_value(input, act_bv->subval[val].type, outfile, true, funcs))) {
                        return false;
                    }
                }
            }

            // Repeat value separator
            if (act_bv->num_values > 1) {
                funcs.fputc(']', outfile);
            }
        }

#if JSON_KEEP_EMPTY == 0
        if (act_bv->is_repeating == 1 && num_repeat > 0) {
#else // JSON_KEEP_EMPTY != 0
        if (act_bv->is_repeating == 1) {
#endif // JSON_KEEP_EMPTY != 0
            funcs.fputc(']', outfile); // It's repeating -> close repeating array bracket
        }

        act_bv = act_bv->next;
    }

    funcs.fputs("}\n", outfile);

    return true;
}


static bool parse_subval(void *input, const binary_subvalue_t * const sv, void *outfile, b2t_func_t funcs) {
    funcs.fputc('(', outfile);

    // check if output can be repeated.
    // If yes, read amount of repeats, if no set num_repeat to 1
    uint32_t num_repeat;
    if (!sv->is_repeating) {
        num_repeat = 1;
    } else if (UNLIKELY(!funcs.get_val(input, &num_repeat, sizeof(uint32_t), 1, funcs))) {
        return false;
    }

    uint_fast32_t val;
    for (uint_fast32_t rep = 0; rep < num_repeat; rep++) {
        // for each output val:
        // check type and write it out, if zero then it contains subvals
        for (val = 0; val < sv->num_values; val++) {
            if (sv->subval[val].type != bt_compound) {
                if (UNLIKELY(!parse_binary_value(input, sv->subval[val].type, outfile, false, funcs))) {
                    return false;
                }
            } else {
                if (UNLIKELY(!parse_subval(input, &sv->subval[val], outfile, funcs))) {
                    return false;
                }
            }

            // Compound value separator
            if (val < sv->num_values - 1) funcs.fputc('_', outfile);
        }

        // Repeat value separator
        if (rep < num_repeat - 1) funcs.fputc(';', outfile);
    }

    funcs.fputc(')', outfile);

    return true;
}


static bool parse_subval_json(void *input, const binary_subvalue_t *sv, void *outfile, b2t_func_t funcs) {
    // check if output can be repeated. If yes, read amount of repeats, if no set num_repeat to 1
    uint32_t num_repeat = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!funcs.get_val(input, &num_repeat, sizeof(uint32_t), 1, funcs))) {
            return false;
        }

        if (num_repeat == 0) {
            return true;
        }

        funcs.fputc('[', outfile);
    }

    for (uint_fast32_t i = 0; i < num_repeat; i++) {
        if (i > 0) {
            funcs.fputc(',', outfile);
#if JSON_PRETTY == 1
            funcs.fputc(' ', outfile);
#endif
        }

        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            funcs.fputc('[', outfile);
        }

        for (uint_fast32_t j = 0; j < sv->num_values; j++) {
            if (j > 0) {
                funcs.fputc(',', outfile);
#if JSON_PRETTY == 1
                funcs.fputc(' ', outfile);
#endif
            }
            if (sv->subval[j].type == bt_compound) {
                if (UNLIKELY(!parse_subval_json(input, &sv->subval[j], outfile, funcs))) {
                    return false;
                }
            } else {
                if (UNLIKELY(!parse_binary_value(input, sv->subval[j].type, outfile, true, funcs))) {
                    return false;
                }
            }
        }

        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            funcs.fputc('[', outfile);
        }

    }

    if (sv->is_repeating) funcs.fputc(']', outfile);

    return true;
}


static bool parse_binary_value(void *input, uint32_t type, void *outfile, bool json, b2t_func_t funcs) {
    const char *quote = (json ? "\"" : "");
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(int8_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRId8, val);
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(int16_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRId16, val);
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(int32_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRId32, val);
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(int64_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRId64, val);
            break;
        }

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRIu8, val);
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint16_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRIu16, val);
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint32_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRIu32, val);
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint64_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%"PRIu64, val);
            break;
        }

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%s0x%02"B2T_PRIX8"%s", quote, val, quote);
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint16_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%s0x%04"B2T_PRIX16"%s", quote, val, quote);
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint32_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%s0x%08"B2T_PRIX32"%s", quote, val, quote);
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint64_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%s0x%016"B2T_PRIX64"%s", quote, val, quote);
            break;
        }

        case bt_float: {
            float val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(float), 1, funcs))) {
                return false;
            }
            if (json) {
                json_print_double(outfile, val, funcs);
            } else {
                funcs.fprintf(outfile, "%.7g", val);
                //funcs.fprintf(outfile, "%f", val);
                //funcs.fprintf(outfile, "%#.6g", val);
                //funcs.fprintf(outfile, "%g", val);
            }
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(double), 1, funcs))) {
                return false;
            }
            if (json) {
                json_print_double(outfile, val, funcs);
            } else {
                funcs.fprintf(outfile, "%f", val);
            }
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(long double), 1, funcs))) {
                return false;
            }
            if (json) {
                json_print_double(outfile, val, funcs);
            } else {
                funcs.fprintf(outfile, "%Lf", val);
            }
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }
            funcs.fputc(val, outfile);
            break;
        }

        case bt_string_class: {
            if (json) funcs.fputc('"', outfile); // print startsign '"'
#if TFS_SAN_UTF8 == 1
            if (UNLIKELY(!b2t_sanitize_utf8(input, outfile, funcs))) {
                return false;
            }
#else // TFS_SAN_UTF8 == 0
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            while (val != '\0') {
                funcs.fputc(val, outfile);
                if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                    return false;
                }
            }
#endif // TFS_SAN_UTF8 == 0
            if (json) funcs.fputc('"', outfile); // print stopsign '"'
            break;
        }

        case bt_string: {
            funcs.fputc('"', outfile); // print startsign '"'
#if TFS_SAN_UTF8 == 1
            if (UNLIKELY(!b2t_sanitize_utf8(input, outfile, funcs))) {
                return false;
            }
#else // TFS_SAN_UTF8 == 0
            // read value
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            while (val != '\0') {
                // print value
                switch (val) {
                    case '\t':
                        funcs.fputs("\\t", outfile);
                        break;
                    case '\n':
                        funcs.fputs("\\n", outfile);
                        break;
                    case '\r':
                        funcs.fputs("\\r", outfile);
                        break;
                    //case '\\':
                    case '"':
                        funcs.fputc('\\', outfile);
                        /* FALLTHRU */
                    default:
                        funcs.fputc(val, outfile);
                        break;
                }
                if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                    return false;
                }
            }
#endif // TFS_SAN_UTF8
            funcs.fputc('"', outfile); // print stopsign '"'
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!funcs.get_val(input, val, l_bt_mac_addr * sizeof(uint8_t), 1, funcs))) {
                return false;
            }
#if MAC_FORMAT == 1
            funcs.fprintf(outfile, "%s0x%016"B2T_PRIX64"%s", quote,
                    ((uint64_t)val[0] << 40) | ((uint64_t)val[1] << 32) | ((uint64_t)val[2] << 24) |
                    ((uint64_t)val[3] << 16) | ((uint64_t)val[4] << 8)  |  (uint64_t)val[5], quote);
#else // MAC_FORMAT == 0
            funcs.fprintf(outfile,
                    "%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                      "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s",
                    quote, val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5], quote);
#endif // MAC_FORMAT == 0
            break;
        }

        case bt_ip4_addr: {
b2t_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!funcs.get_val(input, val, l_bt_ip4_addr * sizeof(uint8_t), 1, funcs))) {
                return false;
            }
#if IP4_FORMAT == 1
            funcs.fprintf(outfile, "%s%03"PRIu8".%03"PRIu8".%03"PRIu8".%03"PRIu8"%s",
                    quote, val[0], val[1], val[2], val[3], quote);
#elif IP4_FORMAT == 2
            funcs.fprintf(outfile, "%s0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%s",
                    quote, val[0], val[1], val[2], val[3], quote);
#elif IP4_FORMAT == 3
            funcs.fprintf(outfile, "%"PRIu32,
                    (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]);
#else // IP4_FORMAT == 0
            funcs.fprintf(outfile, "%s%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"%s",
                    quote, val[0], val[1], val[2], val[3], quote);
#endif // IP4_FORMAT == 0
            break;
        }

        case bt_ip6_addr: {
b2t_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!funcs.get_val(input, val, l_bt_ip6_addr * sizeof(uint8_t), 1, funcs))) {
                return false;
            }
#if IP6_FORMAT == 1
            const uint16_t * const val16 = (uint16_t*)val;
            funcs.fprintf(outfile,
                    "%s%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":"
                      "%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16"%s",
                    quote, ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
                    ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]), quote);
#elif IP6_FORMAT == 2
            funcs.fprintf(outfile,
                    "%s0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%s",
                    quote, val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], quote);
#elif IP6_FORMAT == 3
            funcs.fprintf(outfile,
                    "%s0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%s_"
                    "%s0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%s",
                    quote, val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], quote,
                    quote, val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], quote);
#else // IP6_FORMAT == 0
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            funcs.fprintf(outfile, "%s%s%s", quote, addr, quote);
#endif // IP6_FORMAT == 0
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!funcs.get_val(input, &version, sizeof(uint8_t), 1, funcs))) {
                return false;
            }
            if (version == 4) goto b2t_ip4;
            else if (version == 6) goto b2t_ip6;
            else {
                T2_ERR("Invalid IP version %"PRIu8, version);
                return false;
            }
            break;
        }

        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint64_t), 1, funcs))) {
                return false;
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!funcs.get_val(input, &ns, sizeof(uint32_t), 1, funcs))) {
                return false;
            }

#if B2T_TIME_IN_MICRO_SECS != 0
            ns /= 1000;
#endif

#if B2T_TIMESTR == 1
            if (type == bt_duration) {
#endif
                // XXX are the quotes really necessary?
                funcs.fprintf(outfile, "%s%"PRIu64".%"B2T_TPFRMT"%s", quote, val, ns, quote);
#if B2T_TIMESTR == 1
            } else {
                const struct tm *t;
#if TSTAMP_UTC == 1
                t = gmtime((time_t*)&val);
#else // TSTAMP_UTC == 0
                t = localtime((time_t*)&val);
#endif // TSTAMP_UTC == 0
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
                strftime(timeBuf, sizeof(timeBuf), B2T_TIMEFRMT, t);
                funcs.fprintf(outfile, "%s%s.%"B2T_TPFRMT, quote, timeBuf, ns); // micro/nano-seconds
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                funcs.fprintf(outfile, "+0000%s", quote);
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                funcs.fprintf(outfile, "%s%s", timeBuf, quote);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
#endif // B2T_TIMESTR == 1
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
                return false;
            }
            funcs.fprintf(outfile, "%s%c%s", quote, (val == 0) ? 'A' : 'B', quote);
            break;
        }

        default:
            T2_PERR("bin2txt", "unhandled type %"PRIu32, type);
            return false;
    }

    return true;
}


static void json_print_double(void *outfile, long double val, b2t_func_t funcs) {
    char buf[512];
    int pos = sprintf(buf, "%.*Lg", 17, val);

    // make sure there is an 'e' or a '.' in the double,
    // otherwise it could be interpreted as an int
    if (strchr(buf, '.') == NULL && strchr(buf, 'e') == NULL) {
        buf[pos++] = '.';
        buf[pos++] = '0';
        buf[pos] = '\0';
        funcs.fputs(buf, outfile);
        return;
    }

    // remove leading zeros in the exponent, e.g., 0.1e-002 -> 0.1e-2

    char *start = strchr(buf, 'e');
    if (!start) {
        funcs.fputs(buf, outfile);
        return;
    }

    // Skip 'e'
    start++;

    // Skip +/- sign
    if (*start == '-' || *start == '+') start++;

    // Skip leading zeros
    char *end = start;
    while (*end == '0') end++;

    if (end == start) {
        // No leading zeros to remove
        funcs.fputs(buf, outfile);
        return;
    }

    // Shift the buffer backward to overwrite leading zeros
    const size_t len = strlen(buf);
    memmove(start, end, len - (size_t)(end - buf));
    buf[len-(end-start)] = '\0';
    funcs.fputs(buf, outfile);
}


#if TFS_SAN_UTF8 == 1
/**
 * @brief Skip invalid multi-bytes UTF-8 chars
 * @param input                 pointer to the string to sanitize
 * @param output                pointer where to write the sanitized string
 * @param input_bytes_processed the number of bytes read from input
 * @param output_bytes_written  the number of bytes written to output
 * @retval true on successful UTF-8 sanitization
 * @retval false on error
 */
static bool b2t_sanitize_utf8(void *input, void *outfile, b2t_func_t funcs) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!funcs.get_val(input, &val, sizeof(uint8_t), 1, funcs))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
            switch (val) {
                case '\t':
                    funcs.fputs("\\t", outfile);
                    break;
                case '\n':
                    funcs.fputs("\\n", outfile);
                    break;
                case '\r':
                    funcs.fputs("\\r", outfile);
                    break;
                case '\\':
                case '"':
                    funcs.fputc('\\', outfile);
                    funcs.fputc(val, outfile);
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        funcs.fprintf(outfile, "\\u00%02X", val);
                    } else {
                        funcs.fputc(val, outfile);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            funcs.fputc('.', outfile);
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!funcs.get_val(input, &b2, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                funcs.fputc('.', outfile);
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            funcs.fputc(val, outfile);
            funcs.fputc(b2, outfile);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!funcs.get_val(input, &b2, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                funcs.fputc('.', outfile);
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                funcs.fputc('.', outfile);
                continue;
            }

            // check third byte
            if (UNLIKELY(!funcs.get_val(input, &b3, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                funcs.fputc('.', outfile);
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                funcs.fputc('.', outfile);
                continue;
            }

            // valid UTF-8 char! -> write it out
            funcs.fputc(val, outfile);
            funcs.fputc(b2, outfile);
            funcs.fputc(b3, outfile);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!funcs.get_val(input, &b2, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                funcs.fputc('.', outfile); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
                funcs.fputc('.', outfile);
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                funcs.fputc('.', outfile);
                continue;
            }

            // check third byte
            if (UNLIKELY(!funcs.get_val(input, &b3, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                funcs.fputc('.', outfile);
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!funcs.get_val(input, &b4, sizeof(uint8_t), 1, funcs))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                funcs.fputc('.', outfile);
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                funcs.fputc('.', outfile);
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            funcs.fputc(val, outfile);
            funcs.fputc(b2, outfile);
            funcs.fputc(b3, outfile);
            funcs.fputc(b4, outfile);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", val);
            funcs.fputc('.', outfile);
        }
    }

    return true;
}
#endif // TFS_SAN_UTF8


// estimate the length of the header
static inline uint32_t t2_get_bin_header_len(void *infile, b2t_func_t funcs) {
    assert(funcs.fread && funcs.rewind);

    uint32_t hdrlen = 0;

    uint32_t val = 0;
    while (val != UINT32_MAX) {
        if (UNLIKELY(funcs.fread(&val, sizeof(val), 1, infile) != 1)) {
            T2_ERR("Incorrect header: 0x%08x", val);
            return 0;
        }
        hdrlen++;
        if (UNLIKELY(hdrlen == UINT32_MAX)) {
            T2_ERR("Header is too long");
            return 0;
        }
    }

    funcs.rewind(infile);

    return hdrlen;
}


// Returned value MUST be free'd with bv_header_destroy()
// NULL is return if an error occured
// If offset is not NULL, it will be set to the inferred value of BUF_DATA_SHFT
// (outputBuffer.h) and indicates the number of uint32_t words to skip for each flow
binary_value_t *t2_read_bin_header(void *infile, uint32_t hdrlen, b2t_func_t funcs, uint32_t *offset) {

    assert(funcs.fread);

    if (hdrlen == 0) {
        hdrlen = t2_get_bin_header_len(infile, funcs);
    }/* else if (UNLIKELY(hdrlen > MAIN_OUTPUT_BUFFER_SIZE)) {
        T2_PERR("bin2txt", "Header length is invalid: %"PRIu32" > %d (MAIN_OUTPUT_BUFFER_SIZE)", hdrlen, MAIN_OUTPUT_BUFFER_SIZE);
        return NULL;
    }*/

    // read the header
    uint32_t header[hdrlen];
    if (UNLIKELY(funcs.fread(header, sizeof(uint32_t), hdrlen, infile) != hdrlen)) {
        return NULL;
    }

    uint32_t off = 0;
    if (offset) *offset = 0;

    // First check magic value at header start
    if (UNLIKELY(header[0] != BV_MAGIC_VALUE_1 ||
                 header[1] != BV_MAGIC_VALUE_2))
    {
        // Magic value not found at offset 0,
        // try to see if BUF_DATA_SHFT (outputBuffer.h) was used
        const uint32_t * const magic = memmem(header, hdrlen, BV_MAGIC_VALUE, sizeof(BV_MAGIC_VALUE)-1);
        if (!magic) {
            T2_ERR("Tranalyzer magic value not found in header");
            return NULL;
        }

        off = magic - header;
        if (offset) *offset = off;
    }

    // check header version. currently, only version 1 is supported
    if (UNLIKELY(header[2 + off] != 1)) {
        T2_ERR("header version %"PRIu32" is not supported", header[2]);
        return NULL;
    }

    uint32_t i = 3 + off; // magic value (2) + version (1)
    uint32_t ii, iii;
    size_t len;
    float ceil_strlen;
    binary_value_t *bv = NULL, *act_bv = NULL;

    while (i < hdrlen - 1) {
        if (!bv) {
            bv = malloc(sizeof(binary_value_t));
            act_bv = bv;
        } else {
            act_bv->next = malloc(sizeof(binary_value_t));
            act_bv = act_bv->next;
        }
        act_bv->next = NULL;

        // get name length
        len = strlen((char*)&header[i]) + 1;
        ceil_strlen = ceilf(len / 4.0f);

        // security check
        if (UNLIKELY(i + ceil_strlen >= hdrlen || len >= BV_STRBUF_SHORT)) {
            T2_ERR("Tranalyzer header malformed (1)");
            bv_header_destroy(bv);
            return NULL;
        }

        strncpy(act_bv->name, (char*)&header[i], BV_STRBUF_SHORT);

        // place i at right pos. Because a char is shorter than uint32_t it can be padded
        i += ceil_strlen;

        // get description length
        len = strlen((char*)&header[i]) + 1;
        ceil_strlen = ceilf(len / 4.0f);

        // security check
        if (UNLIKELY(i + ceil_strlen >= hdrlen || len >= BV_STRBUF_LONG)) {
            T2_ERR("Tranalyzer header malformed (2)");
            bv_header_destroy(bv);
            return NULL;
        }

        strncpy(act_bv->desc, (char*)&header[i], BV_STRBUF_LONG);

        // place i at right pos. Because a char is shorter than uint32_t it can be padded
        i += ceil_strlen;

        if (UNLIKELY(header[i] == UINT32_MAX || header[i] == 0)) {
            T2_ERR("Tranalyzer header malformed (3)");
            bv_header_destroy(bv);
            return NULL;
        }

        // get number of subvalues
        act_bv->num_values = header[i];

        // build subvalue structs
        act_bv->subval = malloc(act_bv->num_values * sizeof(binary_subvalue_t));

        // get type of subvalues
        i++;
        for (ii = 0; ii < act_bv->num_values; ii++) {
            // security check
            if (UNLIKELY(header[i] == UINT32_MAX)) {
                T2_ERR("Tranalyzer header malformed (4)");
                bv_header_destroy(bv);
                return NULL;
            }

            //Init with default data
            act_bv->subval[ii].type = header[i];
            act_bv->subval[ii].num_values = 0;
            act_bv->subval[ii].is_repeating = 0;
            act_bv->subval[ii].subval = NULL;

            // check for more subvals
            if (act_bv->subval[ii].type == bt_compound) {
                // next val is amount of subvalues
                i++;
                act_bv->subval[ii].num_values = header[i];
                // malloc space for subvalues
                act_bv->subval[ii].subval = malloc(act_bv->subval[ii].num_values * sizeof(binary_subvalue_t));

                // fill subvalues
                for (iii = 0; iii < act_bv->subval[ii].num_values; iii++) {
                    i++;
                    if (UNLIKELY(!t2_read_bin_header_rec(header, &i, &act_bv->subval[ii].subval[iii]))) {
                        bv_header_destroy(bv);
                        return NULL;
                    }
                }
                i++;
                // check if subvalues might be repeated
                act_bv->subval[ii].is_repeating = header[i];
            }
            i++;
        }

        // check if subvalues might be repeated
        act_bv->is_repeating = header[i];
        i++; // should now be at position of next column
    }

    return bv;
}


static bool t2_read_bin_header_rec(const uint32_t * const header, uint32_t *hdrpos, binary_subvalue_t *bv) {

    // security check
    if (UNLIKELY(header[*hdrpos] == UINT32_MAX)) {
        T2_ERR("Tranalyzer header malformed (5)");
        return false;
    }

    // get type of subvalue
    bv->type = header[*hdrpos];

    // no more subvalues
    if (bv->type != bt_compound) return true;

    (*hdrpos)++;

    // security check
    if (UNLIKELY(header[*hdrpos] == UINT32_MAX)) {
        T2_ERR("Tranalyzer header malformed (6)");
        return false;
    }

    // get amount of subvalues and malloc space for them
    bv->num_values = header[*hdrpos];
    bv->subval = malloc(bv->num_values * sizeof(binary_subvalue_t));

    // fill subvals
    for (uint_fast32_t i = 0; i < bv->num_values; i++) {
        (*hdrpos)++;
        if (UNLIKELY(!t2_read_bin_header_rec(header, hdrpos, &bv->subval[i]))) {
            return false;
        }
    }
    (*hdrpos)++;

    // security check
    if (UNLIKELY(header[*hdrpos] == UINT32_MAX)) {
        T2_ERR("Tranalyzer header malformed (7)");
        return false;
    }

    bv->is_repeating = header[*hdrpos];

    return true;
}
