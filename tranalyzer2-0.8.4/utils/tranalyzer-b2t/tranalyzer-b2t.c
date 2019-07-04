/*
 * tranalyzer-b2t.c
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

#include <getopt.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <zlib.h>


#define TRANALYZER_B2T "tranalyzer-b2t"


static void print_usage() {
    printf("%s - Converts Tranalyzer binary flow files to json or txt\n\n"
            "Usage:\n"
            "    %s [OPTION...] -r <FILE>\n\n"
            "Input:\n"
            "    -r file            Tranalyzer flow file to convert\n\n"
            "Optional arguments:\n"
            "    -j                 Convert to JSON instead of txt\n"
            "    -n                 Do not write column names as first row (txt only)\n"
            "    -c                 Compress (gzip) the output\n"
            "    -w file            Destination file (default: stdout)\n\n"
            "    -?, -h             Show help options and exit\n",
            TRANALYZER_B2T, TRANALYZER_B2T);
}


static __attribute__((noreturn)) void abort_with_help() {
    printf("Try '%s -h' for more information.\n", TRANALYZER_B2T);
    exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {
    bool compress = false;
    bool write_header = true;

    char *in_name = NULL;  // the name for the input file
    char *out_name = NULL; // the name for the output file

    parse_binary_func_t parse_binary_func;

    bool json = false;
    int opt; // parameter option
    while ((opt = getopt(argc, argv, ":r:w:cnjh?")) != EOF) {
        switch (opt) {
            case 'j':
                json = true;
                write_header = false;
                break;
            case 'r':
                in_name = optarg;
                break;
            case 'w':
                out_name = optarg;
                break;
            case 'n':
                write_header = false;
                break;
            case 'c':
                compress = true;
                break;
            case '?':
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            case ':':
                T2_ERR("Option '-%c' requires an argument", optopt);
                abort_with_help();
            default:
                T2_ERR("Unknown option '-%c'", optopt);
                abort_with_help();
        }
    }

    // if no input file is given, print usage and terminate
    if (!in_name) {
        T2_ERR("Input file is required");
        abort_with_help();
    }

    // Function pointers
    b2t_func_t in_funcs;
    b2t_func_t out_funcs = (compress ? b2t_funcs_gz : b2t_funcs);

    const char *has_gz = strstr(in_name, ".gz");
    if (has_gz) {
        GZ2TXT_TEST_ZLIB_VERSION(TRANALYZER_B2T);
        in_funcs = b2t_funcs_gz;
        if (json) {
            parse_binary_func = (parse_binary_func_t)parse_file_gz2json;
        } else {
            parse_binary_func = (parse_binary_func_t)parse_file_gz2txt;
        }
    } else {
        in_funcs = b2t_funcs;
        if (json) {
            parse_binary_func = (parse_binary_func_t)parse_file_bin2json;
        } else {
            parse_binary_func = (parse_binary_func_t)parse_file_bin2txt;
        }
    }

    // try to open input file in read mode
    void *infile;
    if (UNLIKELY(!(infile = in_funcs.fopen(in_name, "r")))) {
        T2_ERR("Failed to open input file %s: %s", in_name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    // if no output file is given, set output file to standard output
    // else try to open output file in write mode
    void *outfile;
    if (!out_name) {
        // XXX alternatively: derive output filename from input filename?
        if (!compress) {
            outfile = stdout;
        } else {
            if (UNLIKELY(!(outfile = gzdopen(fileno(stdout), "w")))) {
                T2_ERR("Failed to open compressed stream: %s", strerror(errno));
                in_funcs.fclose(infile);
                exit(EXIT_FAILURE);
            }
        }
    } else if (UNLIKELY(!(outfile = out_funcs.fopen(out_name, "w")))) {
        T2_ERR("Failed to open output file %s: %s", out_name, strerror(errno));
        in_funcs.fclose(infile);
        exit(EXIT_FAILURE);
    }

    int ret = EXIT_SUCCESS;

    uint32_t offset; // BUF_DATA_SHFT (number of uint32_t words before each flow)
    binary_value_t *bv = t2_read_bin_header(infile, 0, in_funcs, &offset);
    if (!bv) {
        T2_ERR("Failed to read binary header");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    if (write_header) {
        parse_binary_header2text(bv, outfile, out_funcs);
    }

    int c;
    uint32_t u32;
    uint_fast32_t i;
    while ((c = in_funcs.fgetc(infile)) != EOF) {
        if (UNLIKELY(in_funcs.ungetc(c, infile) != c)) {
            T2_ERR("Failed to replace '0x%02x' into '%s'", c, in_name);
            ret = EXIT_FAILURE;
            break;
        }
        // Skip BUF_DATA_SHFT
        for (i = 0; i < offset; i++) {
            if (UNLIKELY(in_funcs.fread(&u32, sizeof(u32), 1, infile) != 1)) {
                T2_ERR("Failed to skip offset %"PRIuFAST32" / %"PRIu32, i+1, offset);
                ret = EXIT_FAILURE;
                goto cleanup;
            }
        }
        if (UNLIKELY(!parse_binary_func(infile, bv, outfile, compress))) {
            ret = EXIT_FAILURE;
            break;
        }
    }

cleanup:
    in_funcs.fclose(infile);
    out_funcs.fclose(outfile);
    bv_header_destroy(bv);

    return ret;
}
