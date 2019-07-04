/*
 * fextractor.c
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <libgen.h>
#include <errno.h>
#include <glob.h>
#ifndef __APPLE__
#include <byteswap.h>
#include <linux/limits.h>
#else // __APPLE__
#include <sys/syslimits.h>
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#endif // __APPLE__

#include "heap.h"

// mode with lower disk I/O but higher memory usage
// test results: no difference, ext4 filesystem is already very good at caching
#define LESS_IO_MORE_MEM  0
// maximum warnings per PCAP (due to packets > MAX_PACKET_SIZE)
// when more warnings occur, we consider that indexes for current PCAP are corrupted
// (see WARNING comment in src/findexer.c) and jump to the next PCAP.
#define MAX_WARN_PER_PCAP 10
// 1: print debug info about which packets are extracted from which XER file and which PCAP.
#define DEBUG_INFO        0

// ------------------------- DO NOT EDIT BELOW HERE -------------------------

#define FINDEXER_V1_MAGIC  0x52455845444e4946 // FINDEXER
#define FINDEXER_V2_MAGIC  0x32455845444e4946 // FINDEXE2
#define PCAP_MAGIC         0xa1b2c3d4
#define MAX_PACKET_SIZE (1 << 16)
#define INITIAL_FLOW_COUNT 16

#define FATAL(format, args...) \
        do { \
            fprintf(stderr, "\e[01;31m[ERR] \e[00m\e[00;31m" format "\e[00m\n", ##args); \
            exit(EXIT_FAILURE); \
        } while (0)
#define WARN(format, args...) \
        fprintf(stderr, "\e[01;33m[WARN] \e[00m\e[00;33m" format "\e[00m\n", ##args)
#define INFO(format, args...) \
        fprintf(stderr, "\e[01;34m[INFO] \e[00m\e[00;34m" format "\e[00m\n", ##args)
#if DEBUG_INFO != 0
    #define DEBUG(format, args...) \
        fprintf(stderr, "\e[01;32m[DEBUG] \e[00m\e[00;32m" format "\e[00m\n", ##args)
#else // DEBUG_INFO == 0
    #define DEBUG(format, args...)
#endif // DEBUG_INFO


// structures definition

// per pcap structure (completely unrelated to the pcap file header structure)
typedef struct {
    char* pcap_path;
    uint64_t flow_count;
    // v1: points to the first flow_index in the PCAP header
    // v2: points to the first flow_header
    uint64_t flow_pointer;
} findexer_pcap_header_t;

typedef enum {
    DIR_BOTH,
    DIR_A,
    DIR_B,
} FlowDirection;

// struct to store info about flows to extract
typedef struct {
    uint64_t findex;      // flow index
    uint64_t start;       // first packet to extract
    uint64_t end;         // last packet to extract
    FlowDirection dir;    // direction(s) to extract
//    bool start_extracted; // start of flow was extracted
//    bool end_extracted;   // end of flow was extracted
} extractable_flow_t;

// flags in findexer v2 flow header
enum FlowFlag {
    REVERSE_FLOW, // flow is a B flow
    FIRST_XER,    // this is the first .xer file in which this flow appears
    LAST_XER,     // this is the last .xer file in which this flow appears
    // reserved for future flags
};

// transform a flag to its bitmask representation
#define FLAG_BITMASK(x) (1 << (x))

// struct to store a single flow extraction state
typedef struct {
    uint64_t index;
    uint64_t start;
    uint64_t end;
#if LESS_IO_MORE_MEM == 1
    uint64_t count;
    uint64_t* packets;
#else //LESS_IO_MORE_MEM == 0
    uint64_t packet_offset;
    uint64_t packet_left;
    uint64_t offset_offset;
#endif // LESS_IO_MORE_MEM
    uint64_t findex;
//    extractable_flow_t *parent;
} flow_state_t;


// global variables
static char findexer_file_path[PATH_MAX]; // -r option: current input XER file
static char* output_file_path = NULL;     // -w option
static char* path_prefix = NULL;          // -p option
static char* flow_file = NULL;            // -i option

static char* multi_file_num_pos = NULL;   // position of num suffix in findexer_file_path
static int64_t multi_start_index = -1;    // -r start index
static int64_t multi_end_index = -1;      // -r end index
static uint64_t multi_current_index = 0;  // index of currently processed findexer file

static bool both_dir = false;       // extract both directions from flow files (-b option)
static bool force = false;          // overwrite output PCAP (-f option)
static bool first_pkt = false;      // print first packet PCAP and timestamp and exit (-n option)
static uint32_t first_pcap = 0;     // start extracting only from this PCAP
static uint64_t extracted_pkts = 0; // total number of extracted packets

static extractable_flow_t* flows;   // list of flows to extract
static uint64_t flow_count = 0;     // number of flows to extract
static uint64_t allocated_flows = INITIAL_FLOW_COUNT;
static heap_t* states;              // extraction state (keeps track of next packets offsets)
static FILE* output;
static uint64_t current_findex;     // keeps track of currently extracted findex for error msg.
static uint8_t findexer_version;    // v1 or v2 (see doc/findexer.pdf for format details)

static uint32_t snaplen, datalink;
static bool header_written = false;

// helper functions

#if DEBUG_INFO != 0
static char* dir_str(FlowDirection dir) {
    switch (dir) {
        case DIR_BOTH: return ":AB";
        case DIR_A: return ":A";
        case DIR_B: return ":B";
        default: return ":UNK";
    }
}
#endif // DEBUG_INFO != 0


void print_usage() {
    fprintf(stdout, "Usage: fextractor -r INPUT[:start][,end] (-w OUTPUT | -n) [OPTIONS]... \\\n"
            "            [[DIR@]FLOWINDEX[:start][,end]]...\n\n"
            "Extract the flows FLOWINDEX using the _flows.xer INTPUT generated by Tranalyzer2 findexer plugin.\n"
            "Alternatively use a list of findexer files generated by Tranalyzer2 -W option from index start\n"
            "to end. The extracted flows are written to the OUTPUT pcap.\n\n"
            "An optional packet range can be provided on each command line FLOWINDEX to only extract packets\n"
            "in the range [start, end] of this flow. If start or end are ommitted, they are replaced by,\n"
            "respectively, the first and the last available packets in the flow. The FLOWINDEX can also\n"
            "optionally be prefixed with a direction A or B, by default both directions are extracted.\n\n"
            "OPTIONS:\n"
            "  -r INPUT[:start][,end]\n"
            "            either read packet indexes from a single _flows.xer file named INPUT\n"
            "            or read packet indexes from multiple _flows.xer files prefixed by INPUT\n"
            "            and with suffix in range [start, end]. If start or end are ommitted,\n"
            "            they are replaced by, respectively, first and last available XER files.\n"
            "  -w OUTPUT write packets to pcap file OUTPUT\n"
            "            OUTPUT \"-\" means that the PCAP is written to stdout.\n"
            "  -f        overwrite OUTPUT if it already exists\n"
            "  -n        print oldest PCAP still available, its first packet timestamp and exit\n"
            "  -h        print this help message\n"
            "  -i FILE   read flow indexes from FILE. FILE can either be in _flows.txt format\n"
            "            (flow index in 2nd tab-separated column), or have one flow index per line.\n"
            "            FILE \"-\" means that flows are read from stdin.\n"
            "  -b        by default when FILE is in _flows.txt format, only directions present in\n"
            "            it are extracted, this option force both directions to be extracted even if\n"
            "            only the A or B direction is present in the flow file.\n"
            "  -s N      skip the first N PCAPs\n"
            "  -p DIR    search pcaps in DIR\n"
            "            should only be set if pcaps were moved since Tranalyzer2 was run\n");
}

/**
 * @brief Removes the line return at the end of a line.
 *
 * Decrement the size for each stripped character.
 *
 * @param  str   the string to strip.
 * @param  size  size of the string to strip.
 */
static void stripln(char *start, ssize_t *size) {
    char *end = start + *size - 1;
    while (*size > 0 && (*end == '\r' || *end == '\n')) {
        *end-- = '\0';
        --(*size);
    }
}

/**
 * @brief Split a string using a delimiter character.
 *
 * This function should be called repetedly until it returns NULL in
 * order to split a line token by token with a char delimiter.
 * This function modifies the input string. The input string must be null-terminated.
 *
 * @param  str    the beginning of the input string to split
 * @param  delim  the delimiter character at which to split the input string
 * @return the start of next token; NULL if str was the last token
 */
static char *splitstr(char* str, char delim) {
    while (*str != delim && *str != '\0') {
        ++str;
    }
    if (*str == '\0') {
        return NULL;
    }
    *str++ = '\0';
    return str;
}

void add_flow_to_extract(uint64_t findex, uint64_t start, uint64_t end, FlowDirection dir) {
    // reallocate memory if flow list is full
    if (flow_count >= allocated_flows) {
        allocated_flows <<= 1;
        extractable_flow_t* tmp = realloc(flows, allocated_flows * sizeof(*flows));
        if (!tmp) {
            free(flows);
            FATAL("Failed to re-allocate memory for flow list.");
        }
        flows = tmp;
    }
    // put flow in list
    extractable_flow_t flow = { findex, start, end, dir };
    flows[flow_count++] = flow;
}

void read_flow_file(char* filename) {
    FILE* file;
    // "-" means stdin, all other values must be files
    if (strcmp("-", filename) == 0) {
        file = stdin;
    } else if (!(file = fopen(filename, "r"))) {
        FATAL("Failed to open flow file %s", filename);
    }

    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        // strip line return at end of line
        stripln(line, &read);
        // skip empty lines or lines starting with '%'
        if (read == 0 || line[0] == '%' || line[0] == '#') {
            continue;
        }
        // must not modify line otherwise next getline call will crash
        char* tmp = line;
        FlowDirection dir = DIR_BOTH;
        char* index = NULL;
        if ((tmp = splitstr(tmp, '\t'))) {
            // if there is at least one tab, use second column
            index = tmp;
            // check direction
            if (!both_dir) {
                if (strcmp(line, "A") == 0) {
                    dir = DIR_A;
                } else if (strcmp(line, "B") == 0) {
                    dir = DIR_B;
                } else {
                    FATAL("Invalid value: direction in flow file must be A or B.");
                }
            }
            // null terminate second column
            splitstr(tmp, '\t');
        } else {
            // no tab, then use whole line
            index = line;
        }
        errno = 0;
        char* end;
        uint64_t findex = strtoull(index, &end, 10);
        if (errno != 0 || findex == 0 || *end != '\0') {
            FATAL("Invalid value: \"%s\": FLOWINDEX must be a strictly positive 64-bit number", index);
        }
        add_flow_to_extract(findex, 0, UINT64_MAX, dir);
    }
    fclose(file);
    free(line);
}

void parse_args(int argc, char** argv) {
    // memset findexer file path to test if required arguments -r was present
    memset(findexer_file_path, 0, PATH_MAX);
    // variable used for argument parsing
    int c;
    extern char* optarg;
    extern int optind, optopt, opterr;
    while ((c = getopt(argc, argv, ":hfnbw:r:R:p:s:i:")) != -1) {
        switch (c) {
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            case 'r': {
                if (strlen(findexer_file_path)) {
                    FATAL("Invalid option: multiple -r provided.");
                }
                size_t len = strlen(optarg);
                if (len > PATH_MAX - 50) { // keep enough space for the number suffix
                    FATAL("-r option argument is too long, move your files to a shorter path.");
                }
                char* prefix_end = optarg + len;
                char* const colon = memchr(optarg, ':', len);
                char* const comma = memchr(optarg, ',', len);
                char* end;
                errno = 0;
                if (colon && comma) {
                    if (colon > comma) {
                        FATAL("Invalid -r value: the colon cannot be after the comma.");
                    }
                    multi_start_index = strtoul(colon + 1, &end, 10);
                    if (errno != 0 || *end != ',' || end == colon + 1 || multi_start_index < 0) {
                        FATAL("Invalid value: -r option start index must be a positive 32 bit number.");
                    }
                    multi_end_index = strtoul(comma + 1, &end, 10);
                    if (errno != 0 || *end != '\0' || end == comma + 1 || multi_end_index < 0) {
                        FATAL("Invalid value: -r option end index must be a positive 32 bit number.");
                    }
                    if (multi_end_index < multi_start_index) {
                        FATAL("Invalid value: -r option start index cannot be bigger than end index.");
                    }
                    prefix_end = colon;
                } else if (colon) {
                    multi_start_index = strtoul(colon + 1, &end, 10);
                    if (errno != 0 || *end != '\0' || end == colon + 1 || multi_start_index < 0) {
                        FATAL("Invalid value: -r option start index must be a positive 32 bit number.");
                    }
                    prefix_end = colon;
                } else if (comma) {
                    multi_end_index = strtoul(comma + 1, &end, 10);
                    if (errno != 0 || *end != '\0' || end == comma + 1 || multi_end_index < 0) {
                        FATAL("Invalid value: -r option end index must be a positive 32 bit number.");
                    }
                    prefix_end = comma;
                }
                // copy the file prefix and keep track of position to append the suffix number
                len = prefix_end - optarg;
                strncpy(findexer_file_path, optarg, len);
                multi_file_num_pos = findexer_file_path + len;
                break;
            }
            case 'w':
                if (output_file_path) {
                    FATAL("Invalid option: multiple -w provided.");
                }
                output_file_path = optarg;
                break;
            case 'p':
                if (path_prefix) {
                    FATAL("Invalid option: multiple -p provided.");
                }
                path_prefix = optarg;
                break;
            case 's': {
                char* end;
                errno = 0;
                first_pcap = strtoul(optarg, &end, 10);
                if (errno != 0 || *end != '\0') {
                    FATAL("Invalid value: -s option argument must be a positive 32 bit number.");
                }
                break;
            }
            case 'f':
                force = true;
                break;
            case 'b':
                both_dir = true;
                break;
            case 'n':
                first_pkt = true;
                break;
            case 'i':
                flow_file = optarg;
                break;
            case ':':
                FATAL("Option -%c requires an argument.\n"
                      "      Run 'fextractor -h' for more information.", optopt);
            case '?':
            default:
                FATAL("Unknown option -%c\n"
                      "      Run 'fextractor -h' for more information.", optopt);
        }
    }
    if (strlen(findexer_file_path) == 0) {
        FATAL("Missing mandatory -r option.\n"
              "      Run 'fextractor -h' for more information.");
    }
    if (!first_pkt && !output_file_path) {
        FATAL("Missing mandatory -w or -n option.\n"
              "      Run 'fextractor -h' for more information.");
    }
    // parse flow file
    if (flow_file) {
        read_flow_file(flow_file);
    }
    // parse flow indexes passed as argument
    for (c = optind; c < argc; ++c) {
        // parse flow direction, start and end optional values
        size_t len = strlen(argv[c]);
        char* const at = memchr(argv[c], '@', len);
        char* const colon = memchr(argv[c], ':', len);
        char* const comma = memchr(argv[c], ',', len);

        char* endc;
        char* findex_start = argv[c];
        char* findex_end = argv[c] + len;
        errno = 0;

        int64_t start = 0;
        int64_t end = UINT64_MAX;
        FlowDirection dir = DIR_BOTH;

        // check flow direction
        if (at) {
            if (at != argv[c] + 1) {
                FATAL("Invalid FLOWINDEX value: the @ is not at a correct position.");
            }
            char d = argv[c][0];
            if (d == 'A' || d == 'a') {
                dir = DIR_A;
            } else if (d == 'B' || d == 'b') {
                dir = DIR_B;
            } else {
                FATAL("Invalid FLOWINDEX value: direction can only be A or B (upper or lowercase).");
            }
            findex_start = at + 1;
        }

        // check packet range
        if (colon && comma) {
            if (colon > comma) {
                FATAL("Invalid FLOWINDEX value: the colon cannot be after the comma.");
            }
            start = strtoull(colon + 1, &endc, 10);
            if (errno != 0 || *endc != ',' || endc == colon + 1 || start < 0) {
                FATAL("Invalid value: FLOWINDEX start packet must be a positive 64-bit number.");
            }
            end = strtoull(comma + 1, &endc, 10);
            if (errno != 0 || *endc != '\0' || endc == comma + 1 || end < 0) {
                FATAL("Invalid value: FLOWINDEX end packet must be a positive 64-bit number.");
            }
            if (end < start) {
                FATAL("Invalid value: FLOWINDEX start packet cannot be bigger than end packet.");
            }
            findex_end = colon;
        } else if (colon) {
            start = strtoull(colon + 1, &endc, 10);
            if (errno != 0 || *endc != '\0' || endc == colon + 1 || start < 0) {
                FATAL("Invalid value: FLOWINDEX start packet must be a positive 64-bit number.");
            }
            findex_end = colon;
        } else if (comma) {
            end = strtoull(comma + 1, &endc, 10);
            if (errno != 0 || *endc != '\0' || endc == comma + 1 || end < 0) {
                FATAL("Invalid value: FLOWINDEX end packet must be a positive 64-bit number.");
            }
            findex_end = comma;
        }

        int64_t findex = strtoull(findex_start, &endc, 10);
        if (errno != 0 || findex == 0 || endc != findex_end || findex < 0) {
            FATAL("Invalid value: \"%s\": FLOWINDEX must be a strictly positive 64-bit number", argv[c]);
        }

        add_flow_to_extract(findex, start, end, dir);
    }

    if (!first_pkt && flow_count == 0) {
        FATAL("Requires at least one FLOWINDEX.\n"
              "      Run 'fextractor -h' for more information.");
    }
}

uint8_t read_version(FILE* f) {
    // go to start of file
    if (fseeko(f, 0, SEEK_SET) != 0) {
        FATAL("Failed to seek to the start of the input file.");
    }
    // read magic value
    uint64_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        FATAL("Failed to read magic value.");
    }
    switch(magic) {
        case FINDEXER_V1_MAGIC:
            return 1;
        case FINDEXER_V2_MAGIC:
            return 2;
        default:
            // TODO: handle opposite endianness flows.xer files
            FATAL("Input file is not a valid findexer file.");
    }
    return 0;
}

uint32_t read_pcap_count(FILE* f) {
    // read magic value
    uint32_t pcap_count;
    if (fread(&pcap_count, sizeof(pcap_count), 1, f) != 1) {
        FATAL("Failed to read number of PCAPs");
    }
    return pcap_count;
}

uint64_t next_pcap_header_pos(FILE* f, uint32_t pcap_index, uint64_t last_pcap_header_pos) {
    // where is next PCAP header pointer stored
    uint64_t pointer_pos = 0;
    switch(findexer_version) {
        case 1:
            pointer_pos = sizeof(uint64_t) + sizeof(uint32_t) + pcap_index * sizeof(uint64_t);
            break;
        case 2:
            if (pcap_index == 0) {
                pointer_pos = sizeof(uint64_t) + sizeof(uint32_t);
            } else {
                pointer_pos = last_pcap_header_pos;
            }
            break;
        default:
            FATAL("Unsuported findexer version: %d.", findexer_version);
    }
    // check if next PCAP header pointer position is valid
    if (pointer_pos == 0) {
        FATAL("Invalid next PCAP pointer position.");
    }
    // read and return the position of the next PCAP header
    if (fseeko(f, pointer_pos, SEEK_SET) != 0) {
        FATAL("Failed to seek to next PCAP header position.");
    }
    uint64_t headerPos;
    if (fread(&headerPos, sizeof(headerPos), 1, f) != 1) {
        FATAL("Failed to read next PCAP header position.");
    }
    return headerPos;
}

findexer_pcap_header_t* read_pcap_header(FILE* f, uint64_t offset) {
    findexer_pcap_header_t* header;
    if (!(header = malloc(sizeof(*header)))) {
        FATAL("Failed to allocate memory for pcap header.");
    }
    if (fseeko(f, offset, SEEK_SET) != 0) {
        FATAL("Failed to seek to the start of the PCAP header.");
    }
    // read flow count and first flow pointer for findexer v2
    if (findexer_version == 2) {
        // skip next PCAP pointer
        if (fseeko(f, sizeof(uint64_t), SEEK_CUR) != 0) {
            FATAL("Failed to skip next PCAP pointer in PCAP header.");
        }
        if (fread(&header->flow_count, sizeof(header->flow_count), 1, f) != 1) {
            FATAL("Failed to read flow count in PCAP header.");
        }
        if (fread(&header->flow_pointer, sizeof(header->flow_pointer), 1, f) != 1) {
            FATAL("Failed to read first flow pointer in PCAP header.");
        }
    }
    // read pcap path
    uint16_t path_len;
    if (fread(&path_len, sizeof(path_len), 1, f) != 1) {
        FATAL("Failed to read the pcap header.");
    }
    if (!(header->pcap_path = malloc(path_len + 1))) {
        FATAL("Failed to allocate memory for pcap path.");
    }
    if (fread(header->pcap_path, sizeof(char), path_len, f) != path_len) {
        FATAL("Failed to read the pcap header.");
    }
    header->pcap_path[path_len] = '\0';
    // read flow count and set flow pointer for findexer v1
    if (findexer_version == 1) {
        if (fread(&header->flow_count, sizeof(header->flow_count), 1, f) != 1) {
            FATAL("Failed to read the pcap header.");
        }
        header->flow_pointer = ftello(f);
    }

    if (!path_prefix) {
        return header;
    }

    // change pcap path if path_prefix is set
    char* origin_path = header->pcap_path;
    char* bn = basename(header->pcap_path);
    size_t len = strlen(path_prefix) + strlen(bn) + 2;
    if (!(header->pcap_path = malloc(len))) {
        FATAL("Failed to allocate memory for pcap path.");
    }
    memset(header->pcap_path, 0, len);
    strcat(header->pcap_path, path_prefix);
    strcat(header->pcap_path, "/");
    strcat(header->pcap_path, bn);

    // free previous pcap_path
    free(origin_path);

    return header;
}

/*
 * Comparator to sort flows with qsort.
 */
int flow_order(const void* a, const void* b) {
    const extractable_flow_t* const fa = (const extractable_flow_t* const)a;
    const extractable_flow_t* const fb = (const extractable_flow_t* const)b;
    if (fa->findex > fb->findex) {
        return 1;
    } else if (fa->findex < fb->findex) {
        return -1;
    } else {
        // WARNING: DO NOT use findexer_version as the _flows.xer file has not been read yet.
        if (fa->dir > fb->dir) {
            return 1;
        } else if (fa->dir < fb->dir) {
            return -1;
        } else {
            return 0;
        }
    }
}

/*
 * Comparator to binary search flows. Slightly different from sort function. If flow in list contains
 * DIR_BOTH, it should also match when testing if A or B are extractable.
 */
int flow_in_list(const void* a, const void* b) {
    const extractable_flow_t* const fa = (const extractable_flow_t* const)a; // compared flow
    const extractable_flow_t* const fb = (const extractable_flow_t* const)b; // list element
    if (fa->findex > fb->findex) {
        return 1;
    } else if (fa->findex < fb->findex) {
        return -1;
    } else {
        // findexer v1 format contains no information about flow direction
        if (findexer_version == 1 || fb->dir == DIR_BOTH || fa->dir == fb->dir) {
            return 0;
        } else if (fa->dir > fb->dir) {
            return 1;
        } else { // fa->dir < fb->dir
            return -1;
        }
    }
}

/*
 * Flow state comparator used to order heap according to next packet position.
 */
int heap_cmp(const void* a, const void* b) {
    const flow_state_t* fa = (const flow_state_t*)a;
    const flow_state_t* fb = (const flow_state_t*)b;
#if LESS_IO_MORE_MEM == 1
    if (fa->packets[fa->index] < fb->packets[fb->index]) {
        return -1;
    } else if (fa->packets[fa->index] > fb->packets[fb->index]) {
        return 1;
    } else {
        return 0;
    }
#else // LESS_IO_MORE_MEM == 0
    if (fa->packet_offset < fb->packet_offset) {
        return -1;
    } else if (fa->packet_offset > fb->packet_offset) {
        return 1;
    } else {
        return 0;
    }
#endif // LESS_IO_MORE_MEM
}

void generate_state(FILE* f, findexer_pcap_header_t* header) {
    for (uint64_t i = 0; i < header->flow_count; ++i) {
        if (flow_count == 0) {
            break; // no more flow to extract
        }
        // go to next flow
        if (fseeko(f, header->flow_pointer, SEEK_SET) != 0) {
            FATAL("Failed to seek to the flow header. Flow pointer: %" PRIu64, header->flow_pointer);
        }
        // update next flow pointer
        switch (findexer_version) {
            case 1:
                header->flow_pointer += 3 * sizeof(uint64_t);
                break;
            case 2:
                if (fread(&header->flow_pointer, sizeof(header->flow_pointer), 1, f) != 1) {
                    FATAL("Failed to read next flow pointer at position: %" PRIu64, header->flow_pointer);
                }
                break;
            default:
                FATAL("Unsupported findexer version: %d.", findexer_version);
        }
        // read flow index
        uint64_t findex;
        if (fread(&findex, sizeof(findex), 1, f) != 1) {
            FATAL("Failed to read flow index from flow header.");
        }
        // parse flags in findexer v2
        FlowDirection dir = DIR_BOTH;
        uint8_t flags = 0;
        if (findexer_version == 2) {
            if (fread(&flags, sizeof(flags), 1, f) != 1) {
                FATAL("Failed to read flags in flow header.");
            }
            // flow direction flag
            if (flags & FLAG_BITMASK(REVERSE_FLOW)) {
                dir = DIR_B;
            } else {
                dir = DIR_A;
            }
        }
        extractable_flow_t flow = { findex, 0, 0, dir };
        // check if flow should be extracted
        extractable_flow_t* match = bsearch(&flow, flows, flow_count, sizeof(*flows), flow_in_list);
        if (!match) {
            continue;
        }
        if (flags & FLAG_BITMASK(FIRST_XER)) {
            DEBUG("Flow %" PRIu64 "%s starts in current XER file.", findex, dir_str(dir));
        }
        if (flags & FLAG_BITMASK(LAST_XER)) {
            DEBUG("Flow %" PRIu64 "%s stops in current XER file.", findex, dir_str(dir));
        }
        // the flow should be extracted
        flow_state_t* state;
        if (!(state = malloc(sizeof(*state)))) {
            FATAL("Failed to allocate memory for flow state.");
        }
        state->findex = findex;
        state->start = match->start;
        state->end = match->end;

        // remove this flow from the list of flows to extract if it won't appear in further .xer
        if (flags & FLAG_BITMASK(LAST_XER)) {
            if (dir == match->dir) {
                // remove this flow from the lists of extractable flows
                size_t size = (flow_count - (match - flows)) * sizeof(extractable_flow_t);
                memmove(match, (char *)match + sizeof(extractable_flow_t), size);
                --flow_count;
                DEBUG("Flow %" PRIu64 " deleted: all requested directions were extracted", findex);
            } else {
                if (dir == DIR_B) {
                    match->dir = DIR_A; // B flow terminated, only extract A flow
                } else {
                    match->dir = DIR_B; // A flow terminated, only extract B flow
                }
            }
        }

        uint64_t count;
        if (fread(&count, sizeof(count), 1, f) != 1) {
            FATAL("Failed to read packet count in flow header.");
        }
        // do not insert flows with zero packets in the extraction state
        if (count == 0) {
            free(state);
            continue;
        }
        DEBUG("Extracting %" PRIu64 " packets from flow %" PRIu64 "%s", count, findex, dir_str(dir));
        uint64_t offset_offset;
        switch (findexer_version) {
            case 1:
                if (fread(&offset_offset, sizeof(offset_offset), 1, f) != 1) {
                    FATAL("Failed to read flow in pcap header.");
                }
                break;
            case 2:
                offset_offset = ftello(f);
                break;
            default:
                FATAL("Unsupported findexer version: %d.", findexer_version);
        }
        if (fseeko(f, offset_offset, SEEK_SET) != 0) {
            FATAL("Failed to seek to the offsets.");
        }
        state->index = 0;
    #if LESS_IO_MORE_MEM == 1
        state->count = count;
        if (!(state->packets = calloc(count, sizeof(*state->packets)))) {
            FATAL("Failed to allocate memory for packet offsets.");
        }
        if (fread(state->packets, sizeof(*state->packets), count, f) != count) {
            FATAL("Failed to read packet offsets.");
        }
    #else // LESS_IO_MORE_MEM == 0
        state->packet_left = count;
        if (fread(&state->packet_offset, sizeof(state->packet_offset), 1, f) != 1) {
            FATAL("Failed to read packet offset.");
        }
        state->offset_offset = offset_offset + sizeof(state->packet_offset);
        state->packet_left--;
    #endif // LESS_IO_MORE_MEM
        if (!heap_push(states, state)) {
            FATAL("Failed to add new state on heap.");
        }
    }
}

/**
 * Return the offset of the next packet to extract.
 * Returns 0 when there is no packet left to extract.
 */
uint64_t next_offset(FILE* f
#if LESS_IO_MORE_MEM == 1
    __attribute__((unused))
#endif // LESS_IO_MORE_MEM == 1
) {
    uint64_t offset = 0;
    bool extractable = false;

    while (!extractable) {
        if (heap_size(states) == 0) {
            return 0;
        }
        flow_state_t* state = heap_pop(states);

        extractable = state->index >= state->start && state->index <= state->end;

        current_findex = state->findex;
#if LESS_IO_MORE_MEM == 1
        offset = state->packets[state->index++];
        // Don't add this flow back to the state if it has no packet left
        if (state->index >= state->count || state->index > state->end) {
            free(state->packets);
            free(state);
            continue;
        }
#else // LESS_IO_MORE_MEM == 0
        offset = state->packet_offset;
        state->index++;
        // Don't add this flow back to the state if it has no packet left
        if (state->packet_left == 0 || state->index > state->end) {
            free(state);
            continue;
        }
        // read next packet offset
        if (fseeko(f, state->offset_offset, SEEK_SET) != 0) {
            FATAL("Failed to seek to packet offset list.");
        }
        if (fread(&state->packet_offset, sizeof(state->packet_offset), 1, f) != 1) {
            FATAL("Failed to read packet offset.");
        }
        state->offset_offset += sizeof(state->packet_offset);
        state->packet_left--;
#endif // LESS_IO_MORE_MEM
        if (!heap_push(states, state)) {
            FATAL("Failed to add new state on heap.");
        }
    }

    return offset;
}

bool process_findexer_file(char* path, bool warning) {
    if (access(path, F_OK) != 0) {
        if (warning) {
            WARN("%s does not exist", path);
        }
        return false;
    }
    INFO("Processing findexer : %s", path);
    // open input flows.xer file
    FILE* input = fopen(path, "rb");
    if (!input) {
        FATAL("Failed to open input file: %s", path);
    }

    // check which version of the findexer plugin generated the _flows.xer file
    findexer_version = read_version(input);

    // read number of pcaps
    const uint32_t pcap_count = read_pcap_count(input);

    uint32_t pcap_header_buffer[6];

    uint64_t pcap_header_pos = 0;

    for (uint32_t i = 0; i < pcap_count; ++i) {
        if (!first_pkt && flow_count == 0) {
            break;
        }
        // read PCAP header
        pcap_header_pos = next_pcap_header_pos(input, i, pcap_header_pos);
        if (first_pcap > i) {
            continue;
        }
        findexer_pcap_header_t* pcapHeader = read_pcap_header(input, pcap_header_pos);
        FILE* pcap;
        // open input pcap file
        if (!(pcap = fopen(pcapHeader->pcap_path, "rb"))) {
            WARN("Failed to open pcap %s", pcapHeader->pcap_path);
            continue;
        }
        // read pcap header
        if (fread(pcap_header_buffer, sizeof(uint32_t), 6, pcap) != 6) {
            WARN("Failed to read the pcap file header of %s", pcapHeader->pcap_path);
            fclose(pcap);
            continue;
        }
        bool opposite_endianness = false;
        if (pcap_header_buffer[0] == bswap_32(PCAP_MAGIC)) {
            opposite_endianness = true;
        } else if (pcap_header_buffer[0] != PCAP_MAGIC) {
            // TODO: handle opposite endianness pcaps (detectable with 0xd4c3b2a1)
            WARN("%s is not a valid pcap.\n"
                    "       PcapNg and big-endian pcaps are not supported.", pcapHeader->pcap_path);
            fclose(pcap);
            continue;
        }
        // -n option: print PCAP name and its first packet timestamp
        if (first_pkt) {
            uint32_t packet_header[4];
            if (fread(packet_header, sizeof(uint32_t), 4, pcap) != 4) {
                FATAL("Failed to read the first packet header of %s", pcapHeader->pcap_path);
            }
            if (opposite_endianness) {
                packet_header[0] = bswap_32(packet_header[0]);
                packet_header[1] = bswap_32(packet_header[1]);
            }
            // transform packet timestamp to double
            double fraction = (double)packet_header[1] / 1000000.0;
            if (fraction >= 1.0) {
                // unreliable method to detect if PCAP was recorder with mirco or nanosecond precision
                // unfortunately tcpdump always leaves the precision info in the PCAP header to 0...
                fraction /= 1000.0;
            }
            double timestamp = (double)packet_header[0] + fraction;
            // print info and exit
            printf("findexer_path: %s\n", path);
            printf("pcap_path: %s\n", pcapHeader->pcap_path);
            printf("pcap_index: %u\n", i);
            printf("timestamp: %f\n", timestamp);
            exit(EXIT_SUCCESS);
        }
        INFO("Processing pcap %u/%u : %s", i + 1, pcap_count, pcapHeader->pcap_path);
        // create the state for current PCAP
        generate_state(input, pcapHeader);
        // output pcap header if this is the first input pcap
        if (!header_written) {
            if (fwrite(pcap_header_buffer, sizeof(uint32_t), 6, output) != 6) {
                FATAL("Failed to write the output pcap file header.");
            }
            snaplen = pcap_header_buffer[4];
            datalink = pcap_header_buffer[5];
            header_written = true;
        } else {
            if (datalink != pcap_header_buffer[5]) {
                WARN("%s has a different data link type than previous pcap.\n"
                     "       File ignored because they cannot be merged in the same output pcap.",
                     pcapHeader->pcap_path);
                fclose(pcap);
                continue;
            }
            if (opposite_endianness) {
                snaplen = bswap_32(pcap_header_buffer[4]) > bswap_32(snaplen) ?
                    pcap_header_buffer[4] : snaplen;
            } else {
                snaplen = pcap_header_buffer[4] > snaplen ? pcap_header_buffer[4] : snaplen;
            }
        }

        // extract all the packets from current pcap
        uint8_t warn_count = 0;
        uint64_t offset;
        while ((offset = next_offset(input))) { // offset == 0 => no packet left
            // seek to pcap packet header and read it
            if (fseeko(pcap, offset, SEEK_SET) != 0) {
                FATAL("Failed to seek to the next packet in input pcap: %s offset: %" PRIu64,
                        strerror(errno), offset);
            }
            if (fread(pcap_header_buffer, sizeof(*pcap_header_buffer), 4, pcap) != 4) {
                FATAL("Failed to read the pcap packet header.");
            }
            uint32_t pkt_size = pcap_header_buffer[2];
            if (opposite_endianness) {
                pkt_size = bswap_32(pkt_size);
            }
            if (pkt_size > MAX_PACKET_SIZE) {
                WARN("Packet in flow %" PRIu64 " is too big for buffer: %u bytes\n"
                     "       at offset %" PRIu64 " of %s",
                     current_findex, pkt_size, offset, pcapHeader->pcap_path);
                // stop processing current PCAP if too many warnings
                if (++warn_count >= MAX_WARN_PER_PCAP) {
                    // clean current PCAP states
                    while (heap_size(states) != 0) {
                        flow_state_t* state = heap_pop(states);
                    #if LESS_IO_MORE_MEM == 1
                        free(state->packets);
                    #endif // LESS_IO_MORE_MEM == 1
                        free(state);
                    }
                    break;
                }
                continue;
            }
            if (fwrite(pcap_header_buffer, sizeof(*pcap_header_buffer), 4, output) != 4) {
                FATAL("Failed to write the pcap packet header.");
            }
            uint8_t buffer[MAX_PACKET_SIZE];
            if (fread(buffer, sizeof(uint8_t), pkt_size, pcap) != pkt_size) {
                FATAL("Failed to read the pcap packet content.");
            }
            if (fwrite(buffer, sizeof(uint8_t), pkt_size, output) != pkt_size) {
                FATAL("Failed to write the pcap packet content.");
            }
            extracted_pkts++;
        }
        if (heap_size(states) != 0) {
            FATAL("State was not empty at the end of pcap processing.");
        }
        // free pcap header
        free(pcapHeader->pcap_path);
        free(pcapHeader);
        // close pcap file
        fclose(pcap);
    }

    fclose(input);

    return true;
}

int64_t find_findexer_start_index(char* prefix) {
    size_t num_pos = strlen(prefix);
    // create glob pattern
    sprintf(prefix + num_pos, "*");
    // get file list matching glob pattern
    glob_t globbuf;
    if (glob(prefix, 0, NULL, &globbuf)) {
        return -1;
    }
    // find smallest numerical index
    int64_t smallest = -1;
    for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
        char* start = globbuf.gl_pathv[i] + num_pos;
        char* end;
        errno = 0;
        int64_t index = strtoul(start, &end, 10);
        if (errno != 0 || *end != '\0' || index < 0 || end == start) {
            // ignore files not ending with a positive integer
            continue;
        }
        if (smallest == -1 || smallest > index) {
            smallest = index;
        }
    }
    return smallest;
}


int main(int argc, char** argv) {
    // create the list of flows to extract
    if (!(flows = calloc(INITIAL_FLOW_COUNT, sizeof(*flows)))) {
        FATAL("Failed to allocate memory for flow list.");
    }
    // parse the command line arguments
    parse_args(argc, argv);

    // sort the flows indices
    qsort(flows, flow_count, sizeof(*flows), flow_order);

    if (!first_pkt) {
        // pcap can be output on stdout
        if (strcmp("-", output_file_path) == 0) {
            output = stdout;
        } else if (!force && access(output_file_path, F_OK) != -1) {
            FATAL("Output file %s already exists.\n"
                  "      Use -f option to overwrite it.", output_file_path);
        } else if (!(output = fopen(output_file_path, "wb"))) { // open output file
            FATAL("Failed to open output file: %s", output_file_path);
        }
    }

    // init the state list
    states = heap_create(INITIAL_FLOW_COUNT, heap_cmp);

    // process the findexer file(s)
    if (multi_start_index == -1 && multi_end_index == -1 && access(findexer_file_path, F_OK) != -1) {
        process_findexer_file(findexer_file_path, true);
    } else {
        if (multi_start_index == -1) {
            if ((multi_start_index = find_findexer_start_index(findexer_file_path)) == -1) {
                FATAL("Could not find any findexer file prefixed with: %s", findexer_file_path);
            }
        }
        multi_current_index = multi_start_index;
        bool warning = true;
        // process all findexer files
        while (multi_end_index == -1 || (int64_t)multi_current_index <= multi_end_index) {
            // all flows were extracted, do not process next .xer
            if (!first_pkt && flow_count == 0) {
                INFO("All flows were extracted: next XER files will not be processed.");
                break;
            }
            sprintf(multi_file_num_pos, "%" PRIu64, multi_current_index);
            if (process_findexer_file(findexer_file_path, warning)) {
                // as soon as the first file is found, disable warning if we don't have an end index
                warning = multi_end_index != -1;
            } else { // findexer file was not found
                if (multi_end_index == -1) {
                    // if no end index was defined and findexer file was not found => abort
                    break;
                }
            }
            ++multi_current_index;
        }
    }

    // -n: no pcap left
    if (first_pkt) {
        printf("findexer_path: \n");
        printf("pcap_path: \n");
        printf("pcap_index: -1\n");
        printf("timestamp: 0.0\n");
        exit(EXIT_FAILURE);
    }

    // overwrite snaplen in header by the max snap length of all processed pcaps
    if (extracted_pkts >  0 && output != stdout) {
        if (fseeko(output, 16, SEEK_SET) != 0) {
            FATAL("Failed to seek to the start of the output pcap.");
        }
        if (fwrite(&snaplen, sizeof(snaplen), 1, output) != 1) {
            FATAL("Failed to overwrite the snap length in the pcap file header.");
        }
    }

    INFO("Extracted %" PRIu64 " packets.", extracted_pkts);

    // free flow list
    free(flows);
    // destroy states heap
    heap_destroy(states);

    // flush and close files
    if (output != stdout) {
        fclose(output);
    }

    return EXIT_SUCCESS;
}
