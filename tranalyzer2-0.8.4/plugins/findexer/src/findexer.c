/*
 * findexer.c
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

// global includes
#include <stdio.h>
#include <stdbool.h>
#ifndef __APPLE__
#include <byteswap.h>
#else // __APPLE__
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#endif // __APPLE__
#include <unistd.h>

// local includes
#include "findexer.h"
#include "global.h"
#include "main.h"
#include "memdebug.h"

// Global variables

// plugin global variables
static findexerFlow_t* findexerFlows;
static bool enabled = true;

static int64_t currentPcapIndex = -1;
static char pcapPath[PATH_MAX];
static bool skip_current_pcap = false;

static char findexerFileName[PATH_MAX];
static FILE* findexerFile;

// used to keep track of packet offset in pcap file
static uint64_t packetOffset = 0;
static uint64_t lastBytesProcessed = 0;
static uint64_t lastNumPackets = 0;
static uint64_t lastPcapSize = 0;

// keep track of previous flow and pcap header to create linked lists
static uint64_t lastPcapPointerPos = 0;
static uint64_t lastFlowPointerPos = 0;
// also keep track of flow count and pcap count positions
static uint64_t flowCountPos; // position of flow count in current PCAP header
static uint64_t flowCount;    // number of flows in current PCAP
static const uint64_t pcapCountPos = 8;
static uint32_t pcapCount;

// queue of open flows in current PCAP (will be written before switching to next pcap)
TAILQ_HEAD(, findexerFlow_s) openFlows;

#if FINDEXER_SPLIT == 1
static uint64_t fileNameIndex;
static uint64_t file_frag_size;
static char* fileNameNumPos = NULL; // points to the numerical part of the filename
// Num. of terminated flows in current output file. This is different from flowCount as a flow packet
// indices can be split in multiple output files in case it spans accross multiple input PCAPs.
static uint64_t terminated_flow_count = 0;
#endif // FINDEXER_SPLIT

// pcap types
typedef enum {
    PCAP_UNKNOWN, // unknown type of PCAP
    PCAP_SE,      // standard PCAP system endianness
    PCAP_OE,      // standard PCAP opposite endianness (currently not implemented in t2)
    PCAPNG_SE,    // PcapNg system endianness
    PCAPNG_OE,    // PcapNg opposite endianness (currently not implemented in t2)
} PcapType;

// helper functions

/**
 * Get PCAP type. Use already openend file by libpcap to avoid being unable to open file if
 * application is out of file descriptor (often happen with httpSniffer extraction).
 */
PcapType get_pcap_type() {
    #define PCAP_MAGIC    0xa1b2c3d4
    #define PCAPNG_HEADER 0x0a0d0d0a
    #define PCAPNG_MAGIC  0x1a2b3c4d

    // NOTE: this libpcap function does not work on Windows
    FILE *f = pcap_file(captureDescriptor);
    if (!f) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "invalid PCAP file stream");
        return PCAP_UNKNOWN;
    }

    // backup position in file and rewind to first byte
    const off_t current_pos = ftello(f);
    if (fseeko(f, 0, SEEK_SET) != 0) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "failed to seek to start of PCAP");
        return PCAP_UNKNOWN;
    }

    // read first 12 bytes of PCAP file
    uint32_t buffer[3];
    if (fread(buffer, sizeof(buffer[0]), 3, f) != 3) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "failed to read PCAP header");
        fseeko(f, current_pos, SEEK_SET);
        return PCAP_UNKNOWN;
    }

    // seek back to position at the start of this function
    if (fseeko(f, current_pos, SEEK_SET) != 0) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "failed to seek back to original position in PCAP");
        return PCAP_UNKNOWN;
    }

    // check the different types of known PCAPs
    if (buffer[0] == PCAP_MAGIC) {
        return PCAP_SE;
    } else if (buffer[0] == bswap_32(PCAP_MAGIC)) {
        return PCAP_OE;
    } else if (buffer[0] == PCAPNG_HEADER) {
        if (buffer[2] == PCAPNG_MAGIC) {
            return PCAPNG_SE;
        } else if (buffer[2] == bswap_32(PCAPNG_MAGIC)) {
            return PCAPNG_OE;
        }
    }
    return PCAP_UNKNOWN;
}

/**
 * Get current PCAP index
 */
static int64_t get_current_pcap_index() {
    switch (capType & CAPTYPE_REQUIRED) {
        case CAPFILE: // -r
            return 1;
        case LISTFILE: // -R
            return (int64_t)caplist_index;
        case DIRFILE: // -D
            return (int64_t)fileNum;
        default:
            T2_PWRN(FINDEXER_PLUGIN_NAME, "mix of several capture types: capType = 0x%04"B2T_PRIX16, capType);
            T2_PWRN(FINDEXER_PLUGIN_NAME, "plugin got disabled");
            enabled = false; // disable plugin to avoid avalanche of warnings
            return -1;
    }
}

/**
 * Get currently processed PCAP full path. Returns false on error.
 * This function assumes that pcap_path is at least PATH_MAX bytes long.
 */
static bool get_pcap_full_path(char* pcap_path) {
    char *path = NULL;
    switch (capType & CAPTYPE_REQUIRED) {
        case CAPFILE: // -r
            path = capName;
            break;
        case LISTFILE: // -R
            path = caplist_elem->name;
            break;
        case DIRFILE: // -D
            path = globFName;
            break;
        default:
            T2_PWRN(FINDEXER_PLUGIN_NAME, "mix of several capture types: capType = 0x%04"B2T_PRIX16, capType);
            return false;
    }
    // useless memset but otherwise valgrind complains
    memset(pcap_path, 0, PATH_MAX);
    // dereference symlinks and get absolute path of PCAP
    if (realpath(path, pcap_path) != pcap_path) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to find real path of PCAP file.");
        return false;
    }
    return true;
}

/**
 * Write the findexer header to file.
 */
static bool writeFindexerHeader(FILE* f) {
    const uint64_t magic = FINDEXER_MAGIC;
    if (fwrite(&magic, sizeof(magic), 1, f) != 1) {
        return false;
    }
    pcapCount = 0;
    if (fwrite(&pcapCount, sizeof(pcapCount), 1, f) != 1) {
        return false;
    }
    uint64_t firstPcap = 0;
    if (fwrite(&firstPcap, sizeof(firstPcap), 1, f) != 1) {
        return false;
    }
    lastPcapPointerPos = sizeof(magic) + sizeof(pcapCount);
    return true;
}

/**
 * Write a findexer PCAP header to file.
 */
static bool writePcapHeader(FILE* f, const char * const pcapPath) {
    // keep track of header start position
    const uint64_t pos = (uint64_t)ftello(f);
    // write next pcap pointer and keep track of it
    const uint64_t zero64 = 0;
    if (fwrite(&zero64, sizeof(zero64), 1, f) != 1) {
        return false;
    }
    // write flow count and keep track of it
    flowCount = 0;
    flowCountPos = (uint64_t)ftello(f);
    if (fwrite(&flowCount, sizeof(flowCount), 1, f) != 1) {
        return false;
    }
    // write first flow pointer and keep track of it
    lastFlowPointerPos = (uint64_t)ftello(f);
    if (fwrite(&zero64, sizeof(zero64), 1, f) != 1) {
        return false;
    }
    // write the length of the pcapName as a unit16_t followed by the pcap name (similar to pascal strings)
    const size_t len = strlen(pcapPath);
    if (len > USHRT_MAX) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "PCAP path is longer than 2^16 bytes.");
        return false;
    }
    const uint16_t slen = (uint16_t)len;
    if (fwrite(&slen, sizeof(slen), 1, f) != 1) {
        return false;
    }
    if (fwrite(pcapPath, sizeof(char), len, f) != len) {
        return false;
    }
    // link previous PCAP header to this one
    if (fseeko(f, lastPcapPointerPos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&pos, sizeof(pos), 1, f) != 1) {
        return false;
    }
    lastPcapPointerPos = pos;
    // increment PCAP count in findexer header
    pcapCount++;
    if (fseeko(f, pcapCountPos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&pcapCount, sizeof(pcapCount), 1, f) != 1) {
        return false;
    }
    // go back to end of file
    if (fseeko(f, 0, SEEK_END) != 0) {
        return false;
    }
    return true;
}

/**
 * Write flow header with all its packets offsets.
 */
static bool writeFlowHeader(FILE* f, findexerFlow_t* const flow) {
    if (skip_current_pcap) {
        return true;
    }
    // keep track of header start position
    const uint64_t pos = (uint64_t)ftello(f);
    // write NULL next flow header pointer
    const uint64_t nextFlowHeader = 0;
    if (fwrite(&nextFlowHeader, sizeof(nextFlowHeader), 1, f) != 1) {
        return false;
    }
    // write flow index
    const uint64_t findex = flows[flow->flowIndex].findex;
    if (fwrite(&findex, sizeof(findex), 1, f) != 1) {
        return false;
    }
    // set direction flag: we do it as late as possible in case a plugin changes
    // this value after the flow creation.
    uint8_t flags = flow->flags;
    if (flows[flow->flowIndex].status & L3FLOWINVERT) {
        flags |= TO_BITMASK(REVERSE_FLOW);
    }
    // write flags
    if (fwrite(&flags, sizeof(flags), 1, f) != 1) {
        return false;
    }
    // write the number of packets in this flow
    if (fwrite(&flow->packetCount, sizeof(flow->packetCount), 1, f) != 1) {
        return false;
    }
    if (flow->packetCount != 0) {
        // write the packet offsets
        if (fwrite(flow->packetOffsets, sizeof(*flow->packetOffsets), flow->packetCount, f) != flow->packetCount) {
            return false;
        }
    }
    // link previous flow header to this one
    if (fseeko(f, lastFlowPointerPos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&pos, sizeof(pos), 1, f) != 1) {
        return false;
    }
    lastFlowPointerPos = pos;
    // increment flow count in PCAP header
    ++flowCount;
    if (fseeko(f, flowCountPos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&flowCount, sizeof(flowCount), 1, f) != 1) {
        return false;
    }
    // go back to end of file
    if (fseeko(f, 0, SEEK_END) != 0) {
        return false;
    }

    return true;
}

/**
 * Initialize default values for findexerFlow_t structure
 */
static bool initFlowHeader(unsigned long flowIndex) {
    findexerFlow_t* const flow = &findexerFlows[flowIndex];
    memset(flow, 0, sizeof(*flow)); // set everything to 0
    // store findex
    flow->flowIndex = flowIndex;
    // initialize list of packet offsets
    if (!(flow->packetOffsets = malloc(FINDEXER_INITIAL_PACKET_ALLOC * sizeof(*flow->packetOffsets)))) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to allocate memory for packet offsets.");
        return false;
    }
    flow->packetAllocated = FINDEXER_INITIAL_PACKET_ALLOC;
    // flag flow as first appearing in current .xer, will be removed on first write
    flow->flags |= TO_BITMASK(FIRST_XER);
    // append to open flows queue
    TAILQ_INSERT_TAIL(&openFlows, flow, entries);

    return true;
}

/**
 * Write all the open flows in queue to the findexer file.
 */
static bool writeOpenFlows(FILE* f) {
    // for each flow in queue
    findexerFlow_t* flow;
    TAILQ_FOREACH(flow, &openFlows, entries) {
        // write flow header
        if (!writeFlowHeader(f, flow)) {
            return false;
        }
        // update flags (remove FIRST_XER bit)
        flow->flags &= ~TO_BITMASK(FIRST_XER);
        // reset the number of stored packet offsets
        flow->packetCount = 0;
    }
    return true;
}

/**
 * Update packetOffset to the end of current packet.
 */
static void update_offset() {
    if (lastNumPackets != numPackets) {
        const uint64_t packetCount = numPackets - lastNumPackets;
        const uint64_t byteCount = bytesProcessed - lastBytesProcessed;
        packetOffset += byteCount + 16 * packetCount;
        lastNumPackets = numPackets;
        lastBytesProcessed = bytesProcessed;
    }
}

/**
 * Update packetOffset to the end of current packet.
 * Write current pcap flow index and pcap header and switch to next pcap if the pcap has
 * changed.
 */
static void update_offset_and_pcap(uint64_t pcap_pkt_len) {
    // keep track of number of processed packet before update
    const uint64_t tmpNumPackets = lastNumPackets;
    // update packet offset
    if (!skip_current_pcap) {
        update_offset();
    }

    // don't switch pcap if the pcap hasn't changed
    const int64_t newPcapIndex = get_current_pcap_index();
    if (newPcapIndex == currentPcapIndex) {
        return;
    }
    // if this isn't the first pcap, write all previous packets offsets and pcap header
    if (currentPcapIndex != -1 && !skip_current_pcap) {
        if (!writeOpenFlows(findexerFile)) {
            T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write previous PCAP open flows. Disk full?");
            exit(-1);
        }
    }

    // update the packet offset (to the end of current packet)
    if (lastNumPackets == tmpNumPackets + 1 || skip_current_pcap) {
        // if only one packet has been processed since last PCAP switch,
        // we can safely assume that it start just after PCAP header.
        // if the last PCAP was in an unsupported format (e.g. PcapNg), we
        // also cannot rely on bytes processed and have to assume that this
        // is the first packet of a newly supported PCAP.
        packetOffset = 24 + pcap_pkt_len; // 24 = size of pcap file header
        lastNumPackets = numPackets;
        lastBytesProcessed = bytesProcessed;
    } else {
        // otherwise, we have to assume that last PCAP was not cut and the sum of its
        // processed packets bytes + headers sizes match the size of the file
        packetOffset = 24 + packetOffset - lastPcapSize; // 24 = size of pcap file header
    }
    // WARNING: the packetOffset will be wrong if the last PCAP was cut in the middle of a packet
    // and the current PCAP first packet did not call claimLayer2Information. This means that all
    // computed indexes for current PCAP will be wrong.

    currentPcapIndex = newPcapIndex;

    // get current PCAP path
    if (!get_pcap_full_path(pcapPath)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to get current PCAP path.");
        terminate();
    }

    // check if this is a PCAP format supported by findexer
    PcapType type = get_pcap_type();
    if (type != PCAP_SE && type != PCAP_OE) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "plugin disabled for current PCAP: PcapNg format not supported");
        skip_current_pcap = true;
        return;
    }
    skip_current_pcap = false;

    // write a new PCAP header in findexer file
    if (!writePcapHeader(findexerFile, pcapPath)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write PCAP header. Disk full?");
        exit(-1);
    }
    // update the size of the newly opened pcap
    struct stat sb;
    if (stat(pcapPath, &sb) == -1) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to stat PCAP file.");
        terminate();
    }
    lastPcapSize = sb.st_size;
}

#if FINDEXER_SPLIT == 1
/**
 * If current output is bigger than the -W size, swith to next output, write findexer header and
 * rewrite current PCAP header.
 */
static void switch_output_if_needed() {
    off_t size; // size of current output file (in #bytes or #flows)
    if (capType & WFINDEX) {
        size = terminated_flow_count;
    } else {
        size = ftello(findexerFile);
        if (size < 0) {
            T2_PERR(FINDEXER_PLUGIN_NAME, "failed to get file size");
            terminate();
        }
    }
    // do not do anything if file size/flow limit is not reached
    if ((uint64_t)size < file_frag_size) {
        return;
    }
    // write open flows, necessary so each open flow appear at least once in each XER file
    // to be able to back-track the start of a flow.
    if (!writeOpenFlows(findexerFile)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write previous PCAP open flows. Disk full?");
        exit(-1);
    }
    // flush and close current findexer file
    fclose(findexerFile);
    // increase findexer file count and update number in findexerFileName
    ++fileNameIndex;
    sprintf(fileNameNumPos, "%" PRIu64, fileNameIndex);
    // open new findexer output file
    if (!(findexerFile = fopen(findexerFileName, "wb"))) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to open findexer file");
        terminate();
    }
    // write new findexer header
    if (!writeFindexerHeader(findexerFile)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write file header. Disk full?");
        exit(-1);
    }
    // re-write header of currently opened PCAP
    if (!writePcapHeader(findexerFile, pcapPath)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write PCAP header. Disk full?");
        exit(-1);
    }
    terminated_flow_count = 0;
}
#endif // FINDEXER_SPLIT


// Tranalyzer functions

T2_PLUGIN_INIT(FINDEXER_PLUGIN_NAME, "0.8.4", 0, 8);


void initialize() {
    // disable plugin on live capture or if BPF is used
    if ((capType & IFACE) || bpfCommand) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "plugin disabled because of live capture or BPF");
        enabled = false;
        return;
    }

    // allocate struct for all flows and initialise to 0
    if (!(findexerFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*findexerFlows)))) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to allocate memory for findexerFlows");
        exit(-1);
    }

    // initialize linked list of open flows
    TAILQ_INIT(&openFlows);

    // check max filename length (including 5 digits for split output mode)
    const size_t len = baseFileName_len + sizeof(FINDEXER_SUFFIX) + 6;
    if (UNLIKELY(len >= PATH_MAX)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "filename too long");
        exit(-1);
    }
    // create the finde.xer full path
    strncpy(findexerFileName, baseFileName, baseFileName_len+1);
    strcat(findexerFileName, FINDEXER_SUFFIX);

    // if necessary, append count at the end of the file name
#if FINDEXER_SPLIT == 1
    if (capType & OFILELN) {
        fileNameIndex = oFileNumB;
        file_frag_size = (uint64_t)oFragFsz;
        fileNameNumPos = findexerFileName + strlen(findexerFileName);
        // append count
        sprintf(fileNameNumPos, "%" PRIu64, fileNameIndex);
    }
#endif // FINDEXER_SPLIT

    // open findexer output file
    if (!(findexerFile = fopen(findexerFileName, "wb"))) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to open findexer file");
        free(findexerFlows);
        exit(-1);
    }

    // write the findexer header
    if (!writeFindexerHeader(findexerFile)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write file header. Disk full?");
        fclose(findexerFile);
        free(findexerFlows);
        exit(-1);
    }
}

void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    // update current packet offset (end of packet)
    // create findexer pcap header if first packet of pcap
    const uint64_t pcap_pkt_len = packet->pcapHeader->caplen + 16;
    update_offset_and_pcap(pcap_pkt_len);
    // initialize tranalyzer flow structure
    initFlowHeader(flowIndex);
}

void process_packet(findexerFlow_t* flow, uint64_t offset) {
    // check if packet was already parsed with the same flow index (SCTP with SCTP_STATFINDEX = 1)
    if (flow->packetCount > 0 && flow->packetOffsets[flow->packetCount - 1] == offset) {
        return;
    }

    // realloc memory if not enough space to store current packet offset
    if (flow->packetCount >= flow->packetAllocated) {
        flow->packetAllocated *= 2;
        uint64_t* tmp = realloc(flow->packetOffsets, flow->packetAllocated * sizeof(*flow->packetOffsets));
        if (!tmp) {
            T2_PERR(FINDEXER_PLUGIN_NAME, "failed to re-allocate memory for packet offsets");
            free(flow->packetOffsets);
            terminate();
        }
        flow->packetOffsets = tmp;
    }
    // store current packet offset
    flow->packetOffsets[flow->packetCount++] = offset;
}

/*
 * Do not delete this function. It is necessary in case there is no packet processed.
 * IPv4 PCAP in IPv6 mode for instance.
 */
void claimLayer2Information(packet_t* packet, unsigned long flowIndex) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    // update current packet offset (end of packet)
    // check if pcap has changed since last packet
    const uint64_t pcap_pkt_len = packet->pcapHeader->caplen + 16;
    update_offset_and_pcap(pcap_pkt_len);

#if ETH_ACTIVATE > 0
    if (skip_current_pcap || flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        return;
    }

    findexerFlow_t* flow = &findexerFlows[flowIndex];
    const uint64_t offset = packetOffset - packet->pcapHeader->caplen - 16;
    process_packet(flow, offset);
#endif // ETH_ACTIVATE > 0
}

void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    // don't do anything in live capture mode or if parsing a PcapNg
    if (!enabled || skip_current_pcap) {
        return;
    }
    findexerFlow_t* flow = &findexerFlows[flowIndex];
    const uint64_t offset = packetOffset - packet->pcapHeader->caplen - 16;
    process_packet(flow, offset);
}


void onFlowTerminate(unsigned long flowIndex) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    findexerFlow_t* flow = &findexerFlows[flowIndex];
    // output only flows containing at least one packet in current PCAP
#if FINDEXER_SPLIT == 1
    // switch to next findexer file if current one is full
    if (capType & OFILELN) {
        switch_output_if_needed();
        ++terminated_flow_count;
    }
#endif // FINDEXER_SPLIT
    // flow is terminated: this is the last .xer in which it will appear
    flow->flags |= TO_BITMASK(LAST_XER);
    // write the packet offsets of this flow
    if (!writeFlowHeader(findexerFile, flow)) {
        T2_PERR(FINDEXER_PLUGIN_NAME, "failed to write flow header. Disk full?");
        exit(-1);
    }
    // free packet offsets list
    free(flow->packetOffsets);
    // remove flow from open flows queue
    TAILQ_REMOVE(&openFlows, flow, entries);
}


void onApplicationTerminate() {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    if (!TAILQ_EMPTY(&openFlows)) {
        T2_PWRN(FINDEXER_PLUGIN_NAME, "open flows not empty on application terminate.");
    }
    if (findexerFlows) {
        free(findexerFlows);
        findexerFlows = NULL;
    }
    // flush and close findexer file
    if (findexerFile) {
        fclose(findexerFile);
    }
}
