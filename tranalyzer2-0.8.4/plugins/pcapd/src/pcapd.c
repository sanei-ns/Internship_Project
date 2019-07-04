/*
 * pcapd.c
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

#include "pcapd.h"
#include <ctype.h> // for isspace

#if PD_MODE_OUT == 1
#include "uthash.h"


#define HASH_FIND_UINT64(head, key, out) \
    HASH_FIND(hh, head, key, sizeof(uint64_t), out)
#define HASH_ADD_UINT64(head, key, add) \
    HASH_ADD(hh, head, key, sizeof(uint64_t), add)


typedef struct {
    uint64_t key; // flowIndex
    pcap_dumper_t *val;
    UT_hash_handle hh;
} pd_lru_item_t;


#define PD_LRU_ITEM_FREE(item) \
    pcap_dump_close(item->val); \
    item->val = NULL; \
    free(item);


static pd_lru_item_t *cache;
#endif // PD_MODE_OUT == 1


// Static variables

static pcap_dumper_t *pd;
static pcap_t *fdPcap;
static uint64_t *findexP;
static uint64_t pd_npkts;
static uint32_t index_cnt;
static char filename[MAX_FILENAME_LEN+1];

#if PD_SPLIT == 1 || PD_MODE_OUT == 1
// -W option
static char *oFileNumP;
#if PD_MODE_OUT == 0
static uint64_t oFileNum, oFileLn;
#endif
#endif // PD_SPLIT == 1 || PD_MODE_OUT == 1


// Function prototypes

static inline void pcapd_load_input_file(const char *filename);
static inline void claimInfo(packet_t* packet, unsigned long flowIndex);


// Tranalyzer plugin functions

T2_PLUGIN_INIT("pcapd", "0.8.4", 0, 8);


void initialize() {
#if PD_MODE_OUT == 0 && PD_SPLIT == 1
    if (capType & OFILELN) {
        oFileLn = (uint64_t)oFragFsz;
#endif // PD_MODE_OUT == 0 && PD_SPLIT == 1
#if PD_MODE_OUT == 1 || PD_SPLIT == 1
        oFileNumP = filename + strlen(filename);
#endif // PD_MODE_OUT == 1 || PD_SPLIT == 1
#if PD_MODE_OUT == 0 && PD_SPLIT == 1
        oFileNum = oFileNumB;
        sprintf(oFileNumP, "%"PRIu64, oFileNum);
    }
#endif // PD_MODE_OUT == 0 && PD_SPLIT == 1

    if (esomFileName) pcapd_load_input_file(esomFileName);
    else index_cnt = 1;

    const char * const temp = (esomFileName) ? esomFileName : baseFileName;
    const size_t len = strlen(temp);
    if (UNLIKELY(len + sizeof(PD_SUFFIX) >= MAX_FILENAME_LEN)) {
        T2_PERR("pcapd", "Filename too long");
        exit(1);
    }

    strncpy(filename, temp, len+1);
    strcat(filename, PD_SUFFIX);

    fdPcap = pcap_open_dead(DLT_EN10MB, 65535);

#if PD_MODE_OUT == 0
    if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
        T2_PERR("pcapd", "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
        exit(1);
    }
#endif
}


static inline void pcapd_load_input_file(const char *filename) {
    FILE *file;
    if (UNLIKELY(!(file = fopen(filename, "r")))) {
        T2_PERR("pcapd", "Failed to open file '%s' for reading: %s", filename, strerror(errno));
        exit(1);
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        if (line[0] == '%' || line[0] == '#' || isspace(line[0])) continue;
        else index_cnt++;
    }

    if (UNLIKELY(index_cnt == 0)) {
        T2_PERR("pcapd", "No usable information in file '%s'", filename);
        free(line);
        exit(1);
    }

    findexP = malloc(sizeof(*findexP) * index_cnt);
    rewind(file);

    uint32_t i = 0;
    while ((read = getline(&line, &len, file)) != -1 && i < index_cnt) {
        if (line[0] == '%' || line[0] == '#' || isspace(line[0])) continue;
#if PD_FORMAT == 0
        sscanf(line, "%"SCNu64, &findexP[i++]); // user index file
#else // PD_FORMAT == 1
        sscanf(line, "%*1c\t%"SCNu64"\t%*c", &findexP[i++]); // read from any flow file
#endif // PD_FORMAT == 1
    }

    fclose(file);
    free(line);

    T2_PINF("pcapd", "%"PRIu32" flow indices", index_cnt);
}


#if PD_MODE_OUT == 1
static inline pcap_dumper_t *pdOpenDump(uint64_t flowIndex) {
    flow_t *flowP = &flows[flowIndex];

    pd_lru_item_t *item;
    HASH_FIND_UINT64(cache, &flowIndex, item);
    if (item) { // file already open
        HASH_DEL(cache, item);
        HASH_ADD_UINT64(cache, key, item);
        return item->val;
    }

    // open the file
    sprintf(oFileNumP, "%"PRIu64, flowP->findex);
    if (UNLIKELY(!(pd = pcap_dump_open_append(fdPcap, filename)))) {
        if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
            T2_PERR("pcapd", "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
            exit(1);
        }
    }

    item = malloc(sizeof(*item));
    item->key = flowIndex;
    item->val = pd;
    HASH_ADD_UINT64(cache, key, item);

    if (HASH_COUNT(cache) > PD_MAX_FD) {
        pd_lru_item_t *tmp_item;
        // close least recently used file
        HASH_ITER(hh, cache, item, tmp_item) {
            HASH_DEL(cache, item);
            PD_LRU_ITEM_FREE(item);
            break;
        }
    }

    return pd;
}
#endif // PD_MODE_OUT == 1


void claimLayer2Information(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


static inline void claimInfo(packet_t* packet, unsigned long flowIndex
#if PD_MODE_IN == 1
        __attribute__((unused))
#endif
        ) {

#if PD_MODE_OUT == 1
    pd = pdOpenDump(flowIndex);
#endif

#if PD_MODE_IN == 0
    flow_t *flowP = &flows[flowIndex];

    unsigned int i;
    for (i = 0; i < index_cnt; i++) {
        if (esomFileName) {
           if (flowP->findex == findexP[i]) {
#if PD_EQ == 0
               return;
#else // PD_EQ == 1
               break;
#endif // PD_EQ == 1
           }
#if PD_EQ == 0
        } else if ((flowP->status & FL_ALARM) == 0) {
            return;
#else // PD_EQ == 1
        } else if ((flowP->status & FL_ALARM) != 0) {
            break;
#endif // PD_EQ == 1
        }
    }

#if PD_EQ == 1
    if (i == index_cnt) return;
#endif

#endif // PD_MODE_IN == 0

    pd_npkts++;
    pcap_dump((u_char*)pd, packet->pcapHeader, packet->raw_packet);

#if PD_MODE_OUT == 0 && PD_SPLIT == 1
    if (capType & OFILELN) {
        const uint64_t offset = pcap_dump_ftell(pd);
        if (offset >= oFileLn) {
            pcap_dump_close(pd);
            oFileNum++;
            sprintf(oFileNumP, "%"PRIu64, oFileNum);
            if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
                T2_PERR("pcapd", "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
                exit(1);
            }
        }
    }
#endif // PD_MODE_OUT == 0 && PD_SPLIT == 1
}


#if PD_MODE_OUT == 1
void onFlowTerminate(unsigned long flowIndex) {
    pd_lru_item_t *item;
    HASH_FIND_UINT64(cache, &flowIndex, item);
    if (item) {
        HASH_DEL(cache, item);
        PD_LRU_ITEM_FREE(item);
    }
}
#endif // PD_MODE_OUT == 1


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "pcapd", "number of packets extracted", pd_npkts, numPackets);
}


void onApplicationTerminate() {
    // TODO delete file if empty
#if PD_MODE_OUT == 0
    if (LIKELY(pd != NULL)) pcap_dump_close(pd);
#endif
}
