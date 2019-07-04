/*
 * macRecorder.c
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

#include "macRecorder.h"
#if MR_MACLBL > 0
#include "macLbl.h"
#endif // MR_MACLBL > 0
#include "global.h"


// Static variables

static macList_t *macList;      // the big struct with all list entrys
static macList_t *macListFree;  // pointer to the first free entry
macRecorder_t *macArray;        // the big struct for all flows


#if MR_MAC_FMT != 1
#define MR_READ_U48(p) (be64toh(*(uint64_t*)(p)) >> 16)
#endif // MR_MAC_FMT != 1


// Function prototypes

#if MR_MANUF > 0
static char mr_manuf[0xffffff+1][MR_MANUF_MAXL+1];
#define MR_READ_U24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2] << 0))
static void mac_load_manuf();
#endif // MR_MANUF > 0

#if MR_MACLBL > 0
static maclbltable_t *maclbltable;
#endif // MR_MACLBL > 0


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("macRecorder", "0.8.4", 0, 8);


void initialize() {
    macArray = calloc(mainHashMap->hashChainTableSize, sizeof(*macArray));
    macList = calloc(2 * mainHashMap->hashChainTableSize, sizeof(*macList));

    if (UNLIKELY(!macArray || !macList)) {
        T2_PERR("macRecorder", "failed to allocate memory");
        exit(-1);
    }

    // connect free entries with each other
    for (unsigned int i = 0; i < 2 * mainHashMap->hashChainTableSize - 1; i++) {
        macList[i].next = &(macList[i+1]);
    }

    // set freeList pointer on first entry
    macListFree = &(macList[0]);

#if MR_MANUF > 0
    mac_load_manuf();

    if (sPktFile) {
        fputs("srcManuf\tdstManuf\t", sPktFile);
    }
#endif // MR_MANUF > 0

#if MR_MACLBL > 0
    if (UNLIKELY(!(maclbltable = maclbl_init(pluginFolder, MACLBLFILE)))) {
        exit(1);
    }
#endif // MR_MACLBL > 0
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
#if MR_NPAIRS == 1
    bv = bv_append_bv(bv, bv_new_bv("Number of distinct Source/Destination MAC addresses pairs", "macPairs", 0, 1, bt_uint_32));
#endif // MR_NPAIRS == 1
    bv = bv_append_bv(bv, bv_new_bv("Source MAC address, destination MAC address, number of packets of MAC address combination", "srcMac_dstMac_numP", 1, 3, MR_MAC_TYPE, MR_MAC_TYPE, bt_uint_64));
#if MR_MANUF > 0
    bv = bv_append_bv(bv, bv_new_bv("Source MAC manufacturer, destination MAC manufacturer", "srcManuf_dstManuf", 1, 2, MR_MANUF_TYPE, MR_MANUF_TYPE));
#endif // MR_MANUF > 0
#if MR_MACLBL > 0
    bv = bv_append_bv(bv, bv_new_bv("Source MAC Label, destination MAC Label", "srcLbl_dstLbl", 1, 2, bt_string_class, bt_string_class));
#endif // MR_MACLBL > 0
    return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
    // first put all attached macList entries back into the free list
    macList_t *temp, *list = macArray[flowIndex].macList;
    while (list) {
        temp = list->next;
        list->next = macListFree;
        macListFree = list;
        list = temp;
    }

    // reset array entry
    memset(&(macArray[flowIndex]), '\0', sizeof(macRecorder_t));
}


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
    if (flows[flowIndex].status & L2_NO_ETH) return;

    const ethernetHeader_t * const l2HdrP = (ethernetHeader_t*)packet->layer2Header;

#if MR_MANUF > 0
    if (sPktFile) {
        if (!l2HdrP) {
            fputs("\t\t", sPktFile);
        } else {
            const uint_fast32_t oui_src = MR_READ_U24(l2HdrP->ethDS.ether_shost);
            const uint_fast32_t oui_dst = MR_READ_U24(l2HdrP->ethDS.ether_dhost);
            fprintf(sPktFile, "%s\t%s\t", mr_manuf[oui_src], mr_manuf[oui_dst]);
        }
    }
#endif // MR_MANUF > 0

    macRecorder_t * const macListP = &macArray[flowIndex];
    macList_t *list = macListP->macList;
    macList_t *temp = list;

    if (macListP->num_entries >= MR_MAX_MAC) {
        // TODO: change status here!
        return;
    }

    while (list) {
        if (memcmp(list->ethHdr.ether_dhost, l2HdrP->ethDS.ether_dhost, 12) == 0) {
            list->numPkts++;
            return;
        }
        temp = list;
        list = list->next;
    }

    // the macList entry wasn't found
    // take a list entry out of the free list
    if (macListP->macList == NULL) {
        macListP->macList = macListFree; // point to first entry in free list
        temp = macListP->macList;        // move temp pointer to entry
    } else {
        temp->next = macListFree; // point to first entry in free list
        temp = temp->next;        // move temp pointer to entry
    }

    macListFree = macListFree->next; // move free list pointer
    temp->next = NULL;               // disconnect entry from free list

    // fill with the right values
    memcpy(&(temp->ethHdr), l2HdrP, sizeof(ethernetHeader_t));
    temp->numPkts = 1;

    // increment the number of mac combos
    macArray[flowIndex].num_entries++;
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    const macRecorder_t * const macListP = &macArray[flowIndex];

#if MR_NPAIRS == 1
    outputBuffer_append(main_output_buffer, (char*) &macListP->num_entries, sizeof(uint32_t));
#endif // MR_NPAIRS == 1

    // write out number of entries, cause output is repeatable
    outputBuffer_append(main_output_buffer, (char*) &macListP->num_entries, sizeof(uint32_t));

#if MR_MAC_FMT != 1
    uint64_t mac;
#endif // MR_MAC_FMT != 1

    // point to actual entry
    macList_t *list = macListP->macList;
    while (list) {
        // print source and dest mac
#if MR_MAC_FMT == 1
        outputBuffer_append(main_output_buffer, (char*) list->ethHdr.ether_shost, l_bt_mac_addr);
        outputBuffer_append(main_output_buffer, (char*) list->ethHdr.ether_dhost, l_bt_mac_addr);
#else // MR_MAC_FMT != 1
        mac = MR_READ_U48(&list->ethHdr.ether_shost);
        outputBuffer_append(main_output_buffer, (char*) &mac, sizeof(uint64_t));
        mac = MR_READ_U48(&list->ethHdr.ether_dhost);
        outputBuffer_append(main_output_buffer, (char*) &mac, sizeof(uint64_t));
#endif // MR_MAC_FMT != 1

        // print number of packets with this src/dst combo
        outputBuffer_append(main_output_buffer, (char*) &list->numPkts, sizeof(uint64_t));

        // goto next entry
        list = list->next;
    }

#if MR_MANUF > 0
    // Manufacturers
    uint_fast32_t oui;
    list = macListP->macList;
    outputBuffer_append(main_output_buffer, (char*) &macListP->num_entries, sizeof(uint32_t));
    while (list) {
        oui = MR_READ_U24(list->ethHdr.ether_shost);
        outputBuffer_append(main_output_buffer, mr_manuf[oui], strlen(mr_manuf[oui])+1);
        oui = MR_READ_U24(list->ethHdr.ether_dhost);
        outputBuffer_append(main_output_buffer, mr_manuf[oui], strlen(mr_manuf[oui])+1);
        list = list->next;
    }
#endif // MR_MANUF > 0

#if MR_MACLBL > 0
    // mac Label
    int32_t i;
    macm_t *macm;
    list = macListP->macList;
    maclbl_t *maclP = maclbltable->maclbls;
    outputBuffer_append(main_output_buffer, (char*) &macListP->num_entries, sizeof(uint32_t));
    while (list) {
        macm = (macm_t*)&list->ethHdr.ether_shost;
        i = maclbl_test(maclbltable, MACM_UINT64(macm));
        outputBuffer_append(main_output_buffer, maclP[i].who, strlen(maclP[i].who)+1);
        macm = (macm_t*)&list->ethHdr.ether_dhost;
        i = maclbl_test(maclbltable, MACM_UINT64(macm));
        outputBuffer_append(main_output_buffer, maclP[i].who, strlen(maclP[i].who)+1);
        list = list->next;
    }
#endif // MR_MACLBL > 0
}
#endif // BLOCK_BUF == 0


void onApplicationTerminate() {
    free(macArray);
    free(macList);
}


#if MR_MANUF > 0
static void mac_load_manuf() {
    FILE *file = t2_open_file(pluginFolder, MR_MANUF_FILE, "r");
    if (UNLIKELY(!file)) exit(-2);

    uint32_t oui;
    char smanuf[32];
    char lmanuf[128];

    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, file) != -1) {
        const int n = sscanf(line, "0x%6x\t%32[^\n\t]\t%128[^\n]", &oui, smanuf, lmanuf);
        if (n < 2 || n > 3) {
            T2_PERR("macRecorder", "failed to parse line '%s': expected oui <tab> name <tab> descr", line);
            continue;
        }
#if MR_MANUF == 1
        strncpy(mr_manuf[oui], smanuf, strlen(smanuf)+1);
#elif MR_MANUF == 2
        if (lmanuf[0] != '\0') strncpy(mr_manuf[oui], lmanuf, strlen(lmanuf)+1);
        // If long name does not exist, use short name
        else strncpy(mr_manuf[oui], smanuf, strlen(smanuf)+1);
#endif // MR_MANUF == 2
    }

    free(line);
    fclose(file);
}
#endif // MR_MANUF > 0
