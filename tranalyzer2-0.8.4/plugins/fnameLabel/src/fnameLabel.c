/*
 * fnameLabel.c
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

#include "fnameLabel.h"


// plugin variables

fnFlow_t *fnFlows;


// Tranalyzer functions

T2_PLUGIN_INIT("fnameLabel", "0.8.4", 0, 8);


void initialize() {
    if (UNLIKELY(!(fnFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*fnFlows))))) {
        T2_PERR("fnameLabel", "failed to allocate memory for fnFlows");
        exit(-1);
    }
}

binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    bv = bv_append_bv(bv, bv_new_bv("FNL_IDX letter of filename", "fnLabel", 0, 1, bt_uint_8));
    bv = bv_append_bv(bv, bv_new_bv("Hash of filename", "fnHash", 0, 1, bt_uint_64));
    bv = bv_append_bv(bv, bv_new_bv("Filename", "fname", 0, 1, bt_string));
    return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
    const char *name;
    if (capType & LISTFILE) name = caplist_elem->name;
    else if (capType & DIRFILE) name = globFName;
    else name = capName;
    strncpy(fnFlows[flowIndex].capname, name, strlen(name)+1);
}


void onFlowTerminate(unsigned long flowIndex) {
    const char * const filename = fnFlows[flowIndex].capname;
    const size_t len = strlen(filename);
    const uint64_t hash = hashTable_hash(filename, len);
    uint8_t label = 0; // unknown
    const char *temp = strrchr(fnFlows[flowIndex].capname, '/');
    if (!temp) temp = filename;
    if (temp && FNL_IDX < strlen(temp)) {
        // use the 'FNL_IDX' letter of the filename as label
        switch (temp[FNL_IDX]) {
            //case 'z': label = 1; break;
            //case 'n': label = 2; break;
            default: label = temp[FNL_IDX]; break;
        }
    }
    outputBuffer_append(main_output_buffer, (char*)&label, sizeof(uint8_t));
    outputBuffer_append(main_output_buffer, (char*)&hash, sizeof(uint64_t));
    outputBuffer_append(main_output_buffer, filename, len+1);
}


void onApplicationTerminate() {
    free(fnFlows);
}
