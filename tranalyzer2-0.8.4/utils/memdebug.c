/*
 * memdebug.c
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

// WARNING: DO NOT include "memdebug.h" as it replaces the malloc, free, ...
//          functions which are needed here.

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "uthash.h"

#define FILE_MAX_LEN  64 // practical version of FILENAME_MAX to avoid wasting memory

#define ERROR(format, args...) \
        fprintf(stderr, "\x1b[1;31m[ERR] \x1b[0;31m%s:%u: " format "\x1b[0m\n", file, line, ##args)
#define WARN(format, args...) \
        fprintf(stderr, "\x1b[1;33m[WRN] \x1b[0;33m%s:%u: " format "\x1b[0m\n", file, line, ##args)

static const uint64_t COOKIE = 0x5f45494b4f4f435f; // _COOKIE_

typedef struct {
    void* address; // hashmap key
    size_t size;
    unsigned int line;
    char file[FILE_MAX_LEN];
    UT_hash_handle hh;  // makes this structure hashable
} memdebug_block;

// static variables

static memdebug_block* blocks = NULL;
static char last_file[FILE_MAX_LEN] = {};
static unsigned int last_line = 0;

// memory management functions

void* memdebug_malloc(size_t size, const char* file, unsigned int line) {
    if (size == 0) {
        WARN("trying to allocated 0 byte of memory.");
        return NULL;
    }
    // allocate memory
    void* block = malloc(size + 2 * sizeof(COOKIE));
    if (!block) {
        ERROR("not enough memory left to allocated main block.");
        return NULL;
    }
    // check for address uniqueness
    memdebug_block* memblock;
    HASH_FIND_PTR(blocks, &block, memblock);
    if (memblock) {
        ERROR("broken malloc returned an already allocated block.");
        free(block);
        return NULL;
    }
    // allocated memory for memory block structure
    if (!(memblock = malloc(sizeof(*memblock)))) {
        ERROR("not enough memory left to allocated memdebug_block struct.");
        free(block);
        return NULL;
    }

    // initialize fields of memdebug_block structure
    memblock->address = block;
    memblock->size = size;
    memblock->line = line;
    strncpy(memblock->file, file, FILE_MAX_LEN - 1);
    memblock->file[FILE_MAX_LEN - 1] = '\0';

    // set cookie values at start and end of memory block
    memcpy(block, &COOKIE, sizeof(COOKIE));
    memcpy(block + size + sizeof(COOKIE), &COOKIE, sizeof(COOKIE));

    // add memblock to hashmap
    HASH_ADD_PTR(blocks, address, memblock);

    return block + sizeof(COOKIE);
}

void memdebug_free(void* ptr, const char* file, unsigned int line) {
    if (!ptr) {
        return; // free(NULL) is valid but does nothing
    }

    // find allocated block
    ptr -= sizeof(COOKIE);
    memdebug_block* memblock;
    HASH_FIND_PTR(blocks, &ptr, memblock);
    if (!memblock) {
        WARN("trying to free a non-allocated memory block. False positive if the\n"
              "       memory was allocated from an external function but freed manually.");
        free(ptr + sizeof(COOKIE));
        return;
    }

    // verify that cookies were not overwritten
    if (memcmp(ptr, &COOKIE, sizeof(COOKIE)) != 0) {
        ERROR("start of memory block allocated at %s:%u was overwritten before free.",
                memblock->file, memblock->line);
    }
    if (memcmp(ptr + memblock->size + sizeof(COOKIE), &COOKIE, sizeof(COOKIE)) != 0) {
        ERROR("end of memory block allocated at %s:%u was overwritten before free.",
                memblock->file, memblock->line);
    }

    // free memory and remove block from hashmap
    free(ptr);
    HASH_DEL(blocks, memblock);
    free(memblock);
}

void* memdebug_calloc(size_t nmemb, size_t size, const char* file, unsigned int line) {
    void* block = memdebug_malloc(nmemb * size, file, line);
    if (!block) {
        return NULL;
    }
    memset(block, 0, nmemb * size); // memset block to 0 (not including cookies)
    return block;
}

void* memdebug_realloc(void* ptr, size_t size, const char* file, unsigned int line) {
    if (!ptr) {
        if (size == 0) {
            WARN("realloc with ptr = NULL and size = 0.");
            return NULL;
        }
        // equivalent to malloc
        return memdebug_malloc(size, file, line);
    }
    // ptr is defined and size = 0: equivalent to free
    if (size == 0) {
        WARN("realloc with size = 0: free.");
        memdebug_free(ptr, file, line);
        return NULL;
    }

    // find previous allocated block
    ptr -= sizeof(COOKIE);
    memdebug_block* memblock;
    HASH_FIND_PTR(blocks, &ptr, memblock);
    if (!memblock) {
        ERROR("trying to realloc a non-allocated memory block.");
        return NULL;
    }

    // do the actual realloc
    void* newblock = realloc(memblock->address, size + 2 * sizeof(COOKIE));
    if (!newblock) {
        ERROR("not enough memory left to realloc main block.");
        return NULL;
    }
    if (newblock != memblock->address) {
        // if address changed, we need to remove and re-add memblock to hashmap
        // so its internal hash is recomputed according to new address
        HASH_DEL(blocks, memblock);
        memblock->address = newblock;
        HASH_ADD_PTR(blocks, address, memblock);
    }

    // update memblock fields
    memblock->size = size;
    memblock->line = line;
    strncpy(memblock->file, file, FILE_MAX_LEN - 1);
    memblock->file[FILE_MAX_LEN - 1] = '\0';

    // set cookie values at start and end of memory block
    memcpy(newblock, &COOKIE, sizeof(COOKIE));
    memcpy(newblock + memblock->size +  sizeof(COOKIE), &COOKIE, sizeof(COOKIE));

    return newblock + sizeof(COOKIE);
}

void memdebug_check_overflow_int(const char* file, unsigned int line) {
    memdebug_block *current, *tmp;
    int error = 0;

    HASH_ITER(hh, blocks, current, tmp) {
        // verify that cookies were not overwritten
        if (memcmp(current->address, &COOKIE, sizeof(COOKIE)) != 0) {
            error = 1;
            ERROR("start of memory block allocated at %s:%u was overwritten.\n"
                  "      Last check with valid memory done at %s:%u", current->file,
                  current->line, last_file, last_line);
        }
        if (memcmp(current->address + current->size + sizeof(COOKIE), &COOKIE,
                    sizeof(COOKIE)) != 0) {
            error = 1;
            ERROR("end of memory block allocated at %s:%u was overwritten.\n"
                  "      Last check with valid memory done at %s:%u", current->file,
                  current->line, last_file, last_line);
        }
    }

    if (!error) {
        last_line = line;
        strncpy(last_file, file, FILE_MAX_LEN - 1);
        last_file[FILE_MAX_LEN - 1] = '\0';
    }
}

void memdebug_check_leak_int(const char* file, unsigned int line) {
    memdebug_block *current, *tmp;

    HASH_ITER(hh, blocks, current, tmp) {
        ERROR("memory leak: block allocated at %s:%u was not freed.", current->file,
                current->line);
        // free memory and delete from hashmap
        free(current->address);
        HASH_DEL(blocks, current);
        free(current);
    }
}

char* memdebug_strndup(const char* s, size_t n, const char* file, unsigned int line) {
    size_t buflen = strlen(s);
    buflen = buflen > n ? n + 1 : buflen + 1;
    char* block = memdebug_malloc(buflen, file, line);
    if (!block) {
        return NULL;
    }
    memcpy(block, s, buflen);
    block[buflen - 1] = '\0';
    return block;
}

char* memdebug_strdup(const char* s, const char* file, unsigned int line) {
    return memdebug_strndup(s, strlen(s), file, line);
}
