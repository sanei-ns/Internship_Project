/*
 * sslBlist.c
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

#include "sslBlist.h"
#include "t2utils.h"

#include <ctype.h>


ssl_blist_t *ssl_blist_load(const char *filename, size_t hash_len, size_t desc_len) {
    FILE *file = t2_open_file(NULL, filename, "r");
    if (UNLIKELY(!file)) exit(1);

    ssl_blist_t *sslbl = calloc(1, sizeof(*sslbl));
    if (UNLIKELY(!sslbl)) {
        T2_PERR("sslDecode", "failed to allocate memory for sslbl");
        fclose(file);
        exit(1);
    }

    sslbl->hash_len = hash_len;
    sslbl->desc_len = desc_len;

    char *line = NULL;
    size_t len = 0;

    ssize_t read = getline(&line, &len, file);
    if (UNLIKELY(read == -1)) {
        T2_PERR("sslDecode", "failed to read first line from '%s'", filename);
        ssl_blist_free(sslbl);
        fclose(file);
        exit(1);
    }

    // read number of rows
    if (UNLIKELY(sscanf(line, "%% %"SCNu32"\n", &sslbl->count) == EOF)) {
        T2_PERR("sslDecode", "expected leading '%%' followed by number of rows");
        ssl_blist_free(sslbl);
        free(line);
        fclose(file);
        exit(1);
    }

    sslbl->hash = malloc(hash_len * sslbl->count + 1);
    sslbl->desc = malloc(desc_len * sslbl->count + 1);
    if (UNLIKELY(!sslbl->hash || !sslbl->desc)) {
        T2_PERR("sslDecode", "failed to allocate memory for sslbl");
        ssl_blist_free(sslbl);
        free(line);
        fclose(file);
        exit(1);
    }

    char format[64];
    snprintf(format, sizeof(format), "%%%zu[0-9a-fA-F]\t%%%zu[^\t\n]",
            hash_len, desc_len);

    uint32_t d = 0, h = 0;
    uint32_t count = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        // skip comments and empty lines
        if (line[0] == '\n' || line[0] == '#' || isspace(line[0])) continue;

        if (count < sslbl->count) {
            sscanf(line, format, &sslbl->hash[h], &sslbl->desc[d]);
            h += hash_len;
            d += desc_len;
            sslbl->desc[d-1] = '\0';
        }

        count++;
    }

    sslbl->hash[h] = '\0';

    free(line);
    fclose(file);

    if (count < sslbl->count) {
        T2_PWRN("sslDecode", "Read %"PRIu32" certificate fingerprints, expected %"PRIu32, count, sslbl->count);
        sslbl->count = count;
    } else if (count > sslbl->count) {
        T2_PWRN("sslDecode", "Read %"PRIu32" certificate fingerprints out of %"PRIu32, sslbl->count, count);
    }

    return sslbl;
}


const char *ssl_blist_lookup(const ssl_blist_t * const sslbl, const char *hash) {
    int start = 0;
    int end = sslbl->count - 1;

    while (start <= end) {
        const int middle = (end + start) / 2;
        const int cmp = memcmp(hash, SSL_BLIST_HASH(sslbl, middle), sslbl->hash_len);
        if (cmp == 0) return SSL_BLIST_DESC(sslbl, middle);
        else if (cmp < 0) end = middle - 1;
        else start = middle + 1;
    }

    return NULL;
}


void ssl_blist_free(ssl_blist_t *sslbl) {
    if (UNLIKELY(!sslbl)) return;

    free(sslbl->hash);
    free(sslbl->desc);
    free(sslbl);
}
