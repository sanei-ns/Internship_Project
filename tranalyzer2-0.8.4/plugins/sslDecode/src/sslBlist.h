/*
 * sslBlist.h
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

#ifndef SSL_BLIST_H
#define SSL_BLIST_H

#include "global.h"

#define SSL_BLIST_NAME "sslblacklist.tsv"
#define SSL_JA3_NAME   "ja3fingerprint.tsv"

// Helper macros to access hashes and descriptions at index 'pos'
#define SSL_BLIST_DESC(sslbl, pos) (&sslbl->desc[sslbl->desc_len * (pos)])
#define SSL_BLIST_HASH(sslbl, pos) (&sslbl->hash[sslbl->hash_len * (pos)])

typedef struct {
    char *hash;
    size_t hash_len;
    char *desc;
    size_t desc_len;
    uint32_t count;
} ssl_blist_t;

ssl_blist_t *ssl_blist_load(const char *filename, size_t hash_len, size_t desc_len);
const char *ssl_blist_lookup(const ssl_blist_t * const sslbl, const char *hash);
void ssl_blist_free(ssl_blist_t *sslbl);

#endif // SSL_BLIST_H
