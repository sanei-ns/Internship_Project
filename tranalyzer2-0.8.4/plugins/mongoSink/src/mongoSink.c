/*
 * mongoSink.c
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

#include "mongoSink.h"
#include "bin2txt.h"

#include <assert.h>
#include <bson.h>
#include <mongoc.h>
#include <string.h>


#if BLOCK_BUF == 0

// Static variables

static uint64_t num_docs;
static bson_t *documents[MONGO_NUM_DOCS];
static mongoc_client_t *client;
static mongoc_database_t *database;
static mongoc_collection_t *collection;
#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static mongoc_bulk_operation_t *bulk;
#endif // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1


// Function prototypes

static inline void db_cleanup();
static bool parse_binary2bson(void *input, binary_value_t * const bv);
static bool parse_subval_bson(void *input, const binary_subvalue_t *sv, const char *name, bson_t *parent);
static bool parse_binary_value_bson(uint32_t type, const char *name, bson_t *parent);
static bool mongo_sanitize_utf8(char *qry, int *pos);
static inline bool mongo_get_val_func(void *dest, size_t size, size_t n);


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define MONGO_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR("mongoSink", "query truncated... increase MONGO_QRY_LEN"); \
        db_cleanup(); \
        exit(1); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("mongoSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("mongoSink", "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

    mongoc_init();

    if (UNLIKELY(!(client = mongoc_client_new("mongodb://" MONGO_HOST ":" MONGO_PORT)))) {
        T2_PERR("mongoSink", "Failed to connect to DB on '%s:%s'", MONGO_HOST, MONGO_PORT);
        exit(1);
    }

    mongoc_client_set_appname(client, MONGO_DBNAME);

    if (UNLIKELY(!(database = mongoc_client_get_database(client, MONGO_DBNAME)))) {
        T2_PERR("mongoSink", "Failed to connect to DB '%s' on '%s:%s'", MONGO_DBNAME, MONGO_HOST, MONGO_PORT);
        db_cleanup();
        exit(1);
    }

    if (UNLIKELY(!(collection = mongoc_client_get_collection(client, MONGO_DBNAME, MONGO_TABLE_NAME)))) {
        T2_PERR("mongoSink", "Failed get collection '%s' from DB '%s' on '%s:%s'", MONGO_TABLE_NAME, MONGO_DBNAME, MONGO_HOST, MONGO_PORT);
        db_cleanup();
        exit(1);
    }

#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
   bulk = mongoc_collection_create_bulk_operation(collection, false, NULL);
#endif // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1

    for (uint_fast64_t i = 0; i < MONGO_NUM_DOCS; i++) {
        if (UNLIKELY(!(documents[i] = bson_new()))) {
            T2_PERR("mongoSink", "Failed to create new BSON document");
            db_cleanup();
            exit(1);
        }
    }

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below, is therefore not activated.


#if BLOCK_BUF == 0

void onApplicationTerminate() {
    db_cleanup();
}


static inline void db_cleanup() {
    for (uint_fast64_t i = 0; i < MONGO_NUM_DOCS; i++) {
        if (LIKELY(documents[i] != NULL)) bson_destroy(documents[i]);
    }
#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    if (LIKELY(bulk != NULL)) mongoc_bulk_operation_destroy(bulk);
#endif // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    if (LIKELY(collection != NULL)) mongoc_collection_destroy(collection);
    if (LIKELY(database != NULL)) mongoc_database_destroy(database);
    if (LIKELY(client != NULL)) mongoc_client_destroy(client);
    mongoc_cleanup();
}


static inline bool mongo_get_val_func(void *dest, size_t size, size_t n) {
    outputBuffer_t *buffer = main_output_buffer;
    const size_t sn = size * n;
    if (UNLIKELY(buffer->size < buffer->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buffer->pos + sn;
        T2_PERR("mongoSink", "Buffer overflow: %zu increase MAIN_OUTPUT_BUFFER_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buffer->buffer + buffer->pos, sn);
    buffer->pos += sn;
    return true;
}


#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static inline void mongo_insert_doc(mongoc_collection_t *collection __attribute__((unused)), bson_t **documents __attribute__((unused)), uint64_t num_docs __attribute__((unused))) {
#else // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static inline void mongo_insert_doc(mongoc_collection_t *collection, bson_t **documents, uint64_t num_docs) {
#endif // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    bson_error_t error;
#if MONGOC_CHECK_VERSION(1,9,0)
#if MONGO_NUM_DOCS <= 1
    assert(num_docs == 0);
    if (UNLIKELY(!mongoc_collection_insert_one(collection, documents[num_docs], NULL, NULL, &error))) {
#else // MONGO_NUM_DOCS > 1
    if (UNLIKELY(!mongoc_collection_insert_many(collection, documents, num_docs, NULL, NULL, &error))) {
#endif // MONGO_NUM_DOCS > 1
#else // MONGOC_VERSION < 1.9.0
#if MONGO_NUM_DOCS <= 1
    assert(num_docs == 0);
    if (UNLIKELY(!mongoc_collection_insert(collection, 0, documents[num_docs], NULL, &error))) {
#else // MONGO_NUM_DOCS > 1
    if (UNLIKELY(!mongoc_bulk_operation_execute(bulk, NULL, &error))) {
#endif // MONGO_NUM_DOCS > 1
#endif // MONGOC_VERSION < 1.9.0
        T2_PERR("mongoSink", "Failed to insert document into collection: %s", error.message);
        db_cleanup();
        exit(1);
    }
}


void bufferToSink(outputBuffer_t *buffer) {

    bson_reinit(documents[num_docs]);

    const uint32_t bufpos = buffer->pos;
    buffer->pos = 0;

    parse_binary2bson(buffer, main_header_bv);

    buffer->pos = bufpos;

#if BSON_DEBUG == 1
    bson_error_t err;
    if (UNLIKELY(!bson_validate_with_error(documents[num_docs], 0, &err))) {
        T2_PERR("mongoSink", "Failed to validate BSON document: %s", err.message);
    }
    char *str = bson_as_canonical_extended_json(documents[num_docs], NULL);
    if (LIKELY(str != NULL)) {
        T2_PINF("mongoSink", "%s", str);
    }
    bson_free(str);
#endif // BSON_DEBUG == 1

#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    mongoc_bulk_operation_insert(bulk, documents[num_docs]);
#endif // !MONGOC_VERSION(1,9,0) && MONGO_NUM_DOCS > 1

#if MONGO_NUM_DOCS > 1
    if (++num_docs == MONGO_NUM_DOCS) {
#endif // MONGO_NUM_DOCS > 1
        mongo_insert_doc(collection, documents, num_docs);
#if MONGO_NUM_DOCS > 1
        num_docs = 0;
    }
#endif // MONGO_NUM_DOCS > 1

}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool mongo_sanitize_utf8(char *qry, int *pos) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!mongo_get_val_func(&val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
            switch (val) {
                case '\t':
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\t");
                    break;
                case '\n':
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\r");
                    break;
                case '\\':
                case '"':
                case '\'':
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\%c", val);
                    break;
                default:
                    // In order to be valid BSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\u00%02X", val);
                    } else {
                        MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!mongo_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!mongo_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mongo_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!mongo_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mongo_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!mongo_get_val_func(&b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", val);
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
        }
    }

    return true;
}


static bool parse_binary2bson(void *input, binary_value_t * const bv) {
    uint32_t num_repeat;
    uint_fast32_t rep, val;

    binary_value_t *act_bv = bv;
    bson_t child1, child2;
    bson_t *parent = documents[num_docs];
    bson_t *child = &child1;
    bson_t *doc = documents[num_docs];

    while (act_bv) {
        // check if output can be repeated
        // If yes, read amount of repeats, if no set num_repeat to 1
        if (act_bv->is_repeating) {
            if (UNLIKELY(!mongo_get_val_func(&num_repeat, sizeof(uint32_t), 1))) {
                return false;
            }
#if BSON_SUPPRESS_EMPTY_ARRAY == 1
            if (num_repeat == 0) {
                act_bv = act_bv->next;
                continue;
            }
#endif // BSON_SUPPRESS_EMPTY_ARRAY == 1
            if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(doc, act_bv->name, &child1))) {
                T2_PERR("mongoSink", "Failed to append array begin for %s", act_bv->name);
                return false;
            }
            parent = &child1;
            child = &child1;
        } else {
            parent = doc;
            child = doc;
            num_repeat = 1;
        }
        for (rep = 0; rep < num_repeat; rep++) {
            if (act_bv->num_values > 1) {
                child = &child2;
                if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(parent, act_bv->name, child))) {
                    T2_PERR("mongoSink", "Failed to append array begin for %s", act_bv->name);
                    return false;
                }
            }

            // for each output val:
            // check type and write it out, if zero then it contains subvals
            for (val = 0; val < act_bv->num_values; val++) {
                if (act_bv->subval[val].type == bt_compound) {
                    if (UNLIKELY(!parse_subval_bson(input, &act_bv->subval[val], act_bv->name, child))) {
                        return false;
                    }
                } else {
                    if (UNLIKELY(!parse_binary_value_bson(act_bv->subval[val].type, act_bv->name, child))) {
                        return false;
                    }
                }
            }

            // Repeat value separator
            if (act_bv->num_values > 1) {
                if (UNLIKELY(!bson_append_array_end(parent, child))) {
                    T2_PERR("mongoSink", "Failed to append array end for %s", act_bv->name);
                    return false;
                }
            }
        }

#if BSON_SUPPRESS_EMPTY_ARRAY == 1
        if (act_bv->is_repeating == 1 && num_repeat > 0) {
#else // BSON_SUPPRESS_EMPTY_ARRAY == 0
        if (act_bv->is_repeating == 1) {
#endif // BSON_SUPPRESS_EMPTY_ARRAY == 0
            if (UNLIKELY(!bson_append_array_end(doc, &child1))) {
                T2_PERR("mongoSink", "Failed to append array end for %s", act_bv->name);
                return false;
            }
        }

        act_bv = act_bv->next;
    }

    return true;
}


static bool parse_subval_bson(void *input, const binary_subvalue_t *sv, const char *name, bson_t *parent) {
    bson_t *p = parent;
    bson_t *child = parent;
    bson_t child1, child2;
    // check if output can be repeated. If yes, read amount of repeats, if no set num_repeat to 1
    uint32_t num_repeat = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!mongo_get_val_func(&num_repeat, sizeof(uint32_t), 1))) {
            return false;
        }

        if (num_repeat == 0) {
            return true;
        }

        if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(parent, name, &child1))) {
            T2_PERR("mongoSink", "Failed to append array begin for %s", name);
            return false;
        }

        p = &child1;
        child = &child1;
    }

    for (uint_fast32_t i = 0; i < num_repeat; i++) {
        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            child = &child2;
            if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(p, name, child))) {
                T2_PERR("mongoSink", "Failed to append array begin for %s", name);
                return false;
            }
        }

        for (uint_fast32_t j = 0; j < sv->num_values; j++) {
            if (sv->subval[j].type == bt_compound) {
                if (UNLIKELY(!parse_subval_bson(input, &sv->subval[j], name, child))) {
                    return false;
                }
            } else {
                if (UNLIKELY(!parse_binary_value_bson(sv->subval[j].type, name, child))) {
                    return false;
                }
            }
        }

        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            if (UNLIKELY(!bson_append_array_end(p, child))) {
                T2_PERR("mongoSink", "Failed to append array end for %s", name);
                return false;
            }
        }
    }

    if (sv->is_repeating) {
        if (UNLIKELY(!bson_append_array_end(parent, &child1))) {
            T2_PERR("mongoSink", "Failed to append array end for %s", name);
            return false;
        }
    }

    return true;
}


static bool parse_binary_value_bson(uint32_t type, const char *name, bson_t *parent) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(int8_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(int16_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(int32_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(int64_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint8_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint16_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint32_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint64_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint8_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint16_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint32_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint64_t), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_float: {
            float val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(float), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(double), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(long double), 1))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint8_t), 1))) {
                return false;
            }
            char str[2];
            snprintf(str, sizeof(str), "%c", val);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_string_class:
        case bt_string: {
            char str[MONGO_QRY_LEN] = {};
            int pos = 0;
            if (UNLIKELY(!mongo_sanitize_utf8(str, &pos))) {
                return false;
            }
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!mongo_get_val_func(val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                return false;
            }
            char str[18];
            snprintf(str, sizeof(str),
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ip4_addr: {
b2t_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!mongo_get_val_func(val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                return false;
            }
            char str[16];
            snprintf(str, sizeof(str), "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, val[0], val[1], val[2], val[3]);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ip6_addr: {
b2t_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!mongo_get_val_func(val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                return false;
            }
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, addr))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!mongo_get_val_func(&version, sizeof(uint8_t), 1))) {
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
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint64_t), 1))) {
                return false;
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!mongo_get_val_func(&ns, sizeof(uint32_t), 1))) {
                return false;
            }

#if B2T_TIME_IN_MICRO_SECS != 0
            ns /= 1000;
#endif // B2T_TIME_IN_MICRO_SECS = 0

            struct timeval t = {
                .tv_sec = val,
                .tv_usec = ns,
            };

            if (UNLIKELY(!BSON_APPEND_TIMEVAL(parent, name, &t))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(&val, sizeof(uint8_t), 1))) {
                return false;
            }
            char str[2];
            snprintf(str, sizeof(str), "%c", (val == 0) ? 'A' : 'B');
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR("mongoSink", "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        default:
            T2_PERR("mongoSink", "unhandled type %"PRIu32, type);
            return false;
    }

    return true;
}

#endif // BLOCK_BUF == 0
