/*
 * sqliteSink.c
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

#include "sqliteSink.h"

#include <sqlite3.h>
#include <string.h>


#if BLOCK_BUF == 0

// Static variables

static sqlite3 *db_conn;
static char * const db_types[] = {
    "TEXT",           // bt_compound
    "INT",            // bt_int_8
    "INT",            // bt_int_16
    "INT",            // bt_int_32
    "INT",            // bt_int_64
    "INT",            // bt_int_128 (XXX precision loss)
    "INT",            // bt_int_256 (XXX precision loss)
    "INT",            // bt_uint_8
    "INT",            // bt_uint_16
    "INT",            // bt_uint_32
    "INT",            // bt_uint_64
    "INT",            // bt_uint_128 (XXX precision loss)
    "INT",            // bt_uint_256 (XXX precision loss)
    SQLITE_HEX_TYPE,  // bt_hex_8
    SQLITE_HEX_TYPE,  // bt_hex_16
    SQLITE_HEX_TYPE,  // bt_hex_32
    SQLITE_HEX_TYPE,  // bt_hex_64
    SQLITE_HEX_TYPE,  // bt_hex_128 (XXX precision loss)
    SQLITE_HEX_TYPE,  // bt_hex_256 (XXX precision loss)
    "REAL",           // bt_float
    "REAL",           // bt_double
    "REAL",           // bt_long_double (XXX precision loss)
    "TEXT",           // bt_char
    "TEXT",           // bt_string
    "TEXT",           // bt_flow_direction
    "TEXT",           // bt_timestamp
    "REAL",           // bt_duration
    "TEXT",           // bt_mac_addr
    "TEXT",           // bt_ip4_addr
    "TEXT",           // bt_ip6_addr
    "TEXT",           // bt_ipx_addr
    "TEXT",           // bt_string_class
};
#if SQLITE_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // SQLITE_TRANSACTION_NFLOWS > 1


// Function prototypes

static inline sqlite3 *db_connect(const char *dbname);
static inline void db_query(sqlite3 *conn, const char *qry);
static inline void db_create_flow_table(sqlite3 *conn, const char *name);
static inline char *db_create_flow_table_qry(sqlite3 *conn, const char *name);
static inline char *db_get_table_schema(sqlite3 *conn, const char *dbname);
#if SQLITE_OVERWRITE == 1
static inline void db_drop_table(sqlite3 *conn, const char *name);
#endif // SQLITE_OVERWRITE == 1
static inline bool db_table_exists(sqlite3 *conn, const char *name);
static inline bool sqlite_get_val_func(void *dest, size_t size, size_t n);
static int sqlite_parse_sv_type(char *qry, int pos, uint32_t type);
static int sqlite_parse_sv(char *qry, int pos, binary_subvalue_t *sv);
static bool sqlite_sanitize_utf8(char *qry, int *pos);


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define SQLITE_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR("sqliteSink", "query truncated... increase SQLITE_QRY_LEN"); \
        sqlite3_close(db_conn); \
        exit(1); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("sqliteSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("sqliteSink", "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

    db_conn = db_connect(SQLITE_DBNAME);

    bool exists = db_table_exists(db_conn, SQLITE_TABLE_NAME);
#if SQLITE_OVERWRITE != 2
    if (exists) {
#if SQLITE_OVERWRITE == 0
        T2_PERR("sqliteSink", "Table '%s' already exists", SQLITE_TABLE_NAME);
        sqlite3_close(db_conn);
        exit(1);
#elif SQLITE_OVERWRITE == 1
        db_drop_table(db_conn, SQLITE_TABLE_NAME);
        exists = false;
#endif // SQLITE_OVERWRITE == 1
    }
#endif // SQLITE_OVERWRITE != 2

    if (!exists) {
        db_create_flow_table(db_conn, SQLITE_TABLE_NAME);
    } else {
        // test that schema matches
        char *new_schema = db_create_flow_table_qry(db_conn, SQLITE_TABLE_NAME);
        char *old_schema = db_get_table_schema(db_conn, SQLITE_TABLE_NAME);
        const size_t new_len = strlen(new_schema) - 1; // new schema has a trailing semicolon
        const size_t old_len = strlen(old_schema);
        const bool differ = (new_len != old_len || memcmp(new_schema, old_schema, new_len) != 0);
        free(new_schema);
        free(old_schema);
        if (differ) {
            T2_PERR("sqliteSink", "Cannot append to existing table: schemas differ");
            sqlite3_close(db_conn);
            exit(1);
        }
    }

#if SQLITE_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "BEGIN TRANSACTION");
#endif // SQLITE_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void onApplicationTerminate() {
#if SQLITE_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // SQLITE_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "END TRANSACTION");
    sqlite3_close(db_conn);
}


static inline sqlite3 *db_connect(const char *dbname) {
    sqlite3 *db;
    if (UNLIKELY(sqlite3_open(dbname, &db) != SQLITE_OK)) {
        T2_PERR("sqliteSink", "Failed to open DB '%s': %s", dbname, sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
    return db;
}


static inline void db_query(sqlite3 *conn, const char *qry) {
    char *err;
    if (UNLIKELY(sqlite3_exec(conn, qry, 0, 0, &err) != SQLITE_OK)) {
        T2_PERR("sqliteSink", "Failed to execute query '%s': %s", qry, err);
        sqlite3_free(err);
        sqlite3_close(conn);
        exit(1);
    }
}


// Returned value MUST be free'd
static inline char *db_create_flow_table_qry(sqlite3 *conn, const char *name) {
    char *qry = t2_malloc(SQLITE_QRY_LEN);
    int pos = snprintf(qry, SQLITE_QRY_LEN, "CREATE TABLE %s (", name);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "\"%s\"", bv->name);
        char *type;
        if (bv->is_repeating || bv->num_values > 1) {
            type = "TEXT";
        } else {
            const uint32_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR("sqliteSink", "Unhandled type %u", t);
                sqlite3_close(conn);
                exit(1);
            }
            type = db_types[t];
        }
        SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, " %s%s", type, bv->next ? ", " : ");");
        bv = bv->next;
    }

    return qry;
}


static inline void db_create_flow_table(sqlite3 *conn, const char *name) {
    char *qry = db_create_flow_table_qry(conn, name);
    db_query(conn, qry);
    free(qry);
}


#if SQLITE_OVERWRITE == 1
static inline void db_drop_table(sqlite3 *conn, const char *name) {
    char qry[SQLITE_QRY_LEN];
    snprintf(qry, SQLITE_QRY_LEN, "DROP TABLE %s;", name);
    db_query(conn, qry);
}
#endif // SQLITE_OVERWRITE == 1


static inline bool db_table_exists(sqlite3 *conn, const char *name) {
    char qry[SQLITE_QRY_LEN];
    snprintf(qry, SQLITE_QRY_LEN, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='%s';", name);

    sqlite3_stmt *res;
    if (UNLIKELY(sqlite3_prepare_v2(conn, qry, -1, &res, 0) != SQLITE_OK)) {
        T2_PERR("sqliteSink", "Failed to prepare query '%s'", qry);
        sqlite3_close(conn);
        exit(1);
    }

    int rc = sqlite3_step(res);
    if (UNLIKELY(rc != SQLITE_ROW)) {
        T2_PERR("sqliteSink", "Failed to execute query '%s'", qry);
        sqlite3_close(conn);
        exit(1);
    }

    const bool exists = sqlite3_column_int(res, 0) ? true : false;

    sqlite3_finalize(res);

    return exists;
}


// Returned value MUST be free'd
static inline char *db_get_table_schema(sqlite3 *conn, const char *dbname) {
    char qry[SQLITE_QRY_LEN];
    snprintf(qry, SQLITE_QRY_LEN, "SELECT sql FROM sqlite_master WHERE type='table' AND name='%s';", dbname);

    sqlite3_stmt *res;
    if (UNLIKELY(sqlite3_prepare_v2(conn, qry, -1, &res, 0) != SQLITE_OK)) {
        T2_PERR("sqliteSink", "Failed to prepare query '%s'", qry);
        sqlite3_close(conn);
        exit(1);
    }

    int rc = sqlite3_step(res);
    if (UNLIKELY(rc != SQLITE_ROW)) {
        T2_PERR("sqliteSink", "Failed to execute query '%s'", qry);
        sqlite3_close(conn);
        exit(1);
    }

    const char *schema = (char*)sqlite3_column_text(res, 0);
    char *ret = schema ? strdup(schema) : NULL;

    sqlite3_finalize(res);

    return ret;
}


static inline bool sqlite_get_val_func(void *dest, size_t size, size_t n) {
    outputBuffer_t *buffer = main_output_buffer;
    const size_t sn = size * n;
    if (UNLIKELY(buffer->size < buffer->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buffer->pos + sn;
        T2_PERR("sqliteSink", "Buffer overflow: %zu increase MAIN_OUTPUT_BUFFER_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buffer->buffer + buffer->pos, sn);
    buffer->pos += sn;
    return true;
}


static int sqlite_parse_sv_type(char *qry, int pos, uint32_t type) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRId8, val);
            break;
        }
        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRId16, val);
            break;
        }
        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRId32, val);
            break;
        }
        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRId64, val);
            break;
        }
        //case bt_int_128:
        //case bt_int_256:
        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRIu8, val);
            break;
        }
        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRIu16, val);
            break;
        }
        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRIu32, val);
            break;
        }
        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRIu64, val);
            break;
        }
        //case bt_uint_128:
        //case bt_uint_256:
        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, SQLITE_PRI_HEX8, val);
            break;
        }
        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, SQLITE_PRI_HEX16, val);
            break;
        }
        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, SQLITE_PRI_HEX32, val);
            break;
        }
        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, SQLITE_PRI_HEX64, val);
            break;
        }
        //case bt_hex_128:
        //case bt_hex_256:
        case bt_float: {
            float val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_double: {
            double val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_long_double: {
            long double val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%Lf", val);
            break;
        }
        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%c", val);
            break;
        }
        case bt_string_class:
        case bt_string: {
            if (UNLIKELY(!sqlite_sanitize_utf8(qry, &pos))) {
                exit(1);
            }
            break;
        }
        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%c", (val == 0) ? 'A' : 'B');
            break;
        }
        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!sqlite_get_val_func(&ns, sizeof(ns), 1))) {
                exit(1);
            }

#if B2T_TIME_IN_MICRO_SECS != 0
            ns /= 1000;
#endif // B2T_TIME_IN_MICRO_SECS != 0

            if (type == bt_duration) {
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%"PRIu64".%"B2T_TPFRMT, val, ns);
            } else {
                const struct tm *t;
#if TSTAMP_UTC == 1
                t = gmtime((time_t*)&val);
#else // TSTAMP_UTC == 0
                t = localtime((time_t*)&val);
#endif // TSTAMP_UTC == 0
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
                strftime(timeBuf, sizeof(timeBuf), B2T_TIMEFRMT, t);
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%s.%"B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "+00:00");
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                const size_t oldpos = pos;
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%s", timeBuf);
                // SQLite does not understand offset formatted as +0100
                // but requires a colon to separate hours from minutes (+01:00)
                if (pos - oldpos == 5 && (qry[oldpos] == '+' || qry[oldpos] == '-')) {
                    if (UNLIKELY(pos+2 >= SQLITE_QRY_LEN - (pos + 2))) {
                        T2_PERR("sqliteSink", "query truncated... increase SQLITE_QRY_LEN");
                        sqlite3_close(db_conn);
                        exit(1);
                    }
                    memmove(&qry[oldpos+4], &qry[oldpos+3], 2);
                    qry[oldpos+3] = ':';
                    pos++;
                    qry[pos] = '\0';
                }
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
            break;
        }
        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!sqlite_get_val_func(&val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos,
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            break;
        }
        case bt_ip4_addr: {
sqlite_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!sqlite_get_val_func(&val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, val, addr, INET_ADDRSTRLEN);
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ip6_addr: {
sqlite_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!sqlite_get_val_func(&val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!sqlite_get_val_func(&version, sizeof(version), 1))) {
                exit(1);
            }
            if (version == 4) {
                goto sqlite_bt_ip4;
            } else if (version == 6) {
                goto sqlite_bt_ip6;
            } else {
                T2_PERR("sqliteSink", "invalid IP version %"PRIu8, version);
                exit(1);
            }
            break;
        }
        default:
            T2_PERR("sqliteSink", "unhandled output type %"PRIu32, type);
            exit(1);
    }
    return pos;
}


static int sqlite_parse_sv(char *qry, int pos, binary_subvalue_t *sv) {
    if (sv->type) {
        return sqlite_parse_sv_type(qry, pos, sv->type);
    }

    SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!sqlite_get_val_func(&nr, sizeof(nr), 1))) {
            exit(1);
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            pos = sqlite_parse_sv(qry, pos, &sv->subval[j]);
            // write value delim
            if (j < nv - 1) {
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "_");
            }
        }

        // write repeat delim
        if (i < nr - 1) {
            SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, ";");
        }
    }
    SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, ")");
    return pos;
}


void bufferToSink(outputBuffer_t *buffer) {
    const uint32_t bufpos = buffer->pos;
    buffer->pos = 0;
    char qry[SQLITE_QRY_LEN];
    int pos = snprintf(qry, SQLITE_QRY_LEN, "INSERT INTO %s VALUES ('", SQLITE_TABLE_NAME);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!sqlite_get_val_func(&nr, sizeof(nr), 1))) {
                exit(1);
            }
        }
        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                pos = sqlite_parse_sv(qry, pos, &bv->subval[j]);
                if (j < nv - 1) {
                    SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "_");
                }
            }
            if (i < nr - 1) {
                SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, ";");
            }
        }
        SQLITE_SNPRINTF(pos, &qry[pos], SQLITE_QRY_LEN - pos, "'%s", bv->next ? ", '" : ");");
        bv = bv->next;
    }
    db_query(db_conn, qry);
    buffer->pos = bufpos;
#if SQLITE_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == SQLITE_TRANSACTION_NFLOWS) {
        db_query(db_conn, "END TRANSACTION;");
        db_query(db_conn, "BEGIN TRANSACTION;");
        flows_to_commit = 0;
    }
#endif // SQLITE_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool sqlite_sanitize_utf8(char *qry, int *pos) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!sqlite_get_val_func(&val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
            switch (val) {
                case '\t':
                    SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "\\t");
                    break;
                case '\n':
                    SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':
                    SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "\\r");
                    break;
                case '\\':
                case '"':
                    SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "\\%c", val);
                    break;
                case '\'':
                    SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "''");
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "\\u00%02X", val);
                    } else {
                        SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!sqlite_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!sqlite_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!sqlite_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
            SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!sqlite_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!sqlite_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!sqlite_get_val_func(&b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", val);
            SQLITE_SNPRINTF(*pos, &qry[*pos], SQLITE_QRY_LEN - *pos, ".");
        }
    }

    return true;
}

#endif // BLOCK_BUF == 0
