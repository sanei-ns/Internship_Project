/*
 * mysqlSink.c
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

#include "mysqlSink.h"
#include "bin2txt.h"

#include <mysql.h>
#include <string.h>


#if BLOCK_BUF == 0

// Static variables

static MYSQL *db_conn;
static char * const db_types[] = {
    "TEXT",              // bt_compound
    "TINYINT",           // bt_int_8
    "SMALLINT",          // bt_int_16
    "INT",               // bt_int_32
    "BIGINT",            // bt_int_64
    "BIGINT",            // bt_int_128 (XXX precision loss)
    "BIGINT",            // bt_int_256 (XXX precision loss)
    "TINYINT UNSIGNED",  // bt_uint_8
    "SMALLINT UNSIGNED", // bt_uint_16
    "INT UNSIGNED",      // bt_uint_32
    "BIGINT UNSIGNED",   // bt_uint_64
    "BIGINT UNSIGNED",   // bt_uint_128 (XXX precision loss)
    "BIGINT UNSIGNED",   // bt_uint_256 (XXX precision loss)
    "TINYINT UNSIGNED",  // bt_hex_8
    "SMALLINT UNSIGNED", // bt_hex_16
    "INT UNSIGNED",      // bt_hex_32
    "BIGINT UNSIGNED",   // bt_hex_64
    "BIGINT UNSIGNED",   // bt_hex_128 (XXX precision loss)
    "BIGINT UNSIGNED",   // bt_hex_256 (XXX precision loss)
    //"BIT(8)",            // bt_hex_8
    //"BIT(16)",           // bt_hex_16
    //"BIT(32)",           // bt_hex_32
    //"BIT(64)",           // bt_hex_64
    //"BIT(128)",          // bt_hex_128
    //"BIT(256)",          // bt_hex_256
    "FLOAT",             // bt_float
    "DOUBLE",            // bt_double
    "DOUBLE",            // bt_long_double (XXX precision loss)
    "CHAR(1)",           // bt_char
    "TEXT",              // bt_string
    "CHAR(1)",           // bt_flow_direction
    "DATETIME(6)",       // bt_timestamp
    //"DECIMAL",           // bt_duration
    "TIME",              // bt_duration
    "TEXT",              // bt_mac_addr
    "TEXT",              // bt_ip4_addr
    "TEXT",              // bt_ip6_addr
    "TEXT",              // bt_ipx_addr
    "TEXT",              // bt_string_class
};
#if MYSQL_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // MYSQL_TRANSACTION_NFLOWS > 1


// Function prototypes

static inline void db_connect(MYSQL *conn, const char *dbname);
static inline void db_create(MYSQL *conn, const char *dbname);
static inline void db_query(MYSQL *conn, const char *qry);
static inline void db_create_flow_table(MYSQL *conn, const char *name);
static inline char *db_create_flow_table_qry(MYSQL *conn, const char *name);
#if MYSQL_OVERWRITE_DB == 1
static inline void db_drop(MYSQL *conn, const char *name);
#endif // MYSQL_OVERWRITE_DB == 1
#if MYSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(MYSQL *conn, const char *name);
#endif // MYSQL_OVERWRITE_TABLE == 1
static inline bool db_exists(MYSQL *conn, const char *name);
static inline bool db_table_exists(MYSQL *conn, const char *name);
static inline bool mysql_get_val_func(void *dest, size_t size, size_t n);
static int mysql_parse_sv_type(char *qry, int pos, uint32_t type);
static int mysql_parse_sv(char *qry, int pos, binary_subvalue_t *sv);
static bool mysql_sanitize_utf8(char *qry, int *pos);


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define MYSQL_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR("mysqlSink", "query truncated... increase MYSQL_QRY_LEN"); \
        mysql_close(db_conn); \
        exit(1); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("mysqlSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("mysqlSink", "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

    if (UNLIKELY(!(db_conn = mysql_init(NULL)))) {
        T2_PERR("mysqlSink", "Failed to initialize DB: %s", mysql_error(db_conn));
        exit(1);
    }

    db_connect(db_conn, NULL);

    if (db_exists(db_conn, MYSQL_DBNAME)) {
#if MYSQL_OVERWRITE_DB == 0
        T2_PERR("mysqlSink", "Database '%s' already exists", MYSQL_DBNAME);
        mysql_close(db_conn);
        exit(1);
#elif MYSQL_OVERWRITE_DB == 1
        db_drop(db_conn, MYSQL_DBNAME);
#endif // MYSQL_OVERWRITE_DB == 1
    }

    db_create(db_conn, MYSQL_DBNAME);
    if (UNLIKELY(mysql_select_db(db_conn, MYSQL_DBNAME) != 0)) {
        T2_PERR("mysqlSink", "Failed to select DB '%s': %s", MYSQL_DBNAME, mysql_error(db_conn));
        mysql_close(db_conn);
        exit(1);
    }

    if (db_table_exists(db_conn, MYSQL_TABLE_NAME)) {
#if MYSQL_OVERWRITE_TABLE == 0
        T2_PERR("mysqlSink", "Table '%s' already exists", MYSQL_TABLE_NAME);
        mysql_close(db_conn);
        exit(1);
#elif MYSQL_OVERWRITE_TABLE == 1
        db_drop_table(db_conn, MYSQL_TABLE_NAME);
#else // MYSQL_OVERWRITE_TABLE == 2
        // TODO test that schema matches
#endif // MYSQL_OVERWRITE_TABLE == 2
    }

    db_create_flow_table(db_conn, MYSQL_TABLE_NAME);

#if MYSQL_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "START TRANSACTION;");
#endif // MYSQL_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void onApplicationTerminate() {
#if MYSQL_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // MYSQL_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "COMMIT;");
    mysql_close(db_conn);
}


static inline void db_connect(MYSQL *conn, const char *dbname) {
    if (UNLIKELY(!(mysql_real_connect(conn, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, dbname, MYSQL_DBPORT, NULL, 0)))) {
        T2_PERR("mysqlSink", "Failed to connect to DB on '%s:%d' with user '%s': %s", MYSQL_HOST, MYSQL_DBPORT, MYSQL_USER, mysql_error(conn));
        mysql_close(conn);
        exit(1);
    }
}


static inline void db_query(MYSQL *conn, const char *qry) {
    if (UNLIKELY(mysql_query(conn, qry) != 0)) {
        T2_PERR("mysqlSink", "Failed to execute query '%s': %s", qry, mysql_error(conn));
        mysql_close(conn);
        exit(1);
    }
}


static inline void db_create(MYSQL *conn, const char *dbname) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8 COLLATE utf8_general_ci;", dbname);
    db_query(conn, qry);
}


// Returned value MUST be free'd
static inline char *db_create_flow_table_qry(MYSQL *conn, const char *name) {
    char *qry = t2_malloc(MYSQL_QRY_LEN);
    int pos = snprintf(qry, MYSQL_QRY_LEN, "CREATE TABLE IF NOT EXISTS %s (", name);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", bv->name);
        char *type;
        if (bv->is_repeating || bv->num_values > 1) {
            type = "TEXT";
        } else {
            const uint32_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR("mysqlSink", "Unhandled type %u", t);
                mysql_close(conn);
                exit(1);
            }
            type = db_types[t];
        }
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, " %s%s", type, bv->next ? ", " : ");");
        bv = bv->next;
    }

    return qry;
}


static inline void db_create_flow_table(MYSQL *conn, const char *name) {
    char *qry = db_create_flow_table_qry(conn, name);
    db_query(conn, qry);
    free(qry);
}


#if MYSQL_OVERWRITE_DB == 1
static inline void db_drop(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "DROP DATABASE %s;", name);
    db_query(conn, qry);
}
#endif // MYSQL_OVERWRITE_DB == 1


#if MYSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "DROP TABLE %s;", name);
    db_query(conn, qry);
}
#endif // MYSQL_OVERWRITE_TABLE == 1


static inline bool db_exists(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "SHOW DATABASES LIKE '%s';", name);
    db_query(conn, qry);
    MYSQL_RES *res = mysql_store_result(conn);
    const bool exists = (res && mysql_num_rows(res) > 0);
    mysql_free_result(res);
    return exists;
}


static inline bool db_table_exists(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "SHOW TABLES LIKE '%s';", name);
    db_query(conn, qry);
    MYSQL_RES *res = mysql_store_result(conn);
    const bool exists = (res && mysql_num_rows(res) > 0);
    mysql_free_result(res);
    return exists;
}


static inline bool mysql_get_val_func(void *dest, size_t size, size_t n) {
    outputBuffer_t *buffer = main_output_buffer;
    const size_t sn = size * n;
    if (UNLIKELY(buffer->size < buffer->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buffer->pos + sn;
        T2_PERR("mysqlSink", "Buffer overflow: %zu increase MAIN_OUTPUT_BUFFER_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buffer->buffer + buffer->pos, sn);
    buffer->pos += sn;
    return true;
}


static int mysql_parse_sv_type(char *qry, int pos, uint32_t type) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRId8, val);
            break;
        }
        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRId16, val);
            break;
        }
        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRId32, val);
            break;
        }
        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRId64, val);
            break;
        }
        //case bt_int_128:
        //case bt_int_256:
        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu8, val);
            break;
        }
        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu16, val);
            break;
        }
        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu32, val);
            break;
        }
        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu64, val);
            break;
        }
        //case bt_uint_128:
        //case bt_uint_256:
        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%02"B2T_PRIX8, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu8, val);
            break;
        }
        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%04"B2T_PRIX16, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu16, val);
            break;
        }
        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%08"B2T_PRIX32, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu32, val);
            break;
        }
        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%016"B2T_PRIX64, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu64, val);
            break;
        }
        //case bt_hex_128:
        //case bt_hex_256:
        case bt_float: {
            float val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_double: {
            double val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_long_double: {
            long double val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%Lf", val);
            break;
        }
        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%c", val);
            break;
        }
        case bt_string_class:
        case bt_string: {
            if (UNLIKELY(!mysql_sanitize_utf8(qry, &pos))) {
                exit(1);
            }
            break;
        }
        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%c", (val == 0) ? 'A' : 'B');
            break;
        }
        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!mysql_get_val_func(&ns, sizeof(ns), 1))) {
                exit(1);
            }

#if B2T_TIME_IN_MICRO_SECS != 0
            ns /= 1000;
#endif // B2T_TIME_IN_MICRO_SECS != 0

            if (type == bt_duration) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%"PRIu64".%"B2T_TPFRMT, val, ns);
            } else {
                const struct tm * const t = gmtime((time_t*)&val);
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day> <hours>:<minutes>:<seconds>.<micro/nano-seconds>
                strftime(timeBuf, sizeof(timeBuf), "%F %T", t);
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s.%"B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
            }
            break;
        }
        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!mysql_get_val_func(&val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            // TODO use t2_mac_to_str
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            break;
        }
        case bt_ip4_addr: {
mysql_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!mysql_get_val_func(&val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, val, addr, INET_ADDRSTRLEN);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ip6_addr: {
mysql_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!mysql_get_val_func(&val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!mysql_get_val_func(&version, sizeof(version), 1))) {
                exit(1);
            }
            if (version == 4) {
                goto mysql_bt_ip4;
            } else if (version == 6) {
                goto mysql_bt_ip6;
            } else {
                T2_PERR("mysqlSink", "invalid IP version %"PRIu8, version);
                exit(1);
            }
            break;
        }
        default:
            T2_PERR("mysqlSink", "unhandled output type %"PRIu32, type);
            exit(1);
    }
    return pos;
}


static int mysql_parse_sv(char *qry, int pos, binary_subvalue_t *sv) {
    if (sv->type) {
        return mysql_parse_sv_type(qry, pos, sv->type);
    }

    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!mysql_get_val_func(&nr, sizeof(nr), 1))) {
            exit(1);
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            pos = mysql_parse_sv(qry, pos, &sv->subval[j]);
            // write value delim
            if (j < nv - 1) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "_");
            }
        }

        // write repeat delim
        if (i < nr - 1) {
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ";");
        }
    }
    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ")");
    return pos;
}


void bufferToSink(outputBuffer_t *buffer) {
    const uint32_t bufpos = buffer->pos;
    buffer->pos = 0;
    char qry[MYSQL_QRY_LEN];
    int pos = snprintf(qry, MYSQL_QRY_LEN, "INSERT INTO %s VALUES ('", MYSQL_TABLE_NAME);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!mysql_get_val_func(&nr, sizeof(nr), 1))) {
                exit(1);
            }
        }
        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                pos = mysql_parse_sv(qry, pos, &bv->subval[j]);
                if (j < nv - 1) {
                    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "_");
                }
            }
            if (i < nr - 1) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ";");
            }
        }
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "'%s", bv->next ? ", '" : ");");
        bv = bv->next;
    }
    db_query(db_conn, qry);
    buffer->pos = bufpos;
#if MYSQL_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == MYSQL_TRANSACTION_NFLOWS) {
        db_query(db_conn, "COMMIT;");
        db_query(db_conn, "START TRANSACTION;");
        flows_to_commit = 0;
    }
#endif // MYSQL_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool mysql_sanitize_utf8(char *qry, int *pos) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!mysql_get_val_func(&val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
            switch (val) {
                case '\t':
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\t");
                    break;
                case '\n':
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\r");
                    break;
                case '\\':
                case '"':
                case '\'':
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\%c", val);
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\u00%02X", val);
                    } else {
                        MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!mysql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!mysql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mysql_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!mysql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mysql_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!mysql_get_val_func(&b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", val);
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
        }
    }

    return true;
}

#endif // BLOCK_BUF == 0
