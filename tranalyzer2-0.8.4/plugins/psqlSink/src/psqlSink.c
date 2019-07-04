/*
 * psqlSink.c
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

#include "psqlSink.h"
#include "bin2txt.h"

#include <libpq-fe.h>
#include <string.h>


#if BLOCK_BUF == 0

// Static variables

static PGconn *db_conn;
static char * const db_types[] = {
    "text",                     // bt_compound
    "smallint",                 // bt_int_8
    "smallint",                 // bt_int_16
    "integer",                  // bt_int_32
    "bigint",                   // bt_int_64
    "numeric",                  // bt_int_128
    "numeric",                  // bt_int_256
    "smallint",                 // bt_uint_8
    "integer",                  // bt_uint_16
    "bigint",                   // bt_uint_32
    "numeric",                  // bt_uint_64   XXX bigint?
    "numeric",                  // bt_uint_128
    "numeric",                  // bt_uint_256
    //"bit(8)",                   // bt_hex_8
    //"bit(16)",                  // bt_hex_16
    //"bit(32)",                  // bt_hex_32
    //"bit(64)",                  // bt_hex_64
    //"bit(128)",                 // bt_hex_128
    //"bit(256)",                 // bt_hex_256
    "smallint",                 // bt_hex_8
    "integer",                  // bt_hex_16
    "bigint",                   // bt_hex_32
    "numeric",                  // bt_hex_64
    "numeric",                  // bt_hex_128
    "numeric",                  // bt_hex_256
    "real",                     // bt_float
    "double precision",         // bt_double
    "double precision",         // bt_long_double (XXX precision loss)
    "char",                     // bt_char
    "text",                     // bt_string
    "char",                     // bt_flow_direction
    "timestamp with time zone", // bt_timestamp
    "interval",                 // bt_duration
    "macaddr",                  // bt_mac_addr
    "inet",                     // bt_ip4_addr
    "inet",                     // bt_ip6_addr
    "inet",                     // bt_ipx_addr
    "text",                     // bt_string_class
};
#if PSQL_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // PSQL_TRANSACTION_NFLOWS > 1


// Function prototypes

static inline PGconn *db_connect(const char *dbname);
static inline void db_cleanup(PGconn *conn);
static inline PGresult *db_query_res(PGconn *conn, const char *qry);
static inline void db_query(PGconn *conn, const char *qry);
static inline void db_create(PGconn *conn, const char *dbname);
static inline void db_create_flow_table(PGconn *conn, const char *name);
#if PSQL_OVERWRITE_DB == 1
static inline void db_drop(PGconn *conn, const char *dbname);
#endif // PSQL_OVERWRITE_DB == 1
#if PSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(PGconn *conn, const char *name);
#endif // PSQL_OVERWRITE_TABLE == 1
static inline bool db_exists(PGconn *conn, const char *dbname);
static inline bool db_table_exists(PGconn *conn, const char *name);
static inline bool psql_get_val_func(void *dest, size_t size, size_t n);
static int psql_parse_sv_type(char *qry, int pos, uint32_t type);
static int psql_parse_sv(char *qry, int pos, binary_subvalue_t *sv);
static bool psql_sanitize_utf8(char *qry, int *pos);


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define PSQL_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR("psqlSink", "query truncated... increase PSQL_QRY_LEN"); \
        db_cleanup(db_conn); \
        exit(1); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("psqlSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("psqlSink", "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

    // Connect to the DB
    db_conn = db_connect("postgres");

    // Create DB
    bool exists = db_exists(db_conn, PSQL_DBNAME);
    if (exists) {
#if PSQL_OVERWRITE_DB == 0
        T2_PERR("psqlSink", "Database '%s' already exists", PSQL_DBNAME);
        db_cleanup(db_conn);
        exit(1);
#elif PSQL_OVERWRITE_DB == 1
        db_drop(db_conn, PSQL_DBNAME);
        exists = false;
#endif // PSQL_OVERWRITE_DB == 1
    }

    if (!exists) {
        db_create(db_conn, PSQL_DBNAME);
    }

    db_cleanup(db_conn);

    // Connect to the DB
    db_conn = db_connect(PSQL_DBNAME);

    // Create table
    exists = db_table_exists(db_conn, PSQL_TABLE_NAME);
    if (exists) {
#if PSQL_OVERWRITE_TABLE == 0
        T2_PERR("psqlSink", "Database '%s' already exists", PSQL_DBNAME);
        db_cleanup(db_conn);
        exit(1);
#elif PSQL_OVERWRITE_TABLE == 1
        db_drop_table(db_conn, PSQL_TABLE_NAME);
        exists = false;
#else // PSQL_OVERWRITE_TABLE == 2
        // TODO test that schema matches
#endif // PSQL_OVERWRITE_TABLE == 2
    }

    if (!exists) {
        db_create_flow_table(db_conn, PSQL_TABLE_NAME);
    }

    // Begin the transaction
#if PSQL_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "BEGIN");
#endif // PSQL_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void onApplicationTerminate() {
    // End the transaction
#if PSQL_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // PSQL_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "COMMIT");
    db_cleanup(db_conn);
}


static inline PGconn *db_connect(const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, sizeof(qry), "host=%s port=%d dbname=%s user=%s password=%s connect_timeout=10 sslmode=disable", PSQL_HOST, PSQL_PORT, dbname, PSQL_USER, PSQL_PASS);
    PGconn *conn = PQconnectdb(qry);
    if (UNLIKELY(PQstatus(conn) == CONNECTION_BAD)) {
        T2_PERR("psqlSink", "Failed to connect to DB '%s' on '%s' with user '%s'", dbname, PSQL_HOST, PSQL_USER);
        PQfinish(conn);
        exit(1);
    }
    return conn;
}


static inline void db_cleanup(PGconn *conn) {
    PQfinish(conn);
}


// Returned value must be free'd with PQclear()
static inline PGresult *db_query_res(PGconn *conn, const char *qry) {
    PGresult *res = PQexec(conn, qry);
    if (UNLIKELY(strlen(PQresultErrorMessage(res)))) {
        T2_PERR("psqlSink", "Failed to execute query '%s': %s", qry, PQresultErrorMessage(res));
        PQclear(res);
        db_cleanup(conn);
        exit(1);
    }
    return res;
}


static inline void db_query(PGconn *conn, const char *qry) {
    PGresult *res = db_query_res(conn, qry);
    PQclear(res);
}


static inline void db_create(PGconn *conn, const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "CREATE DATABASE %s;", dbname);
    db_query(conn, qry);
}


static inline void db_create_flow_table(PGconn *conn, const char *name) {
    char qry[PSQL_QRY_LEN];
    int pos = snprintf(qry, PSQL_QRY_LEN, "CREATE TABLE %s (id bigserial", name);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ", \"%s\"", bv->name);
        char *type, *type2;
        if (bv->num_values > 1) {
            type = "text";
        } else {
            const uint32_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR("psqlSink", "Unhandled type %u", t);
                db_cleanup(conn);
                exit(1);
            }
            type = db_types[t];
        }
        type2 = bv->is_repeating ? "[]" : "";
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, " %s%s", type, type2);
        bv = bv->next;
    }
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ");");
    db_query(conn, qry);
}


#if PSQL_OVERWRITE_DB == 1
static inline void db_drop(PGconn *conn, const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "DROP DATABASE %s;", dbname);
    db_query(conn, qry);
}
#endif // PSQL_OVERWRITE_DB == 1


#if PSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(PGconn *conn, const char *name) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "DROP TABLE %s;", name);
    db_query(conn, qry);
}
#endif // PSQL_OVERWRITE_TABLE == 1


static inline bool db_exists(PGconn *conn, const char *dbname) {
    PGresult *res = db_query_res(conn, "SELECT datname FROM pg_database;");
    if (UNLIKELY(!res)) {
        db_cleanup(conn);
        exit(1);
    }
    bool exists = false;
    const int num_rows = PQntuples(res);
    for (int_fast32_t i = 0; i < num_rows; i++) {
        if (strcasecmp(PQgetvalue(res, i, 0), dbname) == 0) {
            exists = true;
            break;
        }
    }
    PQclear(res);
    return exists;
}


static inline bool db_table_exists(PGconn *conn, const char *name) {
    PGresult *res = db_query_res(conn, "SELECT tablename FROM pg_tables WHERE schemaname = 'public';");
    if (UNLIKELY(!res)) {
        db_cleanup(conn);
        exit(1);
    }
    bool exists = false;
    const int num_rows = PQntuples(res);
    for (int_fast32_t i = 0; i < num_rows; i++) {
        if (strcasecmp(PQgetvalue(res, i, 0), name) == 0) {
            exists = true;
            break;
        }
    }
    PQclear(res);
    return exists;
}


static inline bool psql_get_val_func(void *dest, size_t size, size_t n) {
    outputBuffer_t *buffer = main_output_buffer;
    const size_t sn = size * n;
    if (UNLIKELY(buffer->size < buffer->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buffer->pos + sn;
        T2_PERR("psqlSink", "Buffer overflow: %zu increase MAIN_OUTPUT_BUFFER_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buffer->buffer + buffer->pos, sn);
    buffer->pos += sn;
    return true;
}


static int psql_parse_sv_type(char *qry, int pos, uint32_t type) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRId8, val);
            break;
        }
        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRId16, val);
            break;
        }
        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRId32, val);
            break;
        }
        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRId64, val);
            break;
        }
        //case bt_int_128:
        //case bt_int_256:
        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu8, val);
            break;
        }
        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu16, val);
            break;
        }
        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu32, val);
            break;
        }
        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu64, val);
            break;
        }
        //case bt_uint_128:
        //case bt_uint_256:
        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu8, val);
            break;
        }
        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu16, val);
            break;
        }
        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu32, val);
            break;
        }
        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu64, val);
            break;
        }
        //case bt_hex_128:
        //case bt_hex_256:
        case bt_float: {
            float val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_double: {
            double val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%f", val);
            break;
        }
        case bt_long_double: {
            long double val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%Lf", val);
            break;
        }
        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%c", val);
            break;
        }
        case bt_string_class:
        case bt_string: {
            if (UNLIKELY(!psql_sanitize_utf8(qry, &pos))) {
                exit(1);
            }
            break;
        }
        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%c", (val == 0) ? 'A' : 'B');
            break;
        }
        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
                exit(1);
            }
            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!psql_get_val_func(&ns, sizeof(ns), 1))) {
                exit(1);
            }

#if B2T_TIME_IN_MICRO_SECS != 0
            ns /= 1000;
#endif // B2T_TIME_IN_MICRO_SECS != 0

            if (type == bt_duration) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%"PRIu64".%"B2T_TPFRMT, val, ns);
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
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s.%"B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "+0000");
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", timeBuf);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
            break;
        }
        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!psql_get_val_func(&val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos,
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                    "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            break;
        }
        case bt_ip4_addr: {
psql_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!psql_get_val_func(&val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, val, addr, INET_ADDRSTRLEN);
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ip6_addr: {
psql_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!psql_get_val_func(&val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                exit(1);
            }
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", addr);
            break;
        }
        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!psql_get_val_func(&version, sizeof(version), 1))) {
                exit(1);
            }
            if (version == 4) {
                goto psql_bt_ip4;
            } else if (version == 6) {
                goto psql_bt_ip6;
            } else {
                T2_PERR("psqlSink", "invalid IP version %"PRIu8, version);
                exit(1);
            }
            break;
        }
        default:
            T2_PERR("psqlSink", "unhandled output type %"PRIu32, type);
            exit(1);
    }
    return pos;
}


static int psql_parse_sv(char *qry, int pos, binary_subvalue_t *sv) {
    if (sv->type) {
        return psql_parse_sv_type(qry, pos, sv->type);
    }

    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!psql_get_val_func(&nr, sizeof(nr), 1))) {
            exit(1);
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            pos = psql_parse_sv(qry, pos, &sv->subval[j]);
            // write value delim
            if (j < nv - 1) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "_");
            }
        }

        // write repeat delim
        if (i < nr - 1) {
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ";");
        }
    }
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ")");
    return pos;
}


void bufferToSink(outputBuffer_t *buffer) {
    const uint32_t bufpos = buffer->pos;
    buffer->pos = 0;
    char qry[PSQL_QRY_LEN];
    int pos = snprintf(qry, PSQL_QRY_LEN, "INSERT INTO %s VALUES (nextval('%s_id_seq')", PSQL_TABLE_NAME, PSQL_TABLE_NAME);
    binary_value_t *bv = main_header_bv;
    while (bv) {
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ", '");
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!psql_get_val_func(&nr, sizeof(nr), 1))) {
                exit(1);
            }
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "{%s", (nr > 0) ? "\"" : "");
        }
        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                pos = psql_parse_sv(qry, pos, &bv->subval[j]);
                if (j < nv - 1) {
                    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "_");
                }
            }
            if (i < nr - 1) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, (bv->is_repeating) ? "\", \"" : ";");
            }
        }
        if (bv->is_repeating) {
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s}'", (nr > 0) ? "\"" : "");
        } else {
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "'");
        }
        bv = bv->next;
    }
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ");");
    db_query(db_conn, qry);
    buffer->pos = bufpos;
#if PSQL_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == PSQL_TRANSACTION_NFLOWS) {
        db_query(db_conn, "COMMIT;");
        db_query(db_conn, "BEGIN;");
        flows_to_commit = 0;
    }
#endif // PSQL_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool psql_sanitize_utf8(char *qry, int *pos) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!psql_get_val_func(&val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
            switch (val) {
                case '\t':
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\t");
                    break;
                case '\n':
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\r");
                    break;
                case '\\':
                case '"':
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\%c", val);
                    break;
                case '\'':
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "''");
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\\\u00%02X", val);
                    } else {
                        PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!psql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!psql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!psql_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!psql_get_val_func(&b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!psql_get_val_func(&b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!psql_get_val_func(&b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", val);
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
        }
    }

    return true;
}

#endif // BLOCK_BUF == 0
