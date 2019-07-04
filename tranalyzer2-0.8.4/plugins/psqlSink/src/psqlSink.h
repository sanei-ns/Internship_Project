/*
 * psqlSink.h
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

#ifndef __PSQL_SINK_H__
#define __PSQL_SINK_H__

// local includes
#include "global.h"

// user defines
#define PSQL_OVERWRITE_DB    2 // 0: abort if DB already exists
                               // 1: overwrite DB if it already exists
                               // 2: reuse DB if it already exists

#define PSQL_OVERWRITE_TABLE 2 // 0: abort if table already exists
                               // 1: overwrite table if it already exists
                               // 2: append to table if it already exists

#define PSQL_TRANSACTION_NFLOWS 40000 //   0: one transaction
                                      // > 0: one transaction every n flows

#define PSQL_QRY_LEN    32768           // Max length for query
#define PSQL_HOST       "127.0.0.1"     // Address of the database
#define PSQL_PORT       5432            // Port of the database
#define PSQL_USER       "postgres"      // Username to connect to DB
#define PSQL_PASS       "postgres"      // Password to connect to DB
#define PSQL_DBNAME     "tranalyzer"    // Name of the database
#define PSQL_TABLE_NAME "flow"          // Name of the database flow table

#endif // __PSQL_SINK_H__
