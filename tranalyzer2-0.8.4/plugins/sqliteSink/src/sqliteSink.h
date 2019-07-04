/*
 * sqliteSink.h
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

#ifndef __SQLITE_SINK_H__
#define __SQLITE_SINK_H__

// local includes
#include "global.h"
#include "bin2txt.h"

// user defines
#define SQLITE_OVERWRITE  2  // 0: abort if table already exists
                             // 1: overwrite table if it already exists
                             // 2: append to table if it already exists

#define SQLITE_HEX_AS_INT 0  // 0: store hex numbers (bitfields) as text
                             // 1: store hex numbers (bitfields) as int

#define SQLITE_TRANSACTION_NFLOWS 40000 //   0: one transaction
                                        // > 0: one transaction every n flows

#define SQLITE_QRY_LEN    32768                 // Max length for query
#define SQLITE_DBNAME     "/tmp/tranalyzer.db"  // Name of the database
#define SQLITE_TABLE_NAME "flow"                // Name of the database flow table

#if SQLITE_HEX_AS_INT == 1
#define SQLITE_HEX_TYPE "INT"
#define SQLITE_PREF
#define SQLITE_PRI_HEX8  "%"PRIu8
#define SQLITE_PRI_HEX16 "%"PRIu16
#define SQLITE_PRI_HEX32 "%"PRIu32
#define SQLITE_PRI_HEX64 "%"PRIu64
#else // SQLITE_HEX_AS_INT == 0
#define SQLITE_HEX_TYPE "TEXT"
#define SQLITE_PRI_HEX8  "0x%02"B2T_PRIX8
#define SQLITE_PRI_HEX16 "0x%04"B2T_PRIX16
#define SQLITE_PRI_HEX32 "0x%08"B2T_PRIX32
#define SQLITE_PRI_HEX64 "0x%016"B2T_PRIX64
#endif // SQLITE_HEX_AS_INT == 0

#endif // __SQLITE_SINK_H__
