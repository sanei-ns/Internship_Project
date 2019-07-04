/*
 * mongoSink.h
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

#ifndef __MONGO_SINK_H__
#define __MONGO_SINK_H__

// local includes
#include "global.h"

// user defines
#define MONGO_QRY_LEN    2048            // Max length for query
#define MONGO_HOST       "127.0.0.1"     // Address of the database
#define MONGO_PORT       "27017"         // Port the database is listening to
#define MONGO_DBNAME     "tranalyzer"    // Name of the database
#define MONGO_TABLE_NAME "flow"          // Name of the database flow table
#define MONGO_NUM_DOCS   1               // Number of documents (flows) to write in bulk
                                         // (one minimum, i.e., MUST be > 0)

#define BSON_SUPPRESS_EMPTY_ARRAY 1 // Whether or not to output empty fields
#define BSON_DEBUG                0 // Print debug messages

#endif // __MONGO_SINK_H__
