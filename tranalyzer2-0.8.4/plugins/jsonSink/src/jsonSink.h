/*
 * jsonSink.h
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

#ifndef JSON_SINK_H
#define JSON_SINK_H

// local includes
#include "global.h"
#include "binaryValue.h"

// user defines
#define SOCKET_ON               0 // Whether to output to a socket (1) or file (0)
#define GZ_COMPRESS             0 // Whether or not to compress the output (gzip)
#define JSON_SPLIT              1 // Whether or not to split output file (-W option)
#define JSON_ROOT_NODE          0 // Whether or not to surround the output with a root node (array)
#define SUPPRESS_EMPTY_ARRAY    1 // Whether or not to output empty fields
#define JSON_NO_SPACES          1 // Suppress unnecessary spaces (1)

#define JS_BUFFER_SIZE (1 << 20)  // size of outputbuffer

#if SOCKET_ON == 1

#define SOCKET_ADDR "127.0.0.1"   // address of the socket
#define SOCKET_PORT 5000          // port of the socket

#else // SOCKET_ON == 0

#define JSON_SUFFIX "_flows.json" // suffix for output file

#endif // SOCKET_ON == 0

#endif // JSON_SINK_H
