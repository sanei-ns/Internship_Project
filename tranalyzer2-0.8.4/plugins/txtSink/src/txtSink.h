/*
 * txtSink.h
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

#ifndef __TXT_SINK_H__
#define __TXT_SINK_H__

// global includes
#include "global.h"

// User defines
#define TFS_SPLIT      1 // whether or not to split output file (-W option)
#define TFS_PRI_HDR    1 // 1: print header row at start of flow file
#define TFS_HDR_FILE   1 // 1: print header file with detailed column information
#define TFS_PRI_HDR_FW 0 // -W option, print header in every output fragment
#define GZ_COMPRESS    0 // Whether or not to compress the output (gzip)

#define FLOWS_TXT_SUFFIX "_flows.txt"
#define HEADER_SUFFIX    "_headers.txt"

#endif // __TXT_SINK_H__
