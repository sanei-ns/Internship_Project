/*
 * binSink.h
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

#ifndef __BIN_SINK_H__
#define __BIN_SINK_H__

// global includes

// local includes
#include "global.h"

// user defines
#define GZ_COMPRESS             0 // whether or not to compress the output (gzip)
#define SFS_SPLIT               1 // whether or not to split output file (-W option)
#define FLOWS_SUFFIX "_flows.bin" // suffix for output file

#define STD_BUFSHFT  (BUF_DATA_SHFT * 4)

#endif // __BIN_SINK_H__
