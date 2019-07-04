/*
 * pcapd.h
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

#ifndef __PCAPD_H__
#define __PCAPD_H__

// local includes
#include "global.h"


// user defines

#define PD_MODE_IN  0 // 0: extract flows listed in input file (if -e option was used),
                      //    or extract flows if alarm bit is set (if -e option was not used)
                      // 1: dump all packets

#define PD_EQ       1 // whether to dump matching (1) or non-matching (0) flows

#define PD_MODE_OUT 0 // 0: one pcap,
                      // 1: one pcap per flow

#define PD_SPLIT    1 // whether or not to split output file (-W option)

#define PD_FORMAT   0 // Format of the input file (-e option):
                      //   0: flow index only,
                      //   1: flow file format

#define PD_MAX_FD 128 // Maximum number of simultaneously open file descriptors

#define PD_SUFFIX ".pcap" // extension for generated pcap file

#endif // __PCAPD_H__
