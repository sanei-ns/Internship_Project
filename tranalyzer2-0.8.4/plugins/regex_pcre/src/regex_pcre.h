/*
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


#ifndef __REGEX_PCRE_H__
#define __REGEX_PCRE_H__

// global includes

// local includes
#include "regfile_pcre.h"
#include "global.h"

// User configuration
#define EXPERTMODE  0 // 0: only display the most severe class,
                      // 1: display all matched classes plus some extra information
#define PKTTIME     0 // whether or not to display the time at which a rule was matched
#define LABELSCANS  0 // whether or not to label scans (require tcpFlags plugin)

// defines Regex
#define OVECCOUNT   3 // value % 3
#define MAXREGPOS  30 // Maximal # of matches stored / flow

#define REXPOSIX_FILE "regexfile.txt"   // regexfile name under .tranalyzer/plugins

// defines scans
#define SCANMASK   0x00ff
#define TCPRETRIES 0x0100

// future flag definition
#define REG_F_PRE   0x10
#define REG_F_SUCC  0x20
#define REG_F_PRES  0x40
#define REG_F_ALRM  0x80

// plugin structs

typedef struct rexFlow_s {
	uint16_t pregID[MAXREGPOS];     // pattern match Regex ID
	uint16_t andMsk[MAXREGPOS];     // and mask
	uint16_t andPin[MAXREGPOS];     // and mask
	uint16_t pktN;
#if EXPERTMODE == 1
#if PKTTIME == 1
	struct timeval time[MAXREGPOS];
#endif // PKTTIME == 1
	uint16_t pregPos[MAXREGPOS];
	uint16_t pkt[MAXREGPOS];
#endif // EXPERTMODE == 1
	uint16_t count;
	uint8_t alarmcl[MAXREGPOS];
	uint8_t flags[MAXREGPOS];
	uint8_t severity[MAXREGPOS];
} rexFlow_t;

// global pointer for plugin and potential dependencies
rexFlow_t *rexFlowTable;

#endif // __REGEX_PCRE_H__
