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

#ifndef REGFILE_PCRE_H
#define REGFILE_PCRE_H

#include <pcre.h>
#include <stdio.h>
#include "global.h"

/* Options. Some are compile-time only, some are run-time only, and some are
both, so we keep them all distinct. However, almost all the bits in the options
word are now used. In the long run, we may have to re-use some of the
compile-time only bits for runtime options, or vice versa.

#define PCRE_CASELESS           0x00000001  // Compile
#define PCRE_MULTILINE          0x00000002  // Compile
#define PCRE_DOTALL             0x00000004  // Compile
#define PCRE_EXTENDED           0x00000008  // Compile
#define PCRE_ANCHORED           0x00000010  // Compile, exec, DFA exec
#define PCRE_DOLLAR_ENDONLY     0x00000020  // Compile
#define PCRE_EXTRA              0x00000040  // Compile
#define PCRE_NOTBOL             0x00000080  // Exec, DFA exec
#define PCRE_NOTEOL             0x00000100  // Exec, DFA exec
#define PCRE_UNGREEDY           0x00000200  // Compile
#define PCRE_NOTEMPTY           0x00000400  // Exec, DFA exec
#define PCRE_UTF8               0x00000800  // Compile
#define PCRE_NO_AUTO_CAPTURE    0x00001000  // Compile
#define PCRE_NO_UTF8_CHECK      0x00002000  // Compile, exec, DFA exec
#define PCRE_AUTO_CALLOUT       0x00004000  // Compile
#define PCRE_PARTIAL_SOFT       0x00008000  // Exec, DFA exec
#define PCRE_PARTIAL            0x00008000  // Backwards compatible synonym
#define PCRE_DFA_SHORTEST       0x00010000  // DFA exec
#define PCRE_DFA_RESTART        0x00020000  // DFA exec
#define PCRE_FIRSTLINE          0x00040000  // Compile
#define PCRE_DUPNAMES           0x00080000  // Compile
#define PCRE_NEWLINE_CR         0x00100000  // Compile, exec, DFA exec
#define PCRE_NEWLINE_LF         0x00200000  // Compile, exec, DFA exec
#define PCRE_NEWLINE_CRLF       0x00300000  // Compile, exec, DFA exec
#define PCRE_NEWLINE_ANY        0x00400000  // Compile, exec, DFA exec
#define PCRE_NEWLINE_ANYCRLF    0x00500000  // Compile, exec, DFA exec
#define PCRE_BSR_ANYCRLF        0x00800000  // Compile, exec, DFA exec
#define PCRE_BSR_UNICODE        0x01000000  // Compile, exec, DFA exec
#define PCRE_JAVASCRIPT_COMPAT  0x02000000  // Compile
#define PCRE_NO_START_OPTIMIZE  0x04000000  // Compile, exec, DFA exec
#define PCRE_NO_START_OPTIMISE  0x04000000  // Synonym
#define PCRE_PARTIAL_HARD       0x08000000  // Exec, DFA exec
#define PCRE_NOTEMPTY_ATSTART   0x10000000  // Exec, DFA exec
#define PCRE_UCP                0x20000000  // Compile
*/

// User definition

#define RULE_OPTIMIZE 0 // 0: No opt rules allocated 1: Allocate opt rule structure & compile regex
#define REGEX_MODE PCRE_DOTALL // regex compile time options

// local defines
#define HDRSELMX 5

// global structs
typedef struct {
	uint32_t count;
	pcre **compRex;
#if RULE_OPTIMIZE == 1
	pcre_extra **studyRex;
#endif
	uint16_t *class;
	uint16_t *isstate;
	uint16_t *andMsk;
	uint16_t *andPin;
	uint16_t *hdrSel[HDRSELMX];
	uint16_t *offset;
	uint8_t *flags;
	uint8_t *alarmcl;
	uint8_t *severity;
} rex_table_t;

int16_t rex_load(const char *filename, rex_table_t *preg_table);

#endif // REGFILE_H_
