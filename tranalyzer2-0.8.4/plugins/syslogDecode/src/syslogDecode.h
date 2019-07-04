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

#ifndef __SYSLOGDECODE_H__
#define __SYSLOGDECODE_H__

// local includes
#include "global.h"

// user config: compile switches
//#define SYSLOG_SUFFIX "_syslog.txt" // pkt file name ext

// plugin defines
#define ERROR_PREFIX "syslogDecode"

// SYSLOG  types
//#define SYSLM_JAN 0x4a616e
//#define SYSLM_FEB 0x466562
//#define SYSLM_MAR 0x4d6172
//#define SYSLM_APR 0x417072
//#define SYSLM_MAI 0x4d6179
//#define SYSLM_JUN 0x4a756e
//#define SYSLM_JUL 0x4a756c
//#define SYSLM_AUG 0x417567
//#define SYSLM_SEP 0x536570
//#define SYSLM_OCT 0x4f6374
//#define SYSLM_NOV 0x4e6f76
//#define SYSLM_DEC 0x446563

// syslog status
#define SYS_DET     0x01 // Syslog detected
#define SYS_CNTOVRN 0x80 // Counter for severity/facility overflowed

// global defs
enum SYSL_Fac {
    kernel=0,
    user,
    mail,
    _system,
    authorization,
    internal,
    printer,
    network,
    UUCP,
    _clock,
    security,
    FTP,
    NTP,
    logaudit,
    logalert,
    clockdaemon,
    local0,
    local1,
    local2,
    local3,
    local4,
    local5,
    local6,
    local7,
    SYS_NUM_FAC
};

enum SYSL_Sev {
    Emergency=0,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Informational,
    Debug,
    SYS_NUM_SEV
};

//structures

typedef struct {
    uint32_t sum;
    uint32_t cnt[SYS_NUM_SEV][SYS_NUM_FAC];
    uint8_t stat;
} syslogFlow_t;

#endif // __SYSLOGDECODE_H__
