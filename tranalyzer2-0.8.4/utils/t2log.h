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

#ifndef __T2_LOG_H__
#define __T2_LOG_H__


// includes
#include "t2utils.h"    // for T2_CONV_NUM, t2_conv_readable_num
#include "tranalyzer.h" // for DEBUG

#include <inttypes.h>  // for PRIu64
//#include <stdio.h>     // for FILE
//#ifdef __APPLE__
//#include <sys/time.h>  // for struct timeval
//#else // !__APPLE__
//#include <time.h>
//#endif // !__APPLE__

extern FILE *dooF;

// Configuration options
#define T2_LOG_COLOR 1 // Whether or not to color messages


// Buffer size for time conversion
#define MAX_TM_BUF 35

// Macro to change colors
#if T2_LOG_COLOR == 1
#define RED_BOLD    "\x1b[1;31m"
#define RED         "\x1b[0;31m"
#define GREEN_BOLD  "\x1b[1;32m"
#define GREEN       "\x1b[0;32m"
#define YELLOW_BOLD "\x1b[1;33m"
#define YELLOW      "\x1b[0;33m"
#define BLUE_BOLD   "\x1b[1;34m"
#define BLUE        "\x1b[0;34m"
#define BOLD        "\x1b[1m"
#define NOCOLOR     "\x1b[0m"
#else // T2_LOG_COLOR == 0
#define RED_BOLD
#define RED
#define GREEN_BOLD
#define GREEN
#define YELLOW_BOLD
#define YELLOW
#define BLUE_BOLD
#define BLUE
#define BOLD
#define NOCOLOR
#endif // T2_LOG_COLOR == 0


// Macros to print debug messages
#if DEBUG > 0
#define T2_DBG(format, args...) printf(BOLD "[DBG] " NOCOLOR format "\n", ##args)
#define T2_PDBG(plugin_name, format, args...) printf(BOLD "[DBG] %s: " NOCOLOR format "\n", plugin_name, ##args)
#else // DEBUG == 0
#define T2_DBG(format, args...)
#define T2_PDBG(plugin_name, format, args...)
#endif // DEBUG == 0


// Macro to print
//  - information (blue),
//  - ok (green) messages,
//  - warnings (yellow),
//  - errors (red)
#define T2_FLOG(file, format, args...) fprintf(file, format "\n", ##args)
#define T2_FINF(file, format, args...) fprintf(file, BLUE_BOLD "[INF] " BLUE format NOCOLOR "\n", ##args)
#define T2_FOK(file, format, args...) fprintf(file, GREEN_BOLD "[OK] " GREEN format NOCOLOR "\n", ##args)
#define T2_FWRN(file, format, args...) fprintf(file, YELLOW_BOLD "[WRN] " YELLOW format NOCOLOR "\n", ##args)
#define T2_FERR(file, format, args...) fprintf(file, RED_BOLD "[ERR] " RED format NOCOLOR "\n", ##args)


// Same macros, but with implicit use of dooF (-l option)
#define T2_LOG(format, args...) T2_FLOG(dooF, format, ##args)
#define T2_INF(format, args...) T2_FINF(dooF, format, ##args)
#define T2_OK(format, args...) T2_FOK(dooF, format, ##args)
#define T2_WRN(format, args...) T2_FWRN(dooF, format, ##args)
#define T2_ERR(format, args...) T2_FERR(stderr, format, ##args)


// Same macros, but for the plugins (add plugin_name to the message)
#define T2_FPLOG(stream, plugin_name, format, args...) \
    fprintf(stream, BOLD "%s: " NOCOLOR format "\n", plugin_name, ##args)

#define T2_PLOG(plugin_name, format, args...) \
    T2_FPLOG(dooF, plugin_name, format, ##args)
#define T2_POK(plugin_name, format, args...) \
    fprintf(dooF, GREEN_BOLD "[OK] %s: " GREEN format NOCOLOR "\n", plugin_name, ##args)
#define T2_PINF(plugin_name, format, args...) \
    fprintf(dooF, BLUE_BOLD "[INF] %s: " BLUE format NOCOLOR "\n", plugin_name, ##args)
#define T2_PWRN(plugin_name, format, args...) \
    fprintf(dooF, YELLOW_BOLD "[WRN] %s: " YELLOW format NOCOLOR "\n", plugin_name, ##args)
#define T2_PERR(plugin_name, format, args...) do { \
    fprintf(stderr, RED_BOLD "[ERR] %s: " RED format NOCOLOR "\n", plugin_name, ##args); \
    fflush(stderr); \
} while(0)


// Logs num to stream
#define T2_FLOG_NUM0(stream, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, "%s: %"PRIu64"%s\n", prefix, (uint64_t)(num), str); \
}

// Logs num > 0 to stream
#define T2_FLOG_NUM(stream, prefix, num) \
    if ((num) > 0) T2_FLOG_NUM0(stream, prefix, num)

// Logs num and percentage to stream
#define T2_FLOG_NUMP0(stream, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, "%s: %"PRIu64"%s [%.2f%%]\n", prefix, (uint64_t)(num), str, 100.0*(num)/(double)(total)); \
}

// Logs num > 0 and percentage to stream
#define T2_FLOG_NUMP(stream, prefix, num, total) \
    if ((num) > 0) T2_FLOG_NUMP0(stream, prefix, num, total)

// Logs num with plugin name and percentage to stream
#define T2_FPLOG_NUMP0(stream, plugin, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, BOLD "%s: " NOCOLOR "%s: %"PRIu64"%s [%.2f%%]\n", plugin, prefix, (uint64_t)(num), str, 100.0*(num)/(double)(total)); \
}

// Logs num to dooF (final report file/stdout)
#define T2_LOG_NUM0(prefix, num) T2_FLOG_NUM0(dooF, prefix, num)

// Logs num > 0 to dooF (final report file/stdout)
#define T2_LOG_NUM(prefix, num) T2_FLOG_NUM(dooF, prefix, num)

// Logs num and percentage to dooF (final report file/stdout)
#define T2_LOG_NUMP0(prefix, num, total) T2_FLOG_NUMP0(dooF, prefix, num, total)

// Logs num > 0 and percentage to dooF (final report file/stdout)
#define T2_LOG_NUMP(prefix, num, total) T2_FLOG_NUMP(dooF, prefix, num, total)

// Logs num with plugin name to stream
#define T2_FPLOG_NUM0(stream, plugin, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, BOLD "%s: " NOCOLOR "%s: %"PRIu64"%s\n", plugin, prefix, (uint64_t)(num), str); \
}

// Logs num with plugin name to dooF (final report file/stdout)
#define T2_PLOG_NUM0(plugin, prefix, num) \
    T2_FPLOG_NUM0(dooF, plugin, prefix, num)

// Logs num > 0 with plugin name to dooF (final report file/stdout)
#define T2_PLOG_NUM(plugin, prefix, num) \
    if ((num) > 0) T2_PLOG_NUM0(plugin, prefix, num)

// Logs num > 0 with plugin name to stream
#define T2_FPLOG_NUM(stream, plugin, prefix, num) \
    if ((num) > 0) T2_FPLOG_NUM0(stream, plugin, prefix, num)

// Logs num with plugin name and percentage to dooF (final report file/stdout)
#define T2_PLOG_NUMP0(plugin, prefix, num, total) \
    T2_FPLOG_NUMP0(dooF, plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to dooF (final report file/stdout)
#define T2_PLOG_NUMP(plugin, prefix, num, total) \
    if ((num) > 0) T2_PLOG_NUMP0(plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to stream
#define T2_FPLOG_NUMP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPLOG_NUMP0(stream, plugin, prefix, num, total)

// Logs num with plugin name and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUMP0(stream, plugin, prefix, num, total) \
    T2_FPLOG_NUMP0(stream, plugin, prefix, ((num)-(num##0)), ((total)-(total##0)))

// Logs num > 0 with plugin name and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUMP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPLOG_DIFFNUMP0(stream, plugin, prefix, num, total)

// Logs numbers in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUM0(stream, prefix, num) \
    T2_FLOG_NUM(stream, prefix, ((num)-(num##0)))

// Logs numbers > 0 in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUM(stream, prefix, num) \
    if ((num) > 0) T2_LOG_DIFFNUM0(stream, prefix, num)

// Logs numbers and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUMP0(stream, prefix, num, tot) \
    T2_FLOG_NUMP(stream, prefix, ((num)-(num##0)), ((tot)-(tot##0)))

// Logs numbers > 0 and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUMP(stream, prefix, num, tot) \
    if ((num) > 0) T2_LOG_DIFFNUMP0(stream, prefix, num, tot)

// Logs plugin name, numbers and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_PLOG_DIFFNUMP0(stream, plugin, prefix, num, tot) { \
    char str[64]; \
    T2_CONV_NUM(((num)-(num##0)), str); \
    fprintf(stream, BOLD "%s: " NOCOLOR "%s: %"PRIu64"%s [%.2f%%]\n", plugin, prefix, (uint64_t)((num)-(num##0)), str, 100.0*((num)-(num##0))/(double)((tot)-(tot##0))); \
}

// Logs plugin name, numbers > 0 and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_PLOG_DIFFNUMP(stream, plugin, prefix, num, tot) \
    if ((num) > 0) T2_PLOG_DIFFNUMP0(stream, plugin, prefix, num, tot)

// Assumes num is in Kb/s
#define T2_LOG_SPEED(stream, prefix, num) { \
    char str[64]; \
    t2_conv_readable_num((num)*1000, str, sizeof(str), "b/s"); \
    fprintf(stream, "%s: %.0f b/s%s\n", prefix, (num)*1000, str); \
}


// Log date in unix timestamp and in a human readable way (UTC or localtime)
extern void t2_log_date(FILE *stream, const char *prefix, struct timeval date, int utc);

// Log time in seconds and in a human readable way (days, hours, minutes and seconds)
extern void t2_log_time(FILE *stream, const char *prefix, struct timeval time);

#endif // __T2_LOG_H__
