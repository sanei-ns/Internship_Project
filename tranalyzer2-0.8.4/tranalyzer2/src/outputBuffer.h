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

#ifndef __OUTPUTBUFFER_H__
#define __OUTPUTBUFFER_H__

#include "tranalyzer.h"
#include <stddef.h> // size_t
#include <inttypes.h>

// user defines
#define BUF_DATA_SHFT    0  // adds for each binary output record the length and
                            // shifts the record by n uint32_t words to the right
                            // (see binSink and socketSink plugins)
#define OUTBUF_AUTOPILOT 1  // Automatically increase the output buffer when required
#define OUTBUF_MAXSIZE_F 5  // Maximal factor to increase the output buffer size to
                            // (f * MAIN_OUTPUT_BUFFER_SIZE)

// local defines
#define BUFFER_DATAP (BUF_DATA_SHFT * 4)

typedef struct {
    size_t    size;
    uint32_t  pos;
    char     *buffer;
} outputBuffer_t;


/* Variables */

extern const uint32_t ZERO;
extern const uint32_t ONE;


/* Functions */

outputBuffer_t *outputBuffer_initialize(size_t size);
void outputBuffer_destroy(outputBuffer_t *buffer);

#if BLOCK_BUF == 1
// No output if BLOCK_BUF == 1
#define outputBuffer_append(buf, val, size)
#define outputBuffer_reset(buf)
#else // BLOCK_BUF == 1
extern void outputBuffer_append(outputBuffer_t *buffer, const char *output, size_t size);
extern void outputBuffer_reset(outputBuffer_t *buffer);
#endif // BLOCK_BUF == 1

// Append values with given size
#define OUTBUF_APPEND(buf, val, size) outputBuffer_append(buf, (char*)&(val), size)

// Append unsigned values
#define OUTBUF_APPEND_U8(buf, val)  OUTBUF_APPEND(buf, val, sizeof(uint8_t))
#define OUTBUF_APPEND_U16(buf, val) OUTBUF_APPEND(buf, val, sizeof(uint16_t))
#define OUTBUF_APPEND_U32(buf, val) OUTBUF_APPEND(buf, val, sizeof(uint32_t))
#define OUTBUF_APPEND_U64(buf, val) OUTBUF_APPEND(buf, val, sizeof(uint64_t))

// Append signed values
#define OUTBUF_APPEND_I8(buf, val)  OUTBUF_APPEND(buf, val, sizeof(int8_t))
#define OUTBUF_APPEND_I16(buf, val) OUTBUF_APPEND(buf, val, sizeof(int16_t))
#define OUTBUF_APPEND_I32(buf, val) OUTBUF_APPEND(buf, val, sizeof(int32_t))
#define OUTBUF_APPEND_I64(buf, val) OUTBUF_APPEND(buf, val, sizeof(int64_t))

// Append floating points values
#define OUTBUF_APPEND_FLT(buf, val) OUTBUF_APPEND(buf, val, sizeof(float))
#define OUTBUF_APPEND_DBL(buf, val) OUTBUF_APPEND(buf, val, sizeof(double))

// Append string values
#define OUTBUF_APPEND_STR(buf, val) outputBuffer_append(buf, val, strlen(val)+1)

// Append time values
#define OUTBUF_APPEND_TIME(buf, sec, usec) \
    OUTBUF_APPEND_U64(buf, sec); \
    OUTBUF_APPEND_U32(buf, usec)

// Append IP values
#define OUTBUF_APPEND_IP4(buf, ip) OUTBUF_APPEND_U32(buf, ip.IPv4.s_addr)
#define OUTBUF_APPEND_IP6(buf, ip) OUTBUF_APPEND(buf, ip.IPv6.s6_addr[0], 16)

// Append IPvX
#define OUTBUF_APPEND_IPVX(buf, version, ip) \
    OUTBUF_APPEND_U8(buf, version); \
    if (version == 6) { \
        OUTBUF_APPEND_IP6(buf, ip); \
    } else { \
        OUTBUF_APPEND_IP4(buf, ip); \
    }

// Appends the number of repetitive values (uint32_t)
#define OUTBUF_APPEND_NUMREP(buf, reps) OUTBUF_APPEND_U32(buf, reps)

// Append optional repetitive string (0 or 1), i.e.,
// if val is NULL or empty, append 0 (uint32_t)
// else append 1 (uint32_t) and the string
#define OUTBUF_APPEND_OPTSTR(buf, val) { \
	const size_t len = val ? strlen(val) : 0; \
	if (len == 0) { \
		OUTBUF_APPEND_NUMREP(buf, ZERO); \
	} else { \
		OUTBUF_APPEND_NUMREP(buf, ONE); \
		outputBuffer_append(buf, val, len+1); \
	} \
}

#endif /* __OUTPUTBUFFER_H__ */
