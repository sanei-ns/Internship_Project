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

#include "outputBuffer.h"
#include "global.h"


const uint32_t ZERO = 0;
const uint32_t ONE  = 1;


#if OUTBUF_AUTOPILOT == 1
// Double the buffer size
#define OUTPUTBUFFER_DOUBLE_CAPACITY(buffer) do { \
	char *tmp; \
    buffer->size <<= 1; \
    buffer->buffer -= BUFFER_DATAP; \
	if (UNLIKELY(!(tmp = realloc(buffer->buffer, buffer->size)))) { \
		T2_ERR("Failed to reallocate memory for output buffer"); \
        outputBuffer_destroy(buffer); \
		exit(1); \
	} \
    buffer->buffer = tmp; \
	buffer->buffer += BUFFER_DATAP; \
} while (0)
#endif // OUTBUF_AUTOPILOT == 1


outputBuffer_t *outputBuffer_initialize(size_t size) {
	outputBuffer_t* buffer;
	if (UNLIKELY(!(buffer = malloc(sizeof(*buffer))))) {
		T2_ERR("Failed to allocate memory for outputBuffer");
		exit(-1);
	}

	if (UNLIKELY(!(buffer->buffer = calloc(size+1, sizeof(char))))) {
		T2_ERR("Failed to allocate memory for outputBuffer");
		free(buffer);
		exit(-1);
	}

	buffer->buffer += BUFFER_DATAP;
	buffer->size = size - BUFFER_DATAP;
	buffer->pos = 0;

	return buffer;
}


#if BLOCK_BUF == 0
inline void outputBuffer_append(outputBuffer_t *buffer, const char *output, size_t size) {
#if DEBUG > 0
	if (UNLIKELY(!buffer || !output || size == 0)) {
		T2_ERR("Invalid parameters passed to outputBuffer_append");
		exit(1);
	}
#endif // DEBUG > 0

	if (UNLIKELY(buffer->pos + size >= buffer->size)) {
#if OUTBUF_AUTOPILOT == 1
        if (2 * buffer->size < OUTBUF_MAXSIZE_F * MAIN_OUTPUT_BUFFER_SIZE) {
	   	    T2_INF("output buffer full, doubling its capacity");
            OUTPUTBUFFER_DOUBLE_CAPACITY(buffer);
            return outputBuffer_append(buffer, output, size);
        }
#endif // OUTBUF_AUTOPILOT == 1
		T2_ERR("Buffer overflow in outputBuffer");
		exit(-1); // appending was NOT successful
	}

	memcpy(&(buffer->buffer[buffer->pos]), output, size);
	buffer->pos += size;
	//buffer->buffer[buffer->pos] = '\0'; // terminate string
}
#endif // BLOCK_BUF == 0


#if BLOCK_BUF == 0
inline void outputBuffer_reset(outputBuffer_t *buffer) {
	if (UNLIKELY(!buffer)) {
		T2_ERR("Cannot reset NULL buffer");
		exit(1);
	}

	buffer->buffer[BUFFER_DATAP] = '\0';
	buffer->pos = 0;
}
#endif // BLOCK_BUF == 0


void outputBuffer_destroy(outputBuffer_t *buffer) {
	if (UNLIKELY(!buffer)) return;

	if (LIKELY(buffer->buffer != NULL)) {
		buffer->buffer -= BUFFER_DATAP;
		free(buffer->buffer);
	}

	free(buffer);
}
