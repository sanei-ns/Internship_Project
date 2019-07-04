/*
 * t2buf.h
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

#ifndef __T2_BUFFER_H__
#define __T2_BUFFER_H__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    const uint8_t * const buffer;  // byte buffer
    const size_t size;             // size of the buffer
    size_t pos;                    // current reading position in the buffer
} t2buf_t;

typedef enum {
    T2BUF_ASCII,
    T2BUF_ANSI, // not a real encoding, just reads everything up to '\0', this is useful
                // to read a string in an unknown iso-... / windows-... encoding.
    T2BUF_UTF8,
    T2BUF_UTF16,
    T2BUF_UTF16_LE,
} t2buf_encoding;

/* Creates a t2buf_t struct with a byte buffer of length len */
t2buf_t t2buf_create(const uint8_t *buffer, size_t len);

/*
 * The _read_uX functions read numbers stored (in the packet) in network order (big endian).
 * This is the case for most network protocols.
 *
 * These functions return true if the integer was successfully read, false if there was not enough bytes
 * left in the buffer.
 */
bool t2buf_read_u8(t2buf_t *buf, uint8_t *dst);
bool t2buf_read_u16(t2buf_t *buf, uint16_t *dst);
bool t2buf_read_u24(t2buf_t *buf, uint32_t *dst);
bool t2buf_read_u32(t2buf_t *buf, uint32_t *dst);
bool t2buf_read_u48(t2buf_t *buf, uint64_t *dst);
bool t2buf_read_u64(t2buf_t *buf, uint64_t *dst);
bool t2buf_read_n(t2buf_t *buf, uint8_t *dst, size_t len);

/*
 * Same as above read functions but read numbers stored (in the packet) in little endian.
 */
bool t2buf_read_le_u16(t2buf_t *buf, uint16_t *dst);
bool t2buf_read_le_u24(t2buf_t *buf, uint32_t *dst);
bool t2buf_read_le_u32(t2buf_t *buf, uint32_t *dst);
bool t2buf_read_le_u48(t2buf_t *buf, uint64_t *dst);
bool t2buf_read_le_u64(t2buf_t *buf, uint64_t *dst);

/*
 * Same as the t2buf_read functions but do not consume the bytes from the buffer.
 * Return false if not enough bytes were available in the buffer.
 */
bool t2buf_peek_u8(t2buf_t *buf, uint8_t *dst);
bool t2buf_peek_u16(t2buf_t *buf, uint16_t *dst);
bool t2buf_peek_u24(t2buf_t *buf, uint32_t *dst);
bool t2buf_peek_u32(t2buf_t *buf, uint32_t *dst);
bool t2buf_peek_u48(t2buf_t *buf, uint64_t *dst);
bool t2buf_peek_u64(t2buf_t *buf, uint64_t *dst);

bool t2buf_peek_le_u16(t2buf_t *buf, uint16_t *dst);
bool t2buf_peek_le_u24(t2buf_t *buf, uint32_t *dst);
bool t2buf_peek_le_u32(t2buf_t *buf, uint32_t *dst);
bool t2buf_peek_le_u48(t2buf_t *buf, uint64_t *dst);
bool t2buf_peek_le_u64(t2buf_t *buf, uint64_t *dst);

/*
 * This function ignores the next N bytes in the buffer. Returns false if not enough bytes
 * were left in the buffer
 */
bool t2buf_skip_n(t2buf_t *buf, size_t n);
#define t2buf_skip_u8(buf)  t2buf_skip_n((buf), sizeof(uint8_t))
#define t2buf_skip_u16(buf) t2buf_skip_n((buf), sizeof(uint16_t))
#define t2buf_skip_u24(buf) t2buf_skip_n((buf), 3)
#define t2buf_skip_u32(buf) t2buf_skip_n((buf), sizeof(uint32_t))
#define t2buf_skip_u48(buf) t2buf_skip_n((buf), 6)
#define t2buf_skip_u64(buf) t2buf_skip_n((buf), sizeof(uint64_t))

/*
 * This function returns the number of bytes left in the buffer, a negative number means
 * that too many bytes were read or skipped during a previous operation.
 */
int64_t t2buf_left(t2buf_t *buf);


/*
 * Returns the current position in the buffer. Similar to ftell.
 */
long t2buf_tell(t2buf_t *buf);

/*
 * Seeks to specific position in buffer. "man fseek" for information about whence values.
 * Returns true on successful seek and false if seeking outside the buffer or unknown whence.
 */
bool t2buf_seek(t2buf_t *buf, long offset, int whence);

/*
 * Reads a line from buffer. Line stored in dst is NULL terminated.
 *
 * @param buf   t2buf_t to read from
 * @param dst   destination buffer
 * @param size  size of destination buffer
 * @param trim  true if line return should not be stored in dst, false if storing it
 *
 * @return      on success, number of characters stored in dst, not including NULL terminating
 *              character => strlen(dst). on error, a negative number described below.
 * @retval T2BUF_EMPTY     buf is empty, nothing was read.
 * @retval T2BUF_DST_FULL  dst was not big enough to store the whole line, stopped processing
 *                         buf in the middle of the line. next call will continue to read from
 *                         the middle of the line.
 * @retval T2BUF_NULL      a NULL character was encountered before a line return or the end of
 *                         the buffer. stops reading after NULL character.
 */
#define T2BUF_EMPTY    -1
#define T2BUF_DST_FULL -2
#define T2BUF_NULL     -3
long t2buf_readline(t2buf_t *buf, uint8_t *dst, size_t size, bool trim);

/*
 * Returns the number of bytes of the next line. Line terminating character(s) are included in the
 * returned length.
 *
 * @retval T2BUF_EMPTY     buf is empty, nothing was read.
 */
long t2buf_linelen(t2buf_t *buf);

/*
 * Skip characters in buffer until the next end of line.
 *
 * @return  the number of skipped bytes.
 * @retval T2BUF_EMPTY      buf is empty, nothing was read.
 */
long t2buf_skipline(t2buf_t *buf);

/*
 * Same as t2buf_skipline but skip at most n bytes.
 */
long t2buf_skipnline(t2buf_t *buf, size_t n);

/*
 * Read a string from buffer, stops at NULL character or at the end of the buffer.
 * String stored in dst is NULL terminated and encoded in UTF-8.
 *
 * @param buf       t2buf_t to read from
 * @param dst       destination buffer
 * @param size      size of destination buffer
 * @param encoding  encoding of the input string read from buf, output is always UTF-8
 * @param cont      continue reading on encoding error, invalid characters are replaced by "."
 *
 * @return   on success, number of bytes stored in dst, not including NULL terminating
 *           character => strlen(dst). on error, a negative number described below.
 * @retval T2BUF_EMPTY      buf is empty, nothing was read.
 * @retval T2BUF_DST_FULL   dst was not big enough to store the whole string, stopped processing
 *                          buf in the middle of string. next call will continue to read from
 *                          the next character.
 * @retval T2BUF_ENC_ERROR  string in input buf was not correctly encoded according to provided
 *                          encoding parameter.
 */
#define T2BUF_ENC_ERROR -4
long t2buf_readstr(t2buf_t *buf, uint8_t *dst, size_t size, t2buf_encoding encoding, bool cont);

/*
 * Same as t2buf_readstr but reads at most read_size bytes from the input buffer. Using this function
 * only makes sense when using an UTF-16 encoding where the number of bytes read is different from
 * the number of bytes written.
 */
long t2buf_readnstr(t2buf_t *buf, uint8_t *dst, size_t size, size_t read_size,
        t2buf_encoding encoding, bool cont);

/*
 * Returns the number of bytes of the next string until the null terminating character according to
 * the provided encoding. The null terminating character is included in the returned size.
 *
 * @retval T2BUF_EMPTY     buf is empty, nothing was read.
 */
long t2buf_strlen(t2buf_t *buf, t2buf_encoding encoding);

/*
 * Skip string in the buffer without storing it anywhere. Stops at terminating character according to
 * provided encoding.
 *
 * @return  the number of skipped bytes.
 * @retval T2BUF_EMPTY      buf is empty, nothing was read.
 * @retval T2BUF_ENC_ERROR  provided encoding parameter not supported or unknown.
 */
long t2buf_skipstr(t2buf_t *buf, t2buf_encoding encoding);

/*
 * Same as t2buf_skipstr but skips at most n bytes.
 */
long t2buf_skipnstr(t2buf_t *buf, size_t n, t2buf_encoding encoding);

/*
 * Similar to memmem, finds an occurence of needle in the bytes left in the buffer and consumes every
 * bytes until the start of needle.
 *
 * @return  true if needle found in buffer, false otherwise.
 */
bool t2buf_memmem(t2buf_t *buf, const void *needle, size_t needlelen);

/*
 * Hex-decode "n" bytes from "buf" and write them into "dst" buffer. An optional separator can
 * be provided. The string in dst is always NULL terminated. This function assumes that the dst buffer
 * is big enough (2*n+1 without separator and 3*n with separator).
 *
 * @param buf  t2buf_t to read from
 * @param n    number of source bytes to hex decode from buffer
 * @param dst  where to write the hex-decoded string
 * @param sep  separate each byte (hex 2-tuple) with this character, no separator if sep == 0
 * @return     number of read bytes (= n if there was enough bytes left)
 */
size_t t2buf_hexdecode(t2buf_t *buf, const size_t n, char *dst, char sep);

#endif // __T2_BUFFER_H__
