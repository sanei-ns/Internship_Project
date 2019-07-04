/*
 * t2buf.c
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

// for memmem
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE
#include <string.h>

#ifndef __APPLE__
#include <endian.h>
#else // __APPLE__
#include "missing.h"
#endif // __APPLE__
#include <stdio.h>
#include "t2buf.h"

t2buf_t t2buf_create(const uint8_t *buffer, size_t len) {
    t2buf_t newbuf = {
        .buffer = buffer,
        .size = len,
        .pos = 0,
    };
    return newbuf;
}

/*
 * These read / peek functions use memcpy to avoid the badly aligned pointer casting explained in
 * this article: https://pzemtsov.github.io/2016/11/06/bug-story-alignment-on-x86.html
 *
 * DO NOT replace them by *(uintX_t*) pointer casting.
 */

#define DO_NOTHING(x) (x)

#define T2BUF_PEEK_READ_MACRO(SUFFIX, TYPE, READ_SIZE, ORDER) \
bool t2buf_peek_ ## SUFFIX (t2buf_t *buf, TYPE *dst) { \
    bool result = false; \
    TYPE temp = 0; \
    if (buf->pos + READ_SIZE <= buf->size) { \
        memcpy(&temp, buf->buffer + buf->pos, READ_SIZE); \
        *dst = ORDER(temp) >> ((sizeof(TYPE) - READ_SIZE) * 8); \
        result = true; \
    } \
    return result; \
} \
bool t2buf_read_ ## SUFFIX (t2buf_t *buf, TYPE *dst) { \
    bool result = t2buf_peek_ ## SUFFIX (buf, dst); \
    buf->pos += READ_SIZE; \
    return result; \
}

T2BUF_PEEK_READ_MACRO(u8, uint8_t, sizeof(uint8_t), DO_NOTHING)

T2BUF_PEEK_READ_MACRO(u16, uint16_t, sizeof(uint16_t), be16toh)
T2BUF_PEEK_READ_MACRO(le_u16, uint16_t, sizeof(uint16_t), le16toh)

T2BUF_PEEK_READ_MACRO(u24, uint32_t, 3, be32toh)
T2BUF_PEEK_READ_MACRO(le_u24, uint32_t, 3, le32toh)

T2BUF_PEEK_READ_MACRO(u32, uint32_t, sizeof(uint32_t), be32toh)
T2BUF_PEEK_READ_MACRO(le_u32, uint32_t, sizeof(uint32_t), le32toh)

T2BUF_PEEK_READ_MACRO(u48, uint64_t, 6, be64toh)
T2BUF_PEEK_READ_MACRO(le_u48, uint64_t, 6, le64toh)

T2BUF_PEEK_READ_MACRO(u64, uint64_t, sizeof(uint64_t), be64toh)
T2BUF_PEEK_READ_MACRO(le_u64, uint64_t, sizeof(uint64_t), le64toh)

bool t2buf_read_n(t2buf_t *buf, uint8_t *dst, size_t len) {
    bool result = false;
    if (buf->pos + len <= buf->size) {
        memcpy(dst, buf->buffer + buf->pos, len);
        result = true;
    }
    buf->pos += len;
    return result;
}

bool t2buf_skip_n(t2buf_t *buf, size_t n) {
    buf->pos += n;
    return buf->pos <= buf->size;
}

int64_t t2buf_left(t2buf_t *buf) {
    return (int64_t)buf->size - (int64_t)buf->pos;
}

long t2buf_tell(t2buf_t *buf) {
    return (long)buf->pos;
}

bool t2buf_seek(t2buf_t *buf, long offset, int whence) {
    long new_pos = offset;
    switch (whence) {
        case SEEK_SET:
            break;
        case SEEK_END:
            new_pos += buf->size;
            break;
        case SEEK_CUR:
            new_pos += buf->pos;
            break;
        default:
            return false;
    }
    if (new_pos < 0 || new_pos > (long)buf->size) {
        return false;
    }
    buf->pos = (size_t)new_pos;
    return true;
}

long t2buf_readline(t2buf_t *buf, uint8_t *dst, const size_t size, const bool trim) {
    // check if enough space to write and enough chars to read
    if (size < 1) {
        return T2BUF_DST_FULL;
    }
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        dst[0] = '\0';
        return T2BUF_EMPTY;
    }

    size_t read = 0;
    size_t written = 0; // written bytes
    int retval = 0; // in case of error
    const uint8_t* const src = buf->buffer + buf->pos;

    // read character by character
    while (read < (size_t)left) {
        // check if space left to write
        if (!trim && written + 1 >= size) {
            retval = T2BUF_DST_FULL;
            break;
        }
        // read one character
        uint8_t c = src[read++];
        // special case for '\r\n' end of line
        if (c == '\r' && read < (size_t)left && src[read] == '\n') {
            if (!trim) {
                dst[written++] = c;
                if (written + 1 >= size) {
                    // cannot write last '\n'
                    retval = T2BUF_DST_FULL;
                    break;
                }
                dst[written++] = '\n';
            }
            ++read;
            break;
        } else if (c == '\n') { // '\n' end of line
            if (!trim) {
                dst[written++] = c;
            }
            break;
        } else if (c == '\0') { // NULL string termination
            retval = T2BUF_NULL;
            break;
        } else { // any other character
            if (trim && written + 1 >= size) {
                // one character too much was read
                --read;
                retval = T2BUF_DST_FULL;
                break;
            }
            dst[written++] = c;
        }
    }

    dst[written] = '\0';
    buf->pos += read;

    return retval == 0 ? (long)written : (long)retval;
}

long t2buf_linelen(t2buf_t *buf) {
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        return T2BUF_EMPTY;
    }
    // find next '\n' position
    const uint8_t* const p = memchr(buf->buffer + buf->pos, '\n', (size_t)left);
    if (!p) {
        return (long)t2buf_left(buf);
    }
    return (long)(p - (buf->buffer + buf->pos));
}

long t2buf_skipnline(t2buf_t *buf, size_t n) {
    long len = t2buf_linelen(buf);
    if (len <= 0) {
        return T2BUF_EMPTY;
    }
    // len = min(n, line_length)
    len = len > (long)n ? (long)n : len;
    // skip length and return it
    buf->pos += len;
    return len;
}

long t2buf_skipline(t2buf_t *buf) {
    // check that bytes left is not negative
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        return T2BUF_EMPTY;
    }
    return t2buf_skipnline(buf, (size_t)left);
}

long t2buf_readnstr(t2buf_t *buf, uint8_t *dst, const size_t size, const size_t read_size,
        const t2buf_encoding encoding, const bool cont) {
    // check if enough space to write and enough chars to read
    if (size < 1) {
        return T2BUF_DST_FULL;
    }
    const int64_t lefti = t2buf_left(buf);
    if (lefti <= 0) {
        dst[0] = '\0';
        return T2BUF_EMPTY;
    }
    const size_t left = (size_t)lefti > read_size ? read_size : (size_t)lefti;

    size_t read = 0;
    size_t written = 0;
    int retval = 0; // in case of error
    const uint8_t* const src = buf->buffer + buf->pos;

    switch (encoding) {
        case T2BUF_ASCII:
        case T2BUF_ANSI:
            while (read < left) {
                const uint8_t c = src[read++];
                if (c == '\0') {
                    break; // reached end of string
                }
                if (written + 1 >= size) {
                    retval = retval == 0 ? T2BUF_DST_FULL : retval;
                    --read; // revert read operation
                    break;
                }
                if (encoding == T2BUF_ASCII && c > 0x7f) { // invalid ASCII
                    retval = T2BUF_ENC_ERROR;
                    if (cont) {
                        dst[written++] = '.';
                        continue;
                    } else {
                        --read; // revert read operation
                        break;
                    }
                }

                dst[written++] = c;
            }
            break;

        case T2BUF_UTF8:
            while (read < left) {
                const uint8_t b1 = src[read++];
                if (b1 == 0) {
                    break;
                }
                // enough space to write at least one char?
                if (written + 1 >= size) {
                    retval = retval == 0 ? T2BUF_DST_FULL : retval;
                    --read; // revert read operation
                    break;
                }
                // determine how many bytes to read depending on first byte value
                if (b1 < 0x80) {
                    // single byte character
                    dst[written++] = b1;
                } else if (b1 < 0xc2) {
                    // continuation byte as first byte or invalid overlong encoding (e.g. ISO 8859-1)
                    retval = T2BUF_ENC_ERROR;
                    if (cont) {
                        dst[written++] = '.';
                    } else {
                        --read; // revert read operation
                        break;
                    }
                } else if (b1 < 0xe0) {
                    // 2 bytes character
                    if (read >= left) {
                        // two bytes char cut in the middle
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            dst[written++] = '.';
                            ++read;
                            break;
                        } else {
                            --read; // revert read operation
                            break;
                        }
                    }
                    // check space to write
                    if (written + 2 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        --read; // revert read operation
                        break;
                    }
                    // check second byte
                    const uint8_t b2 = src[read++];
                    if ((b2 & 0xc0) != 0x80) { // start with 0b10 ?
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            dst[written++] = '.';
                            continue;
                        } else {
                            --read; // revert read operation
                            break;
                        }
                    }
                    dst[written++] = b1;
                    dst[written++] = b2;
                } else if (b1 < 0xf0) {
                    // 3 bytes character
                    if (read + 1 >= left) {
                        // 3 bytes char cut in the middle
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            read += 2;
                            dst[written++] = '.';
                            break;
                        } else {
                            --read; // revert read operation
                            break;
                        }
                    }
                    // check space to write
                    if (written + 3 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        --read; // revert read operation
                        break;
                    }
                    dst[written++] = b1;

                    for (int i = 0; i <= 2; ++i) {
                        const uint8_t b = src[read++];
                        if ((b & 0xc0) != 0x80) { // start with 0b10 ?
                            retval = T2BUF_ENC_ERROR;
                            if (cont) {
                                written -= i + 1; // revert previous writes
                                dst[written++] = '.';
                                --read; // revert last byte only to try to read it as single char
                                break;
                            } else {
                                read -= i + 2; // revert read operations
                                goto stop_reading;
                            }
                        }
                        dst[written++] = b;
                    }
                } else if (b1 < 0xf5) {
                    // 4 bytes character
                    if (read + 2 >= left) {
                        // 4 bytes char cut in the middle
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            read += 3;
                            dst[written++] = '.';
                            break;
                        } else {
                            --read; // revert read operation
                            break;
                        }
                    }
                    // check space to write
                    if (written + 4 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        --read; // revert read operation
                        break;
                    }
                    dst[written++] = b1;

                    for (int i = 0; i <= 3; ++i) {
                        const uint8_t b = src[read++];
                        if ((b & 0xc0) != 0x80) { // start with 0b10 ?
                            retval = T2BUF_ENC_ERROR;
                            if (cont) {
                                written -= i + 1; // revert previous writes
                                dst[written++] = '.';
                                --read; // revert last byte only to try to read it as single char
                                break;
                            } else {
                                read -= i + 2; // revert read operations
                                goto stop_reading;
                            }
                        }
                        dst[written++] = b;
                    }

                    // invalid first byte >= 0xf5
                    retval = T2BUF_ENC_ERROR;
                    if (cont) {
                        dst[written++] = '.';
                    } else {
                        --read; // revert read operation
                        break;
                    }
                }
            }
            break;

        case T2BUF_UTF16:
        case T2BUF_UTF16_LE: {
            const long pos = t2buf_tell(buf);
            bool (*reader)(t2buf_t* buf, uint16_t* dst);
            if (encoding == T2BUF_UTF16) {
                reader = t2buf_read_u16;
            } else {
                reader = t2buf_read_le_u16;
            }

            while (1) {
                if (read == left) {
                    break;
                } else if (read + 2 > left) {
                    retval = T2BUF_ENC_ERROR;
                    if (cont) {
                        dst[written++] = '.';
                        read += 2;
                    }
                    break;
                }
                uint16_t b1;
                reader(buf, &b1);
                // null terminating char ?
                if (b1 == 0) {
                    read += 2;
                    break;
                }
                // check that we have at least 1 byte to write
                if (written + 1 >= size) {
                    retval = retval == 0 ? T2BUF_DST_FULL : retval;
                    break;
                }
                uint32_t codepoint;
                // extract utf-16 codepoint
                if (b1 < 0xd800 || b1 > 0xdfff) {
                    // single code unit character
                    codepoint = b1;
                    read += 2;
                } else {
                    // two code units character
                    codepoint = b1 - 0xd800;
                    if (read + 4 > left) {
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            dst[written++] = '.';
                            read += 4;
                        }
                        break;
                    }
                    uint16_t b2;
                    reader(buf, &b2);
                    // check second code unit of utf-16 character
                    if (b2 < 0xdc00 || b2 > 0xdfff) {
                        // invalid second surrogate
                        retval = T2BUF_ENC_ERROR;
                        if (cont) {
                            dst[written++] = '.';
                            // retry to read second surrogate as single character
                            read += 2;
                            t2buf_seek(buf, -2, SEEK_CUR);
                            continue;
                        }
                        break;
                    }
                    codepoint |= (b2 - 0xdc00) >> 10;
                    read += 4;
                }
                // transform codepoint to utf-8
                if (codepoint < 0x80) {
                    dst[written++] = (uint8_t)codepoint;
                } else if (codepoint < 0x0800) {
                    // check if there is enough space to write 2 bytes
                    if (written + 2 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        read -= 2;
                        break;
                    }
                    dst[written++] = 0xc0 | (uint8_t)((codepoint & 0x7c0) >> 6);
                    dst[written++] = 0x80 | (uint8_t)(codepoint & 0x3f);
                } else if (codepoint < 0x10000) {
                    // check if there is enough space to write 3 bytes
                    if (written + 3 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        read -= 2;
                        break;
                    }
                    dst[written++] = 0xe0 | (uint8_t)((codepoint & 0xf000) >> 12);
                    dst[written++] = 0x80 | (uint8_t)((codepoint & 0xfc0) >> 6);
                    dst[written++] = 0x80 | (uint8_t)(codepoint & 0x3f);
                } else {
                    // check if there is enough space to write 4 bytes
                    if (written + 4 >= size) {
                        retval = retval == 0 ? T2BUF_DST_FULL : retval;
                        read -= 4; // codepoint >= 0x10000 takes 4 bytes in utf-16
                        break;
                    }
                    dst[written++] = 0xf0 | (uint8_t)((codepoint & 0x1c0000) >> 18);
                    dst[written++] = 0x80 | (uint8_t)((codepoint & 0x3f000) >> 12);
                    dst[written++] = 0x80 | (uint8_t)((codepoint & 0xfc0) >> 6);
                    dst[written++] = 0x80 | (uint8_t)(codepoint & 0x3f);
                }
            }
            // rewind internal buffer pointer and use read variable instead
            t2buf_seek(buf, pos, SEEK_SET);
            break;
        }

        default:
            // unknown encoding
            retval = T2BUF_ENC_ERROR;
    }

stop_reading:
    dst[written] = '\0';
    buf->pos += read;

    return retval == 0 ? (long)written : (long)retval;
}

long t2buf_readstr(t2buf_t *buf, uint8_t *dst, const size_t size, const t2buf_encoding encoding,
        const bool cont) {
    // check that bytes left is not negative
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        dst[0] = '\0';
        return T2BUF_EMPTY;
    }
    return t2buf_readnstr(buf, dst, size, (size_t)left, encoding, cont);
}

long t2buf_strlen(t2buf_t *buf, t2buf_encoding encoding) {
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        return T2BUF_EMPTY;
    }

    switch (encoding) {
        case T2BUF_ASCII:
        case T2BUF_ANSI:
        case T2BUF_UTF8: {
            uint8_t *p = memchr(buf->buffer + buf->pos, 0, (size_t)left);
            if (!p) {
                // no NULL terminating character, we consider that line ends at end of buffer
                return (long)left;
            }
            // include '\0' in line length
            return (long)(p - (buf->buffer + buf->pos) + 1);
        }

        case T2BUF_UTF16:
        case T2BUF_UTF16_LE: {
            size_t old_pos = buf->pos;
            uint16_t tmp;
            while (t2buf_read_u16(buf, &tmp)) {
                if (tmp == 0) {
                    break;
                }
            }
            long result;
            if (t2buf_left(buf) < 0) {
                // do not return a size bigger than what was left in buffer
                // this can happen if last utf-16 char is cut in the middle
                result = (long)(buf->size - old_pos);
            } else {
                result = (long)(buf->pos - old_pos);
            }
            buf->pos = old_pos;
            return result;
        }

        default:
            return T2BUF_ENC_ERROR;
    }
}

long t2buf_skipnstr(t2buf_t *buf, size_t n, t2buf_encoding encoding) {
    long len = t2buf_strlen(buf, encoding);
    if (len <= 0) {
        return T2BUF_EMPTY;
    }
    // len = min(n, line_length)
    len = len > (long)n ? (long)n : len;
    // skip length and return it
    buf->pos += len;
    return len;
}

long t2buf_skipstr(t2buf_t *buf, t2buf_encoding encoding) {
    // check that bytes left is not negative
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        return T2BUF_EMPTY;
    }
    return t2buf_skipnstr(buf, (size_t)left, encoding);
}

bool t2buf_memmem(t2buf_t *buf, const void *needle, size_t needlelen) {
    const int64_t left = t2buf_left(buf);
    if (left <= 0) {
        return false;
    }
    // find needle in what is left in the buffer
    uint8_t *p = memmem(buf->buffer + buf->pos, (size_t)left, needle, needlelen);
    if (!p) {
        return false;
    }
    // compute new position of buffer cursor
    buf->pos = p - buf->buffer;
    return true;
}

size_t t2buf_hexdecode(t2buf_t *buf, const size_t n, char *dst, char sep) {
    const int64_t left = t2buf_left(buf);
    if (left <= 0 || n == 0) {
        dst[0] = '\0';
        return 0;
    }
    // min(n, left)
    size_t len = n < (size_t)left ? n : (size_t)left;

    const uint8_t* const input = buf->buffer + buf->pos;
    for (size_t i = 0; i < len; ++i) {
        sprintf(dst, "%02x", input[i]);
        dst += 2;
        if (sep && i < len - 1) {
            *dst++ = sep;
        }
    }
    *dst = '\0';
    buf->pos += len;
    return len;
}
