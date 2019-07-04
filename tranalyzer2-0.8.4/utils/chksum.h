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

/*
 * chksum.h
 */

#ifndef __CHKSUM_H__
#define __CHKSUM_H__

#include <inttypes.h>

extern uint16_t Checksum(const uint16_t *data, uint32_t chkSum, uint16_t byteLen, uint16_t chkSumWrdPos);
extern uint32_t Checksum32(const uint32_t *data, uint32_t byteLen);
extern uint32_t sctp_adler32(const uint8_t *data, uint32_t len);
extern uint32_t sctp_crc32c(const uint8_t *data, uint32_t len);

#endif // __CHKSUM_H__
