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
 * Inspired by http://msmvps.com/blogs/vandooren/archive/2007/01/05/creating-a-thread-safe-producer-consumer-queue-in-c-without-using-locks.aspx
 */

#ifndef __IO_BUFFER_H__
#define __IO_BUFFER_H__

// includes
#include <inttypes.h>
#include <pcap.h>

// Input Buffering
// useful in live sniffing if there is a (short) packet burst
#define ENABLE_IO_BUFFERING 0 // enables buffering of the packets in a queue.

#if ENABLE_IO_BUFFERING != 0

#define IO_BUFFER_FULL_WAIT_MS  200 // number of ms to wait if queue is full
#define IO_BUFFER_SIZE         8192 // max number of packets that can be stored in the buffer (power of two is faster)
#define IO_BUFFER_MAX_MTU      2048 // max size of a packet (divisible by 4)

// functions
extern void ioBufferInitialize();
void mainLoop();

// variables
extern volatile uint8_t gBufStat;

#endif // ENABLE_IO_BUFFERING != 0

#endif // __IO_BUFFER_H__
