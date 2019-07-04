/*
 * portClassifier.h
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

#ifndef __PORT_CLASSIFIER_H__
#define __PORT_CLASSIFIER_H__

#include "global.h"


// User defines

#define PBC_NUM 1 // 1: numeric representation of port classification
#define PBC_STR 1 // 1: string representation of port classification

#define PBC_CLASSFILE "portmap.txt" // Input File for the mapping between ports and applications
#define PBC_UNKNOWN   "unknown"     // label for unknown ports


// Plugin defines

#define PBC_NMLENMAX   63


// Plugin structs

typedef struct {
	char name_udp[PBC_NMLENMAX+1];
	char name_tcp[PBC_NMLENMAX+1];
} portAppl_t;

#endif // __PORT_CLASSIFIER_H__
