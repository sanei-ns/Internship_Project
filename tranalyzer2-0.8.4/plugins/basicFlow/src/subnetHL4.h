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

#ifndef __SUBNETHL4_H__
#define __SUBNETHL4_H__

// local includes
#include "utils.h"


// plugin defines

#define SUBNETFILE4 "subnets4_HLP.bin" // subnet IPv4 file name


// structs

typedef struct {
	int32_t count;
	uint32_t ver;
	uint32_t rev;
	subnet4_t *subnets;
} subnettable4_t;


// function prototypes

subnettable4_t* subnet_init4(const char *dir, const char *filename);
extern uint32_t subnet_testHL4(subnettable4_t *table, in_addr_t net);
void subnettable4_destroy(subnettable4_t *table);

#endif // __SUBNETHL4_H__
