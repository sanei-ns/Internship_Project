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

#ifndef __SUBNETHL6_H__
#define __SUBNETHL6_H__

// local includes
#include "utils.h"


// plugin defines

#define SUBNETFILE6 "subnets6_HLP.bin" // subnet IPv6 file name


// structs

typedef struct {
	int32_t count;
	uint32_t ver;
	uint32_t rev;
	subnet6_t *subnets;
} subnettable6_t;


// function prototypes

subnettable6_t* subnet_init6(const char *dir, const char *filename);
extern uint32_t subnet_testHL6(subnettable6_t *table, ipAddr_t net6);
void subnettable6_destroy(subnettable6_t *table);

#endif // __SUBNETHL6_H__
