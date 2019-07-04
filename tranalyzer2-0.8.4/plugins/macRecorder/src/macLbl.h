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

#ifndef __MACLBL_H__
#define __MACLBL_H__

#include <inttypes.h>


// plugin defines

#define MACLBLFILE "maclbl.bin"  // maclbl PC name
#define WHOLEN 20


// structs

typedef struct {
	uint64_t mac;
	uint32_t macID;
	char who[WHOLEN];
} maclbl_t;

typedef struct {
	int32_t count;
	maclbl_t *maclbls;
} maclbltable_t;


// function prototypes

maclbltable_t* maclbl_init(const char *dir, const char *filename);
void maclbltable_destroy(maclbltable_t *table);
extern uint32_t maclbl_test(maclbltable_t *table, uint64_t mac);

#endif // __MACLBL_H__
