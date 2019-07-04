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

#ifndef MALSITE_H_
#define MALSITE_H_

// global plugin defines
#include <stdio.h>
#include "global.h"

// user defines
#define MAL_DOMAIN 1 // 1: check for domain names, 0: check for IPs

#if MAL_DOMAIN == 1
#define TMALFILE "maldm.txt"
#else // MAL_DOMAIN == 0
#define TMALFILE "malip.txt"
#endif // MAL_DOMAIN

// plugin defines
#define LNMXLN 512
#define DMMXLN 50
#define MTMXLN 20

#define INUM(X) #X
#define SNUM(X) INUM(X)

// global plugin structs
typedef struct {
	uint32_t malId;
#if MAL_DOMAIN == 0
	ipAddr_t malIp; // in Host Order !
#else // MAL_DOMAIN == 1
	uint8_t len;
	char malDomain[DMMXLN+1];
	char malTyp[MTMXLN+1];
#endif //MAL_DOMAIN
} malsite_t;

typedef struct {
	uint32_t count;
	malsite_t *malsites;
} malsitetable_t;

extern malsitetable_t *malsite_init();
extern void malsite_destroy(malsitetable_t *table);

#if MAL_DOMAIN == 1
extern uint32_t maldomain_test(malsitetable_t *table, const char *dname);
#else // MAL_DOMAIN == 0
extern uint32_t malip_test(malsitetable_t *table, ipAddr_t ip);
#endif // MAL_DOMAIN == 0

#endif // MALSITE_H_
