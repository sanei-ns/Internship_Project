/*
 * fnameLabel.h
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

#ifndef __FNAME_LABEL_H__
#define __FNAME_LABEL_H__

// global includes

// local includes
#include "global.h"

// user defines
#define FNL_IDX 1 // Use the 'FNL_IDX' letter of the filename as label

// plugin defines

typedef struct {
	char capname[1024];
} fnFlow_t;

// plugin struct pointer for potential dependencies
extern fnFlow_t *fnFlows;

#endif // __FNAME_LABEL_H__
