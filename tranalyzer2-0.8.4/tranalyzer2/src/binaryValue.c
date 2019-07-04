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

#include "binaryValue.h"
#include "global.h"
#include "t2utils.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>


// Double the buffer size
#define BV_HDR_DOUBLE_CAPACITY(header, capacity) do { \
	uint32_t *tmp; \
	capacity <<= 1; \
	if (UNLIKELY(!(tmp = realloc(header, capacity * sizeof(uint32_t))))) { \
		T2_ERR("Failed to reallocate memory for binary header"); \
		free(header); \
		exit(1); \
	} \
	header = tmp; \
} while (0)


static binary_header_t *rek_build_header(binary_subvalue_t *sv, binary_header_t *header, uint32_t *capacity);
static void bv_subvalue_destroy(binary_subvalue_t *subval);


/*
 * Append a new binary value to a (list of) binary values
 */
inline binary_value_t *bv_append_bv(binary_value_t *dest, binary_value_t *new) {
	if (!dest) return new;
	binary_value_t *bv = dest;
	while (bv->next) bv = bv->next;
	bv->next = new;
	return dest;
}


/*
 * add a new subvalue to an existing binary value
 */
binary_value_t *bv_add_sv_to_bv(binary_value_t *dest, uint32_t pos, uint32_t is_repeating, uint32_t num_values, ...) {
	if (UNLIKELY(!dest || pos >= dest->num_values)) return NULL;

	dest->subval[pos].type = 0;
	dest->subval[pos].is_repeating = is_repeating;
	dest->subval[pos].num_values = num_values;

	dest->subval[pos].subval = malloc(num_values * sizeof(binary_subvalue_t));
	if (UNLIKELY(!dest->subval[pos].subval)) {
		T2_ERR("Failed to allocate memory for subvalue");
		exit(1);
	}

	va_list argPtr;
	va_start(argPtr, num_values);

	for (uint_fast32_t i = 0; i < num_values; i++) {
		dest->subval[pos].subval[i].type = va_arg(argPtr, uint32_t);
	}

	va_end(argPtr);

	return dest;
}


/*
 * add a new subvalue to an existing subvalue
 */
binary_subvalue_t *bv_add_sv_to_sv(binary_subvalue_t *dest, uint32_t pos, uint32_t is_repeating, uint32_t num_values, ...) {
	if (UNLIKELY(!dest || pos >= dest->num_values)) return NULL;

	dest->subval[pos].type = 0;
	dest->subval[pos].is_repeating = is_repeating;
	dest->subval[pos].num_values = num_values;

	dest->subval[pos].subval = malloc(num_values * sizeof(binary_subvalue_t));
	if (UNLIKELY(!dest->subval[pos].subval)) {
		T2_ERR("Failed to allocate memory for subvalue");
		exit(1);
	}

	va_list argPtr;
	va_start(argPtr, num_values);

	for (uint_fast32_t i = 0; i < num_values; i++) {
		dest->subval[pos].subval[i].type = va_arg(argPtr, uint32_t);
	}

	va_end(argPtr);

	return dest;
}


/*
 * build a new binary value
 */
binary_value_t *bv_new_bv(const char *desc, const char *name, uint32_t is_repeating, uint32_t num_values, ...) {
	binary_value_t *bv = calloc(1, sizeof(binary_value_t));
	if (UNLIKELY(!bv)) {
		T2_ERR("Failed to allocate memory for binary value");
		exit(1);
	}

	// buffers were calloc'd, so no need to add a trailing '\0'
	memcpy(bv->name, name, MIN(strlen(name), BV_STRBUF_SHORT));
	memcpy(bv->desc, desc, MIN(strlen(desc), BV_STRBUF_LONG));

	bv->num_values = num_values;
	bv->is_repeating = is_repeating;

	bv->subval = calloc(num_values, sizeof(binary_subvalue_t));
	if (UNLIKELY(!bv->subval)) {
		T2_ERR("Failed to allocate memory for binary subvalue");
		free(bv);
		exit(1);
	}

	va_list argPtr;
	va_start(argPtr, num_values);

	for (uint_fast32_t i = 0; i < num_values; i++) {
		bv->subval[i].type = va_arg(argPtr, uint32_t);
	}

	va_end(argPtr);

	return bv;
}


/*
 * build a binary header from a (list of) binary_value(s)
 */
binary_header_t *build_header(binary_value_t *bv) {

	binary_header_t *header;
	if (UNLIKELY(!(header = malloc(sizeof(*header))))) {
		T2_ERR("Failed to allocate memory for binary header");
		exit(1);
	}

	uint32_t capacity = MAX(HDRBUF_MIN_SZ, HDRBUF_INIT_SZ);
	if (UNLIKELY(!(header->header = malloc(capacity * sizeof(uint32_t))))) {
		T2_ERR("Failed to allocate memory for binary header");
		free(header);
		exit(1);
	}

	// write header prefix
	header->header[BUF_DATA_SHFT]   = BV_MAGIC_VALUE_1;
	header->header[BUF_DATA_SHFT+1] = BV_MAGIC_VALUE_2;
	header->header[BUF_DATA_SHFT+2] = BV_VERSION;

	header->length = HDRBUF_MIN_SZ;

	binary_value_t *bvp = bv;
	while (bvp != NULL) {
		// calc needed space for strings in uint32_t, remind offset and trailing '\0'
		const uint32_t nlen = ceilf((strlen(bvp->name) + 1) / 4.0f);
		const uint32_t dlen = ceilf((strlen(bvp->desc) + 1) / 4.0f);

		const uint32_t size = (nlen + dlen + bvp->num_values + 2);

		if (UNLIKELY(header->length + size > capacity)) {
			BV_HDR_DOUBLE_CAPACITY(header->header, capacity);
		}

		// write name
		memcpy(&header->header[header->length], bvp->name, nlen * sizeof(uint32_t));
		header->length += nlen;

		// write description
		memcpy(&header->header[header->length], bvp->desc, dlen * sizeof(uint32_t));
		header->length += dlen;

		// write number of values
		header->header[header->length++] = bvp->num_values;

		// write type of values
		for (uint_fast32_t i = 0; i < bvp->num_values; i++) {
			header->header[header->length++] = bvp->subval[i].type;
			if (bvp->subval[i].type == bt_compound) {
				header = rek_build_header(&bvp->subval[i], header, &capacity);
			}
		}

		// write repeat flag
		header->header[header->length++] = bvp->is_repeating;

		bvp = bvp->next;
	}

	header->header[header->length++] = UINT32_MAX;

	// Get rid of unused memory
	uint32_t *tmp;
	if (UNLIKELY(!(tmp = realloc(header->header, header->length * sizeof(uint32_t))))) {
		T2_ERR("Failed to give back unused memory from binary header");
		free(header->header);
		exit(1);
	}
	header->header = tmp;

	return header;
}


static binary_header_t *rek_build_header(binary_subvalue_t *sv, binary_header_t *header, uint32_t *capacity) {
	if (UNLIKELY(header->length + (sv->num_values + 2) > *capacity)) {
		BV_HDR_DOUBLE_CAPACITY(header->header, *capacity);
	}

	// write number of values
	header->header[header->length++] = sv->num_values;

	// write type of values
	for (uint_fast32_t i = 0; i < sv->num_values; i++) {
		header->header[header->length++] = sv->subval[i].type;
		if (sv->subval[i].type == bt_compound) {
			header = rek_build_header(&sv->subval[i], header, capacity);
		}
	}

	// write repeat flag
	header->header[header->length++] = sv->is_repeating;

	return header;
}


void bv_header_destroy(binary_value_t *header) {
	while (header) {
		if (LIKELY(header->subval != NULL)) {
			// free all subvalue data
			for (uint_fast32_t i = 0; i < header->num_values; i++) {
				bv_subvalue_destroy(&(header->subval[i]));
			}

			// free all subvalues
			free(header->subval);
			header->subval = NULL;
		}

		binary_value_t *tmp = header->next;
		free(header); // free the header itself
		header = tmp;
	}
}


static void bv_subvalue_destroy(binary_subvalue_t *subval) {
	if (UNLIKELY(!subval)) return; // no subvalues

	if (subval->type != bt_compound ||
	    subval->num_values == 0     ||
	    !subval->subval)
	{
		// no subvalues
		return;
	}

	for (uint_fast32_t i = 0; i < subval->num_values; i++) {
		bv_subvalue_destroy(&(subval->subval[i]));
	}

	free(subval->subval);
	subval->subval = NULL;
}
