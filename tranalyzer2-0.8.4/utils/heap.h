/*
 * heap.h
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

#ifndef __HEAP_H__
#define __HEAP_H__

#include <stdbool.h>
#include <stdlib.h>

/*
 * Heap data structure: https://en.wikipedia.org/wiki/Heap_%28data_structure%29
 *
 * This implementation does not store the whole elements on the heap, only pointers
 * to elements are stored in it. This makes the element swapping a lot faster but requires
 * the caller to manage the memory where the actual elements are stored.
 *
 * "comparator" is a function which must return an integer less than, equal to, or greater than
 * zero if the first argument is considered to be respectively less than, equal to, or greater
 * than the second.
 */

// opaque definition of heap
typedef struct heap_s heap_t;

/*
 * Creates a heap with size initial elements in it.
 * Elements are sorted using the comparator function.
 *
 * Returns NULL on malloc error.
 */
extern heap_t* heap_create(size_t size, int (*comparator)(const void* a, const void* b));

/*
 * Free the memory allocated for the heap internal array.
 * The elements pointed from the heap are not automatically freed. If there were
 * allocated with malloc, they should be freed before destroying the heap.
 */
extern void heap_destroy(heap_t* heap);

/* Push a new element on the heap. Returns true on success and false on error. */
extern bool heap_push(heap_t* heap, const void* elem);

/*
 * Pop the smallest element from the heap: order defined by the comparator function.
 * Returns NULL if heap is empty
 */
extern void* heap_pop(heap_t* heap);

/* Return the number of elements on the heap */
extern size_t heap_size(const heap_t* heap);

#endif // __HEAP_H__
