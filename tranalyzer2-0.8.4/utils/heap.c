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

#include <stdlib.h>
#include "heap.h"


struct heap_s {
    size_t allocated;   // number of allocated elements
    size_t count;       // number of used elements
    const void** data;  // array of pointers to elements
    int (*comparator)(const void* a, const void* b); // elements comparator function
};

heap_t* heap_create(size_t size, int (*comparator)(const void* a, const void* b)) {
    heap_t* h = malloc(sizeof(*h));
    if (!h) {
        return NULL;
    }
    if (!(h->data = calloc(size, sizeof(*h->data)))) {
        free(h);
        return NULL;
    }

    h->allocated = size;
    h->count = 0;
    h->comparator = comparator;

    return h;
}

void heap_destroy(heap_t* h) {
    free(h->data);
    free(h);
}

bool heap_push(heap_t* h, const void* const elem) {
    // Resize the heap if it is too small to hold all the data
    if (h->count == h->allocated) {
        h->allocated <<= 1;
        const void** tmp = realloc(h->data, sizeof(*h->data) * h->allocated);
        if (!tmp) {
            return false;
        }
        h->data = tmp;
    }

    // Find out where to put the element
    size_t index, parent;
    for (index = h->count++; index; index = parent) {
        parent = (index - 1) >> 1;
        if (h->comparator(h->data[parent], elem) < 0) {
            break;
        }
        h->data[index] = h->data[parent];
    }
    h->data[index] = elem;
    return true;
}

void* heap_pop(heap_t* h) {
    if (h->count == 0) {
        return NULL;
    }

    const void* first = h->data[0];
    const void* temp = h->data[--h->count];

    // Reorder the elements
    size_t index, swap;
    for (index = 0; 1; index = swap) {
        // Find the child to swap with
        swap = (index << 1) + 1;
        if (swap >= h->count) {
            break; // if there are no children, the heap is reordered
        }
        const size_t other = swap + 1;
        if ((other < h->count) && h->comparator(h->data[other], h->data[swap]) < 0) {
            swap = other;
        }
        if (h->comparator(temp, h->data[swap]) < 0) {
            // if the bigger child is bigger than or equal to its parent, the heap is reordered
            break;
        }
        h->data[index] = h->data[swap];
    }
    h->data[index] = temp;

    return (void*)first;
}

size_t heap_size(const heap_t* const h) {
    return h->count;
}
