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
 * rbTree.h
 *
 * Implements a Red-Black tree.
 *
 * This implementation provides the construction of multiple RB trees out of a
 * "pool" of preallocated tree nodes.
 */

#ifndef __RB_TREE_H__
#define __RB_TREE_H__

/* includes */
#include <inttypes.h>
#include <stdbool.h>

// User defines

#define RBT_DEBUG    0 // enable debug output
#define RBT_ROTATION 0 // activates the Red-Black Tree feature of rotating an unbalanced tree

// RBT defines

#define RBT_RED   0
#define RBT_BLACK 1

typedef struct rbNode_s {
    int32_t value;           // value of a node
    struct rbNode_s *parent; // parent node of a node
    struct rbNode_s *left;   // left child node of a node
    struct rbNode_s *right;  // right child node of a node
    unsigned short color;    // 0: red, 1: black
} rbNode_t;

typedef struct {
    rbNode_t *nodePool;         // pointer to an array of nodes
    rbNode_t *freeNode;         // pointer to the first free Node
    unsigned long numFreeNodes; // number of free nodes in this treeNodePool
    uint32_t size;
} rbTreeNodePool_t;

typedef struct rbTreeNodeQueueBin_s {
    rbNode_t *node;
    unsigned int level;
    struct rbTreeNodeQueueBin_s *next;
    unsigned short printPos;
} rbTreeNodeQueueBin_t;

/* a queue for performing level-order tree traversing */
typedef struct {
    rbTreeNodeQueueBin_t *start;
    rbTreeNodeQueueBin_t *end;
} rbTreeNodeQueue_t;

/*
 * initializes the rbTreeNodePool treeNodePool;
 */
rbTreeNodePool_t* rbTree_initTreeNodePool(uint32_t size);

/*
 * searches a value in the tree and - if the doInsert flag is set - inserts a
 * new node out of the treenode pool into the tree. If the value already exists,
 * the entryExists pointer is set to true.
 *
 * PLEASE NOTE: If the root changed (which can happen because of the rotation in
 * Red-Black trees, you may need to update your the tree pointer. This is NOT
 * done in this function!!! An example code snipped could look like:
 *
 * while (tree->parent) tree = tree->parent;
 *
 * with tree as the tree pointer
 */
rbNode_t* rbTree_search_insert(rbNode_t *tree, rbTreeNodePool_t *treeNodePool, int32_t value, bool doInsert, bool *entryExists);

/* destroys a tree and puts its nodes back into the free node list */
void rbTree_destroy(rbNode_t *tree, rbTreeNodePool_t *treeNodePool);

/* prints a whole tree in nice ascii art :) */
void rbTree_print(rbNode_t *tree, unsigned long maxDepth);

/* TODO: define / implement delete function */

#endif /* __RB_TREE_H__ */
