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

#include "rbTree.h"
#include "global.h"

static inline void rotate_left(rbNode_t *node);
static inline void rotate_right(rbNode_t *node);

static inline void insert_case1(rbNode_t *n);
static inline void insert_case2(rbNode_t *n);
static inline void insert_case3(rbNode_t *n);
static inline void insert_case4(rbNode_t *n);
static inline void insert_case5(rbNode_t *n);

static inline rbNode_t* grandparent(const rbNode_t * const node);
static inline rbNode_t* uncle(const rbNode_t * const node);

static unsigned int rekursiveGetDepth(rbNode_t *tree, unsigned int currentDepth);


/*
 * The following functions handles the rebalancing of the tree, if necessary.
 * Shamelessly stolen from the german Wikipedia:
 * http://de.wikipedia.org/wiki/Rot-Schwarz-Baum
 * TODO: improve speed
 */
static inline void rotate_left(rbNode_t *node) {
#if RBT_DEBUG > 0
    printf("rotate LEFT\n:");
    if (!node->parent) printf("-> parent node is NULL");
#endif

    if (!node->parent) return;

    node->parent->right = node->left;
    if (node->left) node->left->parent = node->parent;

    node->left = node->parent;
    node->parent = node->parent->parent;

    node->left->parent = node;
    if (node->parent) {
        if (node->parent->left == node->left) node->parent->left = node;
        else node->parent->right = node;
    }
}


static inline void rotate_right(rbNode_t *node) {
#if RBT_DEBUG > 0
    printf("rotate RIGHT\n");
    if (!node->parent) printf("-> parent node is NULL");
#endif

    if (UNLIKELY(!node->parent)) return;

    node->parent->left = node->right;
    if (node->right) node->right->parent = node->parent;

    node->right = node->parent;
    node->parent = node->parent->parent;

    node->right->parent = node;
    if (node->parent) {
        if (node->parent->left == node->right) node->parent->left = node;
        else node->parent->right = node;
    }
}


/* case 1: Node is root */
static inline void insert_case1(rbNode_t *n) {
    if (!n->parent) n->color = RBT_BLACK;
    else insert_case2(n);
}


static inline void insert_case2(rbNode_t *n) {
    if (n->parent->color == RBT_BLACK) return; // tree is still OK
    else if (grandparent(n)) insert_case3(n);
}


static inline void insert_case3(rbNode_t *n) {
    rbNode_t * const unc = uncle(n);
    if (!unc || unc->color == RBT_BLACK) {
        insert_case4(n);
    } else {
        n->parent->color = RBT_BLACK;
        unc->color = RBT_BLACK;
        rbNode_t * const gp = grandparent(n);
        gp->color = RBT_RED;
        insert_case1(gp);
    }
}


static inline void insert_case4(rbNode_t *n) {
    rbNode_t * const gp = grandparent(n);
    if (n == n->parent->right && n->parent == gp->left) {
        rotate_left(n);
        // rotate_left(n->parent);
        n = n->left;
    } else if (n == n->parent->left && n->parent == gp->right) {
        rotate_right(n);
        // rotate_right(n->parent);
        n = n->right;
    }
    if (n) insert_case5(n);
}


static inline void insert_case5(rbNode_t *n) {
    n->parent->color = RBT_BLACK;
    rbNode_t * const gp = grandparent(n);
    gp->color = RBT_RED;
    if (n == n->parent->left && n->parent == gp->left) {
        rotate_right(n->parent);
        // rotate_right(gp);
    } else {
        rotate_left(n->parent);
        // rotate_left(gp);
    }
}


static inline rbNode_t* grandparent(const rbNode_t * const node) {
    const rbNode_t * const parent = node->parent;
    return parent ? parent->parent : NULL;
}


static inline rbNode_t* uncle(const rbNode_t * const node) {
    const rbNode_t * const gp = grandparent(node);
    if (!gp) return NULL;
    return (node->parent == gp->left) ? gp->right : gp->left;
}


rbTreeNodePool_t* rbTree_initTreeNodePool(uint32_t size) {
    rbTreeNodePool_t *pool;
    if (UNLIKELY(!(pool = malloc(sizeof(*pool))))) {
        T2_PERR("rbTree", "failed to allocate memory for rbTreeNodePool_t");
        return NULL;
    }

    if (UNLIKELY(!(pool->nodePool = calloc(size, sizeof(rbNode_t))))) {
        T2_PERR("rbTree", "failed to allocate memory for pool->nodePool");
        free(pool);
        return NULL;
    }

    pool->freeNode = &pool->nodePool[0];
    pool->numFreeNodes = size;
    pool->size = size;

    /* set the right pointer of a node to the next node of the array to
     * construct the free node list*/
    for (uint_fast32_t i = 0; i < size-1; i++) {
        pool->nodePool[i].right = &pool->nodePool[i+1];
    }

    return pool;
}


rbNode_t* rbTree_search_insert(rbNode_t *tree, rbTreeNodePool_t *treeNodePool, int32_t value, bool doInsert, bool *entryExists) {
    if (!tree && !doInsert) {
        *entryExists = false;
#if RBT_DEBUG > 0
        printf("Tree does not exist and nothing was created\n");
#endif
        return NULL;
    }

    /* look for a entry with the given value */
    rbNode_t *currentNode = tree;
    rbNode_t *previousNode = NULL;
    while (currentNode) {
        if (currentNode->value == value) {
            *entryExists = true;
            return currentNode;
        }

        previousNode = currentNode;
        if (value < currentNode->value) currentNode = currentNode->left;
        else currentNode = currentNode->right;
    }

    /* No node with the value was found */
    *entryExists = false;

    if (!doInsert) return NULL;

#if RBT_DEBUG > 0
    printf("creating node\n");
#endif

    if (UNLIKELY(treeNodePool->numFreeNodes == 0)) {
#if RBT_DEBUG > 0
        printf("No free nodes in treeNodePool\n");
#endif // RBT_DEBUG > 0
        return NULL;
    }

    /* So generate a new one. Pick a free node out of the free list */
    currentNode = treeNodePool->freeNode;
    treeNodePool->freeNode = treeNodePool->freeNode->right;

    // fill it with the right values
    currentNode->value = value;
    currentNode->parent = previousNode;
    currentNode->left = NULL;
    currentNode->right = NULL;
    currentNode->color = RBT_RED;

    // if there is no parent, then this is a new tree
    if (previousNode) {
        /* connect it to the correct side of the parent */
        if (value < previousNode->value) previousNode->left = currentNode;
        else previousNode->right = currentNode;
    }

    // decrease the nodePool's freeNode counter
    treeNodePool->numFreeNodes--;

    // Test if a reconfiguration of the tree is necessary
#if RBT_DEBUG > 0
    printf("Tree BEFORE:\n:");
    if (tree) rbTree_print(tree, 5);
    else rbTree_print(currentNode, 5);
#endif

#if RBT_ROTATION != 0
    insert_case1(currentNode);
#endif

#if RBT_DEBUG > 0
    previousNode = currentNode;
    while (previousNode->parent) previousNode = previousNode->parent;
    tree = previousNode;
    printf("Tree AFTER:\n:");
    if (tree) rbTree_print(tree, 5);
    else rbTree_print(currentNode, 5);
#endif

    return currentNode;
}


void rbTree_destroy(rbNode_t *tree, rbTreeNodePool_t *treeNodePool) {
    // tree wasn't destroyed because it was not the root node.
    // TODO: switch to delete function
    if (UNLIKELY(!tree || tree->parent)) return;

    // Note: This destroying function is programmed iteratevly (not recursive)
    // because of speed

    rbNode_t *currentNode = tree;
    while (currentNode) {
        if (currentNode->left != NULL) {
            // go deeper in the tree;
            currentNode = currentNode->left;
        } else if (currentNode->right != NULL) {
            // go deeper in the tree;
            currentNode = currentNode->right;
        } else {
            // current node leaves are NULL so put the current Node back in the
            // free list
            currentNode->right = treeNodePool->freeNode;
            treeNodePool->freeNode = currentNode;

            // increase the free list counter
            treeNodePool->numFreeNodes++;

            // check if the currentNode equals the tree root and return 0 if
            // this is true
            if (currentNode == tree) return;

            // disconnect the parent left- or right pointer from the
            // currentNode and set the currentNode to its parent
            if (currentNode->parent->left == currentNode) {
                currentNode = currentNode->parent;
                currentNode->left->parent = NULL;
                currentNode->left = NULL;
            } else {
                currentNode = currentNode->parent;
                currentNode->right->parent = NULL;
                currentNode->right = NULL;
            }
        }
    }
}


/*
 * PLEASE NOTE:
 * This function is NOT designed to be fast, it should only be used to perform
 * a debug output!!!
 */
void rbTree_print(rbNode_t *tree, unsigned long maxDepth) {
    printf("Red-Black tree printing: ----------------------------------\n");
    // first get max depth of tree
    unsigned int treeDepth = rekursiveGetDepth(tree, 0);
    printf("Tree depth is %u\n", treeDepth);
    if (treeDepth > maxDepth) {
        printf("NOTE: Tree output is pruned at height %lu\n", maxDepth);
        treeDepth = maxDepth;
    }

    // initialize a queue
    rbTreeNodeQueue_t queue;
    rbTreeNodeQueueBin_t *currentQueueBin = malloc(sizeof(rbTreeNodeQueueBin_t));
    rbTreeNodeQueueBin_t *childQueueBin;
    currentQueueBin->node = tree;
    currentQueueBin->next = NULL;
    currentQueueBin->level = 1;
    currentQueueBin->printPos = 0;
    queue.start = currentQueueBin;
    queue.end = currentQueueBin;

    // Determine printing pos
    unsigned int i;
    for (i = 1; i < treeDepth; i++) {
        currentQueueBin->printPos = 2 * currentQueueBin->printPos + 3;
    }

    // start processing
    unsigned int currentLevel = 0;
    unsigned int currentPrintingPos = 0;
    while (currentQueueBin) {
        // reset printingPos if tree level changed, also new line
        if (currentLevel < currentQueueBin->level) {
            currentLevel = currentQueueBin->level;
            currentPrintingPos = 0;
            printf("\n");
        }

        // skip to next printing pos
        for (i = currentPrintingPos; i < currentQueueBin->printPos; i++) {
            currentPrintingPos++;
            printf(" ");
        }

        // print out current bin
        printf("%05"PRId32, currentQueueBin->node->value);
        currentPrintingPos = currentPrintingPos + 5; // TODO: What if output of previous line is longer than 5 ?

        // put left and right child of node into queue
        if ((currentLevel < treeDepth) && currentQueueBin->node->left) {
            childQueueBin = malloc(sizeof(rbTreeNodeQueueBin_t));
            childQueueBin->node = currentQueueBin->node->left;
            childQueueBin->level = currentQueueBin->level + 1;

            // determine difference between current printPos and printPos of child
            int j = 0;
            for (i = currentLevel; i < treeDepth; i++) {
                j = 2 * j + 3;
            }

            int k = 0;
            for (i = currentLevel + 1; i < treeDepth; i++) {
                k = 2 * k + 3;
            }

            const int offset = j - k;

            childQueueBin->printPos = currentQueueBin->printPos - offset;
            childQueueBin->next = NULL;
            queue.end->next = childQueueBin;
            queue.end = childQueueBin;
        }

        if ((currentLevel < treeDepth) && currentQueueBin->node->right) {
            childQueueBin = malloc(sizeof(rbTreeNodeQueueBin_t));
            childQueueBin->node = currentQueueBin->node->right;
            childQueueBin->level = currentQueueBin->level + 1;

            // determine difference between current printPos and printPos of child
            int j = 0;
            for (i = currentLevel; i < treeDepth; i++) {
                j = 2 * j + 3;
            }

            int k = 0;
            for (i = currentLevel + 1; i < treeDepth; i++) {
                k = 2 * k + 3;
            }

            const int offset = j - k;

            childQueueBin->printPos = currentQueueBin->printPos + offset;
            childQueueBin->next = NULL;
            queue.end->next = childQueueBin;
            queue.end = childQueueBin;
        }

        // currentQueueBin isn't needed anymore, so free it
        queue.start = queue.start->next;
        free(currentQueueBin);
        // point to next entry
        currentQueueBin = queue.start;
    }
    printf("\n\n-----------------------------------------------------------\n\n");
}


static unsigned int rekursiveGetDepth(rbNode_t *tree, unsigned int currentDepth) {
    unsigned int maxDepth = currentDepth + 1, tempDepth;

    if (tree->left) {
        tempDepth = rekursiveGetDepth(tree->left, currentDepth + 1);
        if (tempDepth > maxDepth) maxDepth = tempDepth;
    }

    if (tree->right) {
        tempDepth = rekursiveGetDepth(tree->right, currentDepth + 1);
        if (tempDepth > maxDepth) maxDepth = tempDepth;
    }

    return maxDepth;
}
