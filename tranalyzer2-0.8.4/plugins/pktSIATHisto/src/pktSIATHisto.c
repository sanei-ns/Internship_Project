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

// local includes
#include "pktSIATHisto.h"


// Global variables

rbTreeNodePool_t *pktSIAT_treeNodePool;
pktSIAT_t *pktSIAT_trees;
psiat_val_t *psiat_vals;


// Static variables

#if PRINT_HISTO == 1
static outputBuffer_t *psiat_buffer;
#endif // PRINT_HISTO == 1

#if BLOCK_BUF == 0 && PRINT_HISTO == 1
static uint32_t psiat_counter;
#endif // BLOCK_BUF == 0 && PRINT_HISTO == 1

// definition of bin count fields
#if IATSECMAX == 1
static const uint32_t IATBinBu[] = { 0, IATBINBu1 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1 };
static const uint32_t IATBinWu[] = { IATBINWu1 };
#elif IATSECMAX == 2
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2 };
#elif IATSECMAX == 3
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3 };
#elif IATSECMAX == 4
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4 };
#elif IATSECMAX == 5
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4, IATBINBu5 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4, IATBINNu5 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4, IATBINWu5 };
#else // IATSECMAX > 5
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4, IATBINBu5, IATBINBu6 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4, IATBINNu5, IATBINNu6 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4, IATBINWu5, IATBINWu6 };
#endif // IATSECMAX 1-6


//static uint32_t IATBinNu[IATSECMAX+1];

//static const float IATBinBf[] = { 0.0f, IATBINBF1, IATBINBF2, IATBINBF3 };
//static const float IATBinWf[] = { IATBINWF1, IATBINWF2, IATBINWF3 };
//static const float IATBinWif[] = { IATBINWIF1, IATBINWIF2, IATBINWIF3 };
//static const uint32_t IATBinNfu[] = { 0, IATBINF1, IATBINF2, IATBINF3 };


static void rekursiveDestroyIATTree(rbNode_t *node, rbTreeNodePool_t *treeNodePool);
#if (HISTO_DEBUG != 0 && DEBUG > 3)
static void printTree_inOrder(rbNode_t *tree);
#endif


// Tranalyzer Plugin Functions

T2_PLUGIN_INIT("pktSIATHisto", "0.8.4", 0, 8);

// new flexible float bin definition

//uint32_t iat2binf(float iat) {
//	int32_t i;
//	float f;
//	for (i = 0; i < IATSECMAX; i++) {
//		f = iat - IATBinBf[i];
//		if (f > 0.0f) return f * IATBinWif[i] + IATBinNfu[i];
//	}
//	return IATSECMAX;
//}
//
//
//float bin2iatf(uint32_t bin) {
//	int32_t i;
//	for (i = 0; i < IATSECMAX; i++) {
//		if (bin < IATBinNu[i+1]) return (bin - IATBinBf[i]) * IATBinWf[i] + IATBinBf[i];
//	}
//	return IATBinNu[IATSECMAX];
//}


// flexible uint bins

static uint32_t iat2bin(struct timeval iat) {
	const uint32_t k = iat.tv_sec * IATNORM + iat.tv_usec / IATNORM;
	for (uint_fast32_t i = 0; i < IATSECMAX; i++) {
		if (k < IATBinBu[i+1]) {
			return (k - IATBinBu[i]) / IATBinWu[i] + IATBinNu[i];
		}
	}
	return IATBinNu[IATSECMAX];
}


int32_t bin2iat(uint32_t bin) {
	for (uint_fast32_t i = 0; i < IATSECMAX; i++) {
		if (bin < IATBinNu[i+1]) {
			return (bin - IATBinNu[i]) * IATBinWu[i] + IATBinBu[i];
		}
	}
	return IATBinBu[IATSECMAX];
}


void initialize() {

#if PRINT_HISTO == 1
	psiat_buffer = outputBuffer_initialize(main_output_buffer->size);
#endif // PRINT_HISTO == 1

	if (UNLIKELY(!(pktSIAT_treeNodePool = rbTree_initTreeNodePool(mainHashMap->hashChainTableSize * HISTO_NODEPOOL_FACTOR)))) {
		T2_PERR("pktSIATHisto", "Failed to initialize tree node pool");
		exit(-1);
	}

	pktSIAT_trees = calloc(mainHashMap->hashChainTableSize, sizeof(pktSIAT_t));
	psiat_vals = calloc(pktSIAT_treeNodePool->size, sizeof(psiat_val_t));

	if (UNLIKELY(!pktSIAT_trees || !psiat_vals)) {
		T2_PERR("pktSIATHisto", "failed to allocate memory");
		exit(-1);
	}

	//IATBinNu[0] = 0;
	//for (i = 1; i <= IATSECMAX; i++) {
	//	IATBinNu[i] = (IATBinBu[i] - IATBinBu[i-1]) / IATBinWu[i-1] + IATBinNu[i-1];
	//}
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];
	// cleanup
	if (pSIAT->packetTree) {
		rekursiveDestroyIATTree(pSIAT->packetTree, pktSIAT_treeNodePool);
		rbTree_destroy(pSIAT->packetTree, pktSIAT_treeNodePool);
		memset(pSIAT, '\0', sizeof(pktSIAT_t));
	}
}


#if PRINT_HISTO == 1
binary_value_t* printHeader() {
 	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("PktIAT Number of tree entries", "tCnt", 0, 1, bt_uint_32));
#if HISTO_PRINT_BIN == 1
	bv = bv_append_bv(bv, bv_new_bv("Packetsize Inter Arrival Time bin histogram", "Ps_IatBin_Cnt_PsCnt_IatCnt", 1, 5, bt_uint_16, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32));
#else // HISTO_PRINT_BIN == 0
	bv = bv_append_bv(bv, bv_new_bv("Packetsize min Inter Arrival Time of bin histogram", "Ps_Iat_Cnt_PsCnt_IatCnt", 1, 5, bt_uint_16, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32));
#endif // HISTO_PRINT_BIN
	return bv;
}
#endif // PRINT_HISTO == 1


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
#if PSI_XCLD == 1
	if (packet->packetLength < PSI_XMIN) return;
#endif // PSI_XCLD == 1
#if PSI_MOD > 1
	int32_t const pLen = packet->packetLength % PSI_MOD;
#else // PSI_MOD == 0
	int32_t const pLen = packet->packetLength;
#endif // PSI_MOD

	pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];

	bool entryExists;
	rbNode_t * const currentPacketNode = rbTree_search_insert(pSIAT->packetTree, pktSIAT_treeNodePool, pLen, true, &entryExists);
	if (UNLIKELY(!currentPacketNode)) {
		T2_PERR("pktSIATHisto", "Failed to insert new tree node. Increase HISTO_NODEPOOL_FACTOR in pktSIATHisto.h and recompile plugin");
		exit(-1);
	}

	pSIAT->numPackets++;

	const unsigned long currPacketTreeBucket = currentPacketNode - &pktSIAT_treeNodePool->nodePool[0];
	if (!currentPacketNode->parent) {
		pSIAT->packetTree = currentPacketNode;
	}
#if RBT_ROTATION == 1
	else {
		// if the tree was rotated at its root, we have to change the information in the current pktSIAT tree
		while (pSIAT->packetTree->parent) {
			pSIAT->packetTree = pSIAT->packetTree->parent;
		}
	}
#endif // RBT_ROTATION == 1

	if (entryExists) {
		psiat_vals[currPacketTreeBucket].numPackets++;
	} else {
		memset(&psiat_vals[currPacketTreeBucket], '\0', sizeof(psiat_val_t));
		psiat_vals[currPacketTreeBucket].numPackets = 1;
	}

	// get IAT
	struct timeval currentIAT;
	if (pSIAT->lastPacketTime.tv_sec) { // marker for flow start
		timersub(&packet->pcapHeader->ts, &pSIAT->lastPacketTime, &currentIAT);
	} else {
		currentIAT.tv_sec = 0;
		currentIAT.tv_usec = 0;
	}

	// update last packet seen time
	pSIAT->lastPacketTime = packet->pcapHeader->ts;

	// store iat
	const int32_t i = iat2bin(currentIAT);
	pSIAT->numPacketsInTimeBin[i]++;

	rbNode_t * const currentIATNode = rbTree_search_insert(psiat_vals[currPacketTreeBucket].iat_tree, pktSIAT_treeNodePool, i, true, &entryExists);
	if (UNLIKELY(!currentIATNode)) {
		T2_PERR("pktSIATHisto", "Failed to insert new tree node. Increase HISTO_NODEPOOL_FACTOR in pktSIATHisto.h");
		exit(-1);
	}

	const unsigned long currIATTreeBucket = currentIATNode - &pktSIAT_treeNodePool->nodePool[0];
	if (!currentIATNode->parent) {
		psiat_vals[currPacketTreeBucket].iat_tree = currentIATNode;
	}
#if RBT_ROTATION == 1
	else {
		// if the tree was rotated at its root, we have to change the information in the current packet tree
		while (psiat_vals[currPacketTreeBucket].iat_tree->parent) {
			psiat_vals[currPacketTreeBucket].iat_tree = psiat_vals[currPacketTreeBucket].iat_tree->parent;
		}
	}
#endif // RBT_ROTATION == 1

	if (entryExists) {
		psiat_vals[currIATTreeBucket].numPackets++;
	} else {
		memset(&psiat_vals[currIATTreeBucket], '\0', sizeof(psiat_val_t));
		psiat_vals[currIATTreeBucket].numPackets = 1;
	}
}


void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	claimInfo(packet, flowIndex);
}


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	claimInfo(packet, flowIndex);
}


#if (BLOCK_BUF == 0 && PRINT_HISTO == 1)
static void rekursivePrintIAT_binary(rbNode_t *node, int32_t packetSize, uint32_t numPacketsPS, pktSIAT_t *tree, outputBuffer_t *buffer) {
	if (node->left) rekursivePrintIAT_binary(node->left, packetSize, numPacketsPS, tree, buffer);

	const unsigned long currIATTreeBucket = node - &pktSIAT_treeNodePool->nodePool[0];

	psiat_counter++;
	outputBuffer_append(buffer, (char*) &packetSize, sizeof(uint16_t));

#if HISTO_PRINT_BIN == 1
	outputBuffer_append(buffer, (char*) &node->value, sizeof(uint32_t));
#else // HISTO_PRINT_BIN == 0
	const uint32_t tempVar = bin2iat(node->value);
	outputBuffer_append(buffer, (char*) &tempVar, sizeof(uint32_t));
#endif // HISTO_PRINT_BIN

	outputBuffer_append(buffer, (char*) &psiat_vals[currIATTreeBucket].numPackets, sizeof(uint32_t));
	outputBuffer_append(buffer, (char*) &numPacketsPS, sizeof(uint32_t));
	outputBuffer_append(buffer, (char*) &tree->numPacketsInTimeBin[node->value], sizeof(uint32_t));

	if (node->right) rekursivePrintIAT_binary(node->right, packetSize, numPacketsPS, tree, buffer);
}
#endif // (BLOCK_BUF == 0 && PRINT_HISTO == 1)


#if (BLOCK_BUF == 0 && PRINT_HISTO == 1)
static void rekursivePrintPacketSize_binary(rbNode_t *node, pktSIAT_t *tree, outputBuffer_t *buffer) {
	if (node->left) rekursivePrintPacketSize_binary(node->left, tree, buffer);

	const unsigned long currPacketTreeBucket = node - pktSIAT_treeNodePool->nodePool;
	rekursivePrintIAT_binary(psiat_vals[currPacketTreeBucket].iat_tree, node->value, psiat_vals[currPacketTreeBucket].numPackets, tree, buffer);

	if (node->right) rekursivePrintPacketSize_binary(node->right, tree, buffer);
}
#endif // (BLOCK_BUF == 0 && PRINT_HISTO == 1)


static void rekursiveDestroyIATTree(rbNode_t *node, rbTreeNodePool_t *treeNodePool) {
	if (node->left) rekursiveDestroyIATTree(node->left, treeNodePool);
	if (node->right) rekursiveDestroyIATTree(node->right, treeNodePool);

	const unsigned long currPacketTreeBucket = node - pktSIAT_treeNodePool->nodePool;
	rbTree_destroy(psiat_vals[currPacketTreeBucket].iat_tree, treeNodePool);
}


#if PSI_XCLD == 0 || HISTO_EARLY_CLEANUP == 1 || (HISTO_DEBUG != 0 && DEBUG > 3) || (BLOCK_BUF == 0 && PRINT_HISTO == 1)
void onFlowTerminate(unsigned long flowIndex) {
	pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];

#if PSI_XCLD == 0
	if (UNLIKELY(!pSIAT->packetTree)) {
		T2_PWRN("pktSIATHisto", "Flow with number %lu has no tree", flowIndex);
        // TODO exit?
		return;
	}
#endif // PSI_XCLD == 0

#if HISTO_DEBUG != 0 && DEBUG > 3
	rbTree_print(pSIAT->packetTree, 5);
	printTree_inOrder(pSIAT->packetTree);
	fputs("\n\n", stdout);
#endif // HISTO_DEBUG != 0 && DEBUG > 3

#if BLOCK_BUF == 0
#if PRINT_HISTO == 1
	psiat_counter = 0;
	// reset the psiat buffer
	outputBuffer_reset(psiat_buffer);
	// print in buffer
#if PSI_XCLD != 0
	if (pSIAT->packetTree)
#endif // PSI_XCLD != 0
		rekursivePrintPacketSize_binary(pSIAT->packetTree, &pktSIAT_trees[flowIndex], psiat_buffer);

	outputBuffer_append(main_output_buffer, (char*) &psiat_counter, sizeof(uint32_t));

	outputBuffer_append(main_output_buffer, (char*) &psiat_counter, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, psiat_buffer->buffer, psiat_buffer->pos);
#endif // PRINT_HISTO == 1
#endif // BLOCK_BUF == 0

#if HISTO_EARLY_CLEANUP == 1
	// cleanup
	rekursiveDestroyIATTree(pSIAT->packetTree, pktSIAT_treeNodePool);
	rbTree_destroy(pSIAT->packetTree, pktSIAT_treeNodePool);
	memset(pSIAT, '\0', sizeof(pktSIAT_t));
#endif // HISTO_EARLY_CLEANUP == 1
}
#endif // PSI_XCLD == 0 || HISTO_EARLY_CLEANUP == 1 || (HISTO_DEBUG != 0 && DEBUG > 3) || (BLOCK_BUF == 0 && PRINT_HISTO == 1)


void onApplicationTerminate() {
	if (pktSIAT_treeNodePool) {
		free(pktSIAT_treeNodePool->nodePool);
		free(pktSIAT_treeNodePool);
	}

	free(pktSIAT_trees);
	free(psiat_vals);

#if PRINT_HISTO == 1
	outputBuffer_destroy(psiat_buffer);
#endif
}


#if (HISTO_DEBUG != 0 && DEBUG > 3)
static void printTree_inOrder(rbNode_t *tree) {
	if (tree->left) printTree_inOrder(tree->left);
	printf("[%"PRId32":%"PRIu32"]\t", tree->value, psiat_vals[tree - &pktSIAT_treeNodePool->nodePool[0]].numPackets);
	if (tree->right) printTree_inOrder(tree->right);
}
#endif // (HISTO_DEBUG != 0 && DEBUG > 3)
