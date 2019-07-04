/*
 * binSink.c
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

#include "binSink.h"
#if BUF_DATA_SHFT > 1
#include "chksum.h"
#endif // BUF_DATA_SHFT > 1

#if GZ_COMPRESS == 1
#include "gz2txt.h"
#else // GZ_COMPRESS == 0
#include "bin2txt.h"
#endif // GZ_COMPRESS == 0


#if BLOCK_BUF == 0
// Global Plugin Variables
static b2t_func_t funcs;
static binary_header_t *header;
static char filename[MAX_FILENAME_LEN+1];

#if SFS_SPLIT == 1
// -W option
static uint64_t oFileNum, oFileLn;
static uint64_t binfIndex;
static char *oFileNumP;
#endif // SFS_SPLIT == 1

#if GZ_COMPRESS == 1
static gzFile outputFile;
#else // GZ_COMPRESS == 0
static FILE *outputFile;
#endif // GZ_COMPRESS == 0
#endif // BLOCK_BUF == 0


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("binSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("binSink", "BLOCK_BUF is set in 'tranalyzer.h', no flow file will be produced");
#else // BLOCK_BUF == 0
#if GZ_COMPRESS == 1
	GZ2TXT_TEST_ZLIB_VERSION("binSink");
	funcs = b2t_funcs_gz;
#else // GZ_COMPRESS == 0
	funcs = b2t_funcs;
#endif // GZ_COMPRESS == 0

	// setup output file names
	if (capType & WSTDOUT) {
#if GZ_COMPRESS == 0
		outputFile = stdout;
#else // GZ_COMPRESS == 1
		if (UNLIKELY(!(outputFile = gzdopen(fileno(stdout), "w")))) {
			T2_PERR("binSink", "Failed to open compressed stream: %s", strerror(errno));
			exit(-1);
		}
#endif // GZ_COMPRESS == 1
	} else {
		size_t len = baseFileName_len + sizeof(FLOWS_SUFFIX) + 1;
#if GZ_COMPRESS == 1
		len += sizeof(GZ_SUFFIX);
#endif // GZ_COMPRESS == 1
		if (UNLIKELY(len > MAX_FILENAME_LEN)) {
			T2_PERR("binSink", "filename too long");
			exit(1);
		}
		strncpy(filename, baseFileName, baseFileName_len+1);
		strcat(filename, FLOWS_SUFFIX);
#if GZ_COMPRESS == 1
		strcat(filename, GZ_SUFFIX);
#endif // GZ_COMPRESS == 1

#if SFS_SPLIT == 1
		if (capType & OFILELN) {
			binfIndex = 0;
			oFileLn = (uint64_t)oFragFsz;
			oFileNumP = filename + strlen(filename);
			oFileNum = oFileNumB;
			sprintf(oFileNumP, "%"PRIu64, oFileNum);
		}
#endif // SFS_SPLIT == 1

		// open flow output file
		if (UNLIKELY(!(outputFile = funcs.fopen(filename, "w")))) {
			T2_PERR("binSink", "Failed to open file '%s' for writing: %s", filename, strerror(errno));
			exit(-1);
		}
	}

	// generate and write header in flow file
	// build binary header from binary values
	header = build_header(main_header_bv);

#if BUF_DATA_SHFT > 0
	uint32_t *bP = header->header;
	const uint32_t i = header->length << 2;
	bP[0] = i;
#if BUF_DATA_SHFT > 1
	bP[1] = 0;
	bP[1] = Checksum32(bP, i);
#endif // BUF_DATA_SHFT > 1
#endif // BUF_DATA_SHFT > 0

#if GZ_COMPRESS == 1
	gzwrite(outputFile, header->header, sizeof(uint32_t)*header->length);
#else // GZ_COMPRESS == 0
	fwrite(header->header, sizeof(uint32_t), header->length, outputFile);
#endif // GZ_COMPRESS == 0
#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void bufferToSink(outputBuffer_t *buffer) {

#if BUF_DATA_SHFT > 0
	char *bP = buffer->buffer - STD_BUFSHFT;
	uint32_t *ubP = (uint32_t*)bP;
	const uint32_t i = buffer->pos + STD_BUFSHFT;
	ubP[0] = buffer->pos;
#if BUF_DATA_SHFT > 1
	ubP[1] = 0;
	ubP[1] = Checksum32(ubP, i);
#endif // BUF_DATA_SHFT > 1
#if GZ_COMPRESS == 1
	gzwrite(outputFile, bP, sizeof(char)*i);
#else // GZ_COMPRESS == 0
	fwrite(bP, sizeof(char), i, outputFile);
#endif // GZ_COMPRESS == 0
#else // BUF_DATA_SHFT == 0
#if GZ_COMPRESS == 1
	gzwrite(outputFile, buffer->buffer, sizeof(char)*buffer->pos);
#else // GZ_COMPRESS == 0
	fwrite(buffer->buffer, sizeof(char), buffer->pos, outputFile);
#endif // GZ_COMPRESS == 0
#endif // BUF_DATA_SHFT

#if SFS_SPLIT == 1
	if (capType & OFILELN) {
		const uint64_t offset = ((capType & WFINDEX) ? ++binfIndex : (uint64_t)funcs.ftell(outputFile));
		if (offset >= oFileLn) {
			funcs.fclose(outputFile);

			oFileNum++;
			sprintf(oFileNumP, "%"PRIu64, oFileNum);

			if (UNLIKELY((outputFile = funcs.fopen(filename, "w")) == NULL)) {
				T2_PERR("binSink", "Failed to open file '%s' for writing: %s", filename, strerror(errno));
				exit(-1);
			}

			// write the header
#if GZ_COMPRESS == 1
			gzwrite(outputFile, header->header, sizeof(uint32_t)*header->length);
#else // GZ_COMPRESS == 0
			fwrite(header->header, sizeof(uint32_t), header->length, outputFile);
#endif // GZ_COMPRESS == 0
			binfIndex = 0;
		}
	}
#endif // SFS_SPLIT == 1
}


void onApplicationTerminate() {
	if (LIKELY(header != NULL)) {
		free(header->header);
		free(header);
	}

	if (LIKELY(outputFile != NULL)) funcs.fclose(outputFile);
}

#endif // BLOCK_BUF == 0
