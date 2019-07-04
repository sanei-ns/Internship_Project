/*
 * ioBuffer.c
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

#include "ioBuffer.h"

#if ENABLE_IO_BUFFERING != 0

#include "main.h"

#include <math.h>
#include <pthread.h>


// Variables
volatile uint8_t gBufStat;


// Static variables
static volatile unsigned long readPos, writePos;
static u_char packetBuffer[IO_BUFFER_SIZE][IO_BUFFER_MAX_MTU];
static struct pcap_pkthdr headerBuffer[IO_BUFFER_SIZE];
static pthread_mutex_t buflock = PTHREAD_MUTEX_INITIALIZER;


// Functions
static void *ioBufferThreadFunc(void *args);
static void ioBufferPush(u_char *inqueue __attribute__((unused)), const struct pcap_pkthdr *pcapHeader, const u_char *packet);
static int ioBufferPop(struct pcap_pkthdr **header, u_char **packet);


inline void ioBufferInitialize() {
	pthread_t thread;
	if (UNLIKELY(pthread_create(&thread, NULL, ioBufferThreadFunc, NULL))) {
		T2_ERR("Failed to create thread for ioBuffer");
		exit(-1);
	}
}


static void *ioBufferThreadFunc(void *args __attribute__((unused))) {

	int pcap_ret;
	char errbuf[PCAP_ERRBUF_SIZE];

	while (LIKELY((globalInt & GI_RUN) > GI_EXIT)) {

		pcap_ret = pcap_dispatch(captureDescriptor, PACKETS_PER_BURST, ioBufferPush, NULL);

		if (LIKELY(pcap_ret > 0)) continue;

		if (UNLIKELY(pcap_ret == -1)) {
			T2_WRN("pcap_dispatch failed: %s", pcap_geterr(captureDescriptor));
			//globalInt = GI_EXIT;
			continue;
		}

		// pcap_ret == 0, no packets
		// processPacket() needs captureDescriptor...
		// wait for the queue to be empty before closing it
		pthread_mutex_lock(&buflock);
		while (writePos != readPos) {
			pthread_mutex_unlock(&buflock);
			if (UNLIKELY(globalInt <= GI_EXIT)) return NULL;
			usleep(IO_BUFFER_FULL_WAIT_MS);
			pthread_mutex_lock(&buflock);
		}
		pthread_mutex_unlock(&buflock);

		// Terminate if we are reading from a file (-r option)
		if (capType & CAPFILE) {
			globalInt = GI_EXIT;
			return NULL;
		}

		// -D option

		if (capType & DIRFILE) {
#if RROP == 0
			if (fileNum >= fileNumE) {
				globalInt = GI_EXIT;
				return NULL;
			}
#endif // RROP == 0

			pcap_close(captureDescriptor);
#if MFPTMOUT > 0
			time_t sec0;
nxtnumB:		sec0 = time(NULL);
#endif // MFPTMOUT > 0

			fileNum++;
			if (numType) {
#if RROP == 1
				if (fileNum > fileNumE) fileNum = strtoul(fileNumB, NULL, 0);
#endif // RROP == 1
				snprintf(fileNumP, fNumLen + 1, "%0*"PRIu32, fNumLen, fileNum);
			} else {
				fNumLen = log(fileNum) / log(10.0) + 2;
#if RROP == 1
				if (fileNum > fileNumE) {
					if (*fileNumB) {
						fileNum = strtoul(fileNumB, NULL, 0);
						fNumLen = log(fileNum) / log(10.0) + 2;
					} else {
						fileNum = 0;
						*fileNumP = 0;
						fNumLen0 = fNumLen = 0;
					}
				}
#endif // RROP == 1
				if (pDot && fNumLen > fNumLen0) {
					size_t len = strlen(pDot) + 1;
					do {
						pDot[len] = pDot[len - 1];
					} while (--len);
					pDot++;
					fNumLen0 = fNumLen;
				}
				snprintf(fileNumP, fNumLen, "%"PRIu32, fileNum);
			}
			if (pDot) *pDot = '.';

			wordexp_t globName;
			wordexp(capName, &globName, 0);
			memcpy(globFName, globName.we_wordv[0], strlen(globName.we_wordv[0]) + 1);
			wordfree(&globName);

			if (!ckpcaphdr(globFName)) return NULL; // check file type

			// capture from next dump file
			while ((captureDescriptor = pcap_open_offline(globFName, errbuf)) == NULL) {
#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
				if (globalInt & GI_RPRT) {
					printGStats();
					globalInt &= ~GI_RPRT;
				}
#endif // (MONINTPSYNC == 1 || MONINTTMPCP == 1)
#if VERBOSE > 1
				if ((capType & LOGFILE) == 0) fputc('.', dooF);
#endif // VERBOSE > 1
				fflush(NULL); // commit all changes in all buffers
				sleep(POLLTM);
				if (UNLIKELY(globalInt == GI_EXIT)) return NULL;
				wordexp(capName, &globName, 0);
				memcpy(globFName, globName.we_wordv[0], strlen(globName.we_wordv[0]) + 1);
				wordfree(&globName);
#if MFPTMOUT > 0
				if (time(NULL) - sec0 >= MFPTMOUT) goto nxtnumB;
#endif // MFPTMOUT > 0
			}

			// get filesize info
			struct stat fileStats;
			if (stat(globFName, &fileStats) == 0) {
				captureFileSize += fileStats.st_size;
			} else {
#if VERBOSE > 0
				T2_WRN("Failed to get stats of file '%s': %s", globFName, strerror(errno));
#endif // VERBOSE > 0
				//captureFileSize = 0;
			}

			BPFSET(captureDescriptor, bpfCommand);
#if VERBOSE > 1
			T2_LOG("Processing file: %s", globFName);
			fflush(dooF);
#endif // VERBOSE > 1

		// -R option

		} else if (capType & LISTFILE) {
			if (!caplist_elem->next) {
				// there is no next file -> terminate
				globalInt = GI_EXIT;
				return NULL;
			}

			pcap_close(captureDescriptor);

			// set descriptor to next file
			caplist_elem = caplist_elem->next;
			caplist_index++;

			if (UNLIKELY(!(captureDescriptor = pcap_open_offline(caplist_elem->name, errbuf)))) {
				T2_ERR("pcap_open_offline failed: %s", errbuf);
				globalInt = GI_EXIT;
				return NULL;
			}

			BPFSET(captureDescriptor, bpfCommand);

#if VERBOSE > 1
			const int linkType = pcap_datalink(captureDescriptor);
			T2_LOG("Processing file no. %"PRIu32" of %"PRIu32": %s", caplist_index + 1, caplist->num_files, caplist_elem->name);
			T2_LOG("Link layer type: %s [%s/%d]", pcap_datalink_val_to_description(linkType), pcap_datalink_val_to_name(linkType), linkType);
			fflush(dooF);
#endif // VERBOSE > 1

		// -i option

		} else {
			// reading from live-interface. As we are using non-blocking mode,
			// pcap_dispatch returns zero immediately if no packets are to be
			// read at the moment. This would cost much CPU consumption when no
			// packets can be read, therefore sleep some time
			usleep(NO_PKTS_DELAY_US);
		}
	}

	return NULL;
}


static void ioBufferPush(u_char *inqueue __attribute__((unused)), const struct pcap_pkthdr *pcapHeader, const u_char *packet) {
	pthread_mutex_lock(&buflock);

	const unsigned long nextElement = (writePos + 1) % IO_BUFFER_SIZE;

	while (nextElement == readPos) {
		pthread_mutex_unlock(&buflock);
		usleep(IO_BUFFER_FULL_WAIT_MS);
		if ((globalInt & GI_RUN) <= GI_EXIT) return;
		pthread_mutex_lock(&buflock);
	}

	headerBuffer[writePos] = *pcapHeader;
	if (LIKELY(pcapHeader->caplen <= IO_BUFFER_MAX_MTU)) {
		memcpy(&packetBuffer[writePos], packet, pcapHeader->caplen);
	} else {
		if (!(globalWarn & PCAPSNPD)) {
			T2_WRN("Packet caplen (%d) is bigger than buffer MAX_MTU (%d): reducing caplen", pcapHeader->caplen, IO_BUFFER_MAX_MTU);
			T2_INF("Fix: Increase IO_BUFFER_MAX_MTU in ioBuffer.h");
			globalWarn |= PCAPSNPD;
		}
		gBufStat = 1;
		headerBuffer[writePos].caplen = IO_BUFFER_MAX_MTU;
		memcpy(&packetBuffer[writePos], packet, IO_BUFFER_MAX_MTU);
	}

	writePos = nextElement;

	pthread_mutex_unlock(&buflock);
}


static int ioBufferPop(struct pcap_pkthdr **header, u_char **packet) {
	pthread_mutex_lock(&buflock);

	while (readPos == writePos) {
		pthread_mutex_unlock(&buflock);
		usleep(IO_BUFFER_FULL_WAIT_MS);
		if (UNLIKELY((globalInt & GI_RUN) <= GI_EXIT)) return 0;
		pthread_mutex_lock(&buflock);
	}

	*packet = packetBuffer[readPos];
	*header = &headerBuffer[readPos];

	readPos = (readPos + 1) % IO_BUFFER_SIZE;

	pthread_mutex_unlock(&buflock);

	return 1;
}


void mainLoop() {

#if MONINTBLK == 1
	sigset_t mask = t2_get_sigset();
#endif // MONINTBLK == 1

	struct pcap_pkthdr *pcapHeader;
	u_char *packet;

	while (ioBufferPop(&pcapHeader, &packet)) {
#if MONINTBLK == 1
		sigprocmask(SIG_BLOCK, &mask, NULL);
#endif // MONINTBLK == 1

		perPacketCallback(NULL, pcapHeader, packet);

#if MONINTBLK == 1
		sigpending(&mask);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
#endif // MONINTBLK == 1

#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
		if (globalInt & GI_RPRT) {
			printGStats();
			globalInt &= ~GI_RPRT;
		}
#endif // (MONINTPSYNC == 1 || MONINTTMPCP == 1)
	}
}

#endif // ENABLE_IO_BUFFERING != 0
