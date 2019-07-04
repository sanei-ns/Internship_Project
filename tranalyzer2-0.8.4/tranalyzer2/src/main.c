/*
 * main.c
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

#include "main.h"
#include "../config.h"
#include "fsutils.h"
#include "memdebug.h"
#include "bin2txt.h"

#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>


// Returns true if flow f is a sentinel
#define FLOW_IS_SENTINEL(f) ((f)->timeout == INFINITY)

#define T2_PRINT_BANNER(file) \
	fputs("\n" \
	      "                                    @      @                                    \n"  \
	      "                                     |    |                                     \n"  \
	      "===============================vVv==(a    a)==vVv===============================\n"  \
	      "=====================================\\    /=====================================\n" \
	      "======================================\\  /======================================\n" \
	      "                                       oo                                       \n", \
	      (file))

#define T2_CONF_REPORT(file) \
	T2_FINF(file, "Creating flows for %s%s%s", \
		(ETH_ACTIVATE > 0) ? "L2, " : "", \
		(IPV6_ACTIVATE == 2) ? "IPv4, IPv6" : \
			(IPV6_ACTIVATE == 1) ? "IPv6" : "IPv4", \
		(SCTP_ACTIVATE == 1) ? ", SCTP" : "")

#define T2_PRINT_GLOBALWARN(file) \
	if (globalWarn & L2SNAPLENGTH) T2_FWRN(file, "L2 header snapped"); \
	if (globalWarn & L3SNAPLENGTH) T2_FWRN(file, "L3 SnapLength < Length in IP header"); \
	if (globalWarn & L3HDRSHRTLEN) T2_FWRN(file, "L3 header snapped"); \
	if (globalWarn & L4HDRSHRTLEN) T2_FWRN(file, "L4 header snapped"); \
	if (globalWarn & LANDATTACK)   T2_FWRN(file, "Landattack"); \
	if (globalWarn & TIMEJUMP)     T2_FWRN(file, "Timestamp jump, probably due to multi path packet delay or NTP operation"); \
	if (globalWarn & DUPIPID)      T2_FWRN(file, "Consecutive duplicate IP ID"); \
	if (globalWarn & PCAPSNPD)     T2_FWRN(file, "PCAP packet length > MAX_MTU in ioBuffer.h, caplen reduced"); \
	if (globalWarn & HDOVRN)       T2_FWRN(file, "Header description overrun"); \
	if (globalWarn & L3_IPVX)      T2_FWRN(file, "IPvX L3 header bogus packets"); \
	if (globalWarn & IPV4_FRAG_HDSEQ_ERR) { \
		T2_FWRN(file, "IPv4/6 fragmentation header packet missing%s", FRAG_HLST_CRFT ? "" : ", trailing packets ignored"); \
	} \
	if (globalWarn & IPV4_FRAG_PENDING) { \
		T2_FWRN(file, "IPv4/6 packet fragmentation sequence not finished"); \
	} \
	if (globalWarn & L2_IPV4)      T2_FINF(file, "IPv4"); \
	if (globalWarn & L2_IPV6)      T2_FINF(file, "IPv6"); \
	if (globalWarn & IPV4_FRAG)    T2_FINF(file, "IPv4/6 fragmentation"); \
	if (globalWarn & L3_IPIP)      T2_FINF(file, "IPv4/6 in IPv4/6"); \
	if (globalWarn & L2_VLAN)      T2_FINF(file, "VLAN encapsulation"); \
	if (globalWarn & FS_VLAN0)     T2_FINF(file, "VLAN ID 0 (priority tag)"); \
	if (globalWarn & L3_VXLAN)     T2_FINF(file, "VXLAN encapsulation"); \
	if (globalWarn & L3_GENEVE)    T2_FINF(file, "GENEVE encapsulation"); \
	if (globalWarn & L2_MPLS)      T2_FINF(file, "MPLS encapsulation"); \
	if (globalWarn & L2_L2TP)      T2_FINF(file, "L2TP encapsulation"); \
	if (globalWarn & L2_PPP)       T2_FINF(file, "PPP/HDLC encapsulation"); \
	if (globalWarn & L2_GRE)       T2_FINF(file, "GRE encapsulation"); \
	if (globalWarn & L2_ERSPAN)    T2_FINF(file, "ERSPAN encapsulation"); \
	if (globalWarn & L2_WCCP)      T2_FINF(file, "WCCP encapsulation"); \
	if (globalWarn & L2_NO_ETH)    T2_FINF(file, "No Ethernet header"); \
	if (globalWarn & L3_ETHIPF)    T2_FINF(file, "EoIP"); \
	if (globalWarn & L3_AYIYA)     T2_FINF(file, "AYIYA tunnel"); \
	if (globalWarn & L3_GTP)       T2_FINF(file, "GTP tunnel"); \
	if (globalWarn & L3_TRDO)      T2_FINF(file, "Teredo tunnel"); \
	if (globalWarn & L3_CAPWAP)    T2_FINF(file, "CAPWAP/LWAPP tunnel"); \
	if (globalWarn & L4_SCTP)      T2_FINF(file, "SCTP flows"); \
	if (globalWarn & L4_UPNP)      T2_FINF(file, "SSDP/UPnP flows"); \
	if (globalWarn & L2_FLOW)      T2_FINF(file, "Ethernet flows"); \
	if (globalWarn & L2_LLDP)      T2_FINF(file, "LLDP flows"); \
	if (globalWarn & L2_ARP)       T2_FINF(file, "ARP flows"); \
	if (globalWarn & L2_RARP)      T2_FINF(file, "RARP flows"); \
	if (globalWarn & L7_SIPRTP)    T2_FINF(file, "SIP/RTP flows"); \
	if (globalWarn & L3_IPSEC_AH)  T2_FINF(file, "Authentication Header (AH)"); \
	if (globalWarn & L3_IPSEC_ESP) T2_FINF(file, "Encapsulating Security Payload (ESP)"); \
	if (globalWarn & TORADD)       T2_FINF(file, "TOR addresses")

// 24 = size of global pcap header,
// 16 = pcap header of every capture packet.
// (see http://wiki.wireshark.org/Development/LibpcapFileFormat)
#define T2_LOG_PERCENT(stream, nfiles, fsize) \
	fprintf(stream, "Percentage completed: %.2f%%\n", \
			100.0f * ((24*(nfiles)) + bytesProcessed + (16*numPackets)) / (double)fsize)


// global main/thread interrupt
#if MONINTTHRD == 1
volatile sig_atomic_t globalInt = GI_INIT;
#else // MONINTTHRD == 0
volatile uint32_t globalInt = GI_INIT;
#endif // MONINTTHRD == 0

uint64_t globalWarn;       // global warning & status register

pcap_t *captureDescriptor; // pcap handler

#if ALARM_MODE == 1
unsigned char supOut;      // suppress output
#endif

#if (FORCE_MODE == 1 || FDURLIMIT > 0)
unsigned long num_rm_flows;
flow_t *rm_flows[10];
#endif

binary_value_t *main_header_bv;
flow_t *flows;
#if FRAGMENTATION >= 1
hashMap_t *fragPendMap;
#endif
hashMap_t *mainHashMap;
outputBuffer_t *main_output_buffer;
t2_plugin_array_t *t2_plugins;

file_manager_t *t2_file_manager;

// counter and monitoring diff mode vars

uint64_t numBytesL2[65536], numBytes0L2[65536];
uint64_t numPacketsL2[65536], numPackets0L2[65536];

uint64_t numBytesL3[256], numBytes0L3[256];
uint64_t numPacketsL3[256], numPackets0L3[256];

uint64_t captureFileSize;
uint64_t bytesProcessed, bytesProcessed0;
uint64_t bytesOnWire, bytesOnWire0;
uint64_t maxNumFlows; //, maxNumFlows0;
uint64_t numAPackets, numAPackets0;
uint64_t numBPackets, numBPackets0;
uint64_t numABytes, numABytes0;
uint64_t numBBytes, numBBytes0;
uint64_t maxNumFlowsPeak; //, maxNumFlowsPeak0;
uint64_t numAlarms, numAlarms0;
#if FORCE_MODE == 1
uint64_t numForced, numForced0;
#endif
uint64_t numFragV4Packets, numFragV4Packets0;
uint64_t numFragV6Packets, numFragV6Packets0;
uint64_t numLLCPackets, numLLCPackets0;
uint64_t numGREPackets, numGREPackets0;
uint64_t numTeredoPackets, numTeredoPackets0;
uint64_t numAYIYAPackets, numAYIYAPackets0;
uint64_t numPackets, numPackets0;
uint64_t numV4Packets, numV4Packets0;
uint64_t numV6Packets, numV6Packets0;
uint64_t numVxPackets, numVxPackets0;
uint64_t padBytesOnWire, padBytesOnWire0;
uint64_t rawBytesOnWire, rawBytesOnWire0;
uint64_t totalAFlows, totalAFlows0;
uint64_t totalBFlows, totalBFlows0;
uint64_t corrReplFlws, corrReplFlws0;
uint64_t totalfIndex; //, totalfIndex0;
uint64_t totalFlows, totalFlows0;
uint64_t memmax0, hshFSize0;

uint16_t maxHdrDesc, minHdrDesc = UINT16_MAX;
float aveHdrDesc;

// endreport max min bandwidth info
#if MIN_MAX_ESTIMATE == 1
uint64_t rawBytesW0, maxBytesPs, lagTm;
uint64_t minBytesPs = UINT64_MAX;
#endif

uint8_t vlanHdrCntMx, mplsHdrCntMx;

struct timeval actTime, startTime;
struct timeval startTStamp, startTStamp0;

// parsing parameters
char *cmdline;                   // command line
char *capName;                   // -D, -i, -r and -R options
uint16_t capType;
char *pluginFolder;              // -p option
#if USE_PLLIST > 0
char *pluginList;                // -b option
#endif
char *baseFileName;              // -w/-W options, prefix for all generated files
char *esomFileName;              // -e option, for pcapd
FILE *dooF;                      // -l option, end report file
FILE *sPktFile;                  // -s option, packet file
uint32_t sensorID = T2_SENSORID; // Sensor ID from central host or user
char *fileNumP, fileNumB[21];    // -D option
uint32_t fileNum;                // -D option, incremental file ID
uint32_t fileNumE;               // -D option, final file ID
uint8_t numType;                 // -D option, trailing 0?
int fNumLen, fNumLen0;           // -D option, Number length
char *pDot;                      // -D option, postion of '.'
char *globFName;                 // -D option
double oFragFsz;                 // -W option
uint64_t oFileNumB;              // -W option
char *bpfCommand;                // bpf filter command
caplist_t *caplist;              // -R option
caplist_elem_t *caplist_elem;    // -R option
uint32_t caplist_index;          // -R option

// Avoid multiple calls to strlen()
// (set in t2_set_baseFileName() and t2_set_pluginFolder())
size_t baseFileName_len;
size_t pluginFolder_len;


// static variables

#if MACHINE_REPORT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1
static const uint16_t monProtL2[] = { MONPROTL2 }; // Monitoring L2 proto array
static const uint8_t  monProtL3[] = { MONPROTL3 }; // Monitoring L3 proto array

#define NUMMONPL2 (sizeof(monProtL2) >> 1)
#define NUMMONPL3  sizeof(monProtL3)

#endif // MACHINE_REPORT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1

#if MACHINE_REPORT == 1 && MONPROTMD == 1
static char ipProtSn[256][16];
#endif

#if REPSUP == 1
static uint64_t numLstPackets; // for alive mode
#endif

static timeout_t *timeout_list;

#if HASH_AUTOPILOT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1
static uint64_t totalRmFlows, totalRmFlows0;
#endif


// Static inline functions prototypes

static inline FILE *t2_create_pktfile();
static inline FILE *t2_open_logFile();

static inline void t2_set_baseFileName();
static inline void t2_set_pluginFolder();

static inline void t2_setup_sigaction();

#if BLOCK_BUF == 0
static inline binary_value_t *buildHeaders();
#endif

static inline void cycleLRUList(timeout_t *th);
static inline void lruPrintFlow(const flow_t * const flow);
static inline void printFlow(unsigned long flowIndex, uint8_t dir);
static inline flow_t *removeFlow(flow_t *aFlow);

#if VERBOSE > 0 || MACHINE_REPORT == 0
static inline void t2_print_report(FILE *stream, bool monitoring);
#endif

#if MACHINE_REPORT == 1
static inline void t2_machine_report_header(FILE *stream);
static inline void t2_machine_report(FILE *stream);
#endif

#if DIFF_REPORT == 1 && VERBOSE > 0
static inline void resetGStats0();
#endif

#if DIFF_REPORT == 1
static inline void updateGStats0();
#endif

#if PID_FNM_ACT == 1
static inline void t2_create_pid_file();
static inline void t2_destroy_pid_file();
#endif

#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
static inline void t2_load_proto_file();
#endif

#ifndef __APPLE__
static inline void t2_set_cpu(int cpu);
#endif


// Static functions prototypes

static __attribute__((noreturn)) void t2_abort_with_help();
static void t2_usage();
static void t2_version();
static void t2_cleanup();
static char *copy_argv(char **argv);
static caplist_t *read_caplist(const char *filename);
#if ENABLE_IO_BUFFERING == 0
static void mainLoop();
#endif
static void prepareSniffing();
static char *read_bpffile(const char *fname);

#if (MONINTTHRD == 1 && MONINTBLK == 0)
static void *intThreadHandler(void *arg);
#endif
static void sigHandler(int scode);

#if REPORT_HIST == 1
static void t2_restore_state();
static void t2_save_state();
#endif


// main Tranalyzer2

int main(int argc, char *argv[]) {

	if (UNLIKELY(argc == 1)) {
		t2_usage();
		exit(EXIT_FAILURE);
	}

	cmdline = copy_argv(&argv[0]);

	int op;
#ifdef __APPLE__
	while ((op = getopt(argc, argv, ":i:r:R:D:w:W:p:b:e:f:x:F:slvh")) != EOF) {
#else // !__APPLE__
	int cpu = -1;
	while ((op = getopt(argc, argv, ":i:r:R:D:w:W:p:b:e:f:x:c:F:slvh?")) != EOF) {
#endif // !__APPLE__
		switch (op) {

			// Input

			case 'r':
				capType |= CAPFILE;
				if (CAPTYPE_ERROR(capType, CAPFILE)) capType |= FILECNFLCT;
				capName = optarg;
				break;

			case 'R':
				capType |= LISTFILE;
				if (CAPTYPE_ERROR(capType, LISTFILE)) capType |= FILECNFLCT;
				capName = optarg;
				break;

			case 'i':
				capType |= IFACE;
				if (CAPTYPE_ERROR(capType, IFACE)) capType |= FILECNFLCT;
				capName = optarg;
				break;

			case 'D': {
				capType |= DIRFILE;
				if (CAPTYPE_ERROR(capType, DIRFILE)) {
					capType |= FILECNFLCT;
					break;
				}

				size_t len = strlen(optarg);
				capName = calloc(len + 21, 1);
				memcpy(capName, optarg, len);
				fileNumP = memrchr(capName, ',', len);
				if (!fileNumP) {
					fileNumE = UINT32_MAX;
				} else {
					len = (fileNumP - capName);
					*fileNumP++ = 0;
					if (*fileNumP == '-') goto frmerr;
					fileNumE = strtoul(fileNumP, NULL, 0);
				}

				char *oBP = memrchr(capName, ':', len);
				if (!oBP) {
					fileNumP = memrchr(capName, SCHR, len);
				} else {
					const char schr = oBP[1];
					len = (oBP - capName);
					*oBP = '\0';
					fileNumP = memrchr(capName, schr, len);
				}

				if (fileNumP) {
					fileNumP++;
					len -= (fileNumP - capName);
					pDot = memchr(fileNumP, '.', len);
					if (pDot) len -= strlen(pDot);
					if (*fileNumP == '0') {
						fNumLen = len;
						numType = 1;
						if (fileNumE == UINT32_MAX) {
							fileNumE = pow(10, fNumLen) - 1;
						}
					}
					fileNum = strtoul(fileNumP, NULL, 0);
					memcpy(fileNumB, fileNumP, len);
					fNumLen0 = len+1;
					break;
				}
frmerr:
				free(capName);
				free(cmdline);
				T2_ERR("Invalid format for option '-%c': expr[:schr][,stop]", op);
				t2_abort_with_help();
			}

			// Output

			case 'w':
				baseFileName = optarg;
				break;

			case 'W': {
				capType |= OFILELN;
				size_t len = strlen(optarg);
				char *oBP1 = memrchr(optarg, ',', len);
				if (oBP1) {
					oFileNumB = strtoull(oBP1+1, NULL, 0);
					*oBP1 = 0;
				}
				char *oBP = memrchr(optarg, ':', len);
				if (!oBP) {
					oFragFsz = OFRWFILELN;
				} else {
					oFragFsz = atof(oBP + 1);
					if (oBP1) oBP1--;
					else oBP1 = optarg + len - 1;
					if (*oBP1 == 'f') {
						capType |= WFINDEX;
						oBP1--;
					}
					if (*oBP1 == 'K') oFragFsz *= 1000.0;
					else if (*oBP1 == 'M') oFragFsz *= 1000000.0;
					else if (*oBP1 == 'G') oFragFsz *= 1000000000.0;
					*oBP = 0;
				}
				baseFileName = optarg;
				break;
			}

			case 'l':
				capType |= LOGFILE;
				break;

			case 's':
				capType |= PKTFILE;
				break;

			// Optional arguments

			case 'p':
				pluginFolder = optarg;
				break;

#if USE_PLLIST > 0
			case 'b':
				pluginList = optarg;
				break;
#endif // USE_PLLIST > 0

			case 'e':
				esomFileName = optarg;
				break;

			case 'f':
				hashFactor = atol(optarg);
				if (hashFactor == 0) {
					T2_ERR("Hash factor must be greater than 0");
					exit(EXIT_FAILURE);
				}
				break;

			case 'x':
				sensorID = atol(optarg);
				break;

#ifndef __APPLE__
			case 'c':
				cpu = atoi(optarg);
				break;
#endif // __APPLE__

			case 'F':
				bpfCommand = read_bpffile(optarg);
				break;

			case 'v':
				t2_version();
				exit(EXIT_SUCCESS);

#ifndef __APPLE__
			case '?':
#endif // __APPLE__
			case 'h':
				t2_usage();
				exit(EXIT_SUCCESS);

			case ':':
				T2_ERR("Option '-%c' requires an argument", optopt);
				t2_abort_with_help();

			default:
				T2_ERR("Unknown option '-%c'", optopt);
				t2_abort_with_help();
		}
	}

	// all remaining parameters belong to the bpf string
	// (except if the '-F' option was used)
	if (!bpfCommand) bpfCommand = copy_argv(&argv[optind]);

	// check that at least one input source was specified
	if (!(capType & CAPTYPE_REQUIRED)) {
		T2_ERR("One of '-r', '-R', '-D' or '-i' option is required");
		t2_abort_with_help();
	}

	// check that only one input source was specified
	if (capType & FILECNFLCT) {
		T2_ERR("'-r', '-R', '-D' and '-i' options can only be used exclusively");
		t2_abort_with_help();
	}

	t2_set_baseFileName();
	t2_set_pluginFolder();

	dooF = t2_open_logFile();

	if (getuid() == 0 && !(capType & IFACE)) {
		T2_WRN("Running Tranalyzer as root on a pcap is not recommended");
		sleep(1);
	}

#if PID_FNM_ACT == 1
	t2_create_pid_file();
#endif // PID_FNM_ACT == 1

#ifndef __APPLE__
	if (cpu != -1) t2_set_cpu(cpu);
#endif // __APPLE__

#if VERBOSE > 0
	T2_LOG("================================================================================"); // 80 chars
	T2_LOG("%s %s (%s), %s. PID: %d", APPNAME, APPVERSION, CODENAME, RELEASE_TYPE, getpid());
	T2_LOG("================================================================================"); // 80 chars
	T2_CONF_REPORT(dooF);
#endif // VERBOSE > 0

	// block all relevant interrupts to be shifted to the thread
	t2_setup_sigaction();

#if MONINTBLK == 0
	sigset_t mask = t2_get_sigset();

#if MONINTTHRD == 0
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
#else // MONINTTHRD == 1
	sigprocmask(SIG_BLOCK, &mask, NULL);
	pthread_t thread;
	pthread_create(&thread, NULL, intThreadHandler, NULL);
#endif // MONINTTHRD == 1
#endif // MONINTBLK == 0

	prepareSniffing();

#if MONINTTMPCP == 0 && MONINTTMPCP_ON == 1
	globalInt |= GI_ALRM;
	alarm(MONINTV);
#endif

	mainLoop();

	terminate();

	// Never called...
	return EXIT_SUCCESS;
}


static void prepareSniffing() {
	struct stat fileStats;
	char errbuf[PCAP_ERRBUF_SIZE];

	// prepare data source
	if (capType & CAPFILE) { // -r option
		if (UNLIKELY(!ckpcaphdr(capName))) exit(-1); // check file type

		// open pcap
		if (UNLIKELY(!(captureDescriptor = pcap_open_offline(capName, errbuf)))) {
		//if (UNLIKELY(!(captureDescriptor = pcap_open_offline_with_tstamp_precision(capName, PTSPREC, errbuf)))) {
			T2_ERR("pcap_open_offline failed: %s", errbuf);
			exit(-1);
		}

		// read number of bytes residing in dump file
		if (stat(capName, &fileStats) == 0) {
			captureFileSize += fileStats.st_size;
		} else {
			if (*capName != '-') T2_WRN("Cannot get stats of file %s: %s", capName, strerror(errno));
			//captureFileSize = 0;
		}
	} else if (capType & IFACE) { // -i option
		// open in promisc mode
		if (UNLIKELY(!(captureDescriptor = pcap_open_live(capName, SNAPLEN, 1, CAPTURE_TIMEOUT, errbuf)))) {
			T2_ERR("pcap_open_live failed: %s", errbuf);
			exit(-1);
		}

		if (UNLIKELY(pcap_setnonblock(captureDescriptor, NON_BLOCKING_MODE, errbuf) == -1)) {
			T2_ERR("Could not set blocking mode %d: %s", NON_BLOCKING_MODE, errbuf);
			exit(1);
		}
	} else if (capType & DIRFILE) { // -D option
		char *tmp;
		wordexp_t globName;
		wordexp(capName, &globName, 0);
		size_t len = strlen(globName.we_wordv[0]);
		globFName = calloc(len + 64, 1);
		memcpy(globFName, globName.we_wordv[0], len + 1);
		wordfree(&globName);

		//if (UNLIKELY(!ckpcaphdr(globFName))) exit(-1); // check file type

		// open 1. capture file
		while ((captureDescriptor = pcap_open_offline(globFName, errbuf)) == NULL) {
#if VERBOSE > 1
			if ((capType & LOGFILE) == 0) fputc('.', dooF);
#endif
			fflush(NULL); // commit all changes in all buffers
			sleep(POLLTM);
			if (UNLIKELY(globalInt == GI_EXIT)) exit(-1);

			wordexp(capName, &globName, 0);
			len = strlen(globName.we_wordv[0]);
			tmp = realloc(globFName, len + 64);
			if (UNLIKELY(!tmp)) {
				T2_ERR("Failed to realloc globFName");
				free(globFName);
				exit(1);
			}
			globFName = tmp;
			memcpy(globFName, globName.we_wordv[0], len + 1);
			wordfree(&globName);
		}

		// acquire filelength
		if (stat(globFName, &fileStats) == 0) {
			captureFileSize += fileStats.st_size;
		} else {
#if VERBOSE > 0
			T2_WRN("Cannot get stats of file '%s': %s", globFName, strerror(errno));
			T2_INF("Waiting for %"PRIu32, fileNum);
#endif
			//captureFileSize = 0;
		}
	} else if (capType & LISTFILE) { // -R option
		// open file with list of pcap dump files in it
		if (UNLIKELY(!(caplist = read_caplist(capName)))) {
			T2_ERR("No valid files found in %s", capName);
			exit(-1);
		}

		// start with the first file in list
		caplist_elem = caplist->file_list;
		caplist_index = 0;
		if (UNLIKELY(!(captureDescriptor = pcap_open_offline(caplist_elem->name, errbuf)))) {
			T2_ERR("pcap_open_offline failed: %s", errbuf);
			exit(-1);
		}
	}

	// setup the bpf filter
	BPFSET(captureDescriptor, bpfCommand);

	// reset lru list
	lruHead.lruNextFlow = &lruTail;
	lruHead.lruPrevFlow = NULL;
	lruTail.lruNextFlow = NULL;
	lruTail.lruPrevFlow = &lruHead;

	// initialize timeout manager with default timeout handler
	timeout_handler_add(FLOW_TIMEOUT);

	// initialize main buffer
	main_output_buffer = outputBuffer_initialize(MAIN_OUTPUT_BUFFER_SIZE);

	t2_plugins = load_tranalyzer_plugins(pluginFolder);

#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
	t2_load_proto_file();
#endif

	mainHashMap = hashTable_init(1.0f, ((char*) &lruHead.layer4Protocol - (char*) &lruHead.srcIP + sizeof(lruHead.layer4Protocol)), "main");

	// initialize flow array
	flows = calloc(mainHashMap->hashChainTableSize, sizeof(flow_t));
	if (UNLIKELY(!flows)) {
		T2_ERR("Failed to allocate memory for flows");
		exit(1);
	}

	// initialize T2 global file manager. max concurrently opened files allowed
	// depend on kernel limit (value can be checked with: ulimit -Hn)
	if (UNLIKELY(!(t2_file_manager = file_manager_new(SIZE_MAX)))) {
		T2_ERR("Failed to create file manager: %s.", strerror(errno));
		exit(1);
	}

#if FRAGMENTATION >= 1
	fragPendMap = hashTable_init(1.0f, ((char*) &lruHead.layer4Protocol - (char*) &lruHead.srcIP + sizeof(uint8_t)), "frag");

	// initialize fragPend array
	fragPend = calloc(fragPendMap->hashChainTableSize, sizeof(unsigned long));
	if (UNLIKELY(!fragPend)) {
		T2_ERR("Failed to allocate memory for fragPend");
		exit(1);
	}
#endif // FRAGMENTATION >= 1

#if BLOCK_BUF == 0
	main_header_bv = buildHeaders();
#endif

	if (capType & PKTFILE) sPktFile = t2_create_pktfile();

	FOREACH_PLUGIN_DO(init);

	if (sPktFile) {
#if SPKTMD_PCNTH == 1
	 	fputs("l7HexContent\t", sPktFile);
#endif
#if SPKTMD_PCNTC == 1
	 	fputs("l7Content\t", sPktFile);
#endif
		t2_discard_trailing_char(sPktFile, '\t');
		fputc('\n', sPktFile);
	}

#if ENABLE_IO_BUFFERING != 0
	ioBufferInitialize();
#endif

#if REPORT_HIST == 1
	t2_restore_state();
#endif

#if VERBOSE > 1
	if (capType & CAPFILE) T2_LOG("Processing file: %s", capName);
	else if (capType & LISTFILE) T2_LOG("Processing list file: %s", capName);
	else if (capType & DIRFILE) T2_LOG("Processing file: %s", globFName);
	else if (capType & IFACE) T2_LOG("Live capture on interface: %s", capName);

	if (bpfCommand) T2_INF("BPF: %s", bpfCommand);

	if (capType & LISTFILE) {
		T2_LOG("Processing file no. %"PRIu32" of %"PRIu32": %s", caplist_index + 1, caplist->num_files, caplist_elem->name);
	}

	const int linkType = pcap_datalink(captureDescriptor);
	T2_LOG("Link layer type: %s [%s/%d]", pcap_datalink_val_to_description(linkType), pcap_datalink_val_to_name(linkType), linkType);
	fflush(dooF);
#endif // VERBOSE > 1

#if MACHINE_REPORT == 1
	t2_machine_report_header(stdout);
#endif

	// begin counting ticks
	gettimeofday(&startTime, NULL);
}


static inline void t2_setup_sigaction() {
	struct sigaction sa;
	sigfillset(&sa.sa_mask);
	sa.sa_handler = sigHandler;
	sa.sa_flags = SA_RESTART; // Restart system call, if possible
	//sa.sa_flags = (SA_RESTART | SA_SIGINFO); // Restart system call, if possible and enable process info
	if (UNLIKELY(sigaction(SIGINT,  &sa, NULL) == -1)) perror("Error: cannot handle SIGINT");
	if (UNLIKELY(sigaction(SIGTERM, &sa, NULL) == -1)) perror("Error: cannot handle SIGTERM");
	if (UNLIKELY(sigaction(SIGUSR1, &sa, NULL) == -1)) perror("Error: cannot handle SIGUSR1");
	if (UNLIKELY(sigaction(SIGUSR2, &sa, NULL) == -1)) perror("Error: cannot handle SIGUSR2");
	if (UNLIKELY(sigaction(SIGALRM, &sa, NULL) == -1)) perror("Error: cannot handle SIGALRM");
	if (UNLIKELY(sigaction(SIGSYS,  &sa, NULL) == -1)) perror("Error: cannot handle SIGSYS");
}


inline sigset_t t2_get_sigset() {
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGUSR2);
	sigaddset(&sigset, SIGALRM);
#if REPSUP == 1
	sigaddset(&sigset, SIGSYS);
#endif
	return sigset;
}


#if ENABLE_IO_BUFFERING == 0
static void mainLoop() {

#if MONINTBLK == 1
	sigset_t mask = t2_get_sigset();
#endif // MONINTBLK == 1

	char errbuf[PCAP_ERRBUF_SIZE];

	while (LIKELY((globalInt & GI_RUN) > GI_EXIT)) {
#if MONINTBLK == 1
		sigprocmask (SIG_BLOCK, &mask, NULL);
#endif

		const int pcap_ret = pcap_dispatch(captureDescriptor, PACKETS_PER_BURST, perPacketCallback, NULL);

#if MONINTBLK == 1
		sigpending(&mask);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
#endif

		if (UNLIKELY(pcap_ret == -1)) {
			T2_WRN("pcap_dispatch failed: %s", pcap_geterr(captureDescriptor));
			//globalInt = GI_EXIT;
		} else if (pcap_ret == 0) {
			// Terminate if we are reading from a file rather than live-sniffing
			if (capType & CAPFILE) globalInt = GI_EXIT;
			else if (capType & DIRFILE) {
#if RROP == 0
				if (fileNum >= fileNumE) {
					globalInt = GI_EXIT;
					return;
				}
#endif // RROP == 0

				pcap_close(captureDescriptor);

#if MFPTMOUT > 0
				time_t sec0;
nxtnum:				sec0 = time(NULL);
#endif
				fileNum++;
				if (numType) {
#if RROP == 1
					if (fileNum > fileNumE) fileNum = strtoul(fileNumB, NULL, 0);
#endif
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

				if (UNLIKELY(!ckpcaphdr(globFName))) exit(-1); // check file type

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
#endif
					fflush(NULL); // commit all changes in all buffers
					sleep(POLLTM);
					if (UNLIKELY(globalInt == GI_EXIT)) return;
					wordexp(capName, &globName, 0);
					memcpy(globFName, globName.we_wordv[0], strlen(globName.we_wordv[0]) + 1);
					wordfree(&globName);
#if MFPTMOUT > 0
					if (time(NULL) - sec0 >= MFPTMOUT) goto nxtnum;
#endif
				}

				// get filesize info
				struct stat fileStats;
				if (stat(globFName, &fileStats) == 0) {
					captureFileSize += fileStats.st_size;
				} else {
#if VERBOSE > 0
					T2_WRN("Failed to get stats of file '%s': %s", globFName, strerror(errno));
#endif
					//captureFileSize = 0;
				}

				BPFSET(captureDescriptor, bpfCommand);
#if VERBOSE > 1
				T2_LOG("Processing file: %s", globFName);
				fflush(dooF);
#endif
			} else if (capType & LISTFILE) {
				if (!caplist_elem->next) {
					// there is no next file -> terminate
					globalInt = GI_EXIT;
				} else {
					pcap_close(captureDescriptor);

					// set descriptor to next file
					caplist_elem = caplist_elem->next;
					caplist_index++;

					if (UNLIKELY(!(captureDescriptor = pcap_open_offline(caplist_elem->name, errbuf)))) {
						T2_ERR("pcap_open_offline failed: %s", errbuf);
						globalInt = GI_EXIT;
						break;
					}

					BPFSET(captureDescriptor, bpfCommand);

#if VERBOSE > 1
					T2_LOG("Processing file no. %"PRIu32" of %"PRIu32": %s", caplist_index + 1, caplist->num_files, caplist_elem->name);
					const int linkType = pcap_datalink(captureDescriptor);
					T2_LOG("Link layer type: %s [%s/%d]", pcap_datalink_val_to_description(linkType), pcap_datalink_val_to_name(linkType), linkType);
					fflush(dooF);
#endif
				}
			} else {
				// reading from live-interface. As we're using non-blocking mode, pcap_dispatch returns zero immediately
				// if no packets are to be read at the moment. This would cost much cpu consumption when no packets can be read,
				// therefore sleep some time
				usleep(NO_PKTS_DELAY_US);
			}
		}

#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
		if (globalInt & GI_RPRT) {
			printGStats();
			globalInt &= ~GI_RPRT;
		}
#endif
	}
}
#endif // ENABLE_IO_BUFFERING == 0


/*
 * Returning 'prev' is necessary because the flow and its opposite could be
 * two following flows. When this is the case, then the pointer used outside
 * of this function would be invalid.
 */
static inline flow_t *removeFlow(flow_t *aFlow) {
	if (UNLIKELY(!aFlow)) return NULL;

	flow_t *remove[] = { aFlow, NULL };

	// Remove the reverse flow as well if it exists
	const unsigned long reverseFlowIndex = aFlow->oppositeFlowIndex;
	if (reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		remove[1] = &flows[reverseFlowIndex];
	}

	flow_t *flow;
	flow_t *prev = aFlow->lruPrevFlow;
	for (uint_fast8_t i = 0; i < 2; i++) {

		if (!(flow = remove[i])) return prev;

		if (UNLIKELY((hashTable_remove(mainHashMap, (char*)&flow->srcIP) == HASHTABLE_ENTRY_NOT_FOUND))) {
#if VERBOSE > 0
			const uint_fast8_t ipver = FLOW_IS_IPV6(flow) ? 6 : 4;
			char srcIP[INET6_ADDRSTRLEN];
			T2_IP_TO_STR(flow->srcIP, ipver, srcIP, INET6_ADDRSTRLEN);
			char dstIP[INET6_ADDRSTRLEN];
			T2_IP_TO_STR(flow->dstIP, ipver, dstIP, INET6_ADDRSTRLEN);
			T2_WRN("Failed to remove flow with flowIndex %lu from mainHashMap: %s:%u -> %s:%u proto %u, vlan %u, findex %"PRIu64,
					flow->flowIndex, srcIP, flow->srcPort, dstIP, flow->dstPort, flow->layer4Protocol, flow->vlanID, flow->findex);
#endif // VERBOSE > 0
			continue;
		}

#if FRAGMENTATION >= 1
		if (flow->status & IPV4_FRAG_PENDING) {
			flow->fragID = flow->lastFragIPID;
			hashTable_remove(fragPendMap, (char*)&flow->srcIP);
			globalWarn |= IPV4_FRAG_PENDING;
		}
#endif // FRAGMENTATION >= 1

		flow->lruNextFlow->lruPrevFlow = flow->lruPrevFlow;
		flow->lruPrevFlow->lruNextFlow = flow->lruNextFlow;

		// handle cases where the A and B flows follow each other
		if (prev == flow) prev = flow->lruPrevFlow;

		--maxNumFlows;
	}

	return prev;
}


inline void cycleLRULists() {

#if MIN_MAX_ESTIMATE == 1
	if (actTime.tv_sec - lagTm >= 1) {
		lagTm = actTime.tv_sec;
		const uint32_t i = rawBytesOnWire - rawBytesW0;
		if (maxBytesPs < i) maxBytesPs = i;
		if (i && minBytesPs > i) minBytesPs = i;
		rawBytesW0 = rawBytesOnWire;
	}
#endif // MIN_MAX_ESTIMATE == 1

#if (FORCE_MODE == 1 || FDURLIMIT > 0)
	flow_t *lruPointer;
	while (num_rm_flows) {
		lruPointer = rm_flows[--num_rm_flows];
		lruPrintFlow(lruPointer);
		removeFlow(lruPointer);
	}
#endif // (FORCE_MODE == 1 || FDURLIMIT > 0)

	timeout_t *t = timeout_list;
	while (t) {
		cycleLRUList(t);
		t = t->next;
	}
}


static inline void cycleLRUList(timeout_t *th) {
	float timeDiff;
	flow_t *revflow, *tmp;

	// from the timeout handler work backwards (commit and remove flows) until we
	// hit a flow which is younger than the timeout value of the timeout handler
	flow_t *lruPointer = th->flow.lruPrevFlow;
	while (lruPointer != &lruHead) {
		// if flow is a sentinel skip it
		if (FLOW_IS_SENTINEL(lruPointer)) {
			lruPointer = lruPointer->lruPrevFlow;
			continue;
		}

		// check if flow would be too young and could not have timed-out
		timeDiff = actTime.tv_sec - lruPointer->lastSeen.tv_sec;
		timeDiff += ((actTime.tv_usec - lruPointer->lastSeen.tv_usec) / 1000000.0f);

		if (timeDiff < th->timeout) break; // flow too young

		tmp = lruPointer->lruPrevFlow;

		if (timeDiff >= lruPointer->timeout) {
			// only remove flow if the opposite flow has timed-out too
			if (lruPointer->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
				lruPrintFlow(lruPointer);
				tmp = removeFlow(lruPointer);
			} else {
				revflow = &flows[lruPointer->oppositeFlowIndex];

				timeDiff = actTime.tv_sec - revflow->lastSeen.tv_sec;
				timeDiff += ((actTime.tv_usec - revflow->lastSeen.tv_usec) / 1000000.0f);

				if (timeDiff >= revflow->timeout) {
					lruPrintFlow(lruPointer);
					tmp = removeFlow(lruPointer);
				}
			}
		}

		lruPointer = tmp;
	}

	if (lruPointer != th->flow.lruPrevFlow) {
		// move timeout handler sentinel flow behind last inspected flow (behind lruPointer)
		th->flow.lruNextFlow->lruPrevFlow = th->flow.lruPrevFlow; // take out, step 1
		th->flow.lruPrevFlow->lruNextFlow = th->flow.lruNextFlow; // take out, step 2

		th->flow.lruNextFlow = lruPointer->lruNextFlow; // place in, step 1
		th->flow.lruPrevFlow = lruPointer;              // place in, step 2

		lruPointer->lruNextFlow->lruPrevFlow = &(th->flow); // connect, step 1
		lruPointer->lruNextFlow = &(th->flow);              // connect, step 2
	}

	// if the LRU list is empty and we want to stop the application from creating new flows, terminate
	if (UNLIKELY(mainHashMap->freeListSize == mainHashMap->hashChainTableSize && (globalInt & GI_RUN) < GI_TERM_THRES)) terminate();
}


#if HASH_AUTOPILOT == 1
inline void lruRmLstFlow() {
	flow_t *lruP = lruTail.lruPrevFlow;
	int n = NUMFLWRM;
	totalRmFlows += NUMFLWRM;
	while (lruP != &lruHead && n > 0) {
		// skip sentinels
		if (FLOW_IS_SENTINEL(lruP)) {
			lruP = lruP->lruPrevFlow;
			continue;
		}
		T2_SET_STATUS(lruP, RMFLOW_HFULL);
		lruPrintFlow(lruP);
		lruP = removeFlow(lruP);
		n--;
	}
}
#endif // HASH_AUTOPILOT == 1


// Print 'A' and 'B' flows (if present)
static inline void lruPrintFlow(const flow_t * const flow) {
	if (flow->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		// flow does not have a reverse flow
		if (flow->status & L3FLOWINVERT) corrReplFlws++;
		printFlow(flow->flowIndex, 0);
	} else if (flow->status & L3FLOWINVERT) {
		// flow is a 'B' flow
		printFlow(flow->oppositeFlowIndex, 0);
		printFlow(flow->flowIndex, 1);
	} else {
		// flow is an 'A' flow
		printFlow(flow->flowIndex, 0);
		printFlow(flow->oppositeFlowIndex, 1);
	}
}


#if BLOCK_BUF == 1
static inline void printFlow(unsigned long flowIndex, uint8_t dir __attribute__((unused))) {
#else
static inline void printFlow(unsigned long flowIndex, uint8_t dir) {
#endif
	if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) return;

	flow_t * const flow = &flows[flowIndex];

	// Compute the duration of the flow (local variables are required as the
	// flow_t structure is packed (see clang -Waddress-of-packed-member option)
	const struct timeval firstSeen = flow->firstSeen;
	const struct timeval lastSeen = flow->lastSeen;
	struct timeval duration;
	timersub(&lastSeen, &firstSeen, &duration);
	flow->duration = duration;

#if ALARM_MODE == 1
	supOut = 1;
#endif

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &dir, sizeof(uint8_t));
#endif

	FOREACH_PLUGIN_DO(onFlowTerm, flowIndex);

#if ALARM_MODE == 1
	if (supOut) {
		outputBuffer_reset(main_output_buffer);
		return;
	}
#endif

#if BLOCK_BUF == 0
	FOREACH_PLUGIN_DO(bufToSink, main_output_buffer);
	outputBuffer_reset(main_output_buffer);
#endif
}


/****************************************************************************
 *
 * Function: copy_argv(u_char **)
 *
 * Purpose: Copies a 2D array (like argv) into a flat string.
 *          Shamelessly stolen from TCPDump.
 *
 * Arguments: argv => 2D array to flatten
 *
 * Returns: Pointer to the flat string
 *
 ****************************************************************************/
static char *copy_argv(char **argv) {
	char **p;
	unsigned int len = 0;
	char *buf;
	char *src, *dst;
	void ftlerr(char *, ...);

	p = argv;
	if (*p == 0) return 0;

	while (*p) len += strlen(*p++) + 1;

	buf = (char *) malloc(len);

	if (buf == NULL) {
		fprintf(stdout, "ERROR: malloc() failed: %s\n", strerror(errno));
	}
	p = argv;
	dst = buf;

	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}

	dst[-1] = '\0';

	return buf;
}


static void t2_usage() {
	printf("%s - High performance flow based network traffic analyzer\n\n", PACKAGE_STRING);
	printf("Usage:\n");
	printf("    tranalyzer [OPTION...] <INPUT>\n");
	printf("\nInput:\n");
	printf("    -i IFACE     Listen on interface IFACE\n");
	printf("    -r PCAP      Read packets from PCAP file or from stdin if PCAP is \"-\"\n");
	printf("    -R FILE      Process every PCAP file listed in FILE\n");
	printf("    -D EXPR[:SCHR][,STOP]\n");
	printf("                 Process every PCAP file whose name matches EXPR, up to an\n");
	printf("                 optional last index STOP. If STOP is omitted, then Tranalyzer\n");
	printf("                 never stops. EXPR can be a filename, e.g., file.pcap0, or an\n");
	printf("                 expression, such as \"dump*.pcap00\", where the star matches\n");
	printf("                 anything (note the quotes to prevent the shell from\n");
	printf("                 interpreting the expression). SCHR can be used to specify the\n");
	printf("                 the last character before the index (default: '%c')\n", SCHR);

	printf("\nOutput:\n");
	printf("    -w PREFIX    Append PREFIX to any output file produced. If omitted, then\n");
	printf("                 output is diverted to stdout\n");
	printf("    -W PREFIX[:SIZE][,START]\n");
	printf("                 Like -w, but fragment flow files according to SIZE, producing\n");
	printf("                 files starting with index START. SIZE can be specified in bytes\n");
	printf("                 (default), KB ('K'), MB ('M') or GB ('G'). Scientific notation,\n");
	printf("                 i.e., 1e5 or 1E5 (=100000), can be used as well. If a 'f' is\n");
	printf("                 appended, e.g., 10Kf, then SIZE denotes the number of flows.\n");
	printf("    -l           Print end report in PREFIX_log.txt instead of stdout\n");
	printf("    -s           Packet forensics mode\n");

	printf("\nOptional arguments:\n");
	printf("    -p PATH      Load plugins from path PATH instead of ~/.tranalyzer/plugins\n");
#if USE_PLLIST > 0
	printf("    -b FILE      Use plugin list FILE instead of plugin_folder/plugins.txt\n");
#endif // USE_PLLIST > 0
	printf("    -e FILE      Creates a PCAP file by extracting all packets belonging to\n");
	printf("                 flow indexes listed in FILE (requires pcapd plugin)\n");
	printf("    -f FACTOR    Sets hash multiplication factor\n");
	printf("    -x ID        Sensor ID\n");
#ifndef __APPLE__
	printf("    -c CPU       Bind tranalyzer to one core. If CPU is 0 then OS selects the\n");
	printf("                 core to bind\n");
#endif // __APPLE__
	printf("    -F FILE      Read BPF filter from FILE\n");
	printf("\nHelp and documentation arguments:\n");
	printf("    -v           Show the version of the program and exit\n");
	printf("    -h           Show help options and exit\n");

	printf("\nRemaining arguments:\n");
	printf("    BPF          Berkeley Packet Filter command, as in tcpdump\n\n");
}


static void t2_version() {
	printf("%s (%s) [%s]\n", PACKAGE_STRING, CODENAME, RELEASE_TYPE);
}


static inline void terminateFlows() {
	if (LIKELY(totalFlows > 0)) {
		flow_t *lruP = lruTail.lruPrevFlow;
		while (lruP != &lruHead && LIKELY(globalInt)) {
			// Skip sentinels
			if (FLOW_IS_SENTINEL(lruP)) {
				lruP = lruP->lruPrevFlow;
				continue;
			}

			lruPrintFlow(lruP);
			lruP = removeFlow(lruP);
		}
	}
}


__attribute__((noreturn)) void terminate() {
	totalFlows = totalAFlows + totalBFlows;

	// commit all changes in all buffers
	fflush(NULL);

#if VERBOSE > 0
	t2_log_date(dooF, "Dump stop : ", actTime, TSTAMP_UTC);

	struct timeval duration;
	timersub(&actTime, &startTStamp, &duration);
	t2_log_time(dooF, "Total dump duration: ", duration);

	struct timeval elapsed, endTime;
	gettimeofday(&endTime, NULL);
	timersub(&endTime, &startTime, &elapsed);
	t2_log_time(dooF, "Finished processing. Elapsed time: ", elapsed);
#endif // VERBOSE > 0

	terminateFlows();

#if VERBOSE > 0
#if DIFF_REPORT == 1
	resetGStats0();
#endif // DIFF_REPORT == 1
	t2_print_report(dooF, false);
#endif // VERBOSE > 0

#if REPORT_HIST == 1
	t2_save_state();
#endif // REPORT_HIST == 1

	t2_cleanup();

	exit(EXIT_SUCCESS);
}


void printGStats() {
	totalFlows = totalAFlows + totalBFlows;

#if MACHINE_REPORT == 0
	t2_print_report(stdout, true);
#else // MACHINE_REPORT == 1
	t2_machine_report(stdout);
#endif // MACHINE_REPORT == 1

#if DIFF_REPORT == 1
	updateGStats0();
#endif // DIFF_REPORT == 1
}


#if VERBOSE > 0 || MACHINE_REPORT == 0
static inline void t2_print_report(FILE *stream, bool monitoring) {

	struct timeval duration;
	timersub(&actTime, monitoring ? &startTStamp0 : &startTStamp, &duration);

	struct timeval endTime;
	gettimeofday(&endTime, NULL);

	struct timeval elapsed;
	timersub(&endTime, &startTime, &elapsed);

	if (!monitoring) {
		t2_log_time(stream, "Finished unloading flow memory. Time: ", elapsed);
	} else {
		T2_PRINT_BANNER(stdout);
		T2_FLOG(stdout, "USR1 %c type report: %s %s (%s), %s. PID: %d", REPTYPE, APPNAME, APPVERSION, CODENAME, RELEASE_TYPE, getpid());
		t2_log_date(stream, "PCAP time: ", actTime, TSTAMP_UTC);
		t2_log_time(stream, "PCAP duration: ", duration);
		t2_log_date(stream, "Time: ", endTime, TSTAMP_R_UTC);
		t2_log_time(stream, "Elapsed time: ", elapsed);
	}

	if ((capType & CAPFILE) && captureFileSize) {
		if (monitoring) T2_FLOG_NUM0(stream, "Total bytes to process", captureFileSize);
		T2_LOG_PERCENT(stream, 1, captureFileSize);
	} else if ((capType & LISTFILE) && caplist->size) {
		if (monitoring) {
			T2_FLOG(stream, "Current file: %s (%"PRIu32"/%"PRIu32")", caplist_elem->name, caplist_index+1, caplist->num_files);
			T2_FLOG_NUM0(stream, "Total bytes to process", caplist->size);
			T2_FLOG_NUM(stream, "Current file size in bytes", caplist_elem->size);
		}
		T2_LOG_PERCENT(stream, caplist->num_files, caplist->size);
	} else if (capType & DIRFILE) {
		if (monitoring) T2_FLOG(stream, "Current file: %s", globFName);
		else T2_LOG_PERCENT(stream, 1, captureFileSize);
	} else if ((capType & IFACE) && captureDescriptor) {
		struct pcap_stat ps;
		pcap_stats(captureDescriptor, &ps);
		const uint64_t ps_tot = (ps.ps_recv + ps.ps_drop + ps.ps_ifdrop);
		T2_FLOG_NUMP(stream, "Number of packets received", ps.ps_recv, ps_tot);
		T2_FLOG_NUMP(stream, "Number of packets dropped by the kernel", ps.ps_drop, ps_tot);
		T2_FLOG_NUMP(stream, "Number of packets dropped by the interface", ps.ps_ifdrop, ps_tot);
	}

	if (monitoring) {
		// 24 = size of global pcap header,
		// 16 = pcap header of every capture packet.
		// (see http://wiki.wireshark.org/Development/LibpcapFileFormat)
		float pb;
		if ((capType & CAPFILE) && captureFileSize) {
			pb = 24 + bytesProcessed + (numPackets * 16);
			T2_FLOG_NUM(stream, "Total bytes processed so far", pb);
			pb /= (double)captureFileSize;
		} else if ((capType & LISTFILE) && caplist->size) {
			pb = ((24 * caplist->num_files) + bytesProcessed + (numPackets * 16)) / (double)caplist->size;
		} else {
			pb = 1;
		}

		if (!(capType & IFACE)) {
			const double u = (elapsed.tv_sec + elapsed.tv_usec/1000000.0f);
			const double c = (1.0 - pb) / pb;
			const double d = u * c;
			const uint64_t a = (uint64_t)d;
			elapsed.tv_sec = a;
			elapsed.tv_usec = (d - a) * 1000000.0f;
			t2_log_time(stream, "Remaining time: ", elapsed);
			struct timeval etfTime;
			timeradd(&endTime, &elapsed, &etfTime);
			t2_log_date(stream, "ETF: ", etfTime, TSTAMP_R_UTC);
		}
	}

	T2_LOG_DIFFNUM(stream, "Number of processed packets", numPackets);
	T2_LOG_DIFFNUM(stream, "Number of processed bytes", bytesProcessed);
	T2_LOG_DIFFNUM(stream, "Number of raw bytes", rawBytesOnWire);
	T2_LOG_DIFFNUM(stream, "Number of pad bytes", padBytesOnWire);
	if (!monitoring && !(capType & IFACE)) {
		T2_FLOG_NUM(stream, "Number of pcap bytes", captureFileSize);
	}

	T2_LOG_DIFFNUMP(stream, "Number of IPv4 packets", numV4Packets, numPackets);
	T2_LOG_DIFFNUMP(stream, "Number of IPv6 packets", numV6Packets, numPackets);
	T2_LOG_DIFFNUMP(stream, "Number of IPvX packets", numVxPackets, numPackets);

	const double numABBytes = numABytes + numBBytes;
	const double numABBytes0 = numABytes0 + numBBytes0;
	const double numABPackets = numAPackets + numBPackets;
	const double numABPackets0 = numAPackets0 + numBPackets0;
	const double numABytesDiff = numABytes - numABytes0;
	const double numBBytesDiff = numBBytes - numBBytes0;
	const double numBytesDiff = bytesProcessed - bytesProcessed0;
	const double numPacketsDiff = numPackets - numPackets0;
	const double numAPacketsDiff = numAPackets - numAPackets0;
	const double numBPacketsDiff = numBPackets - numBPackets0;
	const double numABPacketsDiff = numABPackets - numABPackets0;

	if (numPacketsDiff != numABPacketsDiff && numABPacketsDiff > 0) {
		T2_FLOG_NUMP(stream, "Number of packets without flow", (numPacketsDiff-numABPacketsDiff), numPacketsDiff);
	}

	T2_LOG_DIFFNUMP(stream, "Number of A packets", numAPackets, numABPackets);
	T2_LOG_DIFFNUMP(stream, "Number of B packets", numBPackets, numABPackets);

	T2_LOG_DIFFNUMP(stream, "Number of A bytes", numABytes, numABBytes);
	T2_LOG_DIFFNUMP(stream, "Number of B bytes", numBBytes, numABBytes);

	double tmp = numAPacketsDiff ? (numABytesDiff / numAPacketsDiff) : 0.0;
	char hrnum[64];
	T2_CONV_NUM(tmp, hrnum);
	T2_FLOG(stream, "Average A packet load: %.2f%s", tmp, hrnum);
	tmp = numBPacketsDiff ? (numBBytesDiff / numBPacketsDiff) : 0.0;
	T2_CONV_NUM(tmp, hrnum);
	T2_FLOG(stream, "Average B packet load: %.2f%s", tmp, hrnum);

#if PLUGIN_REPORT > 0
	fputs("--------------------------------------------------------------------------------\n", stream);
	if (monitoring) {
		FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_REPORT);
	} else {
		FOREACH_PLUGIN_DO(report, stream);
	}
#endif // PLUGIN_REPORT > 0

	fputs("--------------------------------------------------------------------------------\n", stream);

#if T2_PRI_HDRDESC == 1
	T2_FLOG(stream, "Headers count: min: %"PRIu16", max: %"PRIu16", average: %.2f", minHdrDesc, maxHdrDesc, aveHdrDesc);
#endif // T2_PRI_HDRDESC == 1

	if (globalWarn & L2_VLAN) T2_FLOG(stream, "Max VLAN header count: %"PRIu8, vlanHdrCntMx);
	if (globalWarn & L2_MPLS) T2_FLOG(stream, "Max MPLS header count: %"PRIu8, mplsHdrCntMx);

	T2_LOG_DIFFNUMP(stream, "Number of LLC packets", numLLCPackets, numPackets);
	T2_FLOG_NUMP(stream, "Number of ARP packets", (numPacketsL2[L2_ARP]-numPackets0L2[L2_ARP]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of RARP packets", (numPacketsL2[L2_RARP]-numPackets0L2[L2_RARP]), numPacketsDiff);
	T2_LOG_DIFFNUMP(stream, "Number of GRE packets", numGREPackets, numPackets);
	T2_LOG_DIFFNUMP(stream, "Number of Teredo packets", numTeredoPackets, numPackets);
	T2_LOG_DIFFNUMP(stream, "Number of AYIYA packets", numAYIYAPackets, numPackets);
	T2_FLOG_NUMP(stream, "Number of IGMP packets", (numPacketsL3[L3_IGMP]-numPackets0L3[L3_IGMP]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of ICMP packets", (numPacketsL3[L3_ICMP]-numPackets0L3[L3_ICMP]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of ICMPv6 packets", (numPacketsL3[L3_ICMP6]-numPackets0L3[L3_ICMP6]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of TCP packets", (numPacketsL3[L3_TCP]-numPackets0L3[L3_TCP]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of TCP bytes", (numBytesL3[L3_TCP]-numBytes0L3[L3_TCP]), numBytesDiff);
	T2_FLOG_NUMP(stream, "Number of UDP packets", (numPacketsL3[L3_UDP]-numPackets0L3[L3_UDP]), numPacketsDiff);
	T2_FLOG_NUMP(stream, "Number of UDP bytes", (numBytesL3[L3_UDP]-numBytes0L3[L3_UDP]), numBytesDiff);
	if (globalWarn & L4_SCTP) {
		T2_FLOG_NUMP(stream, "Number of SCTP packets", (numPacketsL3[L3_SCTP]-numPackets0L3[L3_SCTP]), numPacketsDiff);
		T2_FLOG_NUMP(stream, "Number of SCTP bytes", (numBytesL3[L3_SCTP]-numBytes0L3[L3_SCTP]), numBytesDiff);
	}

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	T2_LOG_DIFFNUMP(stream, "Number of IPv4 fragmented packets", numFragV4Packets, numV4Packets);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
	T2_LOG_DIFFNUMP(stream, "Number of IPv6 fragmented packets", numFragV6Packets, numV6Packets);
#endif // IPV6_ACTIVATE > 0

	fputs("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", stream);

	const double totalFlowsDiff = totalFlows - totalFlows0;
	if (totalFlowsDiff > 0) {
		const double totalAFlowsDiff = totalAFlows - totalAFlows0;
		const double totalBFlowsDiff = totalBFlows - totalBFlows0;
		const double corrReplFlwsDiff = corrReplFlws - corrReplFlws0;
		const double aflwcorrDiff = totalAFlowsDiff - corrReplFlwsDiff;
		const double bflwcorrDiff = totalBFlowsDiff + corrReplFlwsDiff;

		T2_LOG_DIFFNUM0(stream, "Number of processed   flows", totalFlows);
		T2_FLOG_NUMP(stream, "Number of processed A flows", totalAFlowsDiff, totalFlowsDiff);
		T2_FLOG_NUMP(stream, "Number of processed B flows", totalBFlowsDiff, totalFlowsDiff);
		T2_FLOG_NUMP(stream, "Number of request     flows", aflwcorrDiff, totalFlowsDiff);
		T2_FLOG_NUMP(stream, "Number of reply       flows", bflwcorrDiff, totalFlowsDiff);

		T2_FLOG(stream, "Total   A/B    flow asymmetry: %.2f", (totalAFlowsDiff - totalBFlowsDiff) / totalFlowsDiff);
		T2_FLOG(stream, "Total req/rply flow asymmetry: %.2f", (aflwcorrDiff - bflwcorrDiff) / totalFlowsDiff);

		if (numABPacketsDiff > 0) {
			tmp = numABPacketsDiff / totalFlowsDiff;
			T2_CONV_NUM(tmp, hrnum);
			T2_FLOG(stream, "Number of processed   packets/flows: %.2f%s", tmp, hrnum);
		}

		if (totalAFlowsDiff > 0) {
			tmp = numAPacketsDiff / totalAFlowsDiff;
			T2_CONV_NUM(tmp, hrnum);
			T2_FLOG(stream, "Number of processed A packets/flows: %.2f%s", tmp, hrnum);
		}

		if (totalBFlowsDiff > 0) {
			tmp = numBPacketsDiff / totalBFlowsDiff;
			T2_CONV_NUM(tmp, hrnum);
			T2_FLOG(stream, "Number of processed B packets/flows: %.2f%s", tmp, hrnum);
		}
	}

	float f = duration.tv_sec + duration.tv_usec/1000000.0f;
	if (f > 0) {
		tmp = numPacketsDiff / f;
		T2_CONV_NUM(tmp, hrnum);
		T2_FLOG(stream, "Number of processed total packets/s: %.2f%s", tmp, hrnum);

		if (numABPacketsDiff > 0) {
			tmp = numABPacketsDiff / f;
			T2_CONV_NUM(tmp, hrnum);
			T2_FLOG(stream, "Number of processed A+B packets/s: %.2f%s", tmp, hrnum);

			if (numAPacketsDiff > 0) {
				tmp = numAPacketsDiff / f;
				T2_CONV_NUM(tmp, hrnum);
				T2_FLOG(stream, "Number of processed A   packets/s: %.2f%s", tmp, hrnum);
			}

			if (numBPacketsDiff > 0) {
				tmp = numBPacketsDiff / f;
				T2_CONV_NUM(tmp, hrnum);
				T2_FLOG(stream, "Number of processed   B packets/s: %.2f%s", tmp, hrnum);
			}
		}
	}

	fputs("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", stream);

	if (f > 0) {
		tmp = totalFlowsDiff / f;
		T2_CONV_NUM(tmp, hrnum);
		T2_FLOG(stream, "Number of average processed flows/s: %.2f%s", tmp, hrnum);

		f *= 125.0f;
		T2_LOG_SPEED(stream, "Average full raw bandwidth", (rawBytesOnWire - rawBytesOnWire0) / f);
		if (globalWarn & SNAPLENGTH) {
			T2_LOG_SPEED(stream, "Average snapped bandwidth ", (bytesProcessed - bytesProcessed0) / f);
		}
		T2_LOG_SPEED(stream, "Average full bandwidth ", (bytesOnWire - bytesOnWire0) / f);

#if MIN_MAX_ESTIMATE == 1
		T2_LOG_SPEED(stream, "Max full raw bandwidth", maxBytesPs/125.0f);
		T2_LOG_SPEED(stream, "Min full raw bandwidth", minBytesPs/125.0f);
#endif // MIN_MAX_ESTIMATE == 1
	}

	if (mainHashMap) {
		if (monitoring) {
			const uint64_t fillSize = mainHashMap->hashChainTableSize - mainHashMap->freeListSize;
			T2_FLOG(stream, "Fill size of main hash map: %"PRIu64" [%.2f%%]",
					fillSize, 100.0f * fillSize / (double) (mainHashMap->hashChainTableSize));
		}
		T2_FLOG_NUMP(stream, "Max number of flows in memory", maxNumFlowsPeak, mainHashMap->hashChainTableSize);
	}

#if HASH_AUTOPILOT == 1
	T2_LOG_DIFFNUMP(stream, "Number of flows terminated by autopilot", totalRmFlows, totalFlows);
#endif // HASH_AUTOPILOT == 1

	struct rusage r_usage;
	getrusage(RUSAGE_SELF, &r_usage);

	const double memtotal = ((double)sysconf(_SC_PHYS_PAGES) * (double)sysconf(_SC_PAGESIZE));
	double maxrss = r_usage.ru_maxrss;
#ifdef __APPLE__
	maxrss /= 1000; // ru_maxrss is in KB on Linux, but in bytes on OSX
#endif // __APPLE__
	T2_FLOG(stream, "Memory usage: %.2f GB [%.2f%%]", maxrss / 1000000.0, 100.0f * (maxrss * 1000.0) / memtotal);

	T2_FLOG(stream, "Aggregate flow status: 0x%016"B2T_PRIX64, globalWarn);

	if (numAlarms) {
		char str[64];
		const uint64_t numAlarmsDiff = numAlarms - numAlarms0;
		T2_CONV_NUM(numAlarmsDiff, str);
		T2_FWRN(stream, "Number of alarms: %"PRIu64"%s [%.2f%%]", numAlarmsDiff, str, 100.0*numAlarmsDiff/totalFlowsDiff);
	}

#if FORCE_MODE == 1
	if (numForced) {
		char str[64];
		const uint64_t numForcedDiff = numForced - numForced0;
		T2_CONV_NUM(numForcedDiff, str);
		T2_FWRN(stream, "Number of flows terminated by force mode: %"PRIu64"%s [%.2f%%]", numForcedDiff, str, 100.0*numForcedDiff/totalFlowsDiff);
	}
#endif

	T2_PRINT_GLOBALWARN(stream);

	if (monitoring) fputs("================================================================================\n\n", stream);

	fflush(stream);
}
#endif // VERBOSE > 0 || MACHINE_REPORT == 0


#if MACHINE_REPORT == 1
inline void t2_machine_report_header(FILE *stream) {
	fprintf(stream, "%srepTyp\ttime\tdur\t", HDR_CHR);

	if (capType & IFACE) {
		fputs("pktsRec\tpktsDrp\tifDrp\t", stream);
	}

	fputs("memUsageKB\tfillSzHashMap\tnumFlows\tnumAFlows\tnumBFlows\t"
	      "numPkts\tnumAPkts\tnumBPkts\tnumV4Pkts\tnumV6Pkts\t"
	      "numVxPkts\tnumBytes\tnumABytes\tnumBBytes\tnumFrgV4Pkts\t"
	      "numFrgV6Pkts\tnumAlarms\trawBandwidth\tglobalWarn\t", stream);

	uint_fast32_t i;

	for (i = 0; i < NUMMONPL2; i++) {
		fprintf(stream, "0x%04"B2T_PRIX16"Pkts\t0x%04"B2T_PRIX16"Bytes\t", monProtL2[i], monProtL2[i]);
	}

	for (i = 0; i < NUMMONPL3; i++) {
#if MONPROTMD == 1
		fprintf(stream, "%sPkts\t%sBytes\t", ipProtSn[monProtL3[i]], ipProtSn[monProtL3[i]]);
#else // MONPROTMD == 0
		fprintf(stream, "%"PRIu8"Pkts\t%"PRIu8"Bytes\t", monProtL3[i], monProtL3[i]);
#endif // MONPROTMD == 0
	}

	FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_HDR);

	t2_discard_trailing_char(stream, '\t');
	fputc('\n', stream);

	fflush(stream);
}
#endif // MACHINE_REPORT == 1


#if MACHINE_REPORT == 1
inline void t2_machine_report(FILE *stream) {
	struct timeval duration;
	timersub(&actTime, &startTStamp0, &duration);

	const time_t time_sec = actTime.tv_sec;
	const intmax_t time_usec = actTime.tv_usec;
	const time_t dur_sec = duration.tv_sec;
	const intmax_t dur_usec = duration.tv_usec;

	fprintf(stream, "USR1MR_%c\t%ld.%06jd\t%ld.%06jd\t", REPTYPE, time_sec, time_usec, dur_sec, dur_usec);

	if (capType & IFACE) {
		struct pcap_stat ps;
		pcap_stats(captureDescriptor, &ps);
		fprintf(stream, "%u\t%u\t%u\t", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
	}

	struct rusage r_usage;
	getrusage(RUSAGE_SELF, &r_usage);

	uint64_t memmax = r_usage.ru_maxrss;
#ifdef __APPLE__
	memmax /= 1000; // ru_maxrss is in KB on Linux, but in bytes on OSX
#endif // __APPLE__
	fprintf(stream, "%"PRId64"\t", (int64_t)(memmax - memmax0));

	if (mainHashMap) fprintf(stream, "%"PRId64"\t", (int64_t)(mainHashMap->hashChainTableSize - mainHashMap->freeListSize - hshFSize0));
	else fputs("0\t", stream);

	float f = duration.tv_sec + duration.tv_usec/1000000.0f;
	if (f == 0.0f) f = FLT_MIN;
	f *= 125.0f;
	fprintf(stream,
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // totalFlows, totalAFlows, totalBFlows, numPackets
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // numAPackets, numBPackets, numV4Packets, numV6Packets
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // numVxPackets, bytesProcessed, numABytes, numBBytes
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%.3f\t"      // numFragV4Packets, numFragV6Packets, numAlarms, rawBandwidth
			"0x%016"B2T_PRIX64"\t",                        // globalWarn
			totalFlows-totalFlows0, totalAFlows-totalAFlows0, totalBFlows-totalBFlows0, numPackets-numPackets0,
			numAPackets-numAPackets0, numBPackets-numBPackets0, numV4Packets-numV4Packets0, numV6Packets-numV6Packets0,
			numVxPackets-numVxPackets0, bytesProcessed-bytesProcessed0, numABytes-numABytes0, numBBytes-numBBytes0,
			numFragV4Packets-numFragV4Packets0, numFragV6Packets-numFragV6Packets0, numAlarms-numAlarms0, (rawBytesOnWire-rawBytesOnWire0)/f,
			globalWarn);

	uint_fast32_t i;
	for (i = 0; i < NUMMONPL2; i++) {
		fprintf(stream, "%"PRIu64"\t%"PRIu64"\t",
				numPacketsL2[monProtL2[i]] - numPackets0L2[monProtL2[i]],
				numBytesL2[monProtL2[i]] - numBytes0L2[monProtL2[i]]);
	}

	for (i = 0; i < NUMMONPL3; i++) {
		fprintf(stream, "%"PRIu64"\t%"PRIu64"\t",
				numPacketsL3[monProtL3[i]] - numPackets0L3[monProtL3[i]],
				numBytesL3[monProtL3[i]] - numBytes0L3[monProtL3[i]]);
	}

	FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_VAL);

	t2_discard_trailing_char(stream, '\t');
	fputc('\n', stream);

	fflush(stream);
}
#endif // MACHINE_REPORT == 1


static void t2_cleanup() {
	unload_tranalyzer_plugins(t2_plugins);

	// commit all changes in all buffers
	fflush(NULL);

	// terminate timeout handlers
	timeout_t *tcurr = timeout_list;
	timeout_t *tnext;
	while (tcurr) {
		tnext = tcurr->next;
		free(tcurr);
		tcurr = tnext;
	}

	free(baseFileName);
	free(bpfCommand);
	free(cmdline);
	free(flows);
	free(pluginFolder);

	if (captureDescriptor) pcap_close(captureDescriptor);
	if (sPktFile) fclose(sPktFile);

#if VERBOSE > 0
	if (dooF != stdout) fclose(dooF);
#endif

#if PID_FNM_ACT == 1
	t2_destroy_pid_file();
#endif // PID_FNM_ACT == 1

	hashTable_destroy(mainHashMap);

#if FRAGMENTATION >= 1
	hashTable_destroy(fragPendMap);
	free(fragPend);
#endif // FRAGMENTATION >= 1

	outputBuffer_destroy(main_output_buffer);
	bv_header_destroy(main_header_bv);

	if (capType & DIRFILE) {
		free(capName);
		free(globFName);
	} else if (capType & LISTFILE) {
		caplist_elem = caplist->file_list;
		while (caplist_elem) {
			caplist_elem_t *next = caplist_elem->next;
			free(caplist_elem->name);
			free(caplist_elem);
			caplist_elem = next;
		}
		free(caplist);
	}

	// destroy T2 file manager
	file_manager_destroy(t2_file_manager);

	// verify any possible memory leaks (if MEMORY_DEBUG == 1)
	memdebug_check_leak();
}


static inline void sigHandler(int scode) {
#if USE_T2BUS == 1
	// XXX FIXME temporary code to illustrate t2BusCallback usage
	for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
		if (t2_plugins->plugin[i].t2BusCb.cb) {
			const uint16_t plugin_number = t2_plugins->plugin[i].t2BusCb.pl_num;
			t2_plugins->plugin[i].t2BusCb.cb(plugin_number);
		}
	}
#endif // USE_T2BUS == 1

	switch (scode) {
		case SIGINT:
			if (globalInt && (--globalInt & GI_RUN)) {
#if VERBOSE > 0
				T2_INF("SIGINT: Stop flow creation: 0x%04x", globalInt);
#endif // VERBOSE > 0
				break;
			}
			/* FALLTHRU */
		case SIGTERM:
#if VERBOSE > 0
			T2_INF("SIGTERM: Terminate, terminate.");
#endif // VERBOSE > 0
			if (globalInt == GI_DIE) exit(-666);
			//globalInt = GI_EXIT;
			globalInt = GI_DIE;
			break;

		case SIGUSR1:
#if MONINTPSYNC == 1
			globalInt |= GI_RPRT;
#else // MONINTPSYNC == 0
			printGStats();
#endif // MONINTPSYNC == 0
			break;

		case SIGUSR2:
			globalInt ^= GI_ALRM;
			if (globalInt & GI_ALRM) alarm(MONINTV);
			break;

		case SIGALRM:
			if (globalInt & GI_ALRM) {
#if MONINTPSYNC == 1
				globalInt |= GI_RPRT;
#else // MONINTPSYNC == 0
				printGStats();
#endif // MONINTPSYNC == 0
				alarm(MONINTV);
			}
			break;

#if REPSUP == 1
		case SIGSYS:
			if (numPackets != numLstPackets) system(REPCMDAW);
			else system(REPCMDAS);
			numLstPackets = numPackets;
			break;
#endif // REPSUP == 1

		default:
			break;
	}
}


#if (MONINTTHRD == 1 && MONINTBLK == 0)
static void* intThreadHandler(void *arg __attribute__((unused))) {
	t2_setup_sigaction();
	sigset_t mask = t2_get_sigset();
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

#ifndef __APPLE__
	int scode;
	while (globalInt & GI_RUN) {
		sigwait(&mask, &scode);
		sigHandler(scode);
	}
#endif // __APPLE__

	return NULL;
}
#endif // (MONINTTHRD == 1 && MONINTBLK == 0)


#if DIFF_REPORT == 1 && VERBOSE > 0
static inline void resetGStats0() {
	memmax0 = 0;
	hshFSize0 = 0;
	numPackets0 = 0;
	numAPackets0 = 0;
	numBPackets0 = 0;
	numABytes0 = 0;
	numBBytes0 = 0;
	bytesProcessed0 = 0;
	bytesOnWire0 = 0;
	rawBytesOnWire0 = 0;
	padBytesOnWire0 = 0;
	numAlarms0 = 0;
#if FORCE_MODE == 1
	numForced0 = 0;
#endif
	numV4Packets0 = 0;
	numV6Packets0 = 0;
	numVxPackets0 = 0;
	numFragV4Packets0 = 0;
	numFragV6Packets0 = 0;
	numLLCPackets0 = 0;
	numGREPackets0 = 0;
	numTeredoPackets0 = 0;
	numAYIYAPackets0 = 0;
	totalFlows0 = 0;
	totalAFlows0 = 0;
	totalBFlows0 = 0;
	corrReplFlws0 = 0;
	totalRmFlows0 = 0;

	uint_fast32_t i;
	for (i = 0; i < NUMMONPL2; i++) {
		numPackets0L2[monProtL2[i]] = 0;
		numBytes0L2[monProtL2[i]] = 0;
	}

	for (i = 0; i < NUMMONPL3; i++) {
		numPackets0L3[monProtL3[i]] = 0;
		numBytes0L3[monProtL3[i]] = 0;
	}

	//FOREACH_PLUGIN_DO(monitoring, NULL, T2_MON_RESET_VAL);
}
#endif // DIFF_REPORT == 1 && VERBOSE > 0


#if DIFF_REPORT == 1
static inline void updateGStats0() {
	struct rusage r_usage;
	getrusage(RUSAGE_SELF, &r_usage);
	memmax0 = r_usage.ru_maxrss;
#ifdef __APPLE__
	memmax0 /= 1000; // ru_maxrss is in KB on Linux, but in bytes on OSX
#endif // __APPLE__
	if (mainHashMap) {
		hshFSize0 = (mainHashMap->hashChainTableSize - mainHashMap->freeListSize);
	}
	startTStamp0 = actTime;
	numPackets0 = numPackets;
	numAPackets0 = numAPackets;
	numBPackets0 = numBPackets;
	numABytes0 = numABytes;
	numBBytes0 = numBBytes;
	bytesProcessed0 = bytesProcessed;
	bytesOnWire0 = bytesOnWire;
	rawBytesOnWire0 = rawBytesOnWire;
	padBytesOnWire0 = padBytesOnWire;
	numAlarms0 = numAlarms;
#if FORCE_MODE == 1
	numForced0 = numForced;
#endif
	numV4Packets0 = numV4Packets;
	numV6Packets0 = numV6Packets;
	numVxPackets0 = numVxPackets;
	numFragV4Packets0 = numFragV4Packets;
	numFragV6Packets0 = numFragV6Packets;
	numLLCPackets0 = numLLCPackets;
	numGREPackets0 = numGREPackets;
	numTeredoPackets0 = numTeredoPackets;
	numAYIYAPackets0 = numAYIYAPackets;
	totalFlows0 = totalFlows;
	totalAFlows0 = totalAFlows;
	totalBFlows0 = totalBFlows;
	corrReplFlws0 = corrReplFlws;
	totalRmFlows0 = totalRmFlows;

	uint_fast32_t i;
	for (i = 0; i < NUMMONPL2; i++) {
		numPackets0L2[monProtL2[i]] = numPacketsL2[monProtL2[i]];
		numBytes0L2[monProtL2[i]] = numBytesL2[monProtL2[i]];
	}

	for (i = 0; i < NUMMONPL3; i++) {
		numPackets0L3[monProtL3[i]] = numPacketsL3[monProtL3[i]];
		numBytes0L3[monProtL3[i]] = numBytesL3[monProtL3[i]];
	}

	//FOREACH_PLUGIN_DO(monitoring, NULL, T2_MON_UPDATE_VAL);
}
#endif // DIFF_REPORT == 1


#if BLOCK_BUF == 0
static inline binary_value_t *buildHeaders() {
	binary_value_t *bv = bv_new_bv("Flow direction", "dir", 0, 1, bt_flow_direction);
	// get binary values from plugins
	for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
		if (t2_plugins->plugin[i].priHdr) {
			bv = bv_append_bv(bv, t2_plugins->plugin[i].priHdr());
		}
	}
	return bv;
}
#endif // BLOCK_BUF == 0


void timeout_handler_add(float timeout) {
	// first check if there is already a timeout_handler in the list
	timeout_t *t = timeout_list;
	while (t) {
		if (t->timeout == timeout) return; // timeout already in list
		t = t->next;
	}

	// timeout value not in list -> build new timeout handler
	timeout_t *tnew = malloc(sizeof(*tnew));
	tnew->timeout = timeout;
	tnew->flow.timeout = INFINITY;  // a sentinel never times out
	tnew->flow.lastSeen.tv_sec = 0; // An impossible timestamp of zero seconds marks it as a sentinel
	tnew->next = NULL;

	// place it in front of lru_tail
	tnew->flow.lruPrevFlow = lruTail.lruPrevFlow;
	tnew->flow.lruNextFlow = &lruTail;

	lruTail.lruPrevFlow->lruNextFlow = &(tnew->flow);
	lruTail.lruPrevFlow = &(tnew->flow);

	if (!timeout_list) {
		// the new timeout handler is the only one in the list, so place it at the list's head
		timeout_list = tnew;
		return;
	}

	// add it at the right position in the timeout handler list
	// timeout handler with biggest timeout first
	timeout_t *tprev = timeout_list;

	t = tprev;
	while (t) {
		if (tnew->timeout > t->timeout) {
			// add new timeout handler in front of the list
			tnew->next = t;
			if (tprev != t) {
				tprev->next = tnew;
			} else {
				// The new timeout is at the top of the list
				// -> set entry point to new timeout handler
				timeout_list = tnew;
			}

			return;
		}

		if (tprev != t) tprev = tprev->next;
		t = t->next;
	}

	// new timeout is at the end of the list
	tprev->next = tnew;
}


static caplist_t* read_caplist(const char *filename) {
#if VERBOSE > 1
	T2_LOG("Checking list file");
#endif // VERBOSE > 1

	FILE *file = t2_open_file(NULL, filename, "r");
	if (UNLIKELY(!file)) exit(1);

	caplist_t *list = calloc(1, sizeof(*list));
	if (UNLIKELY(!list)) {
		T2_ERR("Failed to allocate memory for file list");
		fclose(file);
		exit(1);
	}

	struct stat fileStats;

	caplist_elem_t *elem = list->file_list;

	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	while ((read = getline(&line, &len, file)) != -1) {
		// skip comments
		if (line[0] == '#') continue;

		// cut off newline char
		if (read > 0 && line[read-1] == '\n') line[--read] = '\0';
		if (read > 0 && line[read-1] == '\r') line[--read] = '\0';

		if (UNLIKELY(access(line, F_OK) != 0)) {
			// file does not exist
			if (read < 2 || !isascii(line[read-1]) || !isascii(line[read-2])) {
				// probably a binary file...
				T2_ERR("'%s' is not a valid list of PCAP files", filename);
				free(line);
				free(list);
				fclose(file);
				exit(1);
			}
		}

#if VERBOSE > 1
		T2_LOG("    checking file '%s'", line);
#endif // VERBOSE > 1

		// Test if valid pcap file
		if (!ckpcaphdr(line)) continue;

		if (stat(line, &fileStats) != 0) {
			T2_WRN("Cannot get complete file stats for '%s': %s", line, strerror(errno));
			continue;
		}

		// file is valid, add it to list
		caplist_elem_t *new_elem = calloc(1, sizeof(*new_elem));
		new_elem->name = malloc(read+1 * sizeof(char));
		strncpy(new_elem->name, line, read+1);

		if (!elem) {
			list->file_list = new_elem;
			elem = new_elem;
		} else {
			elem->next = new_elem;
			elem = elem->next;
		}

		new_elem->size = fileStats.st_size;
		list->size += new_elem->size;
		list->num_files++;
	}

	fclose(file);
	free(line);

	// no valid files were found
	if (list->num_files == 0) {
		free(list);
		return NULL;
	}

	return list;
}


bool ckpcaphdr(const char *pcapname) {
	if (!pcapname || *pcapname == '-' || (capType & DIRFILE)) return true;

	FILE *fp;
	if (UNLIKELY(!(fp = fopen(pcapname, "r")))) {
#if VERBOSE > 1
		T2_ERR("Failed to open file '%s' for reading: %s", pcapname, strerror(errno));
#endif // VERBOSE > 1
		return false;
	}

	struct stat stats;
	if (UNLIKELY(stat(pcapname, &stats) < 0)) {
#if VERBOSE > 1
		T2_ERR("Failed to get stats of file '%s': %s", pcapname, strerror(errno));
#endif // VERBOSE > 1
		fclose(fp);
		return false;
	}

	if (UNLIKELY(stats.st_size == 0)) {
#if VERBOSE > 1
		T2_ERR("PCAP file '%s' is empty", pcapname);
#endif // VERBOSE > 1
		fclose(fp);
		return false;
	}

	uint32_t rbuf[3];
	const size_t read = fread(rbuf, 4, 3, fp);
	if (UNLIKELY(read == 0)) {
#if VERBOSE > 1
		T2_ERR("Failed to read data from file '%s'", pcapname);
#endif // VERBOSE > 1
		fclose(fp);
		return false;
	}

	fclose(fp);

	bool valid = false;
	if (rbuf[0] == PCAPNG) {
#if VERBOSE > 1
		T2_WRN("PCAP-NG, so *percentage completed* in end report might be less than 100%%, will be fixed in a later version");
#endif // VERBOSE > 1
		if (rbuf[2] == PCAPNG_MAGIC_B || rbuf[2] == PCAPNG_MAGIC_L) {
			valid = true;
		}
	} else if (rbuf[0] == PCAP_MAGIC_B || rbuf[0] == PCAP_MAGIC_L) {
		valid = true;
	}

#if VERBOSE > 1
	if (!valid) T2_ERR("File '%s' is not a valid PCAP/PCAP-NG file", pcapname);
#endif // VERBOSE > 1

	return valid;
}


static __attribute__((noreturn)) void t2_abort_with_help() {
	printf("Try '%s -h' for more information.\n", PACKAGE);
	exit(EXIT_FAILURE);
}


#if PID_FNM_ACT == 1
// TODO
//  - test if PID file exists before creating it
//  - if it exists, warn the user and ask whether to continue
//  - delete the file in t2_cleanup()
static inline void t2_create_pid_file() {
	//if (t2_file_exists(pluginFolder, PID_FNM)) {
	//	T2_WRN("A PID file '%s%s' already exists... another instance of Tranalyzer is probably running", pluginFolder, PID_FNM);
	//	//printf("Proceed anyway (Y/n)? ");
	//}
	FILE * const file = t2_open_file(pluginFolder, PID_FNM, "w");
	if (LIKELY(file != NULL)) {
		fprintf(file, "%d\n", getpid());
		fclose(file);
	}
}
#endif // PID_FNM_ACT == 1


#if PID_FNM_ACT == 1
static inline void t2_destroy_pid_file() {
	const size_t plen = pluginFolder_len;
	const size_t flen = sizeof(PID_FNM);
	const size_t len = plen + flen;
	if (UNLIKELY(len >= MAX_FILENAME_LEN)) {
		T2_WRN("Cannot delete file '%s': path is too long", PID_FNM);
		return;
	}

	char filename[len];
	strncpy(filename, pluginFolder, plen+1);
	strncpy(filename + plen, PID_FNM, flen);

	if (UNLIKELY(unlink(filename) != 0)) {
		T2_WRN("Failed to delete file '%s': %s", PID_FNM, strerror(errno));
	}
}
#endif // PID_FNM_ACT == 1


#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
static inline void t2_load_proto_file() {
	FILE * const file = t2_open_file(pluginFolder, MONPROTFL, "r");
	if (UNLIKELY(!file)) exit(1);

	int n;
	for (uint_fast16_t i = 0; i < 256; i++) {
		n = fscanf(file, "%*"SCNu32"\t%15[^\n\t]\t%*99[^\n\t]", ipProtSn[i]);
		if (UNLIKELY(n != 1)) {
			T2_ERR("Failed to read line %"PRIuFAST16" of file '%s': %s", i, MONPROTFL, strerror(errno));
			fclose(file);
			exit(1);
		}
	}

	fclose(file);
}
#endif // (MACHINE_REPORT == 1 && MONPROTMD == 1)


static inline FILE *t2_open_logFile() {
#if VERBOSE == 0
	return stdout;
#else
	FILE *file;
	if (!(capType & LOGFILE)) {
		file = stdout;
	} else {
		file = t2_open_file(baseFileName, LOG_SUFFIX, "w");
		if (UNLIKELY(!file)) exit(1);
	}
	return file;
#endif
}


static inline FILE *t2_create_pktfile() {
	FILE *file = t2_open_file(baseFileName, PACKETS_SUFFIX, "w");
	if (UNLIKELY(!file)) exit(1);

#if SPKTMD_PKTNO == 1
	fprintf(file, "%spktNo\t", HDR_CHR);
#else // SPKTMD_PKTNO == 0
	fputs(HDR_CHR, file);
#endif // SPKTMD_PKTNO == 0

	return file;
}


// baseFileName MUST be free'd
static inline void t2_set_baseFileName() {
	if (baseFileName && strcmp(baseFileName, "-") == 0) {
		baseFileName = NULL;
		capType |= WSTDOUT;
	}

	if (!baseFileName) {
		// Derive the output prefix from the input file
		char * const dot = strrchr(capName, '.');
		if (!dot) {
			baseFileName = strdup(capName);
		} else {
			*dot = '\0';
			if (UNLIKELY(!(baseFileName = malloc(strlen(capName)+1)))) {
				T2_ERR("Failed to allocate memory for baseFileName");
				exit(1);
			}
			strncpy(baseFileName, capName, strlen(capName)+1);
			*dot = '.';
		}
	} else {
		// If baseFileName contains directories, create them
		char *slash = strrchr(baseFileName, '/');
		if (slash) {
			*slash = '\0';
			if (UNLIKELY(!mkpath(baseFileName, S_IRWXU))) {
				T2_ERR("Failed to create directory '%s': %s", baseFileName, strerror(errno));
				exit(EXIT_FAILURE);
			}
			*slash = '/';
		}

		// If baseFileName is not a directory, use it as such
		struct stat st;
		if (stat(baseFileName, &st) == -1 || !S_ISDIR(st.st_mode)) {
			baseFileName = strdup(baseFileName);
		} else {
			// use the directory from baseFileName (-w/-W option)
			const char * const dir = baseFileName;
			const size_t dlen = strlen(dir);
			// and derive the prefix from the input file
			slash = strrchr(capName, '/');
			const char * const prefix = (slash ? slash+1 : capName);
			char * const dot = strrchr(prefix, '.');
			if (dot) *dot = '\0';
			const size_t plen = strlen(prefix);
			const size_t len = dlen + plen + ((dir[dlen-1] == '/') ? 0 : 1) + 1;
			if (UNLIKELY(!(baseFileName = malloc(len)))) {
				T2_ERR("Failed to allocate memory for baseFileName");
				exit(1);
			}
			strncpy(baseFileName, dir, dlen+1);
			if (dir[dlen-1] != '/') strcat(baseFileName, "/");
			strncat(baseFileName, prefix, plen+1);
			if (dot) *dot = '.';
		}
	}

	baseFileName_len = strlen(baseFileName);
}


#ifndef __APPLE__
// Binds Tranalyzer to core number 'cpu'.
// If cpu is 0, then binds tranalyzer to the current core number.
static inline void t2_set_cpu(int cpu) {
	if (UNLIKELY(cpu < 0)) {
		T2_ERR("CPU number must be >= 0");
		exit(EXIT_FAILURE);
	}

	const int old_cpu = sched_getcpu() + 1;
	if (cpu == 0) cpu = old_cpu;

	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu - 1, &cpuset);

	if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) < 0) {
#if VERBOSE > 0
		T2_WRN("Failed to move %s from CPU %d to CPU %d", APPNAME, old_cpu, cpu);
	} else {
		const int new_cpu = sched_getcpu() + 1;
		T2_INF("%s successfully moved from CPU %d to CPU %d", APPNAME, old_cpu, new_cpu);
#endif // VERBOSE > 0
	}
}
#endif // __APPLE__


// Make sure pluginFolder is set and ends with a slash
// pluginFolder MUST be free'd
static inline void t2_set_pluginFolder() {
	// absolute path
	if (!pluginFolder && PLUGIN_FOLDER[0] == '/') pluginFolder = PLUGIN_FOLDER;
	if (pluginFolder) { // -p option
		const size_t len = strlen(pluginFolder);
		if (pluginFolder[len-1] == '/') {
			pluginFolder = strdup(pluginFolder);
		} else {
			char *temp = pluginFolder;
			if (UNLIKELY(!(pluginFolder = malloc(len+2)))) {
				T2_ERR("Failed to allocate memory for pluginFolder");
				exit(1);
			}
			strncpy(pluginFolder, temp, len+1);
			strcat(pluginFolder, "/");
		}
	} else { // relative path (to home)
		const char *home = getenv("HOME");
		const size_t len = strlen(home);
		if (UNLIKELY(!(pluginFolder = malloc(len + sizeof(PLUGIN_FOLDER) + 2)))) {
			T2_ERR("Failed to allocate memory for pluginFolder");
			exit(1);
		}
		strncpy(pluginFolder, home, len+1);
		strcat(pluginFolder, "/" PLUGIN_FOLDER);
	}

	pluginFolder_len = strlen(pluginFolder);
}


// adapted from tcpdump
// returned value must be free'd
static char *read_bpffile(const char *fname) {
	FILE *file;
	if (UNLIKELY(!(file = fopen(fname, "r")))) {
		T2_ERR("Failed to open file '%s' for reading: %s", fname, strerror(errno));
		exit(1);
	}

	struct stat stats;
	if (UNLIKELY(stat(fname, &stats) < 0)) {
		T2_ERR("Failed to get stats of file '%s': %s", fname, strerror(errno));
		fclose(file);
		exit(1);
	}

	if (UNLIKELY(stats.st_size == 0)) {
		T2_ERR("BPF file '%s' is empty", fname);
		fclose(file);
		exit(1);
	}

	char *buf;
	if (UNLIKELY(!(buf = malloc(stats.st_size+1)))) {
		T2_ERR("Failed to allocate memory for BPF filter: %s", strerror(errno));
		fclose(file);
		exit(1);
	}

	size_t read = fread(buf, 1, stats.st_size, file);
	if (UNLIKELY(read == 0)) {
		T2_ERR("Failed to read data from file '%s'", fname);
		free(buf);
		fclose(file);
		exit(1);
	}

	fclose(file);

	if (UNLIKELY((int64_t)read != stats.st_size)) {
		T2_ERR("Failed to read all the data from file '%s': read %zu, file size %jd", fname, read, (intmax_t)stats.st_size);
		free(buf);
		exit(1);
	}

	// replace comments with spaces
	for (uint_fast64_t i = 0; i < read; i++) {
		if (buf[i] == '#') {
			while (i < read && buf[i] != '\n') buf[i++] = ' ';
		}
	}

	// remove trailing spaces and newlines
	while (read > 0 && (buf[read-1] == ' ' || buf[read-1] == '\n')) read--;

	buf[read] = '\0';

	return buf;
}


#if REPORT_HIST == 1
static void t2_restore_state() {

	if (!t2_file_exists(pluginFolder, REPORT_HIST_FILE)) {
#if VERBOSE > 2
		T2_INF("No previous state to restore");
#endif
		return;
	}

	FILE *file = t2_open_file(pluginFolder, REPORT_HIST_FILE, "r");
	if (UNLIKELY(!file)) return;

	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	while ((read = getline(&line, &len, file)) != -1) {
		// Skip comments and empty lines
		if (read == 0 || line[0] == '#' || isspace(line[0])) continue;
		switch (line[0]) {
			case '%':
				if (read+1 != sizeof(REPORT_HIST_HDR) ||
				    strncmp(line, REPORT_HIST_HDR, read) != 0)
				{
					T2_ERR("Cannot restore Tranalyzer state: expected '%s', found '%s'", REPORT_HIST_HDR, line);
					free(line);
					fclose(file);
					exit(1);
				}
				break;

			case REPTYPE: {
				time_t sec;
				intmax_t usec;
				sscanf(line,
						"%*c\t%ld.%06jd\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t" // (REPTYPE), startTStamp, totalfIndex, totalFlows, totalAFlows, totalBFlows
						"%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t"      // numPackets, numAPackets, numBPackets, numV4Packets, numV6Packets
						"%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t"      // numVxPackets, bytesProcessed, numABytes, numBBytes, numFragV4Packets
						"%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t"      // numFragV6Packets, numAlarms, bytesOnWire, rawBytesOnWire, padBytesOnWire
						"%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t%"SCNu64"\t"      // captureFileSize, corrReplFlws, totalRmFlows, numLLCPackets, numGREPackets
						"%"SCNu64"\t%"SCNu64"\t0x016%"SCNx64"\n",                      // numTeredoPackets, numAYIYAPackets, globalWarn
						&sec, &usec, &totalfIndex, &totalFlows, &totalAFlows, &totalBFlows,
						&numPackets, &numAPackets, &numBPackets, &numV4Packets, &numV6Packets,
						&numVxPackets, &bytesProcessed, &numABytes, &numBBytes, &numFragV4Packets,
						&numFragV6Packets, &numAlarms, &bytesOnWire, &rawBytesOnWire, &padBytesOnWire,
						&captureFileSize, &corrReplFlws, &totalRmFlows, &numLLCPackets, &numGREPackets,
						&numTeredoPackets, &numAYIYAPackets, &globalWarn);
				startTStamp.tv_sec = sec;
				startTStamp.tv_usec = usec;
				break;
			}

			case REPORT_SECTION_L2: {
				uint16_t l2proto;
				uint64_t numPkts;
				uint64_t numBytes;
				sscanf(line, "%*c\t0x%04"SCNx16"\t%"SCNu64"\t%"SCNu64"\n", &l2proto, &numPkts, &numBytes);
				numPacketsL2[l2proto] = numPkts;
				numBytesL2[l2proto] = numBytes;
				break;
			}

			case REPORT_SECTION_L3: {
				uint8_t l3proto;
				uint64_t numPkts;
				uint64_t numBytes;
				sscanf(line, "%*c\t0x%02"SCNx8"\t%"SCNu64"\t%"SCNu64"\n", &l3proto, &numPkts, &numBytes);
				numPacketsL3[l3proto] = numPkts;
				numBytesL3[l3proto] = numBytes;
				break;
			}

			case REPORT_SECTION_PL: {
				uint_fast16_t pluginNumber;
				sscanf(line, "%*c\t%03"SCNuFAST16"\t", &pluginNumber);
				for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
					t2_plugin_t plugin = t2_plugins->plugin[i];
					if (plugin.number == pluginNumber && plugin.restoreState) {
						// Skip P <tab> pluginNumber <tab> and send the line to the plugin
						plugin.restoreState(line+5);
					}
				}
				break;
			}

			default:
				break;
		}
	}

#if DIFF_REPORT == 1
	updateGStats0();
	startTStamp0 = startTStamp;
#endif

	free(line);
	fclose(file);

	T2_INF("Tranalyzer state restored from '%s%s'", pluginFolder, REPORT_HIST_FILE);
}
#endif // REPORT_HIST == 1


#if REPORT_HIST == 1
static void t2_save_state() {
	FILE *file = t2_open_file(pluginFolder, REPORT_HIST_FILE, "w");
	if (UNLIKELY(!file)) return;

	struct timeval t;
	gettimeofday(&t, NULL);

	t2_log_date(file, "# Date: ", t, TSTAMP_R_UTC);
	fprintf(file, "# %s %s (%s), %s.\n", PACKAGE_NAME, PACKAGE_VERSION, CODENAME, RELEASE_TYPE);
	fprintf(file, "# Command line: %s\n", cmdline);

	fputs("# Plugins loaded:\n", file);
	for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
		fprintf(file, "#   %02u: %s, version %s\n", i+1, t2_plugins->plugin[i].name, t2_plugins->plugin[i].version);
	}

	fputs("\n"REPORT_HIST_HDR, file);

	const time_t sec = startTStamp.tv_sec;
	const intmax_t usec = startTStamp.tv_usec;
	fprintf(file,
			"%c\t%ld.%06jd\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t"        // REPTYPE, startTStamp, totalfIndex, totalFlows, totalAFlows
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // totalBFlows, numPackets, numAPackets, numBPackets, numV4Packets,
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // numV6Packets, numVxPackets, bytesProcessed, numABytes, numBBytes,
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // numFragV4Packets, numFragV6Packets, numAlarms, bytesOnWire, rawBytesOnWire
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t" // padBytesOnWire, captureFileSize, corrReplFlws, totalRmFlows, numLLCPackets,
			"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t0x%016"PRIx64"\n\n",    // numGREPackets, numTeredoPackets, numAYIYAPackets, globalWarn
			REPTYPE, sec, usec, totalfIndex, totalFlows, totalAFlows,
			totalBFlows, numPackets, numAPackets, numBPackets, numV4Packets,
			numV6Packets, numVxPackets, bytesProcessed, numABytes, numBBytes,
			numFragV4Packets, numFragV6Packets, numAlarms, bytesOnWire, rawBytesOnWire,
			padBytesOnWire, captureFileSize, corrReplFlws, totalRmFlows, numLLCPackets,
			numGREPackets, numTeredoPackets, numAYIYAPackets, globalWarn);

	fputs(REPORT_HIST_HDR, file);

	uint_fast32_t i;
	for (i = 0; i < NUMMONPL2; i++) {
		fprintf(file, "%c\t0x%04"PRIx16"\t%"PRIu64"\t%"PRIu64"\n",
				REPORT_SECTION_L2, monProtL2[i], numPacketsL2[monProtL2[i]], numBytesL2[monProtL2[i]]);
	}

	fputc('\n', file);

	for (i = 0; i < NUMMONPL3; i++) {
		fprintf(file, "%c\t0x%02"PRIx8"\t%"PRIu64"\t%"PRIu64"\n",
				REPORT_SECTION_L3, monProtL3[i], numPacketsL3[monProtL3[i]], numBytesL3[monProtL3[i]]);
	}

	fputc('\n', file);

	for (i = 0; i < t2_plugins->num_plugins; i++) {
		t2_plugin_t plugin = t2_plugins->plugin[i];
		if (plugin.saveState) {
			fprintf(file, "%c\t%03u\t", REPORT_SECTION_PL, plugin.number);
			plugin.saveState(file);
			fprintf(file, " # %s (%s)\n", plugin.name, plugin.version);
		}
	}

	fclose(file);

	T2_INF("Tranalyzer state saved in '%s%s'", pluginFolder, REPORT_HIST_FILE);
}
#endif // REPORT_HIST == 1
