/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <cpuminer-config.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <jansson.h>
#include <openssl/sha.h>

#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "miner.h"

#ifdef WIN32
#include "compat/winansi.h"
BOOL WINAPI ConsoleHandler(DWORD);
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#define LP_SCANTIME		60

#ifndef min
#define min(a,b) (a>b ? b : a)
#define max(a,b) (a<b ? b : a)
#endif

enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands cmd;
	struct thr_info *thr;
	union {
		struct work *work;
	} u;
};

enum algos {
	ALGO_KECCAK,      /* Keccak */
	ALGO_HEAVY,       /* Heavy */
	ALGO_NEOSCRYPT,   /* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */
	ALGO_QUARK,       /* Quark */
	ALGO_AXIOM,       /* Shabal 256 Memohash */
	ALGO_BASTION,
	ALGO_BLAKE,       /* Blake 256 */
	ALGO_BLAKECOIN,   /* Simplified 8 rounds Blake 256 */
	ALGO_BLAKE2S,     /* Blake2s */
	ALGO_BMW,         /* BMW 256 */
	ALGO_C11,         /* C11 Chaincoin/Flaxcoin X11 variant */
	ALGO_CRYPTOLIGHT, /* cryptonight-light (Aeon) */
	ALGO_CRYPTONIGHT, /* CryptoNight */
	ALGO_DECRED,      /* Decred */
	ALGO_DMD_GR,      /* Diamond */
	ALGO_DROP,        /* Dropcoin */
	ALGO_FRESH,       /* Fresh */
	ALGO_GROESTL,     /* Groestl */
	ALGO_JHA,
	ALGO_LBRY,        /* Lbry Sha Ripemd */
	ALGO_LUFFA,       /* Luffa (Joincoin, Doom) */
	ALGO_LYRA2,       /* Lyra2RE */
	ALGO_LYRA2REV2,   /* Lyra2REv2 (Vertcoin) */
	ALGO_MYR_GR,      /* Myriad Groestl */
	ALGO_NIST5,       /* Nist5 */
	ALGO_PENTABLAKE,  /* Pentablake */
	ALGO_PLUCK,       /* Pluck (Supcoin) */
	ALGO_QUBIT,       /* Qubit */
	ALGO_SCRYPT,      /* scrypt */
	ALGO_SCRYPTJANE,  /* Chacha */
	ALGO_SHAVITE3,    /* Shavite3 */
	ALGO_SHA256D,     /* SHA-256d */
	ALGO_SIA,         /* Blake2-B */
	ALGO_SIB,         /* X11 + gost (Sibcoin) */
	ALGO_SKEIN,       /* Skein */
	ALGO_SKEIN2,      /* Double skein (Woodcoin) */
	ALGO_S3,          /* S3 */
	ALGO_TIMETRAVEL,  /* Timetravel-8 (Machinecoin) */
	ALGO_BITCORE,     /* Timetravel-10 (Bitcore) */
	ALGO_VANILLA,     /* Vanilla (Blake256 8-rounds - double sha256) */
	ALGO_VELTOR,      /* Skein Shavite Shabal Streebog */
	ALGO_X11EVO,      /* Permuted X11 */
	ALGO_X11,         /* X11 */
	ALGO_X13,         /* X13 */
	ALGO_X14,         /* X14 */
	ALGO_X15,         /* X15 */
	ALGO_X17,         /* X17 */
	ALGO_XEVAN,
	ALGO_YESCRYPT,
	ALGO_ZR5,
	ALGO_AR2,
	ALGO_EQUIHASH,
	ALGO_COUNT
};

static const char *algo_names[] = {
	"keccak",
	"heavy",
	"neoscrypt",
	"quark",
	"axiom",
	"bastion",
	"blake",
	"blakecoin",
	"blake2s",
	"bmw",
	"c11",
	"cryptolight",
	"cryptonight",
	"decred",
	"dmd-gr",
	"drop",
	"fresh",
	"groestl",
	"jha",
	"lbry",
	"luffa",
	"lyra2re",
	"lyra2rev2",
	"myr-gr",
	"nist5",
	"pentablake",
	"pluck",
	"qubit",
	"scrypt",
	"scrypt-jane",
	"shavite3",
	"sha256d",
	"sia",
	"sib",
	"skein",
	"skein2",
	"s3",
	"timetravel",
	"bitcore",
	"vanilla",
	"veltor",
	"x11evo",
	"x11",
	"x13",
	"x14",
	"x15",
	"x17",
	"xevan",
	"yescrypt",
	"zr5",
	"ar2",
	"equihash",
	"\0"
};

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_redirect = true;
bool opt_showdiff = true;
bool opt_extranonce = true;
bool want_longpoll = false; //tst
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = false;
bool have_stratum = false;
bool opt_stratum_stats = false;
bool allow_mininginfo = false;
bool use_syslog = false;
bool use_colors = true;
static bool opt_background = false;
bool opt_quiet = false;
int opt_maxlograte = 5;
bool opt_randomize = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
static int opt_time_limit = 0;
int opt_timeout = 300;
static int opt_scantime = 5;
static const bool opt_time = true;
static enum algos opt_algo = ALGO_SCRYPT;
static int opt_scrypt_n = 1024;
static int opt_pluck_n = 128;
static unsigned int opt_nfactor = 6;
int opt_n_threads = 0;
int64_t opt_affinity = -1L;
int opt_priority = 0;
int num_cpus;
char *rpc_url;
char *rpc_url_aux;
char *rpc_userpass;
char *rpc_userpass_aux;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
static unsigned char pk_script[25] = { 0 };
static char monero_address[96] = { 0 };
static unsigned char pk_script_aux[34] = { 0 };
static size_t pk_script_size = 0;
static size_t pk_script_aux_size = 0;
static char coinbase_sig[101] = { 0 };
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
bool jsonrpc_2 = false;
char rpc2_id[64] = "";
char *rpc2_blob = NULL;
size_t rpc2_bloblen = 0;
uint32_t rpc2_target = 0;
char *rpc2_job_id = NULL;
bool aes_ni_supported = false;
double opt_diff_factor = 1.0;
pthread_mutex_t rpc2_job_lock;
pthread_mutex_t rpc2_login_lock;
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
uint32_t zr5_pok = 0;

uint32_t solved_count = 0L;
uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
// conditional mining
bool conditional_state[MAX_CPUS] = { 0 };
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;

uint32_t opt_work_size = 0; /* default */
char *opt_api_allow = NULL;
int opt_api_remote = 0;
int opt_api_listen = 4048; /* 0 to disable */

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PACKAGE_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          axiom        Shabal-256 MemoHash\n\
                          bitcore      Timetravel with 10 algos\n\
                          blake        Blake-256 14-rounds (SFR)\n\
                          blakecoin    Blake-256 single sha256 merkle\n\
                          blake2s      Blake2-S (256)\n\
                          bmw          BMW 256\n\
                          c11/flax     C11\n\
                          cryptolight  Cryptonight-light\n\
                          cryptonight  Monero\n\
                          decred       Blake-256 14-rounds 180 bytes\n\
                          dmd-gr       Diamond-Groestl\n\
                          drop         Dropcoin\n\
                          fresh        Fresh\n\
                          groestl      GroestlCoin\n\
                          heavy        Heavy\n\
                          jha          JHA\n\
                          keccak       Keccak\n\
                          luffa        Luffa\n\
                          lyra2re      Lyra2RE\n\
                          lyra2rev2    Lyra2REv2 (Vertcoin)\n\
                          myr-gr       Myriad-Groestl\n\
                          neoscrypt    NeoScrypt(128, 2, 1)\n\
                          nist5        Nist5\n\
                          pluck        Pluck:128 (Supcoin)\n\
                          pentablake   Pentablake\n\
                          quark        Quark\n\
                          qubit        Qubit\n\
                          scrypt       scrypt(1024, 1, 1) (default)\n\
                          scrypt:N     scrypt(N, 1, 1)\n\
                          scrypt-jane:N (with N factor from 4 to 30)\n\
                          shavite3     Shavite3\n\
                          sha256d      SHA-256d\n\
                          sia          Blake2-B\n\
                          sib          X11 + gost (SibCoin)\n\
                          skein        Skein+Sha (Skeincoin)\n\
                          skein2       Double Skein (Woodcoin)\n\
                          s3           S3\n\
                          timetravel   Timetravel (Machinecoin)\n\
                          vanilla      Blake-256 8-rounds\n\
                          x11evo       Permuted x11\n\
                          x11          X11\n\
                          x13          X13\n\
                          x14          X14\n\
                          x15          X15\n\
                          x17          X17\n\
                          xevan        Xevan (BitSend)\n\
                          yescrypt     Yescrypt\n\
                          zr5          ZR5\n\
                          ar2          AR2\n\
                          equihash     EQUIHASH\n\
  -o, --url=URL         URL of mining server\n\
  -U, --urlaux=URL      URL of aux chain mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -A --userpassaux=U:P  username:password pair for aux chain mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
      --time-limit=N    maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       timeout for long poll and stratum (default: 300 seconds)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --randomize       Randomize scan range start to reduce duplicates\n\
  -f, --diff-factor     Divide req. difficulty by this factor (std is 1.0)\n\
  -m, --diff-multiplier Multiply difficulty by this factor (std is 1.0)\n\
  -n, --nfactor         neoscrypt N-Factor\n\
      --coinbase-addr=ADDR  payout address for solo mining\n\
      --coinbase-sig=TEXT  data to insert in the coinbase when possible\n\
      --max-log-rate    limit per-core hashrate logs (default: 5s)\n\
      --no-longpoll     disable long polling support\n\
      --no-getwork      disable getwork support\n\
      --no-gbt          disable getblocktemplate support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-extranonce   disable Stratum extranonce support\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           disable per-thread hashmeter output\n\
      --no-color        disable colored output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n\
      --hide-diff       Hide submitted block and net difficulty\n"
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n"
#endif
"\
  -B, --background      run the miner in the background\n\
      --benchmark       run in offline benchmark mode\n\
      --cputest         debug hashes from cpu algorithms\n\
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1\n\
      --cpu-priority    set process priority (default: 0 idle, 2 normal to 5 highest)\n\
  -b, --api-bind        IP/Port for the miner API (default: 127.0.0.1:4048)\n\
      --api-remote      Allow remote control\n\
      --max-temp=N      Only mine if cpu temp is less than specified value (linux)\n\
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value\n\
      --max-diff=N      Only mine if net difficulty is less than specified value\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";


static char const short_options[] =
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"a:b:Bc:CDf:hm:n:p:Px:qr:R:s:t:T:o:u:O:U:A:V";

static struct option const options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "api-bind", 1, NULL, 'b' },
	{ "api-remote", 0, NULL, 1030 },
	{ "background", 0, NULL, 'B' },
	{ "benchmark", 0, NULL, 1005 },
	{ "cputest", 0, NULL, 1006 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1016 },
	{ "coinbase-addr-aux", 1, NULL, 1017 },
	{ "coinbase-sig", 1, NULL, 1015 },
	{ "config", 1, NULL, 'c' },
	{ "cpu-affinity", 1, NULL, 1020 },
	{ "cpu-priority", 1, NULL, 1021 },
	{ "no-color", 0, NULL, 1002 },
	{ "debug", 0, NULL, 'D' },
	{ "diff-factor", 1, NULL, 'f' },
	{ "diff", 1, NULL, 'f' }, // deprecated (alias)
	{ "diff-multiplier", 1, NULL, 'm' },
	{ "help", 0, NULL, 'h' },
	{ "nfactor", 1, NULL, 'n' },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-getwork", 0, NULL, 1010 },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "no-redirect", 0, NULL, 1009 },
	{ "no-stratum", 0, NULL, 1007 },
	{ "no-extranonce", 0, NULL, 1012 },
	{ "max-temp", 1, NULL, 1060 },
	{ "max-diff", 1, NULL, 1061 },
	{ "max-rate", 1, NULL, 1062 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol", 0, NULL, 'P' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "randomize", 0, NULL, 1024 },
	{ "scantime", 1, NULL, 's' },
	{ "show-diff", 0, NULL, 1013 },
	{ "hide-diff", 0, NULL, 1014 },
	{ "max-log-rate", 1, NULL, 1019 },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 'S' },
#endif
	{ "time-limit", 1, NULL, 1008 },
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "urlaux", 1, NULL, 'U' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "userpassaux", 1, NULL, 'A' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};

static struct work g_work = {{ 0 }};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;
static char *lp_id;

static void workio_cmd_free(struct workio_cmd *wc);


#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid,sz,s) {} /* only do process affinity */
#endif

static void affine_to_cpu_mask(int id, unsigned long mask) {
	cpu_set_t set;
	CPU_ZERO(&set);
	for (uint8_t i = 0; i < num_cpus; i++) {
		// cpu mask
		if (mask & (1UL<<i)) { CPU_SET(i, &set); }
	}
	if (id == -1) {
		// process affinity
		sched_setaffinity(0, sizeof(&set), &set);
	} else {
		// thread only
		pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
	}
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) { }
#endif

void get_currentalgo(char* buf, int sz)
{
	if (opt_algo == ALGO_SCRYPTJANE)
		snprintf(buf, sz, "%s:%d", algo_names[opt_algo], opt_scrypt_n);
	else
		snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason)
{
#ifdef WIN32
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// unhide parent command line windows
			ShowWindow(hcon, SW_SHOWMINNOACTIVE);
		}
	}
#endif
	exit(reason);
}

static inline void work_free(struct work *w)
{
	if (w->txs) free(w->txs);
	if (w->workid) free(w->workid);
	if (w->job_id) free(w->job_id);
	if (w->xnonce2) free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {
		dest->xnonce2 = (uchar*) malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

/* compute nbits to get the network diff */
static void calc_network_diff(struct work *work)
{
	// sample for diff 43.281 : 1c05ea29
	// todo: endian reversed on longpoll could be zr5 specific...
	uint32_t nbits = have_longpoll ? work->data[18] : swab32(work->data[18]);
	if (opt_algo == ALGO_LBRY) nbits = swab32(work->data[26]);
	if (opt_algo == ALGO_DECRED) nbits = work->data[29];
	if (opt_algo == ALGO_SIA) nbits = work->data[11]; // unsure if correct
	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

	double d = (double)0x0000ffff / (double)bits;
	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;
	if (opt_algo == ALGO_DECRED && shift == 28) d *= 256.0; // testnet
	if (opt_debug_diff)
		applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);
	net_diff = d;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	int data_size = 128, target_size = sizeof(work->target);
	int adata_sz = 32, atarget_sz = ARRAY_SIZE(work->target);

	if (opt_algo == ALGO_DROP || opt_algo == ALGO_NEOSCRYPT || opt_algo == ALGO_ZR5) {
		data_size = 80; target_size = 32;
		adata_sz = 20;
		atarget_sz = target_size /  sizeof(uint32_t);
	} else if (opt_algo == ALGO_DECRED) {
		allow_mininginfo = false;
		data_size = 192;
		adata_sz = 180/4;
	}

	if (jsonrpc_2) {
		return rpc2_job_decode(val, work);
	}

	if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}

	for (i = 0; i < adata_sz; i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < atarget_sz; i++)
		work->target[i] = le32dec(work->target + i);

	if ((opt_showdiff || opt_max_diff > 0.) && !allow_mininginfo)
		calc_network_diff(work);

	work->targetdiff = target_to_diff(work->target);

	// for api stats, on longpoll pools
	stratum_diff = work->targetdiff;

	if (opt_algo == ALGO_DROP || opt_algo == ALGO_ZR5) {
		#define POK_BOOL_MASK 0x00008000
		#define POK_DATA_MASK 0xFFFF0000
		if (work->data[0] & POK_BOOL_MASK) {
			applog(LOG_BLUE, "POK received: %08xx", work->data[0]);
			zr5_pok = work->data[0] & POK_DATA_MASK;
		}
	} else if (opt_algo == ALGO_DECRED) {
		// some random extradata to make the work unique
		work->data[36] = (rand()*4);
		work->height = work->data[32];
		// required for the getwork pools (multicoin.co)
		if (!have_longpoll && work->height > net_blocks + 1) {
			char netinfo[64] = { 0 };
			if (opt_showdiff && net_diff > 0.) {
				if (net_diff != work->targetdiff)
					sprintf(netinfo, ", diff %.3f, target %.1f", net_diff, work->targetdiff);
				else
					sprintf(netinfo, ", diff %.3f", net_diff);
			}
			applog(LOG_BLUE, "%s block %d%s",
				algo_names[opt_algo], work->height, netinfo);
			net_blocks = work->height - 1;
		}
	}

	return true;

err_out:
	return false;
}

// good alternative for wallet mining, difficulty and net hashrate
static const char *info_req =
"{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work)
{
	if (have_stratum || have_longpoll || !allow_mininginfo)
		return false;

	int curl_err = 0;
	json_t *val = json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

	if (!val && curl_err == -1) {
		allow_mininginfo = false;
		if (opt_debug) {
			applog(LOG_DEBUG, "getmininginfo not supported");
		}
		return false;
	}
	else {
		json_t *res = json_object_get(val, "result");
		// "blocks": 491493 (= current work height - 1)
		// "difficulty": 0.99607860999999998
		// "networkhashps": 56475980
		if (res) {
			json_t *key = json_object_get(res, "difficulty");
			if (key) {
				if (json_is_object(key))
					key = json_object_get(key, "proof-of-work");
				if (json_is_real(key))
					net_diff = json_real_value(key);
			}
			key = json_object_get(res, "networkhashps");
			if (key && json_is_integer(key)) {
				net_hashrate = (double) json_integer_value(key);
			}
			key = json_object_get(res, "blocks");
			if (key && json_is_integer(key)) {
				net_blocks = json_integer_value(key);
			}
			if (!work->height) {
				// complete missing data from getwork
				work->height = (uint32_t) net_blocks + 1;
				if (work->height > g_work.height) {
					restart_threads();
					if (!opt_quiet) {
						char netinfo[64] = { 0 };
						char srate[32] = { 0 };
						sprintf(netinfo, "diff %.2f", net_diff);
						if (net_hashrate) {
							format_hashrate(net_hashrate, srate);
							strcat(netinfo, ", net ");
							strcat(netinfo, srate);
						}
						applog(LOG_BLUE, "%s block %d, %s",
							algo_names[opt_algo], work->height, netinfo);
					}
				}
			}
		}
	}
	json_decref(val);
	return true;
}

#define BLOCK_VERSION_CURRENT 3

char aux_hash [81];
uint32_t aux_target[8];
uint32_t aux_version = 0;
uint32_t aux_curtime = 0;
uchar* aux_scriptsig = 0;
size_t aux_scriptsig_size = 0;
uint32_t best_hash[32];
uint32_t par_target[32];
struct work * work_aux = 0;
uchar* par_cbtx = 0;
uchar* par_cbtx_lp = 0;
size_t par_cbtx_size = 0;
size_t par_cbtx_lp_size = 0;
uchar** par_cbmb = 0;
uchar** par_cbmb_lp = 0;
size_t par_cbmb_size = 0;
size_t par_cbmb_lp_size = 0;
bool lp = false;
char * tx_blob = 0;

static bool gbt_work_decode(const json_t *val, struct work *work, bool aux)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	uchar *cbtx = NULL;
	int tx_count, tx_size;
	uchar txc_vi[9];
	uchar(*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool version_force = false;
	bool version_reduce = false;
	json_t *tmp, *txa;
	bool rc = false;

	if (jsonrpc_2 && opt_algo == ALGO_CRYPTONIGHT) {
	  int i = 0;
	  const int xmr_res = 40;
	  printf("decode rpc2 cryptonight template\n");
	  const char * header = json_string_value(json_object_get(val, "blockhashing_blob"));
	  //const char * header = "0808a2a4b1d7051737f36c1a60b8ef470bf744ee276da6f2d1c747fe7f6b1d2f0c67a010c78c7600000000d479f4bf49eec6faf09d01a35f348bc4f33ea87e28d0372af36e7f155c23f8a303";
	  const char * block = json_string_value(json_object_get(val, "blocktemplate_blob"));
	  //const char * block = "0808a2a4b1d7051737f36c1a60b8ef470bf744ee276da6f2d1c747fe7f6b1d2f0c67a010c78c760000000002aee94201fff2e842018aa192c4a6e601026234bbecc38e58c294fd3f8c742e6947f9ddd86d629e90a03def74deadfdc5764b01d26e3b6da4d83026d1071d8d5d3b977f2ff632ddec484912bd177936a5c8779e02280000000000000000000000000000000000000000000000000000000000000000000000000000000000020118c126af8560811ee8230249d61b7aeaf15637a7fec270a905558a552d9a8098a66a745355a0fdde528a403d8c415c284477baf7d1f78635970a38f2bba7d8";
	  const int reserved_offset = json_integer_value(json_object_get(val,"reserved_offset"));
	  printf("header (%d) = %s\n", strlen(header), header);
	  printf("block (%d) = %s\n",strlen(block), block);
	  printf("reserved_offset = %d\n",reserved_offset);
	  cbtx_size = reserved_offset-43+xmr_res;
	  cbtx = (uchar*) malloc(cbtx_size);
	  if (cbtx_size < 60 || !hex2bin(cbtx,block+43*2,cbtx_size)) {
	    //if (cbtx_size < 60 || !hex2bin(cbtx,"0281e94201ffc5e84201daeec8fea1e60102a82474cb583e98de21a5afa9a14626b6fe40e302c31900ac2f6f1604922337db2101706120000d3b38e3f6e31bb3e2bcc87f46ec663b5e90d38d9b68a49a06e217c4",cbtx_size)) {
	    applog(LOG_ERR, "JSON invalid coinbasetxn");
	    goto out;
	  }
	  printf("aux_hash = %s\n",aux_hash);
	  if (!aux_hash || strlen(aux_hash)==0) {
	    strcpy(aux_hash,"ed80736b00e09a000205d96db19b6e4a8421f38e9b4f50ca0d2579d22f9487ff0100000000000000");
	    printf("fix aux_hash = %s\n",aux_hash);
	  }
	    
	  hex2bin(cbtx+reserved_offset-43,aux_hash,40);
	  printf("cbtx=\n");
	  for (int i=0;i<cbtx_size;i++) {
	    printf("%02x",cbtx[i]);
	  }
	  printf("\n");
	  uchar * n_us = malloc(1);
	  hex2bin(n_us,header+2*75,1);
	  printf("n_us = %u\n",*n_us);
	  n = *n_us;
	  free(n_us);
	  printf("n=%d\n",n);
	  /* generate merkle root */
	  uchar * cbtx_md = malloc(200);
	  keccak(cbtx,cbtx_size,cbtx_md,200);
	  hex2bin(cbtx_md+32,"bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",32);
	  hex2bin(cbtx_md+64,"0000000000000000000000000000000000000000000000000000000000000000",32);
	  keccak(cbtx_md,96,cbtx_md,200);
	  printf("cbtx hash\n");
	  for (i=0;i<32;i++) {
	    printf("%02x",cbtx_md[i]);
	  }
	  printf("\n");
	  printf("cbtx_size = %d\n",cbtx_size);
	  int cbmb_cap = log2_ceil(n);
	  int m = 1 << (log2_floor(n));
	  printf("m=%d\n",m);
	  printf("n=%d calloc\n",n);
	  uchar ** txs = malloc(n*sizeof(uchar*));
	  merkle_tree = (uchar(*)[32]) calloc(((4*m) & ~1), 32);
	  txs[0] = malloc(32);
	  memcpy(txs[0],cbtx_md,32);
	  for (i = 1; i < n; i++) {
	    txs[i] = malloc(32);
	    hex2bin(txs[i],block+2*(43+cbtx_size+2+32*(i-1)),32);
	    printf("txs[%d] =\n",i);
	    for (int j=0;j<32;j++) {
	      printf("%02x",txs[i][j]);
	    }
	    printf("\n");
	  }
	  par_cbmb_size = 0;
	  if (lp) {
	    par_cbmb_lp = malloc(cbmb_cap*sizeof(uchar*));
	  }
	  else {
	    par_cbmb = malloc(cbmb_cap*sizeof(uchar*));
	  }
	  printf("n=%d par_cbmb_cap = %lu\n",n,cbmb_cap);
	  if (!aux && n>1) {
	    par_cbmb[0] = malloc(32);
	    memcpy(par_cbmb[0],txs[1],32);
	    printf("par_cbmb[0] =\n");
	    for (i=0;i<32;i++) {
	      printf("%02x",par_cbmb[0][i]);
	    }
	    printf("\n");
	  }
	  int i_cbmb = 0;

	  for (i=6*m-2*n;i<=4*m-1;i++) {
	    memcpy(merkle_tree[i],txs[i-4*m+n],32);
	    printf("merkle_tree[%d] =\n",i);
	    for (int j=0;j<32;j++) {
	      printf("%02x",merkle_tree[i][j]);
	    }
	    printf("\n");
	  }

	  for (i=m; i<=3*m-n-1; i++) {
	    memcpy(merkle_tree[i],txs[i-m],32);
	    printf("merkle_tree[%d] =\n",i);
	    for (int j=0;j<32;j++) {
	      printf("%02x",merkle_tree[i][j]);
	    }
	    printf("\n");
	  }

	  i=2*m-1;
	  while (i>0) {
	    if (i>m-1 && i<3*m-n) {
	      i=m-1;
	      continue;
	    }
	    uchar md[200];
	    keccak(merkle_tree[2*i],64,md,200);
	    memcpy(merkle_tree[i],md,32);
	    printf("merkle_tree[%d] =\n",i);
	    for (int j=0;j<32;j++) {
	      printf("%02x",merkle_tree[i][j]);
	    }
	    printf("\n");
	    int i_powfloor = 1 << (log2_floor(n));
	    if (i==i_powfloor+1) {
	      par_cbmb[i_cbmb] = malloc(32);
	      memcpy(par_cbmb[i_cbmb],merkle_tree[i],32);
	      printf("added merkle tree to par_cbmb %u\n",i_cbmb);
	      i_cbmb++;
	    }
	    i--;
	  }

	  if (lp) {
	    par_cbmb_lp_size = i_cbmb;
	  }
	  else {
	    par_cbmb_size = i_cbmb;
	  }

	  /*
	  while (n > 1) {
	    i_cbmb++;
	    printf("i_cbmb=%d\n",i_cbmb);
	    if (n % 2) {
	      printf("copy merkle tree %d to merkle tree %d\n",n-1,n);
	      memcpy(merkle_tree[n], merkle_tree[n-1], 32);
	      ++n;
	    }
	    n /= 2;
	    for (i = 0; i < n; i++) {
	      uchar md[200];
	      printf("i=%d\n",i);
	      keccak(merkle_tree[2*i], 64, md, 200);
	      memcpy(merkle_tree[i],md,32);
	      printf("merkle_tree[%d] =\n",i);
	      for (int j=0;j<32;j++) {
		printf("%02x",merkle_tree[i][j]);
	      }
	      printf("\n");
	      /*	      if (i==1 && !aux) {
		par_cbmb[i_cbmb] = malloc(32);
		memcpy(par_cbmb[i_cbmb],merkle_tree[i],32);
		printf("added merkle tree to par_cbmb %u\n",i_cbmb);
		for (int j=0; j<32; j++) {
		  printf("%02x",par_cbmb[i_cbmb][j]);
		}
		printf("\n");
		}*/
	  //  }
	  //}
	  hex2bin(work->data,header,43);
	  memcpy((uchar*)work->data+43,merkle_tree[1],32);
	  ((uchar*)work->data)[75] = n;
	  printf("work->data = \n");
	  for (i=0;i<76;i++) {
	    printf("%02x",((uchar*)work->data)[i]);
	  }
	  printf("\n");

	  if (tx_blob) free(tx_blob);
	  tx_blob = malloc(strlen(block)+1);
	  strcpy(tx_blob,block+43*2);
	  memcpy(tx_blob+2*(reserved_offset-43),aux_hash,80);
	  tx_blob[strlen(block)] = '\0';
	  printf("tx_blob= %s\n",tx_blob);

	  
	  ((uchar*)target)[0] = 0;
	  ((uchar*)target)[1] = 0;
	  for (i=2;i<32;i++) {
	    ((uchar*)target)[i] = 0xff;
	  }

	  /*((uchar*)target)[31] = 0;
	  ((uchar*)target)[30] = 0x80;
	  for (i=0;i<30;i++) {
	    ((uchar*)target)[i] = 0xff;
	    }*/

	  for (i = 0; i < ARRAY_SIZE(work->target); i++) {
	    work->target[7 - i] = be32dec(target + i);
	  }

	  if (lp) {
	    if (par_cbtx_lp_size) free(par_cbtx_lp);
	    par_cbtx_lp = malloc(cbtx_size);
	    memcpy(par_cbtx_lp,cbtx,cbtx_size);
	    par_cbtx_lp_size = cbtx_size;
	  }
	  else {
	    if (par_cbtx_size) free(par_cbtx);
	    par_cbtx = malloc(cbtx_size);
	    memcpy(par_cbtx,cbtx,cbtx_size);
	    par_cbtx_size = cbtx_size;
	  }
	  printf("par_cbtx = (%d)\n",par_cbtx_size);
	  for (int i=0; i<par_cbtx_size; i++) {
	    printf("%02x",par_cbtx[i]);
	  }
	  printf("\n");
	  
	  rc = true;
	  goto out;
	}

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = (int) json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
			else if (!strcmp(s, "version/force"))
				version_force = true;
			else if (!strcmp(s, "version/reduce"))
				version_reduce = true;
		}
	}
	
	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = (int) json_integer_value(tmp);
	applog(LOG_BLUE, "Current block is %d", work->height);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = (uint32_t) json_integer_value(tmp);
	if ((version & 0xffU) > BLOCK_VERSION_CURRENT && (version != 4 || opt_algo != ALGO_EQUIHASH)) {
		if (version_reduce) {
		  printf("version_reduce\n");
			version = (version & ~0xffU) | BLOCK_VERSION_CURRENT;
		} else if (have_gbt && allow_getwork && !version_force) {
			applog(LOG_DEBUG, "Switching to getwork, gbt version %d", version);
			have_gbt = false;
			goto out;
		} else if (!version_force) {
			applog(LOG_ERR, "Unrecognized block version: %u", version);
			goto out;
		}
	}

	if (unlikely(!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = (uint32_t) json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = (int) json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += (int) (strlen(tx_hex) / 2);
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		//printf("initial cbtx=\n%s\n",cbtx_hex);
		cbtx_size = cbtx_hex ? (int) strlen(cbtx_hex) / 2 : 0;
		cbtx = (uchar*) malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = (int64_t) (json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp));
		printf("cbvalue = %lu\n",cbvalue);
		cbtx = (uchar*) malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		if (aux) {
		  cbtx[41] = (char)aux_scriptsig_size;
		  memcpy(cbtx+42,aux_scriptsig,aux_scriptsig_size);
		  cbtx_size = 42+aux_scriptsig_size;
		}
		else {
		  cbtx_size = 43;
		  /* BIP 34: height in coinbase */
		  for (n = work->height; n; n >>= 8)
		    cbtx[cbtx_size++] = n & 0xff;
		  cbtx[42] = cbtx_size - 43;
		  cbtx[41] = cbtx_size - 42; /* scriptsig length */
		}
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		if (aux) {
		  if (opt_algo == ALGO_EQUIHASH) {
		    cbtx[cbtx_size++] = (uint8_t) pk_script_aux_size+1;
		    cbtx[cbtx_size++] = (uint8_t) pk_script_aux_size-1;
		  }
		  else {
		    cbtx[cbtx_size++] = (uint8_t) pk_script_aux_size; /* txout-script length */
		  }
		  memcpy(cbtx+cbtx_size, pk_script_aux, pk_script_aux_size);
		  cbtx_size += (int) pk_script_aux_size;
		  coinbase_append = false;
		}
		else {
		  cbtx[cbtx_size++] = (uint8_t) pk_script_size; /* txout-script length */
		  memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		  cbtx_size += (int) pk_script_size;
		  coinbase_append = true;
		}
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
		  printf("have coinbase_sig\n");
			n = (int) strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? (int) (strlen(s) / 2) : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
				  printf("copy coinbaseaux\n");
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
			               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}
	printf("cbtx = ");
	for (int i=0; i<cbtx_size; i++) printf("%02x",cbtx[i]);
	printf("\n");
	if (rpc_url_aux && !aux) {
	  printf("append to coinbase: %s\n",aux_hash);
	  int script_start = 41;
	  if (opt_algo == ALGO_EQUIHASH) script_start = 45;
	  unsigned char xsig[100];
	  int xsig_len = 0;
	  if (*coinbase_sig) {
	    printf("have coinbase_sig\n");
	    n = (int) strlen(coinbase_sig);
	    if (cbtx[script_start] + xsig_len + n <= 100) {
	      memcpy(xsig+xsig_len, coinbase_sig, n);
	      xsig_len += n;
	    } else {
	      applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
	    }
	  }
	  unsigned char buf[100];
	  const char *s = aux_hash;
	  n = s ? (int) (strlen(s) / 2) : 0;
	  if (!s || n > 100 || !hex2bin(buf, s, n)) {
	    applog(LOG_ERR, "JSON invalid coinbaseaux");
	    return false;
	  }
	  printf("cbtxss %u\n",cbtx[script_start]);
	  if (cbtx[script_start] + xsig_len + n <= 100) {
	    printf("copy to coinbase\n");
	    memcpy(xsig+xsig_len, buf, n);
	    xsig_len += n;
	  }
	  if (xsig_len) {
	    printf("move and copy to coinbase\n");
	    unsigned char *ssig_end = cbtx + script_start + 1 + cbtx[script_start];
	    int push_len = cbtx[script_start] + xsig_len < 76 ? 1 :
	      cbtx[script_start] + 2 + xsig_len > 100 ? 0 : 2;
	    n = xsig_len + push_len;
	    memmove(ssig_end + n, ssig_end, cbtx_size - script_start - 1 - cbtx[script_start]);
	    cbtx[script_start] += n;
	    if (push_len == 2)
	      *(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
	    if (push_len)
	      *(ssig_end++) = xsig_len;
	    memcpy(ssig_end, xsig, xsig_len);
	    cbtx_size += n;
	    if (lp) {
	      if (par_cbtx_lp_size) free(par_cbtx_lp);
	      par_cbtx_lp = malloc(cbtx_size);
	      memcpy(par_cbtx_lp,cbtx,cbtx_size);
	      par_cbtx_lp_size = cbtx_size;
	    }
	    else {
	      if (par_cbtx_size) free(par_cbtx);
	      par_cbtx = malloc(cbtx_size);
	      memcpy(par_cbtx,cbtx,cbtx_size);
	      par_cbtx_size = cbtx_size;
	    }
	    printf("par_cbtx = (%d)\n",par_cbtx_size);
	    for (int i=0; i<par_cbtx_size; i++) {
	      printf("%02x",par_cbtx[i]);
	    }
	    printf("\n");
	  }
	}

	n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = (char*) malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);
	
	/* generate merkle root */
	merkle_tree = (uchar(*)[32]) calloc(((1 + tx_count + 1) & ~1), 32);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	printf("cbtx hash\n");
	for (i=0;i<32;i++) {
	  printf("%02x",merkle_tree[0][i]);
	}
	printf("\n");
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? (int) (strlen(tx_hex) / 2) : 0;
		unsigned char *tx = (uchar*) malloc(tx_size);
		if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
			applog(LOG_ERR, "JSON invalid transactions");
			free(tx);
			goto out;
		}
		sha256d(merkle_tree[1 + i], tx, tx_size);
		if (!submit_coinbase) {
			strcat(work->txs, tx_hex);
		}
	}
	n = 1 + tx_count;
	par_cbmb_size = 0;
	int cbmb_cap = log2_ceil(n);
	if (lp) {
	  par_cbmb_lp = malloc(cbmb_cap*sizeof(uchar*));
	}
	else {
	  par_cbmb = malloc(cbmb_cap*sizeof(uchar*));
	}
	printf("n=%d par_cbmb_cap = %lu\n",n,cbmb_cap);
	if (!aux && n>1) {
	  par_cbmb[0] = malloc(32);
	  memcpy(par_cbmb[0],merkle_tree[1],32);
	  printf("par_cbmb[0] =\n");
	  for (i=0;i<32;i++) {
	    printf("%02x",par_cbmb[0][i]);
	  }
	  printf("\n");
	}
	int i_cbmb = 0;
	while (n > 1) {
	  i_cbmb++;
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++) {
		  sha256d(merkle_tree[i], merkle_tree[2*i], 64);
		  if (i==1 && !aux) {
		    par_cbmb[i_cbmb] = malloc(32);
		    memcpy(par_cbmb[i_cbmb],merkle_tree[i],32);
		    printf("added merkle tree to par_cbmb %u\n",i_cbmb);
		    for (int j=0; j<32; j++) {
		      printf("%02x",par_cbmb[i_cbmb][j]);
		    }
		    printf("\n");
		  }
		}
	}
	if (lp) {
	  par_cbmb_lp_size = i_cbmb;
	}
	else {
	  par_cbmb_size = i_cbmb;
	}
	printf("i_cbmb = %d\n",i_cbmb);

	/* assemble block header */
	if (aux) printf("aux true\n");
	if (!aux) printf("aux false\n");
	printf("version is %u\n",version);
	if (aux) {
	  work->data[0] = swab32(aux_version);
	}
	else {
	  work->data[0] = swab32(version);
	}
	
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	printf("hash merkle root =\n");
	for (i=0;i<32;i++) {
	  printf("%02x",((unsigned char *)work->data)[36+i]);
	}
	printf("\n");
	if (opt_algo == ALGO_EQUIHASH) {
	  for (i = 0; i < 8; i++)
	    work->data[17 + i] = 0;
	  printf("work data 0 for hash reserved\n");
	  //uint32_t curtime_s = swab32(curtime);
	  if (aux) {
	    work->data[25] = swab32(aux_curtime);
	  }
	  else {
	    work->data[25] = swab32(curtime);
	  }
	  work->data[26] = le32dec(&bits);
	  for (i=0;i<8;i++)
	    work->data[27+i] = 0;
	  memset(work->data+35,0x00,1);
	  /*memset(work->data+35,0x00,48);
	  work->data[35] = 0x80000000;
	  work->data[46] = 0x00000280;*/
	}
	else {
	  work->data[17] = swab32(curtime);
	  work->data[18] = le32dec(&bits);
	  memset(work->data + 19, 0x00, 52);

	  work->data[20] = 0x80000000;
	  work->data[31] = 0x00000280;
	}

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	
	for (i = 0; i < ARRAY_SIZE(work->target); i++) {
	  work->target[7 - i] = be32dec(target + i);
	}

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	if (!work->txs) printf("!work->txs\n");

	rc = true;
out:
	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = json_is_string(tmp) ? strdup(json_string_value(tmp)) : rpc_url;
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}

	free(merkle_tree);
	free(cbtx);

	if (!aux) {
	  printf("par work data: ");
	  for (int i=0; i<140; i++) {
	    printf("%02x",((unsigned char *)work->data)[i]);
	  }
	  printf("\n");
	}
	return rc;
}

static bool gab_work_decode(const json_t *val, struct work *work) {

  uint32_t target[8];
  bool rc = false;
  
  if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
    applog(LOG_ERR, "JSON invalid target");
    printf("no target goto outgab\n");
    goto outgab;
  }

  int i = 0;
  for (i = 0; i < 8; i++) {
    aux_target[i] = target[i];
  }

  aux_version = (uint32_t) json_integer_value(json_object_get(val, "version"));
  printf("aux_version = %u\n",aux_version);

  aux_curtime = (uint32_t) json_integer_value(json_object_get(val, "curtime"));
  printf("aux_curtime = %u\n",aux_curtime);

  const char * scriptsig = json_string_value(json_object_get(val, "scriptsig"));
  aux_scriptsig_size = strlen(scriptsig)/2;
  aux_scriptsig = malloc(aux_scriptsig_size);
  hex2bin(aux_scriptsig,scriptsig,aux_scriptsig_size);

  const char * hash = json_string_value(json_object_get(val, "hash"));
  strcpy(aux_hash,hash);
  strcat(aux_hash,"0100000000000000");

  rc = true;
  
  outgab:
  printf("leave gab decode\n");
  return rc;  
  
}
  

#define YES "yes!"
#define YAY "yay!!!"
#define BOO "booooo"

static int share_result(int result, struct work *work, const char *reason)
{
	const char *flag;
	char suppl[32] = { 0 };
	char s[345];
	double hashrate;
	double sharediff = work ? work->sharediff : stratum.sharediff;
	int i;

	hashrate = 0.;
	pthread_mutex_lock(&stats_lock);
	for (i = 0; i < opt_n_threads; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
	pthread_mutex_unlock(&stats_lock);

	global_hashrate = (uint64_t) hashrate;

	if (!net_diff || sharediff < net_diff) {
		flag = use_colors ?
			(result ? CL_GRN YES : CL_RED BOO)
		:	(result ? "(" YES ")" : "(" BOO ")");
	} else {
		solved_count++;
		flag = use_colors ?
			(result ? CL_GRN YAY : CL_RED BOO)
		:	(result ? "(" YAY ")" : "(" BOO ")");
	}

	if (opt_showdiff)
		sprintf(suppl, "diff %.3f", sharediff);
	else // accepted percent
		sprintf(suppl, "%.2f%%", 100. * accepted_count / (accepted_count + rejected_count));

	switch (opt_algo) {
	case ALGO_AXIOM:
	case ALGO_CRYPTOLIGHT:
	case ALGO_CRYPTONIGHT:
	case ALGO_PLUCK:
	case ALGO_SCRYPTJANE:
		sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", hashrate);
		applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s H/s %s",
			accepted_count, accepted_count + rejected_count,
			suppl, s, flag);
		break;
	default:
		sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", hashrate / 1000.0);
		applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s kH/s %s",
			accepted_count, accepted_count + rejected_count,
			suppl, s, flag);
		break;
	}

	if (reason) {
		applog(LOG_WARNING, "reject reason: %s", reason);
		if (0 && strncmp(reason, "low difficulty share", 20) == 0) {
			opt_diff_factor = (opt_diff_factor * 2.0) / 3.0;
			applog(LOG_WARNING, "factor reduced to : %0.2f", opt_diff_factor);
			return 0;
		}
	}
	return 1;
}

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

static const char *gbt_req =
          "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
  GBT_CAPABILITIES "}], \"id\":0}\r\n";

static bool submit_upstream_work(CURL *curl, struct work *work)
{

  printf("submit upstream work\n");
  
  json_t *val, *res, *reason;
	char s[JSON_BUF_LEN];
	int i;
	bool rc = false;
	int err;
	
	/* pass if the previous hash is not the current previous hash */
	if (opt_algo != ALGO_SIA && !submit_old && memcmp(&work->data[1], &g_work.data[1], 32)) {
	  if (!rpc_url_aux) {
	    printf("previous hash not current\n");
	    if (opt_debug)
	      applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
	    return true;
	  }
	}

	if (!have_stratum && allow_mininginfo) {
		struct work wheight;
		get_mininginfo(curl, &wheight);
		if (work->height && work->height <= net_blocks) {
			if (opt_debug)
				applog(LOG_WARNING, "block %u was already solved", work->height);
			printf("block already solved\n");
			if (!rpc_url_aux) {
			  return true;
			}
		}
	}

	if (have_stratum) {
	  printf("have stratum\n");
		uint32_t ntime, nonce;
		char ntimestr[9], noncestr[9];

		if (jsonrpc_2) {
			uchar hash[32];

			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
			switch(opt_algo) {
			  /*case ALGO_CRYPTOLIGHT:
				cryptolight_hash(hash, work->data, 76);
				break;
			case ALGO_CRYPTONIGHT:
			cryptonight_hash(hash, work->data, 80);*/
			default:
				break;
			}
			char *hashhex = abin2hex(hash, 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}\r\n",
					rpc2_id, work->job_id, noncestr, hashhex);
			free(hashhex);
		} else {
			char *xnonce2str;

			switch (opt_algo) {
			case ALGO_DECRED:
				/* reversed */
				be32enc(&ntime, work->data[34]);
				be32enc(&nonce, work->data[35]);
				break;
			case ALGO_LBRY:
				le32enc(&ntime, work->data[25]);
				le32enc(&nonce, work->data[27]);
				break;
			case ALGO_DROP:
			case ALGO_NEOSCRYPT:
			case ALGO_ZR5:
				/* reversed */
				be32enc(&ntime, work->data[17]);
				be32enc(&nonce, work->data[19]);
				break;
			case ALGO_SIA:
				/* reversed */
				be32enc(&ntime, work->data[10]);
				be32enc(&nonce, work->data[8]);
				break;
			default:
				le32enc(&ntime, work->data[17]);
				le32enc(&nonce, work->data[19]);
			}

			bin2hex(ntimestr, (const unsigned char *)(&ntime), 4);
			bin2hex(noncestr, (const unsigned char *)(&nonce), 4);
			if (opt_algo == ALGO_DECRED) {
				xnonce2str = abin2hex((unsigned char*)(&work->data[36]), stratum.xnonce1_size);
			} else if (opt_algo == ALGO_SIA) {
				uint16_t high_nonce = swab32(work->data[9]) >> 16;
				xnonce2str = abin2hex((unsigned char*)(&high_nonce), 2);
			} else {
				xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			}
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
					rpc_user, work->job_id, xnonce2str, ntimestr, noncestr);
			free(xnonce2str);
		}

		// store to keep/display solved blocs (work struct not linked on accept notification)
		stratum.sharediff = work->sharediff;

		if (unlikely(!stratum_send_line(&stratum, s))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			goto out;
		}

	} else if (work->txs || tx_blob) { /* gbt */
	  printf("have work->txs\n");
		char data_str[2 * sizeof(work->data) + 1];
		char *req;

		if (!(opt_algo==ALGO_CRYPTONIGHT && tx_blob)) {
		  for (i = 0; i < ARRAY_SIZE(work->data); i++)
		    be32enc(work->data + i, work->data[i]);
		}
		int header_len = 80;
		if (opt_algo == ALGO_EQUIHASH) header_len = 1487;
		if (opt_algo == ALGO_CRYPTONIGHT) header_len = 76;
		bin2hex(data_str, (unsigned char *)work->data, header_len);

		printf("best_hash= ");
		for (i=0;i<32;i++) {
		  printf("%02x",((unsigned char *)best_hash)[i]);
		}
		printf("\n");
		printf("target= ");
		for (i=0;i<32;i++) {
		  printf("%02x",((unsigned char *)par_target)[i]);
		}
		printf("\naux target= ");
		for (i=0;i<32;i++) {
		  printf("%02x",((unsigned char *)aux_target)[i]);
		}
		printf("\n");

		if (true||fulltest(best_hash,par_target)) {
		  printf("submit to parent chain\n");
		  if (work->workid) {
		    char *params;
		    val = json_object();
		    json_object_set_new(val, "workid", json_string(work->workid));
		    params = json_dumps(val, 0);
		    json_decref(val);
		    req = (char*) malloc(128 + 2 * header_len + strlen(work->txs) + strlen(params));
		    sprintf(req,
			    "{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":4}\r\n",
			    data_str, work->txs, params);
		    free(params);
		  } else {
		    if (jsonrpc_2) {
		      printf("submitblock jsonrpc_2\n");
		      req = (char*) malloc(strlen(tx_blob)+400);
		      char header [43*2+1];
		      bin2hex(header,work->data,43);
		      sprintf(req,"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"submitblock\",\"params\":[\"%s%s\"]}\r\n",header,tx_blob);
		    }
		    else {
		      req = (char*) malloc(128 + 2 * header_len + strlen(work->txs));
		      sprintf(req,
			      "{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
			      data_str, work->txs);
		    }
		  }
		  printf("req = %s\n",req);
		  if (jsonrpc_2) {
		    printf("do json rpc2 call\n");
		    val = json_rpc2_call(curl, rpc_url, rpc_userpass, req, &err, 0);
		    printf("did json rpc2 call\n");
		  }
		  else {
		    val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
		  }
		  //submit aux block todo
		  free(req);
		  if (unlikely(!val)) {
		    applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
		    //goto out;
		  }
		}
		uchar * par_cbtx_cur = 0;
		size_t par_cbtx_cur_size = 0;
		uchar ** par_cbmb_cur = 0;
		size_t par_cbmb_cur_size = 0;
		if (lp) {
		  par_cbtx_cur = par_cbtx_lp;
		  par_cbtx_cur_size = par_cbtx_lp_size;
		  par_cbmb_cur = par_cbmb_lp;
		  par_cbmb_cur_size = par_cbmb_lp_size;
		}
		else {
		  par_cbtx_cur = par_cbtx;
		  par_cbtx_cur_size = par_cbtx_size;
		  par_cbmb_cur = par_cbmb;
		  par_cbmb_cur_size = par_cbmb_size;
		}
		if (true || fulltest(best_hash,aux_target) && par_cbmb_cur) {
		  printf("submit to aux chain\n");
		  //printf("aux_hash = %s\n",aux_hash);
		  //val = json_rpc_call(curl, rpc_url_aux, rpc_userpass_aux, gbt_req, &err, JSON_RPC_QUIET_404);
		  printf("aux_hash= %s\n",aux_hash);
		  printf("par_cbtx= \n");
		  for (i=0;i<par_cbtx_cur_size;i++) {
		    printf("%02x",par_cbtx_cur[i]);
		  }
		  printf("\n");
		  char data_str_aux[2 * sizeof(work_aux->data) + 1 + 2*par_cbtx_size+64+2*par_cbmb_size*32+6];
		  printf("par_cbmb (%d) =\n",par_cbmb_cur_size);
		  for (i=0;i<par_cbmb_cur_size;i++) {
		    for (int j=0;j<32;j++) {
		      printf("%02x",par_cbmb_cur[i][j]);
		    }
		    printf("\n");
		  }
		  printf("\n");
		  //bool rca = gbt_work_decode(json_object_get(val, "result"), work_aux, true);
		  /*		  for (i = 0; i < ARRAY_SIZE(work_aux->data); i++)
				  be32enc(work_aux->data + i, work_aux->data[i]);*/
		  if (opt_algo == ALGO_EQUIHASH || opt_algo == ALGO_CRYPTONIGHT) {
		    printf("equihash or cryptonight\n");
		    //bin2hex(data_str_aux, (unsigned char *)work_aux->data, 141);
		    sprintf(data_str_aux,"%02x",(unsigned char)par_cbtx_cur_size);
		    //sprintf(data_str_aux+2*141+2,"%04x",bswap_16(par_cbtx_size));
 		    bin2hex(data_str_aux+2, (unsigned char *)par_cbtx_cur,par_cbtx_cur_size);
		    uchar md[200];
		    keccak(work->data,76,md,200);
		    bin2hex(data_str_aux+2+2*par_cbtx_cur_size,md,32);
		    sprintf(data_str_aux+2+2*par_cbtx_cur_size+64,"%02x",(unsigned char)par_cbmb_cur_size);
		    for (i=0;i<par_cbmb_cur_size;i++) {
		      bin2hex(data_str_aux+2+2*par_cbtx_cur_size+64+2+i*64,par_cbmb_cur[i],32);
		    }
		  }
		  else {
		    //bin2hex(data_str_aux, (unsigned char *)work_aux->data, header_len);
		    bin2hex(data_str_aux, (unsigned char *)par_cbtx_cur,par_cbtx_cur_size);
		    bin2hex(data_str_aux+2*par_cbtx_cur_size, (unsigned char *)best_hash,32);
		    for (i=0;i<par_cbmb_cur_size;i++) {
		      bin2hex(data_str_aux+2*par_cbtx_cur_size+64+i*64,par_cbmb_cur[i],32);
		    }
		  }
		  strcat(data_str_aux,"000000000000000000");
		  if (opt_algo == ALGO_CRYPTONIGHT) {
		    strcat(data_str_aux,"4c");
		    //sprintf(data_str_aux+2+2*par_cbtx_cur_size+64+2+(par_cbmb_cur_size)*64,"%02x",76);
		  }
		  
		  //unsigned char hash_test[32];
		  //sha256d(hash_test,(unsigned char *)work_aux->data,141);
		  /* 		  printf("work_aux->data= ");
		  for(i=0;i<141;i++) {
		    printf("%02x",((unsigned char *)work_aux->data)[i]);
		  }
		  printf("\n");
		  printf("hash_test= ");
		  for (i=0;i<32;i++) {
		    printf("%02x",hash_test[i]);
		  }
		  printf("\n");*/
		  char aux_hash_trimmed [65];
		  for (i=0;i<32;i++) {
		    memcpy(aux_hash_trimmed+2*i,aux_hash+2*i,2);
		  }
		  aux_hash_trimmed[64] = '\0';
		  printf("submitting aux with aux_hash_trimmed=%s\n",aux_hash_trimmed);
		  printf("data_str_aux=%s\n",data_str_aux);
		  printf("data_str=%s\n",data_str);
		  
		  req = (char*) malloc(300 + 2 * sizeof(work_aux->data) + 1 + 2*par_cbtx_cur_size + 64 + par_cbmb_cur_size*64+strlen(data_str)+4);
		  sprintf(req,
			  "{\"method\": \"getauxblock\", \"params\": [\"%s\",\"%s%s\"], \"id\":4}\r\n",
			  aux_hash_trimmed,data_str_aux,data_str);
		  printf("aux req: %s\n",req);
		  //val = json_rpc_call(curl, rpc_url_aux, rpc_userpass_aux, req, NULL, 0); tmp
		  free(req);
		  if (unlikely(!val)) {
		    applog(LOG_ERR, "aux submit_upstream_work json_rpc_call failed");
		    //goto out;
		  }
		}
		

		res = json_object_get(val, "result");
		if (json_is_object(res)) {
			char *res_str;
			bool sumres = false;
			void *iter = json_object_iter(res);
			while (iter) {
				if (json_is_null(json_object_iter_value(iter))) {
					sumres = true;
					break;
				}
				iter = json_object_iter_next(res, iter);
			}
			res_str = json_dumps(res, 0);
			share_result(sumres, work, res_str);
			free(res_str);
		} else
			share_result(json_is_null(res), work, json_string_value(res));

		json_decref(val);

	} else {

		char* gw_str = NULL;
		int data_size = 128;
		int adata_sz;

		if (jsonrpc_2) {
			char noncestr[9];
			uchar hash[32];
			char *hashhex;

			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);

			switch(opt_algo) {
			  /*case ALGO_CRYPTOLIGHT:
				cryptolight_hash(hash, work->data, 76);
				break;
			case ALGO_CRYPTONIGHT:
			cryptonight_hash(hash, work->data, 80);**/
			default:
				break;
				}
			hashhex = abin2hex(&hash[0], 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": "
						"{\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"},"
					"\"id\":4}\r\n",
					rpc2_id, work->job_id, noncestr, hashhex);
			free(hashhex);

			/* issue JSON-RPC request */
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
			if (unlikely(!val)) {
				applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
				goto out;
			}
			res = json_object_get(val, "result");
			json_t *status = json_object_get(res, "status");
			bool valid = !strcmp(status ? json_string_value(status) : "", "OK");
			if (valid) {
				share_result(valid, work, NULL);
			}
			else {
				json_t *err = json_object_get(res, "error");
				const char *sreason = json_string_value(json_object_get(err, "message"));
				share_result(valid, work, sreason);
				if (!strcasecmp("Invalid job id", sreason)) {
					work_free(work);
					work_copy(work, &g_work);
					g_work_time = 0;
					restart_threads();
				}
			}
			json_decref(val);
			return true;

		} else if (opt_algo == ALGO_DROP || opt_algo == ALGO_NEOSCRYPT || opt_algo == ALGO_ZR5) {
			/* different data size */
			data_size = 80;
		} else if (opt_algo == ALGO_DECRED) {
			/* bigger data size : 180 + terminal hash ending */
			data_size = 192;
		}
		adata_sz = data_size / sizeof(uint32_t);
		if (opt_algo == ALGO_DECRED) adata_sz = 180 / 4; // dont touch the end tag

		/* build hex string */
		for (i = 0; i < adata_sz; i++)
			le32enc(&work->data[i], work->data[i]);

		gw_str = abin2hex((uchar*)work->data, data_size);

		if (unlikely(!gw_str)) {
			applog(LOG_ERR, "submit_upstream_work OOM");
			return false;
		}

		//applog(LOG_WARNING, gw_str);

		/* build JSON-RPC request */
		snprintf(s, JSON_BUF_LEN,
			"{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n", gw_str);
		free(gw_str);

		/* issue JSON-RPC request */
		val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}
		res = json_object_get(val, "result");
		reason = json_object_get(val, "reject-reason");
		share_result(json_is_true(res), work, reason ? json_string_value(reason) : NULL);

		json_decref(val);
	}

	rc = true;

out:
	return rc;
}

static const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";
static const char *gab_req =
	"{\"method\": \"getauxblock\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work, struct work *work_aux)
{
  printf("in get upstream work\n");
	json_t *val;
	json_t* val_aux;
	json_t* val_auxgbt;
	int err;
	int err_aux;
	int err_auxgbt;
	bool rc;
	struct timeval tv_start, tv_end, diff;

start:
	gettimeofday(&tv_start, NULL);

	printf("note gbt req: %s\n",gbt_req);
	if (jsonrpc_2 && opt_algo == ALGO_CRYPTONIGHT) {
	  printf("do json2 request\n");
		char s[500];
		sprintf(s,"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"getblocktemplate\",\"params\":{\"wallet_address\":\"%s\",\"reserve_size\":40}}\r\n",monero_address);
		val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, &err, 0);
		printf("got val\n");
	} else {
		val = json_rpc_call(curl, rpc_url, rpc_userpass,
		                    have_gbt ? gbt_req : getwork_req,
		                    &err, have_gbt ? JSON_RPC_QUIET_404 : 0);
	}

	if (rpc_url_aux) {
	  val_aux = json_rpc_call(curl, rpc_url_aux, rpc_userpass_aux, gab_req, &err_aux, JSON_RPC_QUIET_404);
	  printf("got val aux\n");
	  //val_auxgbt = json_rpc_call(curl, rpc_url_aux, rpc_userpass_aux, gbt_req, &err_auxgbt, JSON_RPC_QUIET_404);
	}

	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!have_gbt && !allow_getwork) {
		applog(LOG_ERR, "No usable protocol");
		if (val)
			json_decref(val);
		return false;
	}

	if (have_gbt && allow_getwork && !val && err == CURLE_OK) {
		applog(LOG_NOTICE, "getblocktemplate failed, falling back to getwork");
		have_gbt = false;
		goto start;
	}

	if (!val)
		return false;

	if (have_gbt) {
	  json_dumps(json_object_get(val,"result"),0);
	  json_dumps(json_object_get(val_aux,"result"),0);
	  if (work_aux && !aux_scriptsig) {
	    aux_hash[0] = '\0';
	    rc = gab_work_decode(json_object_get(val_aux,"result"),work_aux);
	    //rc = gbt_work_decode(json_object_get(val_auxgbt, "result"), work_aux, true);
	    /*for (int i = 0; i < ARRAY_SIZE(work_aux->data); i++)
	      be32enc(work_aux->data + i, work_aux->data[i]);
	      unsigned char hash_tmp[32];*/
	    /*	    printf("new work_aux->data= ");
	    for(int i=0;i<141;i++) {
	      printf("%02x",((unsigned char *)work_aux->data)[i]);
	    }
	    printf("\n");
	    sha256d(hash_tmp,(unsigned char *)work_aux->data,141);
	    for (int i=0; i<32; i++) {
	      sprintf(aux_hash+2*i,"%02x",hash_tmp[31-i]);
	    }
	    strcat(aux_hash,"0100000000000000");*/
	    //printf("new aux_hash = %s\n",aux_hash);
	    //memcpy(aux_target,work_aux->target,32);
	    if (!rc) printf("bad rc after gab decode\n");
	  }
	  printf("do gbt work decode par\n");
	  lp = false;
	  rc = gbt_work_decode(json_object_get(val, "result"), work, false);
	  if (!rc) printf("bad rc after gbt decode\n");
	  memcpy(par_target,work->target,32);
	  printf("work target: ");
	  for (int i=0; i<32; i++) {
	    printf("%02x",((unsigned char *)work->target)[i]);
	  }
	  printf("\n");
	  if (work_aux) {
	    printf("aux work target: ");
	    for (int i=0; i<32; i++) {
	      printf("%02x",((unsigned char *)work_aux->target)[i]);
	    }
	    printf("\n");
	  }
	  if (!have_gbt) {
	    json_decref(val);
	    goto start;
	  }
	} else {
	  rc = work_decode(json_object_get(val, "result"), work);
	}

	if (opt_protocol && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "got new work in %.2f ms",
		       (1000.0 * diff.tv_sec) + (0.001 * diff.tv_usec));
	}

	json_decref(val);

	// store work height in solo
	//printf("do getmininginfo\n");
	//get_mininginfo(curl, work);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		work_free(wc->u.work);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc)); /* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
  printf("in workio_get_work\n");
	struct work *ret_work;
	struct work *ret_work_aux;
	int failures = 0;

	ret_work = (struct work*) calloc(1, sizeof(*ret_work));
	if (rpc_url_aux) {
	  ret_work_aux = (struct work*) calloc(1, sizeof(*ret_work_aux));
	}
	else {
	  ret_work_aux = 0;
	}
	if (!ret_work)
		return false;

	work_aux = ret_work_aux;
	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(curl, ret_work, ret_work_aux)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}
	printf("got upstream work\n");

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		if (!opt_benchmark)
			applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

bool rpc2_login(CURL *curl)
{
	json_t *val;
	bool rc = false;
	struct timeval tv_start, tv_end, diff;
	char s[JSON_BUF_LEN];

	if (!jsonrpc_2)
		return false;

	snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {"
		"\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
		rpc_user, rpc_pass, USER_AGENT);

	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	gettimeofday(&tv_end, NULL);

	if (!val)
		goto end;

//	applog(LOG_DEBUG, "JSON value: %s", json_dumps(val, 0));

	rc = rpc2_login_decode(val);

	json_t *result = json_object_get(val, "result");

	if (!result)
		goto end;

	json_t *job = json_object_get(result, "job");
	if (!rpc2_job_decode(job, &g_work)) {
		goto end;
	}

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
				diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

	json_decref(val);
end:
	return rc;
}

bool rpc2_workio_login(CURL *curl)
{
	int failures = 0;
	if (opt_benchmark)
		return true;
	/* submit solution to bitcoin via JSON-RPC */
	pthread_mutex_lock(&rpc2_login_lock);
	while (!rpc2_login(curl)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			pthread_mutex_unlock(&rpc2_login_lock);
			return false;
		}

		/* pause, then restart work-request loop */
		if (!opt_benchmark)
			applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		sleep(opt_fail_pause);
		pthread_mutex_unlock(&rpc2_login_lock);
		pthread_mutex_lock(&rpc2_login_lock);
	}
	pthread_mutex_unlock(&rpc2_login_lock);

	return true;
}

static void *workio_thread(void *userdata)
{
  printf("in workio_thread\n");
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	if(jsonrpc_2 && !have_stratum) {
	  //ok = rpc2_workio_login(curl); tmp
	}

	while (ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_GET_WORK:
			ok = workio_get_work(wc, curl);
			break;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	if (opt_benchmark) {
		uint32_t ts = (uint32_t) time(NULL);
		for (int n=0; n<74; n++) ((char*)work->data)[n] = n;
		//memset(work->data, 0x55, 76);
		work->data[17] = swab32(ts);
		memset(work->data + 19, 0x00, 52);
		if (opt_algo == ALGO_DECRED) {
			memset(&work->data[35], 0x00, 52);
		} else {
			work->data[20] = 0x80000000;
			work->data[31] = 0x00000280;
		}
		memset(work->target, 0x00, sizeof(work->target));
		return true;
	}

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
	work_heap = (struct work*) tq_pop(thr->q, NULL);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = (struct work*) malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	work_copy(wc->u.work, work_in);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	uint32_t extraheader[32] = { 0 };
	uchar merkle_root[64] = { 0 };
	int i, headersize = 0;

	pthread_mutex_lock(&sctx->work_lock);

	if (jsonrpc_2) {
		work_free(work);
		work_copy(work, &sctx->work);
		pthread_mutex_unlock(&sctx->work_lock);
	} else {
		free(work->job_id);
		work->job_id = strdup(sctx->job.job_id);
		work->xnonce2_len = sctx->xnonce2_size;
		work->xnonce2 = (uchar*) realloc(work->xnonce2, sctx->xnonce2_size);
		memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

		/* Generate merkle root */
		switch (opt_algo) {
			case ALGO_DECRED:
				// getwork over stratum, getwork merkle + header passed in coinb1
				memcpy(merkle_root, sctx->job.coinbase, 32);
				headersize = min((int)sctx->job.coinbase_size - 32, sizeof(extraheader));
				memcpy(extraheader, &sctx->job.coinbase[32], headersize);
				break;
			case ALGO_HEAVY:
				heavyhash(merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size);
				break;
			case ALGO_GROESTL:
			case ALGO_KECCAK:
			case ALGO_BLAKECOIN:
				SHA256(sctx->job.coinbase, (int) sctx->job.coinbase_size, merkle_root);
				break;
			case ALGO_SIA:
				// getwork over stratum, getwork merkle + header passed in coinb1
				memcpy(merkle_root, sctx->job.coinbase, 32);
				headersize = min((int)sctx->job.coinbase_size - 32, sizeof(extraheader));
				memcpy(extraheader, &sctx->job.coinbase[32], headersize);
				break;
			default:
				sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
		}

		if (!headersize)
		for (i = 0; i < sctx->job.merkle_count; i++) {
			memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
			if (opt_algo == ALGO_HEAVY)
				heavyhash(merkle_root, merkle_root, 64);
			else
				sha256d(merkle_root, merkle_root, 64);
		}

		/* Increment extranonce2 */
		for (size_t t = 0; t < sctx->xnonce2_size && !(++sctx->job.xnonce2[t]); t++)
			;

		/* Assemble block header */
		memset(work->data, 0, 128);
		work->data[0] = le32dec(sctx->job.version);
		for (i = 0; i < 8; i++)
			work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
		for (i = 0; i < 8; i++)
			work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);

		if (opt_algo == ALGO_DECRED) {
			uint32_t* extradata = (uint32_t*) sctx->xnonce1;
			for (i = 0; i < 8; i++) // prevhash
				work->data[1 + i] = swab32(work->data[1 + i]);
			for (i = 0; i < 8; i++) // merkle
				work->data[9 + i] = swab32(work->data[9 + i]);
			for (i = 0; i < headersize/4; i++) // header
				work->data[17 + i] = extraheader[i];
			// extradata
			for (i = 0; i < sctx->xnonce1_size/4; i++)
				work->data[36 + i] = extradata[i];
			for (i = 36 + (int) sctx->xnonce1_size/4; i < 45; i++)
				work->data[i] = 0;
			work->data[37] = (rand()*4) << 8;
			sctx->bloc_height = work->data[32];
			//applog_hex(work->data, 180);
			//applog_hex(&work->data[36], 36);
		} else if (opt_algo == ALGO_LBRY) {
			for (i = 0; i < 8; i++)
				work->data[17 + i] = ((uint32_t*)sctx->job.claim)[i];
			work->data[25] = le32dec(sctx->job.ntime);
			work->data[26] = le32dec(sctx->job.nbits);
			work->data[28] = 0x80000000;
		} else if (opt_algo == ALGO_SIA) {
			for (i = 0; i < 8; i++) // prevhash
				work->data[i] = ((uint32_t*)sctx->job.prevhash)[7-i];
			work->data[8] = 0; // nonce
			work->data[9] = swab32(extraheader[0]);
			work->data[9] |= rand() & 0xF0;
			work->data[10] = be32dec(sctx->job.ntime);
			work->data[11] = be32dec(sctx->job.nbits);
			for (i = 0; i < 8; i++) // prevhash
				work->data[12+i] = ((uint32_t*)merkle_root)[i];
			//applog_hex(&work->data[0], 80);
		} else {
			work->data[17] = le32dec(sctx->job.ntime);
			work->data[18] = le32dec(sctx->job.nbits);
			// required ?
			work->data[20] = 0x80000000;
			work->data[31] = 0x00000280;
		}

		if (opt_showdiff || opt_max_diff > 0.)
			calc_network_diff(work);

		if (opt_algo == ALGO_DROP || opt_algo == ALGO_NEOSCRYPT || opt_algo == ALGO_ZR5) {
			/* reversed endian */
			for (i = 0; i <= 18; i++)
				work->data[i] = swab32(work->data[i]);
		}

		pthread_mutex_unlock(&sctx->work_lock);

		if (opt_debug && opt_algo != ALGO_DECRED && opt_algo != ALGO_SIA) {
			char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
					work->job_id, xnonce2str, swab32(work->data[17]));
			free(xnonce2str);
		}

		switch (opt_algo) {
			case ALGO_DROP:
			case ALGO_JHA:
			case ALGO_SCRYPT:
			case ALGO_SCRYPTJANE:
			case ALGO_NEOSCRYPT:
			case ALGO_PLUCK:
			case ALGO_YESCRYPT:
				work_set_target(work, sctx->job.diff / (65536.0 * opt_diff_factor));
				break;
			case ALGO_FRESH:
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
			case ALGO_LBRY:
			case ALGO_LYRA2REV2:
			case ALGO_TIMETRAVEL:
			case ALGO_BITCORE:
			case ALGO_XEVAN:
				work_set_target(work, sctx->job.diff / (256.0 * opt_diff_factor));
				break;
			case ALGO_KECCAK:
			case ALGO_LYRA2:
				work_set_target(work, sctx->job.diff / (128.0 * opt_diff_factor));
				break;
			default:
				work_set_target(work, sctx->job.diff / opt_diff_factor);
		}

		if (stratum_diff != sctx->job.diff) {
			char sdiff[32] = { 0 };
			// store for api stats
			stratum_diff = sctx->job.diff;
			if (opt_showdiff && work->targetdiff != stratum_diff)
				snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
			applog(LOG_WARNING, "Stratum difficulty set to %g%s", stratum_diff, sdiff);
		}
	}
}

bool rpc2_stratum_job(struct stratum_ctx *sctx, json_t *params)
{
	bool ret = false;
	pthread_mutex_lock(&sctx->work_lock);
	ret = rpc2_job_decode(params, &sctx->work);

	if (ret) {
		work_free(&g_work);
		work_copy(&g_work, &sctx->work);
		g_work_time = 0;
	}

	pthread_mutex_unlock(&sctx->work_lock);

	return ret;
}

static bool wanna_mine(int thr_id)
{
	bool state = true;

	if (opt_max_temp > 0.0) {
		float temp = cpu_temp(0);
		if (temp > opt_max_temp) {
			if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
				applog(LOG_INFO, "temperature too high (%.0fC), waiting...", temp);
			state = false;
		}
	}
	if (opt_max_diff > 0.0 && net_diff > opt_max_diff) {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
			applog(LOG_INFO, "network diff too high, waiting...");
		state = false;
	}
	if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate) {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet) {
			char rate[32];
			format_hashrate(opt_max_rate, rate);
			applog(LOG_INFO, "network hashrate too high, waiting %s...", rate);
		}
		state = false;
	}
	if (thr_id < MAX_CPUS)
		conditional_state[thr_id] = (uint8_t) !state;
	return state;
}

static void *miner_thread(void *userdata)
{
  printf("in miner thread\n");
	struct thr_info *mythr = (struct thr_info *) userdata;
	int thr_id = mythr->id;
	struct work work;
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	time_t tm_rate_log = 0;
	time_t firstwork_time = 0;
	unsigned char *scratchbuf = NULL;
	char s[16];
	int i;

	memset(&work, 0, sizeof(work));

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	if (!opt_benchmark && opt_priority == 0) {
		setpriority(PRIO_PROCESS, 0, 19);
		drop_policy();
	} else {
		int prio = 0;
#ifndef WIN32
		prio = 18;
		// note: different behavior on linux (-19 to 19)
		switch (opt_priority) {
			case 1:
				prio = 5;
				break;
			case 2:
				prio = 0;
				break;
			case 3:
				prio = -5;
				break;
			case 4:
				prio = -10;
				break;
			case 5:
				prio = -15;
		}
		if (opt_debug)
			applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
				thr_id,	opt_priority, prio);
#endif
		setpriority(PRIO_PROCESS, 0, prio);
		if (opt_priority == 0) {
			drop_policy();
		}
	}

	/* Cpu thread affinity */
	if (num_cpus > 1) {
		if (opt_affinity == -1 && opt_n_threads > 1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)", thr_id,
						thr_id % num_cpus, (1 << (thr_id % num_cpus)));
			affine_to_cpu_mask(thr_id, 1UL << (thr_id % num_cpus));
		} else if (opt_affinity != -1L) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu mask %x", thr_id,
						opt_affinity);
			affine_to_cpu_mask(thr_id, (unsigned long)opt_affinity);
		}
	}

	if (opt_algo == ALGO_SCRYPT) {
		scratchbuf = scrypt_buffer_alloc(opt_scrypt_n);
		if (!scratchbuf) {
			applog(LOG_ERR, "scrypt buffer allocation failed");
			pthread_mutex_lock(&applog_lock);
			exit(1);
		}
	}

	else if (opt_algo == ALGO_PLUCK) {
		scratchbuf = malloc(opt_pluck_n * 1024);
		if (!scratchbuf) {
			applog(LOG_ERR, "pluck buffer allocation failed");
			pthread_mutex_lock(&applog_lock);
			exit(1);
		}
	}

	while (1) {
		uint64_t hashes_done;
		struct timeval tv_start, tv_end, diff;
		int64_t max64;
		bool regen_work = false;
		int wkcmp_offset = 0;
		int nonce_oft = 19*sizeof(uint32_t); // 76
		int wkcmp_sz = nonce_oft;
		int rc = 0;

		if (opt_algo == ALGO_DROP || opt_algo == ALGO_ZR5) {
			// Duplicates: ignore pok in data[0]
			wkcmp_sz -= sizeof(uint32_t);
			wkcmp_offset = 1;
		} else if (opt_algo == ALGO_DECRED) {
			wkcmp_sz = nonce_oft = 140; // 35 * 4
			regen_work = true; // ntime not changed ?
		} else if (opt_algo == ALGO_LBRY) {
			wkcmp_sz = nonce_oft = 108; // 27
			//regen_work = true;
		} else if (opt_algo == ALGO_SIA) {
			nonce_oft = 32;
			wkcmp_offset = 32 + 16;
			wkcmp_sz = 32; // 35 * 4
		}

		if (jsonrpc_2) {
			wkcmp_sz = nonce_oft = 39;
		}

		uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);

		if (have_stratum) {
			while (!jsonrpc_2 && time(NULL) >= g_work_time + 120)
				sleep(1);

			while (!stratum.job.diff && opt_algo == ALGO_NEOSCRYPT) {
				applog(LOG_DEBUG, "Waiting for Stratum to set the job difficulty");
				sleep(1);
			}

			pthread_mutex_lock(&g_work_lock);

			// to clean: is g_work loaded before the memcmp ?
			regen_work = regen_work || ( (*nonceptr) >= end_nonce
				&& !( memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
				 jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0));
			if (regen_work) {
				stratum_gen_work(&stratum, &g_work);
			}

		} else {

			int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
			/* obtain new work from internal workio thread */
			pthread_mutex_lock(&g_work_lock);
			if (!have_stratum &&
			    (time(NULL) - g_work_time >= min_scantime ||
			     work.data[19] >= end_nonce)) {
				if (unlikely(!get_work(mythr, &g_work))) {
					applog(LOG_ERR, "work retrieval failed, exiting "
						"mining thread %d", mythr->id);
					pthread_mutex_unlock(&g_work_lock);
					goto out;
				}
				g_work_time = have_stratum ? 0 : time(NULL);
			}
			if (have_stratum) {
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}
		if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
			jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0)
		{
			work_free(&work);
			work_copy(&work, &g_work);
			nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);
			*nonceptr = 0xffffffffU / opt_n_threads * thr_id;
			if (opt_randomize)
				nonceptr[0] += ((rand()*4) & UINT32_MAX) / opt_n_threads;
		} else
			++(*nonceptr);
		pthread_mutex_unlock(&g_work_lock);
		work_restart[thr_id].restart = 0;

		if (opt_algo == ALGO_DECRED) {
			if (have_stratum && strcmp(stratum.job.job_id, work.job_id))
				continue; // need to regen g_work..
			// extradata: prevent duplicates
			nonceptr[1] += 1;
			nonceptr[2] |= thr_id;
		} else if (opt_algo == ALGO_SIA) {
			if (have_stratum && strcmp(stratum.job.job_id, work.job_id))
				continue; // need to regen g_work..
			// extradata: prevent duplicates
			nonceptr[1] += 0x10;
			nonceptr[1] |= thr_id;
			//applog_hex(nonceptr, 8);
		}

		// prevent scans before a job is received
		// beware, some testnet (decred) are using version 0
		// no version in sia draft protocol
		if (opt_algo != ALGO_SIA && have_stratum && !work.data[0] && !opt_benchmark) {
			sleep(1);
			continue;
		}

		/* conditional mining */
		if (!wanna_mine(thr_id)) {
			sleep(5);
			continue;
		}

		/* adjust max_nonce to meet target scan time */
		if (have_stratum)
			max64 = LP_SCANTIME;
		else
			max64 = g_work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
					- time(NULL);

		/* time limit */
		if (opt_time_limit && firstwork_time) {
			int passed = (int)(time(NULL) - firstwork_time);
			int remain = (int)(opt_time_limit - passed);
			if (remain < 0) {
				if (thr_id != 0) {
					sleep(1);
					continue;
				}
				if (opt_benchmark) {
					char rate[32];
					format_hashrate((double)global_hashrate, rate);
					applog(LOG_NOTICE, "Benchmark: %s", rate);
					fprintf(stderr, "%llu\n", (long long unsigned int) global_hashrate);
				} else {
					applog(LOG_NOTICE,
						"Mining timeout of %ds reached, exiting...", opt_time_limit);
				}
				proper_exit(0);
			}
			if (remain < max64) max64 = remain;
		}

		max64 *= (int64_t) thr_hashrates[thr_id];

		if (max64 <= 0) {
			switch (opt_algo) {
			case ALGO_SCRYPT:
			case ALGO_NEOSCRYPT:
				max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
				if (opt_nfactor > 3)
					max64 >>= (opt_nfactor - 3);
				else if (opt_nfactor > 16)
					max64 = 0xF;
				break;
			case ALGO_AXIOM:
			case ALGO_CRYPTOLIGHT:
			case ALGO_CRYPTONIGHT:
			case ALGO_SCRYPTJANE:
				max64 = 0x40LL;
				break;
			case ALGO_DROP:
			case ALGO_PLUCK:
			case ALGO_YESCRYPT:
				max64 = 0x1ff;
				break;
			case ALGO_LYRA2:
			case ALGO_LYRA2REV2:
			case ALGO_TIMETRAVEL:
			case ALGO_BITCORE:
			case ALGO_XEVAN:
				max64 = 0xffff;
				break;
			case ALGO_C11:
			case ALGO_DMD_GR:
			case ALGO_FRESH:
			case ALGO_GROESTL:
			case ALGO_MYR_GR:
			case ALGO_SIB:
			case ALGO_VELTOR:
			case ALGO_X11EVO:
			case ALGO_X11:
			case ALGO_X13:
			case ALGO_X14:
				max64 = 0x3ffff;
				break;
			case ALGO_LBRY:
			case ALGO_X15:
			case ALGO_X17:
			case ALGO_ZR5:
				max64 = 0x1ffff;
				break;
			case ALGO_BMW:
			case ALGO_PENTABLAKE:
				max64 = 0x3ffff;
				break;
			case ALGO_SKEIN:
			case ALGO_SKEIN2:
				max64 = 0x7ffffLL;
				break;
			case ALGO_BLAKE:
			case ALGO_BLAKECOIN:
			case ALGO_DECRED:
			case ALGO_VANILLA:
				max64 = 0x3fffffLL;
				break;
			case ALGO_SIA:
			default:
				max64 = 0x1fffffLL;
				break;
			}
		}
		if ((*nonceptr) + max64 > end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = (*nonceptr) + (uint32_t) max64;

		hashes_done = 0;
		gettimeofday((struct timeval *) &tv_start, NULL);

		if (firstwork_time == 0)
			firstwork_time = time(NULL);

		/* scan nonces for a proof-of-work hash */
		switch (opt_algo) {

		case ALGO_AXIOM:
			rc = scanhash_axiom(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BASTION:
			rc = scanhash_bastion(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BLAKE:
			rc = scanhash_blake(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BLAKECOIN:
			rc = scanhash_blakecoin(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BLAKE2S:
			rc = scanhash_blake2s(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BMW:
			rc = scanhash_bmw(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_C11:
			rc = scanhash_c11(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_CRYPTOLIGHT:
			rc = scanhash_cryptolight(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_CRYPTONIGHT:
		  if (jsonrpc_2) {
		    rc = scanhash_cryptonight(thr_id, &work, max_nonce, &hashes_done, true, aux_target, best_hash);
		  }
		  else {
		    rc = scanhash_cryptonight(thr_id, &work, max_nonce, &hashes_done, false, aux_target, best_hash);
		  }
		  break;
		case ALGO_DECRED:
			rc = scanhash_decred(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_DROP:
			rc = scanhash_drop(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_FRESH:
			rc = scanhash_fresh(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
			rc = scanhash_groestl(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_KECCAK:
			rc = scanhash_keccak(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_HEAVY:
			rc = scanhash_heavy(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_JHA:
			rc = scanhash_jha(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_LBRY:
			rc = scanhash_lbry(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_LUFFA:
			rc = scanhash_luffa(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_LYRA2:
			rc = scanhash_lyra2(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_LYRA2REV2:
			rc = scanhash_lyra2rev2(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_MYR_GR:
			rc = scanhash_myriad(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_NEOSCRYPT:
			rc = scanhash_neoscrypt(thr_id, &work, max_nonce, &hashes_done,
				0x80000020 | (opt_nfactor << 8));
			break;
		case ALGO_NIST5:
			rc = scanhash_nist5(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_PENTABLAKE:
			rc = scanhash_pentablake(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_PLUCK:
			rc = scanhash_pluck(thr_id,  &work, max_nonce, &hashes_done, scratchbuf, opt_pluck_n);
			break;
		case ALGO_QUARK:
			rc = scanhash_quark(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_QUBIT:
			rc = scanhash_qubit(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SCRYPT:
			rc = scanhash_scrypt(thr_id, &work, max_nonce, &hashes_done, scratchbuf, opt_scrypt_n);
			break;
		case ALGO_SCRYPTJANE:
			rc = scanhash_scryptjane(opt_scrypt_n, thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SHAVITE3:
			rc = scanhash_ink(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SHA256D:
			rc = scanhash_sha256d(thr_id, &work, max_nonce,	&hashes_done);
			break;
		case ALGO_SIA:
			rc = scanhash_sia(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SIB:
			rc = scanhash_sib(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SKEIN:
			rc = scanhash_skein(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_SKEIN2:
			rc = scanhash_skein2(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_S3:
			rc = scanhash_s3(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_TIMETRAVEL:
			rc = scanhash_timetravel(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_BITCORE:
			rc = scanhash_bitcore(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_VANILLA:
			rc = scanhash_blakecoin(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_VELTOR:
			rc = scanhash_veltor(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X11EVO:
			rc = scanhash_x11evo(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X11:
			rc = scanhash_x11(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X13:
			rc = scanhash_x13(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X14:
			rc = scanhash_x14(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X15:
			rc = scanhash_x15(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_X17:
			rc = scanhash_x17(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_XEVAN:
			rc = scanhash_xevan(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_YESCRYPT:
			rc = scanhash_yescrypt(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_ZR5:
			rc = scanhash_zr5(thr_id, &work, max_nonce, &hashes_done);
			break;
		case ALGO_AR2:
		  rc = scanhash_ar2(thr_id, &work, max_nonce, &hashes_done);
		  break;
		case ALGO_EQUIHASH:
		  if (rpc_url_aux) {
		    rc = scanhash_equihash(thr_id, &work, max_nonce, &hashes_done, aux_target, best_hash);
		  }
		  else {
		    rc = scanhash_equihash(thr_id, &work, max_nonce, &hashes_done, 0, 0);
		  }
		  break;
		default:
			/* should never happen */
			goto out;
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet && (time(NULL) - tm_rate_log) > opt_maxlograte) {
			switch(opt_algo) {
			case ALGO_AXIOM:
			case ALGO_CRYPTOLIGHT:
			case ALGO_CRYPTONIGHT:
			case ALGO_PLUCK:
			case ALGO_SCRYPTJANE:
				applog(LOG_INFO, "CPU #%d: %.2f H/s", thr_id, thr_hashrates[thr_id]);
				break;
			default:
				sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
						thr_hashrates[thr_id] / 1e3);
				applog(LOG_INFO, "CPU #%d: %s kH/s", thr_id, s);
				break;
			}
			tm_rate_log = time(NULL);
		}
		if (opt_benchmark && thr_id == opt_n_threads - 1) {
			double hashrate = 0.;
			for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
				hashrate += thr_hashrates[i];
			if (i == opt_n_threads) {
				switch(opt_algo) {
				case ALGO_CRYPTOLIGHT:
				case ALGO_CRYPTONIGHT:
				case ALGO_AXIOM:
				case ALGO_SCRYPTJANE:
					sprintf(s, "%.3f", hashrate);
					applog(LOG_NOTICE, "Total: %s H/s", s);
					break;
				default:
					sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", hashrate / 1000);
					applog(LOG_NOTICE, "Total: %s kH/s", s);
					break;
				}
				global_hashrate = (uint64_t) hashrate;
			}
		}

		/* if nonce found, submit work */
		if (rc && !opt_benchmark) {
			if (!submit_work(mythr, &work))
				break;
			// prevent stale work in solo
			// we can't submit twice a block!
			if (!have_stratum && !have_longpoll) {
				pthread_mutex_lock(&g_work_lock);
				// will force getwork
				g_work_time = 0;
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}

	}

out:
	tq_freeze(mythr->q);

	return NULL;
}

void restart_threads(void)
{
	int i;

	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static void *longpoll_thread(void *userdata)
{
  printf("in longpoll_thread\n");
	struct thr_info *mythr = (struct thr_info*) userdata;
	CURL *curl = NULL;
	char *copy_start, *hdr_path = NULL, *lp_url = NULL;
	bool need_slash = false;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL init failed");
		goto out;
	}

start:
	hdr_path = (char*) tq_pop(mythr->q, NULL);
	if (!hdr_path)
		goto out;

	/* full URL */
	if (strstr(hdr_path, "://")) {
		lp_url = hdr_path;
		hdr_path = NULL;
	}

	/* absolute path, on current server */
	else {
		copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
		if (rpc_url[strlen(rpc_url) - 1] != '/')
			need_slash = true;

		lp_url = (char*) malloc(strlen(rpc_url) + strlen(copy_start) + 2);
		if (!lp_url)
			goto out;

		sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
	}

	if (!opt_quiet)
		applog(LOG_BLUE, "Long-polling on %s", lp_url);

	while (1) {
		json_t *val;
		char *req = NULL;
		int err;

		if (jsonrpc_2) {
			char s[128];
			pthread_mutex_lock(&rpc2_login_lock);
			if (!strlen(rpc2_id)) {
				sleep(1);
				continue;
			}
			snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
			pthread_mutex_unlock(&rpc2_login_lock);
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, &err, JSON_RPC_LONGPOLL);
		} else {
			if (have_gbt) {
				req = (char*) malloc(strlen(gbt_lp_req) + strlen(lp_id) + 1);
				sprintf(req, gbt_lp_req, lp_id);
			}
			val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, JSON_RPC_LONGPOLL);
			val = json_rpc_call(curl, lp_url, rpc_userpass,
					    req ? req : getwork_req, &err,
					    JSON_RPC_LONGPOLL);
			free(req);
		}

		if (have_stratum) {
			if (val)
				json_decref(val);
			goto out;
		}
		if (likely(val)) {
			bool rc;
			char *start_job_id;
			double start_diff = 0.0;
			json_t *res, *soval;
			res = json_object_get(val, "result");
			if (!jsonrpc_2) {
				soval = json_object_get(res, "submitold");
				submit_old = soval ? json_is_true(soval) : false;
			}
			pthread_mutex_lock(&g_work_lock);
			start_job_id = g_work.job_id ? strdup(g_work.job_id) : NULL;
			if (have_gbt) {
			  printf("do gbt work decode par longpoll\n");
			  lp = true;
			  rc = gbt_work_decode(res, &g_work, false);
			}
			else {
			  rc = work_decode(res, &g_work);
			}
			if (rc) {
				bool newblock = g_work.job_id && strcmp(start_job_id, g_work.job_id);
				newblock |= (start_diff != net_diff); // the best is the height but... longpoll...
				if (newblock) {
					start_diff = net_diff;
					if (!opt_quiet) {
						char netinfo[64] = { 0 };
						if (net_diff > 0.) {
							sprintf(netinfo, ", diff %.3f", net_diff);
						}
						if (opt_showdiff)
							sprintf(&netinfo[strlen(netinfo)], ", target %.3f", g_work.targetdiff);
						applog(LOG_BLUE, "%s detected new block%s", short_url, netinfo);
					}
					time(&g_work_time);
					restart_threads();
				}
			}
			free(start_job_id);
			pthread_mutex_unlock(&g_work_lock);
			json_decref(val);
		} else {
			pthread_mutex_lock(&g_work_lock);
			g_work_time -= LP_SCANTIME;
			pthread_mutex_unlock(&g_work_lock);
			if (err == CURLE_OPERATION_TIMEDOUT) {
				restart_threads();
			} else {
				have_longpoll = false;
				restart_threads();
				free(hdr_path);
				free(lp_url);
				lp_url = NULL;
				sleep(opt_fail_pause);
				goto start;
			}
		}
	}

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;
	bool valid = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val))
		goto out;

	if (jsonrpc_2)
	{
		if (!res_val && !err_val)
			goto out;

		json_t *status = json_object_get(res_val, "status");
		if(status) {
			const char *s = json_string_value(status);
			valid = !strcmp(s, "OK") && json_is_null(err_val);
		} else {
			valid = json_is_null(err_val);
		}
		share_result(valid, NULL, err_val ? json_string_value(err_val) : NULL);

	} else {

		if (!res_val || json_integer_value(id_val) < 4)
			goto out;
		valid = json_is_true(res_val);
		share_result(valid, NULL, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);
	}

	ret = true;

out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	char *s;

	stratum.url = (char*) tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

	while (1) {
		int failures = 0;

		if (stratum_need_reset) {
			stratum_need_reset = false;
			stratum_disconnect(&stratum);
			if (strcmp(stratum.url, rpc_url)) {
				free(stratum.url);
				stratum.url = strdup(rpc_url);
				applog(LOG_BLUE, "Connection changed to %s", short_url);
			} else if (!opt_quiet) {
				applog(LOG_DEBUG, "Stratum connection reset");
			}
		}

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url)
					|| !stratum_subscribe(&stratum)
					|| !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				if (!opt_benchmark)
					applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}

			if (jsonrpc_2) {
				work_free(&g_work);
				work_copy(&g_work, &stratum.work);
			}
		}

		if (stratum.job.job_id &&
			(!g_work_time || strcmp(stratum.job.job_id, g_work.job_id)) )
		{
			pthread_mutex_lock(&g_work_lock);
			stratum_gen_work(&stratum, &g_work);
			time(&g_work_time);
			pthread_mutex_unlock(&g_work_lock);

			if (stratum.job.clean || jsonrpc_2) {
				static uint32_t last_bloc_height;
				if (!opt_quiet && last_bloc_height != stratum.bloc_height) {
					last_bloc_height = stratum.bloc_height;
					if (net_diff > 0.)
						applog(LOG_BLUE, "%s block %d, diff %.3f", algo_names[opt_algo],
							stratum.bloc_height, net_diff);
					else
						applog(LOG_BLUE, "%s %s block %d", short_url, algo_names[opt_algo],
							stratum.bloc_height);
				}
				restart_threads();
			} else if (opt_debug && !opt_quiet) {
					applog(LOG_BLUE, "%s asks job %lu for block %d", short_url,
						strtoul(stratum.job.job_id, NULL, 16), stratum.bloc_height);
			}
		}

		if (!stratum_socket_full(&stratum, opt_timeout)) {
			applog(LOG_ERR, "Stratum connection timeout");
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		free(s);
	}
out:
	return NULL;
}

static void show_version_and_exit(void)
{
	printf(" built "
#ifdef _MSC_VER
	 "with VC++ %d", msver());
#elif defined(__GNUC__)
	 "with GCC ");
	printf("%d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
	printf(" the " __DATE__ "\n");

	// Note: if compiled with cpu opts (instruction sets),
	// the binary is no more compatible with older ones!
	printf(" compiled for"
#if defined(__ARM_NEON__)
		" ARM NEON"
#elif defined(__AVX2__)
		" AVX2"
#elif defined(__AVX__)
		" AVX"
#elif defined(__XOP__)
		" XOP"
#elif defined(__SSE4_1__)
		" SSE4"
#elif defined(_M_X64) || defined(__x86_64__)
		" x64"
#elif defined(_M_IX86) || defined(__x86__)
		" x86"
#else
		" general use"
#endif
		"\n");

	printf(" config features:"
#if defined(USE_ASM) && defined(__i386__)
		" i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
		" x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
		" SSE2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
		" XOP"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
		" AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
		" AVX2"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
		" ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
		" ARMv5E"
#endif
#if defined(__ARM_NEON__)
		" NEON"
#endif
#endif
		"\n\n");
	/* dependencies versions */
	printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
	printf("jansson/%s ", JANSSON_VERSION);
#endif
#ifdef PTW32_VERSION
	printf("pthreads/%d.%d.%d.%d ", PTW32_VERSION);
#endif
	printf("\n");
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

void parse_arg(int key, char *arg)
{
	char *p;
	int v, i;
	uint64_t ul;
	double d;

	switch(key) {
	case 'a':
		for (i = 0; i < ALGO_COUNT; i++) {
			v = (int) strlen(algo_names[i]);
			if (v && !strncasecmp(arg, algo_names[i], v)) {
				if (arg[v] == '\0') {
					opt_algo = (enum algos) i;
					break;
				}
				if (arg[v] == ':') {
					char *ep;
					v = strtol(arg+v+1, &ep, 10);
					if (*ep || (i == ALGO_SCRYPT && v & (v-1)) || v < 2)
						continue;
					opt_algo = (enum algos) i;
					opt_scrypt_n = v;
					break;
				}
			}
		}

		if (i == ALGO_COUNT) {

			if (strstr(arg, ":")) {
				// pick and strip the optional factor
				char *nf = strstr(arg, ":");
				opt_scrypt_n = strtol(&nf[1], NULL, 10);
				*nf = '\0';
			}

			// some aliases...
			if (!strcasecmp("blake2", arg))
				i = opt_algo = ALGO_BLAKE2S;
			else if (!strcasecmp("cryptonight-light", arg))
				i = opt_algo = ALGO_CRYPTOLIGHT;
			else if (!strcasecmp("flax", arg))
				i = opt_algo = ALGO_C11;
			else if (!strcasecmp("diamond", arg))
				i = opt_algo = ALGO_DMD_GR;
			else if (!strcasecmp("droplp", arg))
				i = opt_algo = ALGO_DROP;
			else if (!strcasecmp("jackpot", arg))
				i = opt_algo = ALGO_JHA;
			else if (!strcasecmp("lyra2", arg))
				i = opt_algo = ALGO_LYRA2;
			else if (!strcasecmp("lyra2v2", arg))
				i = opt_algo = ALGO_LYRA2REV2;
			else if (!strcasecmp("scryptjane", arg))
				i = opt_algo = ALGO_SCRYPTJANE;
			else if (!strcasecmp("sibcoin", arg))
				i = opt_algo = ALGO_SIB;
			else if (!strcasecmp("timetravel10", arg))
				i = opt_algo = ALGO_BITCORE;
			else if (!strcasecmp("ziftr", arg))
				i = opt_algo = ALGO_ZR5;
			else
				applog(LOG_ERR, "Unknown algo parameter '%s'", arg);
		}
		if (i == ALGO_COUNT) {
			show_usage_and_exit(1);
		}
		if (!opt_nfactor && opt_algo == ALGO_SCRYPT)
			opt_nfactor = 9;
		if (opt_algo == ALGO_SCRYPTJANE && opt_scrypt_n == 0)
			opt_scrypt_n = 5;
		break;
	case 'b':
		p = strstr(arg, ":");
		if (p) {
			/* ip:port */
			if (p - arg > 0) {
				free(opt_api_allow);
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if (arg && strstr(arg, ".")) {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
		}
		else if (arg) {
			/* port or 0 to disable */
			opt_api_listen = atoi(arg);
		}
		break;
	case 1030: /* --api-remote */
		opt_api_remote = 1;
		break;
	case 'n':
		if (opt_algo == ALGO_NEOSCRYPT) {
			v = atoi(arg);
			/* Nfactor = lb(N) - 1; N = (1 << (Nfactor + 1)) */
			if ((v < 0) || (v > 30)) {
				fprintf(stderr, "incorrect Nfactor %d\n", v);
				show_usage_and_exit(1);
			}
			opt_nfactor = v;
		}
		break;
	case 'B':
		opt_background = true;
		use_colors = false;
		break;
	case 'c': {
		json_error_t err;
		json_t *config;
		if (arg && strstr(arg, "://")) {
			config = json_load_url(arg, &err);
		} else {
			config = JSON_LOADF(arg, &err);
		}
		if (!json_is_object(config)) {
			if (err.line < 0)
				fprintf(stderr, "%s\n", err.text);
			else
				fprintf(stderr, "%s:%d: %s\n",
					arg, err.line, err.text);
		} else {
			parse_config(config, arg);
			json_decref(config);
		}
		break;
	}
	case 'C':
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999) /* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = (char*) calloc(p - ap + 1, 1);
				strncpy(rpc_user, ap, p - ap);
				free(rpc_pass);
				rpc_pass = strdup(++p);
				if (*p) *p++ = 'x';
				v = (int) strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "http://", 7) &&
			    strncasecmp(arg, "https://", 8) &&
			    strncasecmp(arg, "stratum+tcp://", 14)) {
				fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
			short_url = &rpc_url[ap - arg];
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "invalid URL -- '%s'\n",
					arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = (char*) malloc(strlen(hp) + 8);
			sprintf(rpc_url, "http://%s", hp);
			short_url = &rpc_url[sizeof("http://")-1];
		}
		have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
		break;
	}
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = (char*) calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(++p);
		strhide(p);
		break;
	case 'U': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass_aux);
				rpc_userpass_aux = strdup(ap);
				if (*p) *p++ = 'x';
				v = (int) strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "http://", 7) &&
			    strncasecmp(arg, "https://", 8) &&
			    strncasecmp(arg, "stratum+tcp://", 14)) {
				fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url_aux);
			rpc_url_aux = strdup(arg);
			strcpy(rpc_url_aux + (ap - arg), hp);
			short_url = &rpc_url_aux[ap - arg];
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "invalid URL -- '%s'\n",
					arg);
				show_usage_and_exit(1);
			}
			free(rpc_url_aux);
			rpc_url_aux = (char*) malloc(strlen(hp) + 8);
			sprintf(rpc_url_aux, "http://%s", hp);
			short_url = &rpc_url[sizeof("http://")-1];
		}
		have_stratum = !opt_benchmark && !strncasecmp(rpc_url_aux, "stratum", 7);
		break;
	}
	case 'A':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		free(rpc_userpass_aux);
		rpc_userpass_aux = strdup(arg);
		//free(rpc_user);
		strhide(p);
		break;		
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:
		use_colors = false;
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1005:
		opt_benchmark = true;
		want_longpoll = false;
		want_stratum = false;
		have_stratum = false;
		break;
	case 1006:
		print_hash_tests();
		exit(0);
	case 1007:
		want_stratum = false;
		opt_extranonce = false;
		break;
	case 1008:
		opt_time_limit = atoi(arg);
		break;
	case 1009:
		opt_redirect = false;
		break;
	case 1010:
		allow_getwork = false;
		break;
	case 1011:
		have_gbt = false;
		break;
	case 1012:
		opt_extranonce = false;
		break;
	case 1013:
		opt_showdiff = true;
		break;
	case 1014:
		opt_showdiff = false;
		break;
	case 1016:			/* --coinbase-addr */
 	  if (opt_algo == ALGO_EQUIHASH) {
	    printf("have algo equihash\n");
	    //pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg, 1);
	    CURL *curl = curl_easy_init();
	    json_t* val;
	    int err;
	    char validate_req [300];
	    sprintf(validate_req,"{\"method\": \"validateaddress\", \"params\": [\"%s\"], \"id\":99}\r\n",arg);
	    val = json_rpc_call(curl, rpc_url, rpc_userpass, validate_req, &err, JSON_RPC_QUIET_404);
	    if (!val) printf("!val\n");
	    val = json_object_get(val,"result");
	    if (!val) printf("!val 2\n");
	    val = json_object_get(val,"scriptPubKey");
	    if (!val) printf("!val 3\n");
	    const char * pk_script_hex = 0;
	    if (json_is_string(val)) {
	      pk_script_hex = json_string_value(val);
	    }
	    else {
	      printf("not string\n");
	      exit(0);
	    }
	    int added = 0;
	    unsigned char* pk_script_it = pk_script;
	    pk_script_size = 0;
	    do {
	      added = sscanf(pk_script_hex+pk_script_size*2,"%2hhx",pk_script_it);
	      if (added>0) pk_script_size += added;
	      pk_script_it++;
	      //printf("pks added %c%c %d\n",*(pk_script_hex+2*pk_script_size-2*added),*(pk_script_hex+2*pk_script_size-2*added+1),added);
	    } while (added>0);
	    //printf("size of pk script = %lu\n",pk_script_size);
	    curl_easy_cleanup(curl);
	  }
	  else if (opt_algo == ALGO_CRYPTONIGHT && strlen(arg)==95) {
	    printf("copy monero address\n");
	    strcpy(monero_address,arg);
	    jsonrpc_2 = true;
	    break;
	  }
	  else {
	    pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg, 0);
	  }
		if (!pk_script_size) {
			fprintf(stderr, "invalid address -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		break;
	case 1017:
	  if (opt_algo == ALGO_EQUIHASH) {
	    printf("have algo equihash aux\n");
	    //pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg, 1);
	    CURL *curl = curl_easy_init();
	    json_t* val;
	    int err;
	    char validate_req [300];
	    sprintf(validate_req,"{\"method\": \"validateaddress\", \"params\": [\"%s\"], \"id\":98}\r\n",arg);
	    val = json_rpc_call(curl, rpc_url_aux, rpc_userpass_aux, validate_req, &err, JSON_RPC_QUIET_404);
	    if (!val) printf("!val\n");
	    val = json_object_get(val,"result");
	    if (!val) printf("!val 2\n");
	    val = json_object_get(val,"pubkey");
	    if (!val) printf("!val 3\n");
	    const char * pk_script_hex = 0;
	    if (json_is_string(val)) {
	      pk_script_hex = json_string_value(val);
	    }
	    else {
	      printf("not string\n");
	      exit(0);
	    }
	    int added = 0;
	    unsigned char* pk_script_it = pk_script_aux;
	    pk_script_aux_size = 0;
	    do {
	      added = sscanf(pk_script_hex+pk_script_aux_size*2,"%2hhx",pk_script_it);
	      if (added>0) pk_script_aux_size += added;
	      pk_script_it++;
	      //printf("pks added %c%c %d\n",*(pk_script_hex+2*pk_script_size-2*added),*(pk_script_hex+2*pk_script_size-2*added+1),added);
	    } while (added>0);
	    pk_script_aux[33] = 0xac;
	    pk_script_aux_size = 34;
	    //printf("size of pk script = %lu\n",pk_script_size);
	    curl_easy_cleanup(curl);
	  }
	  else {
	    pk_script_aux_size = address_to_script(pk_script_aux, sizeof(pk_script_aux), arg, 0);
	  }
	case 1015:			/* --coinbase-sig */
		if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
			fprintf(stderr, "coinbase signature too long\n");
			show_usage_and_exit(1);
		}
		strcpy(coinbase_sig, arg);
		break;
	case 'f':
		d = atof(arg);
		if (d == 0.)	/* --diff-factor */
			show_usage_and_exit(1);
		opt_diff_factor = d;
		break;
	case 'm':
		d = atof(arg);
		if (d == 0.)	/* --diff-multiplier */
			show_usage_and_exit(1);
		opt_diff_factor = 1.0/d;
		break;
	case 'S':
		use_syslog = true;
		use_colors = false;
		break;
	case 1019: // max-log-rate
		opt_maxlograte = atoi(arg);
		break;
	case 1020:
		p = strstr(arg, "0x");
		if (p)
			ul = strtoul(p, NULL, 16);
		else
			ul = atol(arg);
		if (ul > (1UL<<num_cpus)-1)
			ul = -1;
		opt_affinity = ul;
		break;
	case 1021:
		v = atoi(arg);
		if (v < 0 || v > 5)	/* sanity check */
			show_usage_and_exit(1);
		opt_priority = v;
		break;
	case 1060: // max-temp
		d = atof(arg);
		opt_max_temp = d;
		break;
	case 1061: // max-diff
		d = atof(arg);
		opt_max_diff = d;
		break;
	case 1062: // max-rate
		d = atof(arg);
		p = strstr(arg, "K");
		if (p) d *= 1e3;
		p = strstr(arg, "M");
		if (p) d *= 1e6;
		p = strstr(arg, "G");
		if (p) d *= 1e9;
		opt_max_rate = d;
		break;
	case 1024:
		opt_randomize = true;
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

void parse_config(json_t *config, char *ref)
{
	int i;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;
		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int)json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
			options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		proper_exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		proper_exit(0);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
		applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
		proper_exit(0);
		break;
	case CTRL_BREAK_EVENT:
		applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
		proper_exit(0);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int thread_create(struct thr_info *thr, void* func)
{
	int err = 0;
	pthread_attr_init(&thr->attr);
	err = pthread_create(&thr->pth, &thr->attr, func, thr);
	pthread_attr_destroy(&thr->attr);
	return err;
}

static void show_credits()
{
	printf("** " PACKAGE_NAME " " PACKAGE_VERSION " by tpruvot@github **\n");
	printf("BTC donation address: 1FhDPLPpw18X4srecguG3MxJYe4a1JsZnd (tpruvot)\n\n");
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

int main(int argc, char *argv[]) {
	struct thr_info *thr;
	long flags;
	int i, err;

	pthread_mutex_init(&applog_lock, NULL);

	show_credits();

	rpc_user = strdup("");
	rpc_pass = strdup("");
	opt_api_allow = strdup("127.0.0.1"); /* 0.0.0.0 for all ips */

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif
	if (num_cpus < 1)
		num_cpus = 1;

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!opt_benchmark && !rpc_url) {
		// try default config file in binary folder
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig)) {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
	}

	if (!opt_n_threads)
		opt_n_threads = num_cpus;
	if (!opt_n_threads)
		opt_n_threads = 1;

	if (opt_algo == ALGO_QUARK) {
		init_quarkhash_contexts();
	} else if(opt_algo == ALGO_CRYPTONIGHT || opt_algo == ALGO_CRYPTOLIGHT) {
	  //jsonrpc_2 = true;
	  opt_extranonce = false;
		aes_ni_supported = has_aes_ni();
		if (!opt_quiet) {
			applog(LOG_INFO, "Using JSON-RPC 2.0");
			applog(LOG_INFO, "CPU Supports AES-NI: %s", aes_ni_supported ? "YES" : "NO");
		}
	} else if(opt_algo == ALGO_DECRED || opt_algo == ALGO_SIA) {
		have_gbt = false;
	}

	if (!opt_benchmark && !rpc_url) {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
	}

	if (!rpc_userpass) {
		rpc_userpass = (char*) malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&rpc2_job_lock, NULL);
	pthread_mutex_init(&rpc2_login_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

	flags = !opt_benchmark && strncmp(rpc_url, "https:", 6)
	        ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	        : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

#ifndef WIN32
	if (opt_background) {
		i = fork();
		if (i < 0) exit(1);
		if (i > 0) exit(0);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
		signal(SIGHUP, signal_handler);
		signal(SIGTERM, signal_handler);
	}
	/* Always catch Ctrl+C */
	signal(SIGINT, signal_handler);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// this method also hide parent command line window
			ShowWindow(hcon, SW_HIDE);
		} else {
			HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
			CloseHandle(h);
			FreeConsole();
		}
	}
	if (opt_priority > 0) {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority) {
		case 1:
			prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
		case 3:
			prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		case 4:
			prio = HIGH_PRIORITY_CLASS;
			break;
		case 5:
			prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
#endif
	if (opt_affinity != -1) {
		if (!opt_quiet)
			applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
		affine_to_cpu_mask(-1, (unsigned long)opt_affinity);
	}

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif

	work_restart = (struct work_restart*) calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = (struct thr_info*) calloc(opt_n_threads + 4, sizeof(*thr));
	if (!thr_info)
		return 1;

	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	if (rpc_pass && rpc_user)
		opt_stratum_stats = (strstr(rpc_pass, "stats") != NULL) || (strcmp(rpc_user, "benchmark") == 0);

	/* start work I/O thread */
	if (thread_create(thr, workio_thread)) {
		applog(LOG_ERR, "work thread create failed");
		return 1;
	}

	/* ESET-NOD32 Detects these 2 thread_create... */
	if (want_longpoll && !have_stratum) {
		/* init longpoll thread info */
		longpoll_thr_id = opt_n_threads + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start longpoll thread */
		err = thread_create(thr, longpoll_thread);
		if (err) {
			applog(LOG_ERR, "long poll thread create failed");
			return 1;
		}
	}
	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = opt_n_threads + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start stratum thread */
		err = thread_create(thr, stratum_thread);
		if (err) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}
		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}

	if (opt_api_listen) {
	  printf("start api thread\n");
		/* api thread */
		api_thr_id = opt_n_threads + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create(thr, api_thread);
		if (err) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
	}

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		err = thread_create(thr, miner_thread);
		if (err) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started, "
		"using '%s' algorithm.",
		opt_n_threads,
		algo_names[opt_algo]);

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);

	applog(LOG_WARNING, "workio thread dead, exiting.");

	return 0;
}
