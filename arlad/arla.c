/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Test to talk with FS
 */

#include "arla_local.h"
#include <parse_units.h>
#include <getarg.h>

RCSID("$Id: arla.c,v 1.177 2007/03/02 15:39:26 abo Exp $") ;

enum connected_mode connected_mode = CONNECTED;

static void
initrx (int userport)
{
    int port = userport;
    int error;

    if (port == 0)
	port = afscallbackport;

    error = rx_Init (htons(port));
    if (error == RX_ADDRINUSE && userport == 0)
	error = rx_Init(0);
    if (error)
	arla_err (1, ADEBERROR, error, "rx_init");
}


void
store_state (void)
{
    arla_warnx (ADEBMISC, "storing state");
    fcache_store_state ();
    volcache_store_state ();
    cm_store_state ();
}

typedef enum { CONF_PARAM_INT, 
	       CONF_PARAM_STR,
	       CONF_PARAM_BOOL,
	       CONF_PARAM_INT64
} conf_type;

struct conf_param {
    const char *name;
    conf_type type;
    void *val;
};

/*
 * Reads in a configuration file, and sets some defaults.
 */

static struct units size_units[] = {
    { "G", 1024 * 1024 * 1024 },
    { "M", 1024 * 1024 },
    { "k", 1024 },
    { NULL, 0 }
};

static void
read_conffile(const char *fname,
	      struct conf_param *params)
{
    FILE *fp;
    char buf[256];
    int lineno;
    struct conf_param *p;

    arla_warnx (ADEBINIT, "read_conffile: %s", fname);

    fp = fopen(fname, "r");
    if (fp == NULL) {
	arla_warn (ADEBINIT, errno, "open %s", fname);
	return;
    }

    lineno = 0;

    while (fgets (buf, sizeof(buf), fp) != NULL) {
	struct conf_param *partial_param = NULL;
	int partial_match = 0;
	char *save = NULL;
	char *n;
	char *v;
	int64_t val;
	char *endptr;

	++lineno;
	buf[strcspn(buf, "\n")] = '\0';
	if (buf[0] == '\0' || buf[0] == '#')
	    continue;

	n = strtok_r (buf, " \t", &save);
	if (n == NULL) {
	    fprintf (stderr, "%s:%d: no parameter?\n", fname, lineno);
	    continue;
	}

	v = strtok_r (NULL, " \t", &save);
	if (v == NULL) {
	    fprintf (stderr, "%s:%d: no value?\n", fname, lineno);
	    continue;
	}

    
	for (p = params; p->name; ++p) {
	    if (strcmp(n, p->name) == 0) {
		partial_match = 1;
		partial_param = p;
		break;
	    } else if(strncmp(n, p->name, strlen(n)) == 0) {
		++partial_match;
		partial_param = p;
	    }
	}
	if (partial_match == 0) {
	    fprintf (stderr, "%s:%d: unknown parameter `%s'\n",
		     fname, lineno, n);
	    continue;
	} else if (partial_match != 1) {
	    fprintf (stderr, "%s:%d: ambiguous parameter `%s'\n",
		     fname, lineno, n);
	    continue;
	}

	p = partial_param;

	switch (p->type) {
	case CONF_PARAM_INT:
	case CONF_PARAM_INT64:

	    /* parse_units is currently broken, so we roll our own for now */

#ifdef HAVE_STRTOLL
	    val = strtoll(v, &endptr, 0);
#else
	    val = strtol(v, &endptr, 0);
#endif

	    if (*endptr != '\0') {
		struct units *u = size_units;

		while (u->name != NULL) {
		    if (!strcmp(endptr, u->name)) {
			val *= u->mult;
			break;
		    }
		    u++;
		}

		if (u->name == NULL)
		    fprintf (stderr, "%s:%d: bad value `%s'\n",
			     fname, lineno, v);
	    }

	    if (p->type == CONF_PARAM_INT)
		    *((unsigned *)partial_param->val) = val;
	    else if (p->type == CONF_PARAM_INT64)
		    *((int64_t *)partial_param->val) = val;
	    else
		    abort();
	    break;

	case CONF_PARAM_STR:

	    *((char **)partial_param->val) = strdup(v);
	    
	    break;

	case CONF_PARAM_BOOL:

	    if (strcasecmp(v, "yes") == 0 || strcasecmp(v, "true") == 0)
		*((unsigned *)partial_param->val) = 1;
	    else if (strcasecmp(v, "no") == 0 || strcasecmp(v, "false") == 0)
		*((unsigned *)partial_param->val) = 0;
	    else
		fprintf (stderr, "%s:%d: bad boolean value `%s'\n",
			 fname, lineno, v);
	    break;
	default:
	    abort();
	}



    }
    fclose(fp);
}

static unsigned low_vnodes	= ARLA_LOW_VNODES;
static unsigned high_vnodes	= ARLA_HIGH_VNODES;
static int64_t low_bytes	= ARLA_LOW_BYTES;
static int64_t high_bytes	= ARLA_HIGH_BYTES;
static uint64_t blocksize 	= ARLA_BLOCKSIZE;
static unsigned numcreds	= ARLA_NUMCREDS;
static unsigned numconns	= ARLA_NUMCONNS;
static unsigned numvols		= ARLA_NUMVOLS;
static unsigned dynrootlevel	= DYNROOT_DEFAULT;
static char *conf_sysname	= NULL;	/* sysname from conf file */
const char *argv_sysname	= NULL; /* sysname from argv */
int nnpfs_trace = 0;
int num_workers = 16;
#ifdef KERBEROS
const char *rxkad_level_string = "crypt";
#endif

static struct conf_param conf_params[] = {
    {"dynroot",			CONF_PARAM_BOOL,	&dynrootlevel},
    {"fake_stat",		CONF_PARAM_BOOL,	&fake_stat},
    {"fake_mp",			CONF_PARAM_BOOL,	&fake_mp},
    {"fetch_block",		CONF_PARAM_INT64,	&fetch_block_size},
    {"blocksize",		CONF_PARAM_INT64,	&blocksize},
    {"low_vnodes",		CONF_PARAM_INT,		&low_vnodes},
    {"high_vnodes",		CONF_PARAM_INT,		&high_vnodes},
    {"low_bytes",		CONF_PARAM_INT64,	&low_bytes},
    {"high_bytes",		CONF_PARAM_INT64,	&high_bytes},
    {"numcreds",		CONF_PARAM_INT,		&numcreds},
    {"numconns",		CONF_PARAM_INT,		&numconns},
    {"numvols",			CONF_PARAM_INT,		&numvols},
    {"sysname",			CONF_PARAM_STR,		&conf_sysname},
    {"workers",			CONF_PARAM_INT,		&num_workers},
    {"nnpfs_trace",		CONF_PARAM_BOOL,	&nnpfs_trace},
    {"nnpfs_trace_file",	CONF_PARAM_STR,		&trace_file},
#ifdef KERBEROS
    {"rxkad-level",		CONF_PARAM_STR,		&rxkad_level_string},
#endif
    { NULL }
};

const char *conf_file = ARLACONFFILE;
char *log_file  = NULL;
char *debug_levels = NULL;
char *connected_mode_string = NULL;
char *root_volume;
int cpu_usage;
int version_flag;
int help_flag;
int recover = 0;
int dynroot_enable = 0;
int cm_consistency = 0;
int fake_stat = 0;

/*
 * These are exported to other modules
 */

char *cache_dir;
int fake_mp;
int fork_flag = 1;
int use_o_largefile = 1;
char *trace_file = "arla.trace";

/*
 * Global AFS variables, se arla_local.h for comment
 */

int afs_BusyWaitPeriod = 15;

/*
 *
 */

static int
parse_string_list (const char *s, const char **units)
{
    const char **p;
    int partial_val = 0;
    int partial_match = 0;
    
    for (p = units; *p; ++p) {
	if (strcmp (s, *p) == 0)
	    return p - units;
	if (strncmp (s, *p, strlen(s)) == 0) {
	    partial_match++;
	    partial_val = p - units;
	}
    }
    if (partial_match == 1)
	return partial_val;
    else
	return -1;
}

#ifdef KERBEROS
static const char *rxkad_level_units[] = {
"clear",			/* 0 */
"auth",				/* 1 */
"crypt",			/* 2 */
NULL
};

static int
parse_rxkad_level (const char *s)
{
    return parse_string_list (s, rxkad_level_units);
}
#endif

static const char *connected_levels[] = {
"connected",			/* CONNECTED   = 0 */
"fetch-only",			/* FETCH_ONLY  = 1 */
"disconnected",			/* DISCONNCTED = 2 */
NULL
};

static int
set_connected_mode (const char *s)
{
    return parse_string_list (s, connected_levels);
}

/*
 *
 */

int
arla_init (void)
{
    log_flags log_flags;
    char fpriofile[MAXPATHLEN];
    const char *temp_sysname;

    if (log_file == NULL)
	log_file = default_log_file;

    if (strcmp(log_file, "syslog") == 0)
	log_file = "syslog:no-delay";

    log_flags = 0;
    if (cpu_usage)
	log_flags |= LOG_CPU_USAGE;
    arla_loginit(log_file, log_flags);
     
    if (debug_levels != NULL) {
	if (arla_log_set_level (debug_levels) < 0) {
	    warnx ("bad debug levels: `%s'", debug_levels);
	    arla_log_print_levels (stderr);
	    exit (1);
	}
    }

    if (connected_mode_string != NULL) {
	int tmp = set_connected_mode (connected_mode_string);

	if (tmp < 0)
	    errx (1, "bad connected mode: `%s'", connected_mode_string);
	connected_mode = tmp;
	if (connected_mode != CONNECTED)
	    disco_openlog();
    }

    read_conffile(conf_file, conf_params);

    if (low_vnodes > high_vnodes)
	arla_errx (1, ADEBERROR, "low vnode is larger then high vnodes, "
		   "cowardly refusing to start (%d > %d) "
		   "(check BUGS section in arla.conf manual page)",
		   low_vnodes, high_vnodes);
    if (low_bytes > high_bytes)
	arla_errx (1, ADEBERROR, "low bytes is larger then high bytes, "
		   "cowardly refusing to start "
		   "(check BUGS section in arla.conf manual page)");


#ifdef KERBEROS
    conn_rxkad_level = parse_rxkad_level (rxkad_level_string);
    if (conn_rxkad_level < 0)
	errx (1, "bad rxkad level `%s'", rxkad_level_string);
#endif

    if (cache_dir == NULL)
	cache_dir = get_default_cache_dir();

    if (mkdir (cache_dir, 0777) < 0 && errno != EEXIST)
	arla_err (1, ADEBERROR, errno, "mkdir %s", cache_dir);
    if (chdir (cache_dir) < 0)
	arla_err (1, ADEBERROR, errno, "chdir %s", cache_dir);


    if (argv_sysname)
	temp_sysname = argv_sysname;
    else if (conf_sysname)
	temp_sysname = conf_sysname;
    else
	temp_sysname = arla_getsysname ();

    if (temp_sysname != NULL)
	fcache_setdefsysname(temp_sysname);

    if (dynrootlevel || dynroot_enable)
	dynroot_setenable (TRUE);

    if (!nnpfs_trace)
	trace_file = NULL;


    snprintf(fpriofile, sizeof(fpriofile), "%s/%s", cache_dir, "fprio");

    /*
     * Init
     */ 

    arla_warnx (ADEBINIT,"Arlad booting sequence:");
    arla_warnx (ADEBINIT, "connected mode: %s",
		connected_levels[connected_mode]);
    arla_warnx (ADEBINIT, "ports_init");
    ports_init ();
    arla_warnx (ADEBINIT, "uae_init");
    uae_init ();
    arla_warnx (ADEBINIT, "rx");
    initrx (client_port);
    arla_warnx (ADEBINIT, "conn_init numconns = %u", numconns);
    conn_init (numconns);
    arla_warnx (ADEBINIT, "cellcache");
    cell_init (0, arla_log_method);
    arla_warnx (ADEBINIT, "poller");
    poller_init();
    arla_warnx (ADEBINIT, "fprio");
    fprio_init(fpriofile);
    arla_warnx (ADEBINIT, "volcache numvols = %u", numvols);
    volcache_init (numvols, recover);
    if (root_volume != NULL)
	volcache_set_rootvolume (root_volume);
#ifdef KERBEROS
    arla_warnx (ADEBINIT, "using rxkad level %s",
		rxkad_level_units[conn_rxkad_level]);
#endif

    /*
     * Credential cache
     */
    arla_warnx (ADEBINIT, "credcache numcreds = %u", numcreds);
    cred_init (numcreds);

    arla_warnx (ADEBINIT,
		"fcache low_vnodes = %u, high_vnodes = %u "
		"low_bytes = %lld, high_bytes = %lld",
		low_vnodes, high_vnodes,
		(long long)low_bytes, (long long)high_bytes);
    fcache_init (low_vnodes, high_vnodes,
		 low_bytes, high_bytes, blocksize, recover);

    arla_warnx (ADEBINIT, "cmcb");
    cmcb_init ();

    arla_warnx(ADEBINIT, "cm");
    cm_init ();

    if (cm_consistency) {
	arla_warnx(ADEBINIT, "turning on consistency test");
	cm_turn_on_consistency_check();
    }

    arla_warnx(ADEBINIT, "arla init done.");

    return 0;
}
