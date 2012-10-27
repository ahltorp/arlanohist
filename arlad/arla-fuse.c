/*
 * Copyright (c) 1995 - 2007 Kungliga Tekniska Högskolan
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

#include <arla_local.h>
#include <sl.h>
#include <getarg.h>
#include <vers.h>
#include <arlalib.h>
#include <pts.cs.h>


#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>

#include "lsprint.h"

RCSID("$Id: arla-fuse.c,v 1.1 2007/11/05 21:28:57 tol Exp $");

char *default_log_file = "/dev/stderr";
char *default_arla_cachedir = ".arlacache";
int client_port = 4712;


/* creds used for all the interactive usage */

static VenusFid cwd;
static VenusFid rootcwd;

static Hashtab *ptscache;

struct ptscache_entry {
    int32_t cell;
    int32_t id;
    char *name;
};

static int
ptscachecmp (void *a, void *b)
{
    struct ptscache_entry *e1 = (struct ptscache_entry *)a;
    struct ptscache_entry *e2 = (struct ptscache_entry *)b;
    
    return e1->id != e2->id ||
	e1->cell != e2->cell;
}

static unsigned
ptscachehash (void *a)
{
    struct ptscache_entry *e = (struct ptscache_entry *)a;
    
    return e->id + e->cell;
}

/*
 *
 */

static void
arla_start(char *device_file, const char *cache_dir)
{
    int error;

    {
	struct cred_rxkad cred;
	struct ClearToken ct;

	error = arlalib_getcred(cell_getthiscell(), &ct,
				cred.ticket, sizeof(cred.ticket),
				&cred.ticket_len);

	cred.ct.AuthHandle = ct.AuthHandle;
	memcpy(&cred.ct.HandShakeKey, &ct.HandShakeKey, sizeof(ct.HandShakeKey));
	cred.ct.ViceId = ct.ViceId;
	cred.ct.BeginTimestamp = ct.BeginTimestamp;
	cred.ct.EndTimestamp = ct.EndTimestamp;

	if (error) {
	    arla_warn(ADEBERROR, error, "arlalib_getcred");
	} else {
	    cred_add (getuid(), CRED_KRB4, 2, cell_name2num(cell_getthiscell()),
		      cred.ct.EndTimestamp,
		      &cred, sizeof(cred), cred.ct.ViceId);
	
	}
    }
    
    CredCacheEntry *ce;
    ce = cred_get (cell_name2num(cell_getthiscell()), getuid(), CRED_ANY);

    assert (ce != NULL);

    ptscache = hashtabnewf (0, ptscachecmp, ptscachehash, HASHTAB_GROW);
    if (ptscache == NULL)
	arla_errx (1, ADEBERROR, "arla_start: hashtabnewf failed");
    
    nnpfs_message_init ();
    kernel_opendevice ("null");
    
    arla_warnx (ADEBINIT, "Getting root...");
    error = getroot (&rootcwd, ce);
    if (error)
	    arla_err (1, ADEBERROR, error, "getroot");
    cred_free(ce);
    cwd = rootcwd;
    error = 0;
}

static void
arla_stop(void)
{
    store_state();
    fcache_giveup_all_callbacks();
}

char *
get_default_cache_dir (void)
{
    static char cache_path[MAXPATHLEN];
    char *home;

    home = getenv("HOME");
    if (home == NULL)
	home = "/var/tmp";

    snprintf (cache_path, sizeof(cache_path), "%s/.arla-cache",
	      home);
    return cache_path;
}

static int
getentry(const char *path, FCacheEntry **entry, CredCacheEntry **ce)
{
    int error;
    VenusFid fid;

    error = cm_walk(rootcwd, path, &fid);
    if (error) {
	printf("cm_walk: %s\n", koerr_gettext(error));
	return -EIO; /* XXX */
    }

    *ce = cred_get(fid.Cell, getuid() /* XXX */, CRED_ANY);
    error = fcache_get(entry, fid, *ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	cred_free(*ce);
	return -EIO; /* XXX */
    }
    return 0;
}

/*
 * FCacheEntry -> struct stat
 */

static void
entry2stat(FCacheEntry *entry, struct stat *stbuf)
{
    AFSFetchStatus *status = &entry->status;
    int mode;

    switch (status->FileType) {
    case TYPE_FILE :
	mode = S_IFREG;
	break;
    case TYPE_DIR :
	mode = S_IFDIR;
	break;
    case TYPE_LINK :
	mode = S_IFLNK;
	break;
    default :
	arla_warnx(ADEBMSG, "afsstatus2stat: default");
	abort();
    }
    stbuf->st_nlink = status->LinkCount;
    stbuf->st_size = fcache_get_status_length(status);
    stbuf->st_uid = status->Owner;
    stbuf->st_gid = status->Group;
    stbuf->st_atime = status->ClientModTime;
    stbuf->st_mtime = status->ClientModTime;
    stbuf->st_ctime = status->ClientModTime;
    stbuf->st_ino = afsfid2inode(&entry->fid);

    /* XXX this is wrong, need to keep track of `our` ae for this req */
    if (fake_stat) {
	nnpfs_rights rights;
	
	rights = afsrights2nnpfsrights(status->CallerAccess,
				       status->FileType,
				       status->UnixModeBits);
	
	if (rights & NNPFS_RIGHT_R)
	    mode |= 0444;
	if (rights & NNPFS_RIGHT_W)
	    mode |= 0222;
	if (rights & NNPFS_RIGHT_X)
	    mode |= 0111;
    } else
	mode |= status->UnixModeBits;

    stbuf->st_mode = mode;
}

static int
arla_getattr(const char *path, struct stat *stbuf)
{
    int error;
    FCacheEntry *entry;
    CredCacheEntry *ce;

    /* printf("getattr(%s)\n", path); */

    error = getentry(path, &entry, &ce);
    if (error)
	return error;

    error = cm_getattr(entry, ce);
    if (error) {
	fcache_release(entry);
	printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return -EIO; /* XXX */
    }
    
    memset(stbuf, 0, sizeof(struct stat));
    entry2stat(entry, stbuf);

    fcache_release(entry);
    cred_free(ce);

    return 0;
}

struct readdir_context {
    fuse_fill_dir_t filler;
    void *buf;
};

static int
readdir_func(VenusFid *fid, const char *name, void *v)
{
    struct readdir_context *context = (struct readdir_context *)v;

    return context->filler(context->buf, name, NULL, 0);
}

static int
arla_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	     off_t offset, struct fuse_file_info *fi)
{
    int error;
    FCacheEntry *entry;
    CredCacheEntry *ce;
    struct readdir_context context;

    /* printf("readdir(%s)\n", path); */

    error = getentry(path, &entry, &ce);
    if (error)
	return error;

    error = cm_getattr(entry, ce);
    if (error) {
	fcache_release(entry);
	printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return -EIO;
    }
    
    if (entry->status.FileType != TYPE_DIR) {
	fcache_release(entry);
	printf("readdir: not a directory\n");
	cred_free(ce);
	return -EISDIR;
    }

    context.filler = filler;
    context.buf = buf;
    error = adir_readdir(&entry, readdir_func, &context, &ce);

    fcache_release(entry);
    cred_free(ce);

    if (error) {
	printf ("adir_readdir failed: %s\n", koerr_gettext(error));
	return -EIO;
    }

    return 0;
}

static int
arla_open(const char *path, struct fuse_file_info *fi)
{
    /* printf("open(%s)\n", path); */
    return 0;
}

static int
arla_read(const char *path, char *buf, size_t size, off_t offset,
	  struct fuse_file_info *fi)
{
    FCacheEntry *entry;
    CredCacheEntry *ce;
    size_t len;
    int error;

    /* printf("read(%s)\n", path); */

    error = getentry(path, &entry, &ce);
    if (error)
	return error;

    error = cm_getattr(entry, ce);
    if (error) {
	fcache_release(entry);
	printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return -EIO;
    }
    
    error = cm_open(entry, ce, NNPFS_DATA_R); /* XXX */
    if (error) {
	fcache_release(entry);
	printf ("cm_open failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return -EIO;
    }

    if (entry->status.FileType != TYPE_FILE) {
	fcache_release(entry);
	printf("read: not a file\n");
	cred_free(ce);
	return -EISDIR;
    }

    len = fcache_get_status_length(&entry->status);

    if (offset < len) {
	fbuf f;

        if (offset + size > len)
            size = len - offset;

	error = fcache_get_data(&entry, &ce, 0, len); /* XXX use req */
	if (error) {
	    fcache_release(entry);
	    printf ("fcache_get_data failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return -EIO;
	}

	error = fcache_get_fbuf(entry, &f, FBUF_READ);
	if (!error) {
	    memcpy(buf, (char *)fbuf_buf(&f) + offset, size);
	    abuf_end(&f);
	}
    } else
        size = 0;

    fcache_release(entry);
    cred_free(ce);

    if (error) {
	printf ("fcache_get_fbuf failed: %s\n", koerr_gettext(error));
	return -EIO;
    }

    return size;
}

static struct fuse_operations arla_oper = {
    .getattr    = arla_getattr,
    .readdir    = arla_readdir,
    .open       = arla_open,
    .read       = arla_read,
};

static struct getargs args[] = {
    {"conffile", 'c',	arg_string,	&conf_file,
     "path to configuration file", "file"},
    {"check-consistency", 'C', arg_flag, &cm_consistency,
     "if we want extra paranoid consistency checks", NULL },
    {"log",	'l',	arg_string,	&log_file,
     "where to write log (stderr (default), syslog, or path to file)", NULL},
    {"debug",	0,	arg_string,	&debug_levels,
     "what to write in the log", NULL},
    {"connected-mode", 0, arg_string,	&connected_mode_string,
     "initial connected mode [conncted|fetch-only|disconnected]", NULL},
    {"dynroot", 'D', arg_flag,	&dynroot_enable,
     "if dynroot is enabled", NULL},
#ifdef KERBEROS
    {"rxkad-level", 'r', arg_string,	&rxkad_level_string,
     "the rxkad level to use (clear, auth or crypt)", NULL},
#endif
    {"sysname",	 's',	arg_string,	&argv_sysname,
     "set the sysname of this system", NULL},
    {"root-volume",0,   arg_string,     &root_volume},
    {"port",	0,	arg_integer,	&client_port,
     "port number to use",	"number"},
    {"recover",	'z',	arg_negative_flag, &recover,
     "don't recover state",	NULL},
    {"cache-dir", 0,	arg_string,	&cache_dir,
     "cache directory",	"directory"},
    {"workers",	  0,	arg_integer,	&num_workers,
     "number of worker threads", NULL},
    {"fake-mp",	  0,	arg_flag,	&fake_mp,
     "enable fake mountpoints", NULL},
    {"version",	0,	arg_flag,	&version_flag,
     NULL, NULL},
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL}
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "mountpoint");
    exit (ret);
}

int
main (int argc, char **argv)
{
    char *fuse_argv[] = {argv[0], "-f", "-s", argv[argc - 1]};
    int fuse_argc = sizeof(fuse_argv)/sizeof(*fuse_argv);
    int optind = 0;
    int ret;

    setprogname(argv[0]);
    tzset();
    srand(time(NULL));

    if (getarg(args, sizeof(args)/sizeof(*args), argc, argv, &optind))
	usage(1);

    argc -= optind;
    argv += optind;

    if (help_flag)
	usage(0);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }
    
    if (argc != 1)
	usage(1);

    default_log_file = "/dev/stderr";

    ret = arla_init();
    if (ret)
	return ret;

    {
	struct timeval tv = { 0, 10000} ;
	IOMGR_Select(0, NULL, NULL, NULL, &tv);
    }

    arla_start(NULL, cache_dir);

    ret = fuse_main(fuse_argc, fuse_argv, &arla_oper, NULL);

    arla_stop();
    return ret;
}
