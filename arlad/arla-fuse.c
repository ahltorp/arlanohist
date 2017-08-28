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
#include <fuse/fuse_lowlevel.h>
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

struct arla_fuse_node {
  int type;
  VenusFid fid;
};

static struct arla_fuse_node *nodelist;
static int nodelist_size;
static int nodelist_next;

static int
add_to_nodelist(VenusFid fid, int type)
{
  if (nodelist_next >= nodelist_size) {
    int old_nodelist_size = nodelist_size;
    nodelist_size *= 2;
    nodelist = realloc(nodelist, nodelist_size);
    memset(&nodelist[old_nodelist_size], 0, (nodelist_size - old_nodelist_size) * sizeof(*nodelist));
  }

  int nodenr = nodelist_next;

  nodelist[nodenr].fid = fid;
  nodelist[nodenr].type = type;
  nodelist_next++;

  return nodenr;
}

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
    nodelist_size = 1024;
    nodelist = calloc(nodelist_size, sizeof(*nodelist));
    nodelist_next = 2;
    nodelist[1].fid = rootcwd;
    nodelist[1].type = TYPE_DIR;
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

static void
set_nnpfsattr(struct stat *attr, struct nnpfs_attr *nnpfs_attr)
{
  memset(attr, 0, sizeof(*attr));
  attr->st_ino = nnpfs_attr->xa_fileid;
  attr->st_mode = nnpfs_attr->xa_mode;
  attr->st_size = nnpfs_attr->xa_size;
  attr->st_nlink = nnpfs_attr->xa_nlink;
  attr->st_uid = nnpfs_attr->xa_uid;
  attr->st_gid = nnpfs_attr->xa_gid;
  attr->st_atime = nnpfs_attr->xa_atime;
  attr->st_mtime = nnpfs_attr->xa_mtime;
  attr->st_ctime = nnpfs_attr->xa_ctime;
}

static int
get_entry(fuse_ino_t ino, CredCacheEntry **ce, FCacheEntry **entry, int getattrp) {
  assert(ino < nodelist_next);

  struct arla_fuse_node *node = &nodelist[ino];
  VenusFid fid = node->fid;
  int ret;

  *ce = cred_get (fid.Cell, getuid() /* XXX */, CRED_ANY);
  
  ret = fcache_get(entry, fid, *ce);
  if (ret) {
    return ret;
  }
  
  if (getattrp) {
    ret = cm_getattr(*entry, *ce);
    if (ret) {
      arla_warnx(ADEBMSG, "cm_getattr failed: %s", koerr_gettext(ret));
      fcache_release(*entry);
      *entry = NULL;
      return ret;
    }
  }

  return 0;
}

static int
try_again (int *ret, CredCacheEntry **ce, const VenusFid *fid)
{
  return FALSE;
}

static void
arla_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  arla_warnx (ADEBMSG, "arla_ll_lookup %llu %s", (long long unsigned) parent, name);

  CredCacheEntry *ce;
  int ret;
  FCacheEntry *dentry = NULL;

  ret = get_entry(parent, &ce, &dentry, 0);

  if (ret) {
    goto out;
  }

  arla_warnx (ADEBMSG, "arla_ll_lookup dirfid %d.%d.%d.%d", dentry->fid.Cell, dentry->fid.fid.Volume, dentry->fid.fid.Vnode, dentry->fid.fid.Unique);

  VenusFid fid;
  VenusFid dirfid;
  VenusFid real_fid;
  FCacheEntry *entry = NULL;
  AFSFetchStatus status;

  do {
    ret = cm_lookup (&dentry, name, &fid, &ce, TRUE);
    dirfid = dentry->fid;
  } while (try_again (&ret, &ce, &dirfid));
  
  if (ret) {
    goto out;
  }
  
  fcache_release(dentry);
  dentry = NULL;
  
  ret = fcache_get(&entry, fid, ce);
  if (ret) {
    goto out;
  }
  
  do {
    ret = cm_getattr(entry, ce);
    status = entry->status;
    real_fid = *fcache_realfid(entry);
  } while (try_again (&ret, &ce, &fid));

  if (ret) {
    goto out;
  }

  int nodenr = add_to_nodelist(fid, status.FileType);
  
  struct fuse_entry_param e;

  struct nnpfs_attr attr;

  afsstatus2nnpfs_attr (&status, &real_fid, &attr, FCACHE2NNPFSNODE_ALL);

  memset(&e, 0, sizeof(e));
  e.ino = nodenr;
  e.generation = 1;
  e.attr_timeout = 10000;
  e.entry_timeout = 10000;
  set_nnpfsattr(&e.attr, &attr);
  fuse_reply_entry(req, &e);

 out:
  if (ret) {
    fuse_reply_err(req, ENOENT);
  }
  if (entry) {
    fcache_release(entry);
  }
  if (dentry) {
    fcache_release(dentry);
  }
  cred_free (ce);
  return;
}

static void
arla_ll_getattr(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  arla_warnx (ADEBMSG, "arla_ll_getattr %llu", (long long unsigned) ino);

  CredCacheEntry *ce;
  int ret;
  FCacheEntry *entry = NULL;

  ret = get_entry(ino, &ce, &entry, 1);

  if (ret) {
    goto out;
  }

  AFSFetchStatus status;

  arla_warnx (ADEBMSG, "arla_ll_getattr fid %d.%d.%d.%d", entry->fid.Cell, entry->fid.fid.Volume, entry->fid.fid.Vnode, entry->fid.fid.Unique);

  status = entry->status;

  struct stat attr;

  struct nnpfs_attr nnpfs_attr;

  afsstatus2nnpfs_attr (&status, &entry->fid, &nnpfs_attr, FCACHE2NNPFSNODE_ALL);

  set_nnpfsattr(&attr, &nnpfs_attr);
  fuse_reply_attr(req, &attr, 10000);
 out:
  if (ret) {
    fuse_reply_err(req, ENOENT);
  }
  if (entry) {
    fcache_release(entry);
  }
  cred_free (ce);

  return;
}

struct readdir_context {
  off_t offset;
  off_t start_offset;
  char *buf;
  size_t bytes_left;
  fuse_req_t req;
};

static int
readdir_func(VenusFid *fid, const char *name, void *v)
{
  struct readdir_context *context = (struct readdir_context *)v;

  context->offset+=1;

  struct stat st = {
    .st_ino = context->offset,
    .st_mode = 0/*S_IFREG*/,
  };

  if (context->offset > context->start_offset) {
    size_t entry_size = fuse_add_direntry(context->req, context->buf, context->bytes_left, name, &st, context->offset);
    
    if (entry_size > context->bytes_left) {
      return -1;
    }
    context->bytes_left -= entry_size;
    context->buf += entry_size;
    return 0;
  }
  
  return 0;
}



static void
arla_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t off, struct fuse_file_info *fi)
{
  arla_warnx (ADEBMSG, "arla_ll_readdir %lu %zu %zd", ino, size, off);

  CredCacheEntry *ce;
  int ret;
  FCacheEntry *entry;
  ret = get_entry(ino, &ce, &entry, 1);

    struct readdir_context context;

    if (ret) {
      goto out;
    }
    
    if (entry->status.FileType != TYPE_DIR) {
	fcache_release(entry);
	printf("readdir: not a directory\n");
	fuse_reply_err(req, ENOTDIR);
	ret = 0; // XXX: prevent another reply
	goto out;
    }

    char *buf = calloc(size, 1);

    context.offset = 0;
    context.start_offset = off;
    context.buf = buf;
    context.bytes_left = size;
    context.req = req;
    ret = adir_readdir(&entry, readdir_func, &context, &ce);

    if (ret) {
	printf ("adir_readdir failed: %s\n", koerr_gettext(ret));
	goto out;
    }
    
    fuse_reply_buf(req, buf, size - context.bytes_left);
    arla_warnx (ADEBMSG, "arla_readdir %lu reply %zu bytes", ino, size - context.bytes_left);

 out:
  if (ret) {
    fuse_reply_err(req, ENOENT);
  }
  if (buf) {
    free(buf);
  }
  if (entry) {
    fcache_release(entry);
  }
  cred_free (ce);

  return;
}

static void
arla_ll_open(fuse_req_t req, fuse_ino_t ino,
               struct fuse_file_info *fi)
{
  arla_warnx (ADEBMSG, "arla_ll_open %llu", (long long unsigned) ino);

  CredCacheEntry *ce;
  int ret;
  FCacheEntry *entry;
  ret = get_entry(ino, &ce, &entry, 1);

  if (ret) {
    goto out;
  }

  fuse_reply_open(req, fi);

 out:
  if (ret) {
    fuse_reply_err(req, EINVAL);
  }
  if (entry) {
    fcache_release(entry);
  }
  cred_free (ce);
}

static void
arla_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
               off_t offset, struct fuse_file_info *fi)
{
  arla_warnx (ADEBMSG, "arla_ll_read %lu %zu %zd", ino, size, offset);

  CredCacheEntry *ce;
  int ret;
  FCacheEntry *entry;
  ret = get_entry(ino, &ce, &entry, 1);

  if (ret) {
    goto out;
  }

  ret = cm_open(entry, ce, NNPFS_DATA_R); /* XXX */
  if (ret) {
    printf ("cm_open failed: %s\n", koerr_gettext(ret));
    goto out;
  }

  if (entry->status.FileType != TYPE_FILE) {
    ret = EISDIR;
    goto out;
  }

  size_t len;

  len = fcache_get_status_length(&entry->status);

  if (offset < len) {
    fbuf f;
    
    if (offset + size > len)
      size = len - offset;
    
    ret = fcache_get_data(&entry, &ce, 0, len); /* XXX use req */
    if (ret) {
      printf ("fcache_get_data failed: %s\n", koerr_gettext(ret));
      goto out;
    }
    
    ret = fcache_get_fbuf(entry, &f, FBUF_READ);
    if (!ret) {
      fuse_reply_buf(req, (char *)fbuf_buf(&f) + offset, size);

      //memcpy(buf, (char *)fbuf_buf(&f) + offset, size);
      abuf_end(&f);
    }
  } else {
    size = 0;
  }

 out:
  if (ret) {
    fuse_reply_err(req, EINVAL);
  }
  if (entry) {
    fcache_release(entry);
  }
  cred_free (ce);
}

static struct fuse_lowlevel_ops arla_ll_oper = {
  .lookup         = arla_ll_lookup,
  .getattr        = arla_ll_getattr,
  .readdir        = arla_ll_readdir,
  .open           = arla_ll_open,
  .read           = arla_ll_read,
#if 0
  .write          = arla_ll_write,
  .mknod          = arla_ll_mknod,
  .rename         = arla_ll_rename,
  .mkdir          = arla_ll_mkdir,
#endif
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

static int
arla_fuse_main(char *mountpoint)
{
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *channel;
  int ret;
  channel = fuse_mount(mountpoint, &args);
  if (channel == NULL) {
    return -1;
  }

  ret = -1;

  struct fuse_session *session;
  session = fuse_lowlevel_new(&args, &arla_ll_oper,
			      sizeof(arla_ll_oper), NULL);
  if (session != NULL) {
    ret = fuse_set_signal_handlers(session);
    if (ret == 0) {
      fuse_session_add_chan(session, channel);
      ret = fuse_session_loop(session);
      fuse_remove_signal_handlers(session);
      fuse_session_remove_chan(channel);
    }
    fuse_session_destroy(session);
  }

  fuse_unmount(mountpoint, channel);

  return ret;
}

int
main (int argc, char **argv)
{
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

    arla_fuse_main(argv[0]);

    arla_stop();
    return ret;
}
