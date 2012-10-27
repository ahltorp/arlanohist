/*
 * Copyright (c) 1995 - 2005 Kungliga Tekniska Högskolan
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

//#include <readline/readline.h>

#include "lsprint.h"

#ifdef HAVE_READLINE
extern char *rl_line_buffer;
char **completion_matches(const char *, char *(*)(const char *, int));
extern char **(*rl_attempted_completion_function)(const char *, int, int);
extern char *(*rl_completion_entry_function)(const char *, int);
extern int rl_completion_append_character;
#endif

RCSID("$Id: arla-cli.c,v 1.67 2007/11/25 20:41:30 map Exp $");

char *default_log_file = "/dev/stderr";
char *default_arla_cachedir = ".arlacache";
int client_port = 4712;


/* creds used for all the interactive usage */

static VenusFid cwd;
static VenusFid rootcwd;

static int arla_chdir(int, char **);
static int arla_ls(int, char **);
static int arla_cat(int, char **);
static int arla_sleep(int, char **);
static int arla_wc(int, char **);
static int arla_pwd(int, char **);
static int help(int, char **);
static int arla_quit(int, char **);
static int arla_checkserver(int, char **);
static int arla_conn_status(int, char **);
static int arla_connect(int, char **);
static int arla_vol_status(int, char **);
static int arla_tokens(int, char **);
static int arla_afslog(int, char **);
static int arla_fcache_status(int, char **);
static int arla_cell_status (int, char **);
static int arla_sysname(int, char**);
static int arla_mkdir (int, char**);
static int arla_rmdir (int, char**);
static int arla_rm (int, char**);
static int arla_put (int, char**);
static int arla_get (int, char**);
#ifdef RXDEBUG
static int arla_rx_status(int argc, char **argv);
#endif
static int arla_flushfid(int argc, char **argv);
static int arla_listacl (int argc, char **argv);
static int arla_fs (int argc, char **argv);

static char *copy_dirname(const char *s);
static char *copy_basename(const char *s);


static SL_cmd cmds[] = {
    {"chdir", arla_chdir, "chdir directory"},
    {"cd"},
    {"ls",    arla_ls, "ls"},
    {"cat",   arla_cat, "cat file"},
    {"sleep", arla_sleep, "sleep seconds"},
    {"wc",    arla_wc, "wc file"},
    {"mkdir", arla_mkdir, "mkdir dir"},
    {"rmdir", arla_rmdir, "rmdir dir"},
    {"rm",    arla_rm, "rm file"},
    {"put",   arla_put, "put localfile [afsfile]"},
    {"get",   arla_get, "get afsfile [localfile]"},
    {"pwd",   arla_pwd, "pwd"},
    {"listacl",arla_listacl, "listacl"},
    {"la"},
    {"fs",    arla_fs, "fs"},
    {"help",  help, "help"},
    {"?"},
    {"checkservers", arla_checkserver, "poll servers are down"},
    {"conn-status", arla_conn_status, "connection status"},
    {"vol-status", arla_vol_status, "volume cache status"},
    {"tokens", arla_tokens, "credentials status"},
    {"afslog", arla_afslog, "get credentials"},
    {"fcache-status", arla_fcache_status, "file cache status"},
    {"cell-status", arla_cell_status, "cell status"},
#ifdef RXDEBUG
    {"rx-status", arla_rx_status, "rx connection status"},
#endif
    {"flushfid", arla_flushfid, "flush a fid from the cache"},
    {"quit", arla_quit, "quit"},
    {"exit"},
    {"sysname", arla_sysname, "sysname"},
    {"connect", arla_connect,
     "connect [connected|fetch-only|disconnected|callback-connected]"},
    { NULL }
};

/*
 * Return a malloced copy of the dirname of `s'
 */

static char *
copy_dirname (const char *s)
{
    const char *p;
    char *res;

    p = strrchr (s, '/');
    if (p == NULL)
	return strdup(".");
    res = malloc (p - s + 1);
    if (res == NULL)
	return NULL;
    memmove (res, s, p - s);
    res[p - s] = '\0';
    return res;
}

/*
 * Return the basename of `s'.
 * The result is malloc'ed.
 */

static char *
copy_basename (const char *s)
{
     const char *p, *q;
     char *res;

     p = strrchr (s, '/');
     if (p == NULL)
	  p = s;
     else
	  ++p;
     q = s + strlen (s);
     res = malloc (q - p + 1);
     if (res == NULL)
	 return NULL;
     memmove (res, p, q - p);
     res[q - p] = '\0';
     return res;
}

/*
 *
 */

static int
arla_quit (int argc, char **argv)
{
    printf("Thank you for using arla\n");
    return -2;
}

static int
arla_flushfid(int argc, char **argv)
{
    AFSCallBack broken_callback = {0, 0, CBDROPPED};
    VenusFid fid;
    
    if (argc != 2) {
	fprintf(stderr, "flushfid fid\n");
	return 0;
    }
    
    if ((sscanf(argv[1], "%d.%d.%d.%d", &fid.Cell, &fid.fid.Volume, 
		&fid.fid.Vnode, &fid.fid.Unique)) == 4) {
	;
    } else if ((sscanf(argv[1], "%d.%d.%d", &fid.fid.Volume, 
		       &fid.fid.Vnode, &fid.fid.Unique)) == 3) {
	fid.Cell = cwd.Cell;
    } else {
	fprintf(stderr, "flushfid fid\n");
	return 0;
    }
    
    fcache_stale_entry(fid, broken_callback);
    
    return 0;
}


static int
arla_chdir (int argc, char **argv)
{
    VenusFid new_cwd;
    FCacheEntry *entry;
    int error;
    CredCacheEntry *ce;

    if (argc != 2) {
	printf ("usage: %s dir\n", argv[0]);
	return 0;
    }

    error = cm_walk (cwd, argv[1], &new_cwd);
    if (error) {
	printf("chdir: %s: %s\n", argv[1], koerr_gettext(error));
	return 0;
    }

    ce = cred_get (new_cwd.Cell, getuid(), CRED_ANY);

    error = fcache_get(&entry, new_cwd, ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }

    error = cm_getattr (entry, ce);
    if (error) {
	fcache_release(entry);
	printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }
    
    if (entry->status.FileType != TYPE_DIR) {
	fcache_release(entry);
	printf("not a directory\n");
	cred_free(ce);
	return 0;
    }

    fcache_release(entry);

    cwd = new_cwd;
    cred_free(ce);

    return 0;
}

struct ls_context {
    VenusFid *dir_fid;
    arla_ftsent **current;
    unsigned long maxnlink;
    unsigned long maxsize;
    unsigned long maxuser;
    unsigned long maxgroup;
    DISPLAY d;
    char *filter;
};

static char *
read_symlink(FCacheEntry *entry)
{
    int error;
    int len;
    fbuf f;
    char *buf;
    CredCacheEntry *ce;

    ce = cred_get (entry->fid.Cell, getuid(), CRED_ANY);
    
    error = fcache_get_data (&entry, &ce, 0, 0);
    if (error) {
	arla_warn (ADEBWARN, error, "fcache_get_data");
	cred_free(ce);
	return NULL;
    }

    error = fcache_get_fbuf(entry, &f, FBUF_READ);
    if (error) {
	arla_warn (ADEBWARN, error, "fcache_get_fbuf");
	cred_free(ce);
	return NULL;
    }
    
    len = fbuf_len(&f);
    if (len <= 0) {
	abuf_end(&f);
	arla_warnx(ADEBWARN, "symlink with bad length: %d", len);
	cred_free(ce);
	return NULL;
    }
    
    buf = malloc(len + 1);
    memcpy(buf, fbuf_buf(&f), len);
    buf[len] = '\0';
    
    abuf_end(&f);
    cred_free(ce);
    
    return buf;
}

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

static char *
id_to_name_cached(VenusFid *fid, int32_t id)
{
    struct ptscache_entry key;
    struct ptscache_entry *e;

    key.cell = fid->Cell;
    key.id = id;

    e = (struct ptscache_entry *)hashtabsearch (ptscache, (void *)&key);

    if (e == NULL) {
	return NULL;
    }

    return strdup(e->name);
}

static char *
id_to_name(VenusFid *fid, int32_t id)
{
    struct rx_connection *connptdb = NULL;
    struct db_server_context conn_context;
    char *name = NULL;
    cell_entry *cell = cell_get_by_id(fid->Cell);
    int error;

    if (id == 0) {
	return strdup("root");
    }

    name = id_to_name_cached(fid, id);
    if (name) {
	return name;
    }
    
    error = ENETDOWN;
    for (connptdb = arlalib_first_db(&conn_context, cell->name, NULL, afsprport,
				     PR_SERVICE_ID,
				     arlalib_getauthflag (0, 0, 0, 0));
	 connptdb != NULL && arlalib_try_next_db (error);
	 connptdb = arlalib_next_db(&conn_context)) {

	error = 0;
	
	namelist nlist;
	idlist ilist;
	nlist.len = 1;
	nlist.val = malloc(sizeof(prname) * nlist.len);
	ilist.len = 1;
	ilist.val = malloc(sizeof(int32_t) * ilist.len);
	if((ilist.val == NULL) || (nlist.val == NULL))
	    errx(1, "Out of memory");
	ilist.val[0]=id;
	error = PR_IDToName(connptdb, &ilist, &nlist);
	if (error == 0) {
	    name = strdup(nlist.val[0]);
	}
	free(ilist.val);
	free(nlist.val);
	if (error == 0) {
	    break;
	}
    }

    free_db_server_context(&conn_context);

    if (name) {
	struct ptscache_entry *e;

	e = malloc(sizeof(struct ptscache_entry));
	if (e == NULL) {
	    errx(1, "Out of memory");
	}
	e->cell = fid->Cell;
	e->id = id;
	e->name = strdup(name);
	
	hashtabadd(ptscache, e);
    }

    return name;
}

static int
print_dir_fts (VenusFid *fid, const char *name, void *v)
{
    struct ls_context *context = (struct ls_context *)v;

    int ret;
    FCacheEntry *FCentry;
    CredCacheEntry *ce;

    if (VenusFid_cmp(fid, context->dir_fid) == 0)
	return 0;

    if (context->filter != NULL &&
	strcmp(context->filter, name) != 0) {
	return 0;
    }

    ce = cred_get (fid->Cell, getuid(), CRED_ANY);

    ret = followmountpoint (fid, context->dir_fid, NULL, &ce);
    if (ret) {
	fprintf (stderr, "%s: %s while following mount point\n", name, koerr_gettext(ret));
	cred_free(ce);
	return 0;
    }

    cred_free(ce);

    /* Have we follow a mountpoint to ourself ? */
    if (VenusFid_cmp(fid, context->dir_fid) == 0)
	return 0;

    ce = cred_get (fid->Cell, getuid(), CRED_ANY);
    ret = fcache_get(&FCentry, *fid, ce);
    if (ret) {
	fprintf (stderr, "%s: %s (fcache_get)\n", name, koerr_gettext(ret));
	cred_free(ce);
	return 0;
    }

    ret = cm_getattr (FCentry, ce);
    if (ret) {
	fcache_release(FCentry);
	fprintf (stderr, "%s: %s while getting attributes\n", name, koerr_gettext(ret));
	cred_free(ce);
	return 0;
    }

    

    arla_ftsent *entry;

    NAMES *np = malloc(sizeof(NAMES));
    np->flags = "";
    
    entry = malloc(sizeof(arla_ftsent) + strlen(name));
    entry->fts_number = 0;
    entry->fts_pointer = np;
    entry->fts_namelen = strlen(name);
    strcpy(entry->fts_name, name);
    struct stat *stat = malloc(sizeof (struct stat));
    memset(stat, 0, sizeof(struct stat));
    entry->fts_statp = stat;
    entry->fts_level = ARLA_FTS_ROOTLEVEL;
    entry->fts_link = NULL;
    entry->fts_linkname = NULL;
    *context->current = entry;
    context->current = &entry->fts_link;

    context->d.entries++;
    context->d.maxlen = max(entry->fts_namelen, context->d.maxlen);

    np->user = id_to_name(fid, FCentry->status.Owner);
    asprintf(&np->group, "");

    switch (FCentry->status.FileType) {
    case TYPE_FILE :
	stat->st_mode = S_IFREG;
	break;
    case TYPE_DIR :
	stat->st_mode = S_IFDIR;
	break;
    case TYPE_LINK :
	stat->st_mode = S_IFLNK;
	entry->fts_linkname = read_symlink(FCentry);
	break;
    default :
	abort ();
    }

    stat->st_mode |= FCentry->status.UnixModeBits;

    stat->st_atime = FCentry->status.ClientModTime;
    stat->st_mtime = FCentry->status.ClientModTime;
    stat->st_ctime = FCentry->status.ClientModTime;

    stat->st_nlink = FCentry->status.LinkCount;

    stat->st_size = fcache_get_status_length(&FCentry->status);

    context->maxnlink = max(stat->st_nlink, context->maxnlink);
    context->maxsize = max(stat->st_size, context->maxsize);
    context->maxuser = max(strlen(np->user), context->maxuser);
    context->maxgroup = max(strlen(np->group), context->maxgroup);

    fcache_release(FCentry);
    cred_free(ce);
    return 0;
}

static int
print_dir_fts_nostat (VenusFid *fid, const char *name, void *v)
{
    struct ls_context *context = (struct ls_context *)v;

    arla_ftsent *entry;

    if (context->filter != NULL &&
	strcmp(context->filter, name) != 0) {
	return 0;
    }

    entry = malloc(sizeof(arla_ftsent) + strlen(name));
    entry->fts_number = 0;
    entry->fts_pointer = NULL;
    entry->fts_namelen = strlen(name);
    strcpy(entry->fts_name, name);
    entry->fts_statp = NULL;
    entry->fts_level = ARLA_FTS_ROOTLEVEL;
    entry->fts_link = NULL;
    entry->fts_linkname = NULL;
    *context->current = entry;
    context->current = &entry->fts_link;

    context->d.entries++;
    context->d.maxlen = max(entry->fts_namelen, context->d.maxlen);

    return 0;
}

static int
arla_ls (int argc, char **argv)
{
    struct getargs args[] = {
	{NULL, 'l', arg_flag, NULL},
    };
    int l_flag = 0;
    int error;
    int optind = 0;
    struct ls_context context;
    FCacheEntry *entry;
    CredCacheEntry *ce;
    VenusFid fid;

    args[0].value = &l_flag;

    if (getarg (args, sizeof(args)/sizeof(*args),  argc, argv, &optind)) {
	arg_printusage (args, sizeof(args)/sizeof(*args), "ls", NULL);
	return 0;
    }

    argc -= optind;
    argv += optind;

    if (argc > 0) {
	error = cm_walk (cwd, argv[0], &fid);
	if (error) {
	    printf("ls: %s: %s\n", argv[0], koerr_gettext(error));
	    return 0;
	}
    } else {
	fid = cwd;
    }

    ce = cred_get (fid.Cell, getuid(), CRED_ANY);
    error = fcache_get(&entry, fid, ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }

    error = cm_getattr (entry, ce);
    if (error) {
	fcache_release(entry);
	printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }
    
    arla_ftsent *list = NULL;
    
    context.filter = NULL;
    context.current = &list;
    context.d.entries = 0;
    context.d.maxlen = 0;
    context.d.btotal = 0;
    context.d.bcfile = 0;
      
    context.d.s_block = 0;
    context.d.s_flags = 0;
    context.d.s_group = 0;
    context.d.s_inode = 0;
    context.d.s_nlink = 0;
    context.d.s_size = 0;
    context.d.s_user = 0;
    
    context.maxnlink = 0;
    context.maxsize = 0;
    context.maxuser = 0;
    context.maxgroup = 0;
    
    if (entry->status.FileType != TYPE_DIR) {
	char *dirname;
	char *basename;

	fcache_release(entry);
	
	dirname = copy_dirname(argv[0]);
	if (dirname == NULL)
	    err(1, "copy_dirname");
	basename = copy_basename(argv[0]);
	if (basename == NULL)
	    err(1, "copy_basename");

	error = cm_walk (cwd, dirname, &fid);
	if (error) {
	    printf("ls: %s: %s\n", dirname, koerr_gettext(error));
	    return 0;
	}
	
	ce = cred_get (fid.Cell, getuid(), CRED_ANY);
	error = fcache_get(&entry, fid, ce);
	if (error) {
	    printf ("fcache_get failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return 0;
	}
	
	error = cm_getattr (entry, ce);
	if (error) {
	    fcache_release(entry);
	    printf ("cm_getattr failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return 0;
	}
	context.filter = basename;
    }

    context.dir_fid = &fid;
    
    error = adir_readdir (&entry,
			  l_flag ? print_dir_fts : print_dir_fts_nostat,
			  &context, &ce);

    char buf[21];
    context.d.s_nlink = snprintf(buf, sizeof(buf), "%lu", context.maxnlink);
    context.d.s_size = snprintf(buf, sizeof(buf), "%lu", context.maxsize);
    context.d.s_user = context.maxuser;
    context.d.s_group = context.maxgroup;
    
    context.d.list = list;
    
    if (l_flag) {
	printlong(&context.d);
    } else {
	printcol(&context.d);
    }


    fcache_release(entry);
    if (error) {
	printf ("adir_readdir failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }
    cred_free(ce);

    return 0;
}

static int
arla_sysname (int argc, char **argv)
{
    switch (argc) {
    case 1:
	printf("sysname: %s\n", fcache_getdefsysname());
	break;
    case 2:
	fcache_setdefsysname(argv[1]);
	printf("setting sysname to: %s\n", fcache_getdefsysname());
	break;
    default:
	printf("syntax: sysname <sysname>\n");
	break;
    }
    return 0;
}

static int
arla_mkdir (int argc, char **argv)
{
    VenusFid fid;
    int error;
    FCacheEntry *e;
    char *argcopy;
    char *dirname;
    char *basename;
    AFSStoreStatus store_attr;
    VenusFid res;
    AFSFetchStatus fetch_attr;
    
    if (argc != 2) {
	printf ("usage: %s file\n", argv[0]);
	return 0;
    }

    argcopy = strdup(argv[1]);
    if (argcopy == NULL)
	err(1, "strdup");
    basename = strrchr(argcopy, '/');
    if (basename == NULL) {
	basename = argcopy;
	dirname = ".";
    } else {
	basename[0] = '\0';
	basename++;
	dirname = argcopy;
    }

    error =  cm_walk (cwd, dirname, &fid);

    if (error) {
	printf("mkdir: %s: %s\n", dirname, koerr_gettext(error));
	free(argcopy);
	return 0;
    }

    CredCacheEntry *ce;
    
    ce = cred_get (fid.Cell, getuid(), CRED_ANY);
    
    error = fcache_get(&e, fid, ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	free(argcopy);
	cred_free(ce);
	return 0;
    }
    
    store_attr.Mask = 0;
    store_attr.ClientModTime = 0;
    store_attr.Owner = 0;
    store_attr.Group = 0;
    store_attr.UnixModeBits = 0;
    store_attr.SegSize = 0;
    error = cm_mkdir(&e, basename, &store_attr, &res, &fetch_attr, &ce);
    if (error)
	arla_warn (ADEBWARN, error,
		   "%s: cannot create directory `%s'",
		   argv[0], argv[1]);
    
    fcache_release(e);
    cred_free(ce);
    free(argcopy);
    return 0;
}

static int
arla_rmdir (int argc, char **argv)
{
    VenusFid fid;
    int error;
    FCacheEntry *e;
    char *argcopy;
    char *dirname;
    char *basename;
    
    if (argc != 2) {
	printf ("usage: %s file\n", argv[0]);
	return 0;
    }

    argcopy = strdup(argv[1]);
    if (argcopy == NULL)
	err(1, "strdup");
    basename = strrchr(argcopy, '/');
    if (basename == NULL) {
	basename = argcopy;
	dirname = ".";
    } else {
	basename[0] = '\0';
	basename++;
	dirname = argcopy;
    }

    error = cm_walk (cwd, dirname, &fid);
    if (error) {
	printf("rmdir: %s: %s\n", dirname, koerr_gettext(error));
	free(argcopy);
	return 0;
    }

    CredCacheEntry *ce;
    
    ce = cred_get (fid.Cell, getuid(), CRED_ANY);
    
    error = fcache_get(&e, fid, ce);
    if (error) {
	printf ("fcache_get failed: %d\n", error);
	free(dirname);
	cred_free(ce);
	return 0;
    }
    
    FCacheEntry *child;
    
    error = cm_rmdir(&e, basename, &child, &ce);
    if (error)
	arla_warn (ADEBWARN, error,
		   "%s: cannot remove directory `%s'",
		   argv[0], argv[1]);
    fcache_release(e);
    cred_free(ce);
    free(argcopy);
    return 0;
}

static int
arla_rm (int argc, char **argv)
{
    VenusFid fid;
    int error;
    FCacheEntry *e;
    char *dirname;
    char *basename;
    
    if (argc != 2) {
	printf ("usage: %s file\n", argv[0]);
	return 0;
    }
    dirname = copy_dirname(argv[1]);
    if (dirname == NULL)
	err(1, "copy_dirname");
    basename = copy_basename(argv[1]);
    if (basename == NULL)
	err(1, "copy_basename");


    error =  cm_walk (cwd, dirname, &fid);
    if (error) {
	printf("rm: %s: %s\n", dirname, koerr_gettext(error));
	free(dirname);
	free(basename);
	return 0;
    }

    CredCacheEntry *ce;
    
    ce = cred_get (fid.Cell, getuid(), CRED_ANY);
    
    error = fcache_get(&e, fid, ce);
    if (error) {
	printf ("fcache_get failed: %d\n", error);
	free(dirname);
	free(basename);
	cred_free(ce);
	return 0;
    }
    
    FCacheEntry *child;
    
    error = cm_remove(&e, basename, &child, &ce);
    if (error)
	arla_warn (ADEBWARN, error,
		   "%s: cannot remove file `%s'",
		   argv[0], argv[1]);
    
    fcache_release(e);
    cred_free(ce);
    free(dirname);
    free(basename);
    return 0;
}

static int
arla_put (int argc, char **argv)
{
    VenusFid dirfid;
    int ret;
    FCacheEntry *e;
    char *localname;
    char *localbasename;
    char *afsname;
    char *afsbasename;
    char *afsdirname;
    AFSStoreStatus store_attr;
    int afs_fd;
    int local_fd;
    char buf[8192];
    int write_ret;
    CredCacheEntry *ce;
    
    if (argc != 2 && argc != 3) {
	printf ("usage: %s localfile [afsfile]\n", argv[0]);
	return 0;
    }

    localname = argv[1];

    localbasename = copy_basename(localname);
    if (localbasename == NULL)
	err(1, "copy_basename");

    if (argc == 3) {
	afsname = argv[2];
    } else {
	afsname = localbasename;
    }

    afsdirname = copy_dirname(afsname);
    if (afsdirname == NULL)
	err(1, "copy_dirname");
    afsbasename = copy_basename(afsname);
    if (afsbasename == NULL)
	err(1, "copy_basename");


    printf("localbasename: *%s* afsname: *%s* afsdirname: *%s* afsbasename: *%s*\n",
	   localbasename, afsname, afsdirname, afsbasename);

    local_fd = open (localname, O_RDONLY, 0);

    if (local_fd < 0) {
	printf ("open %s: %s\n", localname, strerror(errno));
	ret = 0;
	goto out;
    }

    if(cm_walk (cwd, afsdirname, &dirfid))
	goto out;

    ce = cred_get (dirfid.Cell, getuid(), CRED_ANY);

    ret = fcache_get(&e, dirfid, ce);
    if (ret) {
	printf ("fcache_get failed: %d\n", ret);
	ret = 1;
	goto out;
    }

    memset(&store_attr, 0, sizeof(store_attr));

    FCacheEntry *entry;
    VenusFid fid;

    ret = cm_create(&e, afsbasename, &store_attr, &entry, &ce);
    if (ret) {
	if (ret != EEXIST) {
	    arla_warn (ADEBWARN, ret,
		       "%s: cannot create file `%s'",
		       argv[0], afsname);
	    fcache_release(e);
	    ret = 1;
	    goto out;
	} else {
	    ret = cm_lookup (&e, afsbasename, &fid, &ce, 1);
	    if (ret) {
		arla_warn (ADEBWARN, ret,
			   "%s: cannot open file `%s'",
			   argv[0], afsname);
		fcache_release(e);
		ret = 1;
		goto out;
	    }
	}
    } else {
      fid = entry->fid;
      fcache_release(entry);
    }
    
    fcache_release(e);

    ret = fcache_get(&e, fid, ce);
    if (ret) {
	printf ("fcache_get failed: %d\n", ret);
	ret = 1;
	goto out;
    }

    uint64_t blocksize;
    uint64_t offset = 0;
    blocksize = fcache_getblocksize();

    struct stat st_buf;

    ret = fstat(local_fd, &st_buf);

    uint64_t filesize = st_buf.st_size;

    while (filesize > offset) {

	afs_fd = fcache_open_block(e, offset, 1);
      
	if (afs_fd < 0) {
	    fcache_release(e);
	    printf ("fcache_open_file failed: %d\n", errno);
	    ret = 0;
	    goto out;
	}
      
	ret = ftruncate(afs_fd, 0);
	if (ret) {
	    fcache_release(e);
	    printf ("ftruncate failed: %d\n", errno);
	}

	uint64_t written_bytes = 0;
      
	while ((ret = read (local_fd, buf, sizeof(buf))) > 0) {
	    write_ret = write (afs_fd, buf, ret);
	    if (write_ret < 0) {
		printf("write failed: %d\n", errno);
		ret = 1;
		goto out;
	    } else if (write_ret != ret) {
		printf("short write: %d should be %d\n", write_ret, ret);
		ret = 1;
		goto out;
	    }
	    written_bytes += write_ret;
	    if (written_bytes == blocksize) {
		break;
	    } else if (written_bytes > blocksize) {
		printf("write over blocksize limit: %lld\n", written_bytes);
		ret = 1;
		goto out;
	    }
	}
      
	close(afs_fd);
      
	memset(&store_attr, 0, sizeof(store_attr));
      
	ret = cm_write(e, NNPFS_WRITE, offset, written_bytes, &store_attr, ce);
	if (ret) {
	    arla_warn (ADEBWARN, ret,
		       "%s: cannot close file `%s'",
		       argv[0], afsname);
	    fcache_release(e);
	    ret = 1;
	    goto out;
	}

	offset += blocksize;
      
    }
    close(local_fd);

    fcache_release(e);

 out:
    free(localbasename);
    free(afsdirname);
    free(afsbasename);
    return 0;
}

static int
arla_cat_et_wc (int argc, char **argv, int do_cat, int out_fd)
{
    VenusFid fid;
    int fd;
    char buf[8192];
    int ret;
    FCacheEntry *e;
    size_t size = 0;
    
    if (argc != 2) {
	printf ("usage: %s file\n", argv[0]);
	return 0;
    }
    if(cm_walk (cwd, argv[1], &fid) == 0) {
	CredCacheEntry *ce;

	ce = cred_get (fid.Cell, getuid(), CRED_ANY);

	ret = fcache_get(&e, fid, ce);
	if (ret) {
	    printf ("fcache_get failed: %d\n", ret);
	    cred_free(ce);
	    return 0;
	}

        ret = fcache_verify_attr (e, NULL, NULL, ce);
        if (ret) {
	    printf ("fcache_verify_attr failed: %d\n", ret);
	    cred_free(ce);
            return 0;
	}


	uint64_t blocksize;
	uint64_t offset = 0;
	blocksize = fcache_getblocksize();

	uint64_t filesize = fcache_get_status_length(&e->status);

	while (filesize > offset) {
	    ret = fcache_get_data (&e, &ce, offset, offset + blocksize);
	    if (ret) {
		fcache_release(e);
		printf ("fcache_get_data failed: %d\n", ret);
		cred_free(ce);
		return 0;
	    }

	    fd = fcache_open_block(e, offset, 0);

	    if (fd < 0) {
		fcache_release(e);
		printf ("fcache_open_file failed: %d\n", errno);
		cred_free(ce);
		return 0;
	    }
	    while ((ret = read (fd, buf, sizeof(buf))) > 0) {
		if(do_cat)
		    write (out_fd, buf, ret);
		else
		    size += ret;
	    }
	    close (fd);

	    offset += blocksize;
	}

	if(!do_cat)
	    printf("%lu %s\n", (unsigned long)size, argv[1]);

	fcache_release(e);
	cred_free(ce);
    }
    return 0;
}

static int
arla_cat (int argc, char **argv)
{
    return arla_cat_et_wc(argc, argv, 1, STDOUT_FILENO);
}

static int
arla_get (int argc, char **argv)
{
    char *nargv[3];
    int fd, ret;

    if (argc != 3) {
	printf ("usage: %s from-file to-file\n", argv[0]);
	return 0;
    }
    
    fd = open (argv[2], O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) {
	warn ("open");
	return 0;
    }	

    nargv[0] = argv[0];
    nargv[1] = argv[1];
    nargv[2] = NULL;

    ret = arla_cat_et_wc(argc-1, nargv, 1, fd);
    close (fd);
    return ret;
	
}

static int
arla_sleep(int argc, char **argv)
{
    struct timeval tv;

    if (argc != 2) {
	printf ("usage: %s <time>\n", argv[0]);
	return 0;
    }

    tv.tv_sec = atoi(argv[1]);
    tv.tv_usec = 0;
    IOMGR_Select(0, NULL, NULL, NULL, &tv);

    return 0;
}

static int
arla_wc (int argc, char **argv)
{
    return arla_cat_et_wc(argc, argv, 0, -1);
}

struct lookup_fid_context {
    VenusFid parent_fid;
    VenusFid fid;
    char *name;
    int only_cached;
};

static int
lookup_fid(VenusFid *fid, const char *name, void *v)
{
    int ret;
    struct lookup_fid_context *context = (struct lookup_fid_context *) v;

#if 0
    printf("name: %s fid: %d.%d.%d.%d\n", name, fid->Cell, fid->fid.Volume,
	   fid->fid.Vnode, fid->fid.Unique);
#endif

    if (VenusFid_cmp(fid, &context->parent_fid) == 0) {
	return 0;
    }

    if (VenusFid_cmp(fid, &context->fid) == 0) {
	context->name = strdup(name);
	return 1;
    }

#if 0
    printf("following mountpoints\n");
#endif

    CredCacheEntry *ce;

    ce = cred_get (fid->Cell, getuid(), CRED_ANY);

    if (context->only_cached) {
	FCacheEntry *entry;
	int cached;

	ret = fcache_get(&entry, *fid, ce);
	if (ret) {
	    printf ("fcache_get failed: %s\n", koerr_gettext(ret));
	    cred_free(ce);
	    return 0;
	}

	if (entry->flags.usedp &&
	    entry->flags.attrp) {
	    cached = 1;
	} else {
	    cached = 0;
	}
	
	fcache_release(entry);

	if (!cached) {
	    cred_free(ce);
	    return 0;
	}
    }

    ret = followmountpoint (fid, &context->parent_fid, NULL, &ce);
    if (ret) {
	if (ret == ENOENT) {
	    cred_free(ce);
	    return 0;
	}
	printf ("follow %s: %d\n", name, ret);
	cred_free(ce);
	return 0;
    }

    if (VenusFid_cmp(fid, &context->fid) == 0) {
	context->name = strdup(name);
	cred_free(ce);
	return 1;
    }
    
    cred_free(ce);
    return 0;
}

static int
arla_pwd (int argc, char **argv)
{
    VenusFid dir_fid = cwd;
    VenusFid new_fid;
    FCacheEntry *entry;
    int error;
    char *path = strdup("");
    CredCacheEntry *ce;

    ce = cred_get (dir_fid.Cell, getuid(), CRED_ANY);

    error = fcache_get(&entry, dir_fid, ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }

    while (1) {
	error = cm_lookup(&entry, "..", &new_fid, &ce, 0);
	if (error) {
	    printf ("cm_lookup failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return 0;
	}
	
	fcache_release(entry);
	
#if 0
	printf("fid: %d.%d.%d.%d\n", new_fid.Cell, new_fid.fid.Volume,
	       new_fid.fid.Vnode, new_fid.fid.Unique);
#endif
	
	if (new_fid.Cell == 0 && new_fid.fid.Volume == 0 &&
	    new_fid.fid.Vnode == 0 && new_fid.fid.Unique == 0) {
	    break;
	}
	
	error = fcache_get(&entry, new_fid, ce);
	if (error) {
	    printf ("fcache_get failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return 0;
	}
	
	struct lookup_fid_context context;
	
	context.parent_fid = new_fid;
	context.fid = dir_fid;
	context.name = NULL;
	
#if 0
	printf("fid: %d.%d.%d.%d\n", dir_fid.Cell, dir_fid.fid.Volume,
	       dir_fid.fid.Vnode, dir_fid.fid.Unique);
#endif
	
	/* First only try cached, much faster */
	context.only_cached = 1;

	error = adir_readdir (&entry, lookup_fid,
			      &context, &ce);
	if (error) {
	    printf ("adir_readdir failed: %s\n", koerr_gettext(error));
	    cred_free(ce);
	    return 0;
	}

	if (context.name == NULL) {
	    /* Didn't find fid in cached entries, try all entries */
	    context.only_cached = 0;
	    
	    error = adir_readdir (&entry, lookup_fid,
				  &context, &ce);
	    if (error) {
		printf ("adir_readdir failed: %s\n", koerr_gettext(error));
		cred_free(ce);
		return 0;
	    }
	}

	{
	    char *old_path = path;
	    asprintf(&path, "/%s%s", context.name, old_path);
	    free(old_path);
	}
#if 0
	printf("name: %s\n", context.name);
#endif
	dir_fid = new_fid;
    }

    printf("/afs%s\n", path);
    free(path);

    cred_free(ce);
    return 0;
}

static int
help (int argc, char **argv)
{
    sl_help(cmds, argc, argv);
    return 0;
}

static int
arla_checkserver (int argc, char **argv)
{
    uint32_t hosts[12];
    int num = sizeof(hosts)/sizeof(hosts[0]);

    conn_downhosts(cwd.Cell, hosts, &num, 0);
    if (num < 0 || num > sizeof(hosts)/sizeof(hosts[0])) {
	fprintf (stderr, "conn_downhosts returned bogus num: %d\n", num);
	return 0;
    }
    if (num == 0) {
	printf ("no servers down in %s\n", cell_num2name(cwd.Cell));
    } else {
	while (num) {
	    struct in_addr in;
	    in.s_addr = hosts[num];
	    printf ("down: %s\n", inet_ntoa(in));
	    num--;
	}
    }
    
    return 0;
}

static int
arla_conn_status (int argc, char **argv)
{
    conn_status ();
    return 0;
}

static int
arla_vol_status (int argc, char **argv)
{
    volcache_status ();
    return 0;
}

static Bool
print_cred(CredCacheEntry *ce)
{
    if (ce->cred != getuid()) {
	return FALSE;
    }

    if (ce->flags.killme) {
	return FALSE;
    }

    if (ce->type > CRED_MAX) {
	return FALSE;
    }

    if (ce->cell == -1) {
	return FALSE;
    }

    if (ce->type == CRED_NONE) {
	return FALSE;
    }

    cell_entry *cell = cell_get_by_id(ce->cell);

    char *cred_string[CRED_MAX+1] = {
	"none",
	"Kerberos 4",
	"-",
	"rxgk"
    };

    const char *cellname = "unknown";

    if (cell) {
	cellname = cell->name;
    }

    printf("%s: %s\n", cellname, cred_string[ce->type]);

    return FALSE;
}

static int
arla_tokens (int argc, char **argv)
{
    cred_foreach(print_cred);
    return 0;
}

static int
arla_afslog (int argc, char **argv)
{
    struct cred_rxkad cred;
    struct ClearToken ct;
    int error;

    if (argc != 2) {
	printf ("usage: %s <cell-name>\n", argv[0]);
	return 0;
    }

    char *cellname = argv[1];

    cell_entry *c = cell_get_by_name(cellname);
    if (c == NULL) {
	printf ("no such cell\n");
	return 0;
    }
    
    error = arlalib_getcred(cellname, &ct,
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
	cred_add (getuid(), CRED_KRB4, 2, cell_name2num(cellname),
		  cred.ct.EndTimestamp,
		  &cred, sizeof(cred), cred.ct.ViceId);
	
    }

    return 0;
}


static int
arla_fcache_status (int argc, char **argv)
{
    fcache_status ();
    return 0;
}

static int
arla_cell_status (int argc, char **argv)
{
    cell_entry *c;

    if (argc != 2) {
	printf ("usage: %s <cell-name>\n", argv[0]);
	return 0;
    }
    c = cell_get_by_name(argv[1]);
    if (c == NULL)
	printf ("no such cell\n");
    else
	cell_print_cell (c, stdout);
    return 0;
}

static int
arla_connect (int argc, char **argv)
{
    int error = (argc > 2) ? 1 : 0;
    int32_t mode;
    if (argc == 2) {
	struct nnpfs_cred cred;

	if (strncmp("dis", argv[1], 3) == 0) 
	    mode = arla_CONNMODE_DISCONN;
	else if (strncmp("fetch", argv[1], 5) == 0)
	    mode = arla_CONNMODE_FETCH;
	else if (strncmp("conn", argv[1], 4) == 0)
	    mode = arla_CONNMODE_CONN;
	else if (strncmp(argv[1], "call", 4) == 0)
	    mode = arla_CONNMODE_CONN_WITHCALLBACKS;
	else
	    mode = -1;

	if (mode >= 0)
	    error = set_connmode(mode, &cred);
    }
    if (error) {
	printf("usage: %s [connected|fetch|disconnected|callback-connected]\n",
	       argv[0]);
	return 0;
    }

    get_connmode(&mode);
    switch(mode) {
    case arla_CONNMODE_CONN:
	printf("Connected mode\n");
	break;
    case arla_CONNMODE_FETCH:
	printf("Fetch only mode\n");
	break;
    case arla_CONNMODE_DISCONN:
	printf("Disconnected mode\n");
	break;
    default:
	printf("Unknown or error\n");
	break;
    }
    return 0;
}

#ifdef RXDEBUG
static int
arla_rx_status(int argc, char **argv)
{
    rx_PrintStats(stderr);
    return 0;
}
#endif

static void
skipline(char **curptr)
{
  while(**curptr!='\n') (*curptr)++;
  (*curptr)++;
}

#define MAXNAME 100

struct Acl {
    int NumPositiveEntries;
    int NumNegativeEntries;
    struct AclEntry *pos;
    struct AclEntry *neg;
};

struct AclEntry {
    struct AclEntry *next;
    int32_t RightsMask;
    char name[MAXNAME];
};

static struct Acl *
afs_getacl(char *path)
{
    struct Acl *oldacl;
    struct AclEntry *pos=NULL;
    struct AclEntry *neg=NULL;
    char *curptr;
    char tmpname[MAXNAME];
    int tmprights;
    int i;
    int error;
    AFSOpaque opaque;
    VenusFid fid;
    CredCacheEntry *ce;

    if (path) {
	error = cm_walk (cwd, path, &fid);
	if (error) {
	    printf("%s: %s\n", path, koerr_gettext(error));
	    return 0;
	}
    } else {
	fid = cwd;
    }

    ce = cred_get (fid.Cell, getuid(), CRED_ANY);

    error = getacl (fid, ce, &opaque);

    if (error) {
	printf("getacl: %s\n", koerr_gettext(error));
	cred_free(ce);
	return 0;
    }

    curptr = opaque.val;

    oldacl=(struct Acl *) malloc(sizeof(struct Acl));
    if(oldacl == NULL) {
	free(opaque.val);
	printf("getacl: Out of memory\n");
	cred_free(ce);
	return NULL;
    }

    /* Number of pos/neg entries parsing */
    sscanf(curptr, "%d\n%d\n", &oldacl->NumPositiveEntries,
	   &oldacl->NumNegativeEntries);
    skipline(&curptr);
    skipline(&curptr);
  
    if(oldacl->NumPositiveEntries)
	for(i=0; i<oldacl->NumPositiveEntries; i++) {      
	    sscanf(curptr, "%99s %d", tmpname, &tmprights);
	    skipline(&curptr);
	    if(!i) {
		pos=malloc(sizeof(struct AclEntry));
		oldacl->pos=pos;
	    }
	    else {
		pos->next=malloc(sizeof(struct AclEntry));
		pos=pos->next;
	    }
	    pos->RightsMask=tmprights;
	    strlcpy(pos->name, tmpname, sizeof(pos->name));
	    pos->next=NULL;
	}

    if(oldacl->NumNegativeEntries)
	for(i=0; i<oldacl->NumNegativeEntries; i++) {      
	    sscanf(curptr, "%99s %d", tmpname, &tmprights);
	    skipline(&curptr);
	    if(!i) {
		neg=malloc(sizeof(struct AclEntry));
		oldacl->neg=neg;
	    }
	    else {
		neg->next=malloc(sizeof(struct AclEntry));
		neg=neg->next;
	    }
	    neg->RightsMask=tmprights;
	    strlcpy(neg->name, tmpname, sizeof(neg->name));
	    neg->next=NULL;
	}

    free(opaque.val);
    return oldacl;
}

static void
afs_listacl(char *path)
{
    struct Acl *acl;
    struct AclEntry *position;
    int i;

    acl = afs_getacl(path);
    if (acl == NULL) {
	if (errno == EACCES)
	    return;
	else
	    exit(1);
    }

    printf("Access list for %s is\n", path == NULL ? "." : path);
    if(acl->NumPositiveEntries) {
	printf("Normal rights:\n");

	position=acl->pos;
	for(i=0;i<acl->NumPositiveEntries;i++) {
	    printf("  %s ", position->name);
	    if(position->RightsMask&PRSFS_READ)
		printf("r");
	    if(position->RightsMask&PRSFS_LOOKUP)
		printf("l");
	    if(position->RightsMask&PRSFS_INSERT)
		printf("i");
	    if(position->RightsMask&PRSFS_DELETE)
		printf("d");
	    if(position->RightsMask&PRSFS_WRITE)
		printf("w");
	    if(position->RightsMask&PRSFS_LOCK)
		printf("k");
	    if(position->RightsMask&PRSFS_ADMINISTER)
		printf("a");
	    printf("\n");
	    position=position->next;
	}
    }
    if(acl->NumNegativeEntries) {
	printf("Negative rights:\n");

	position=acl->neg;
	for(i=0;i<acl->NumNegativeEntries;i++) {
	    printf("  %s ", position->name);
	    if(position->RightsMask&PRSFS_READ)
		printf("r");
	    if(position->RightsMask&PRSFS_LOOKUP)
		printf("l");
	    if(position->RightsMask&PRSFS_INSERT)
		printf("i");
	    if(position->RightsMask&PRSFS_DELETE)
		printf("d");
	    if(position->RightsMask&PRSFS_WRITE)
		printf("w");
	    if(position->RightsMask&PRSFS_LOCK)
		printf("k");
	    if(position->RightsMask&PRSFS_ADMINISTER)
		printf("a");
	    printf("\n");
	    position=position->next;
	}
    }
}

static int
arla_listacl (int argc, char **argv)
{
    unsigned int i;

    argc--;
    argv++;

    if(!argc)
      afs_listacl(NULL);
    else
      for(i=0;i<argc;i++) {
	if(i)
	  printf("\n");
	afs_listacl(argv[i]);
      }

    return 0;
}

static int
arla_fs (int argc, char **argv)
{
    unsigned int i;

    if (argc == 1) {
	printf("usage: %s <command> <arguments>\n", argv[0]);
	return 0;
    }

    argc--;
    argv++;

    if (strcmp(argv[0], "la") == 0) {
	arla_listacl(argc, argv);
    }

    return 0;
}



#if 0

static int
get_cred(const char *princ, const char *inst, const char *krealm, 
         CREDENTIALS *c)
{
  KTEXT_ST foo;
  int k_errno;

  k_errno = krb_get_cred((char*)princ, (char*)inst, (char*)krealm, c);

  if(k_errno != KSUCCESS) {
    k_errno = krb_mk_req(&foo, (char*)princ, (char*)inst, (char*)krealm, 0);
    if (k_errno == KSUCCESS)
      k_errno = krb_get_cred((char*)princ, (char*)inst, (char*)krealm, c);
  }
  return k_errno;
}

#endif

struct get_dir_context {
    int allocated;
    int current;
    char *text;
    char **names;
    VenusFid dir_fid;
    CredCacheEntry *ce;
    char *dirname;
    int onlydir;
};

static uint32_t
get_file_type(VenusFid fid, VenusFid parent_fid, CredCacheEntry *ce)
{
    int ret;
    FCacheEntry *entry;
    uint32_t filetype;

    ret = fcache_get(&entry, fid, ce);
    if (ret) {
	printf("fcache_get: %d\n", ret);
	return 0;
    }

    ret = fcache_verify_attr(entry, NULL, NULL, ce);
    if (ret) {
	fcache_release(entry);
	if (ret == EACCES) {
	    return 0;
	}
	printf("fcache_verify_attr: %d\n", ret);
	return 0;
    }

    if (entry->flags.mountp) {
	fcache_release(entry);
	return TYPE_DIR;
    }
    
    ret = cm_getattr (entry, ce);
    if (ret) {
	fcache_release(entry);
	printf ("cm_getattr: %d\n", ret);
	return 0;
    }
    
    filetype = entry->status.FileType;

    fcache_release(entry);

    return filetype;
}

static int
insert_dir_entry(VenusFid *fid, const char *name, void *v)
{
    struct get_dir_context *context = (struct get_dir_context *) v;

    if (strncmp(name, context->text, strlen(context->text)) == 0) {

	if (VenusFid_cmp(fid, &context->dir_fid) == 0)
	    return 0;

	uint32_t filetype = get_file_type(*fid, context->dir_fid, context->ce);

	if (filetype == TYPE_DIR || filetype == TYPE_LINK || !context->onlydir) {
	    char *s;
	    char *slash = filetype == TYPE_DIR ? "/" : " ";

	    if (strcmp(context->dirname, ".") == 0) {
		asprintf(&s, "%s%s", name, slash);
	    } else {
		asprintf(&s, "%s/%s%s", context->dirname, name, slash);
	    }
	    context->names[context->current] = s;
	    context->current++;
	    if (context->current >= context->allocated) {
		void *p;
		context->allocated *= 2;
		p = realloc(context->names, context->allocated * sizeof(char*));
		if (p == NULL) {
		    arla_errx(1, ADEBERROR, "realloc %lu recovered_map failed",
		              (unsigned long) context->allocated);
		    exit(1);
		}
		context->names = p;
	    }
	}

    }

    return 0;
}

static char**
get_dir(VenusFid dir, const char *path, int onlydir) {
    char *basename = copy_basename(path);
    char *dirname = copy_dirname(path);

    int error;
    struct get_dir_context context;
    FCacheEntry *entry;

    VenusFid res;

    error = cm_walk(cwd, dirname, &res);
    if (error) {
	printf ("cm_walk failed: %s\n", koerr_gettext(error));
	free(basename);
	free(dirname);
        return NULL;
    }

    CredCacheEntry *ce;
    ce = cred_get (res.Cell, getuid(), CRED_ANY);

    context.allocated = 100;
    context.names = malloc(context.allocated * sizeof(char*));
    context.current = 0;
    context.text = basename;
    context.dir_fid = res;
    context.dirname = dirname;
    context.onlydir = onlydir;
    
    error = fcache_get(&entry, res, ce);
    if (error) {
	printf ("fcache_get failed: %s\n", koerr_gettext(error));
	free(basename);
	free(dirname);
	cred_free(ce);
	return NULL;
    }

    error = fcache_get_data (&entry, &ce, 0, 0);
    if (error) {
	printf ("fcache_get_data failed: %s\n", koerr_gettext(error));
	free(basename);
	free(dirname);
	fcache_release(entry);
	cred_free(ce);
	return NULL;
    }

    context.ce = ce;

    error = adir_readdir (&entry, insert_dir_entry,
			  &context, &ce);
    fcache_release(entry);
    if (error) {
	printf ("adir_readdir failed: %s\n", koerr_gettext(error));
	free(basename);
	free(dirname);
	cred_free(ce);
	return NULL;
    }

    free(basename);
    free(dirname);

    context.names[context.current] = NULL;

    cred_free(ce);

    return context.names;
}

static char **completion_names;

static char *
afs_directory_generator(const char *text, int state)
{
    static int current = 0;

    if (state == 0) {
	completion_names = get_dir(cwd, text, 1);
	current = 0;
	if (completion_names == NULL) {
	    return NULL;
	}
    }
    
    return completion_names[current++];
}

static char *
afs_file_generator(const char *text, int state)
{
    static int current = 0;

    if (state == 0) {
	completion_names = get_dir(cwd, text, 0);
	current = 0;
	if (completion_names == NULL) {
	    return NULL;
	}
    }
    
    return completion_names[current++];
}

static char *
null_generator(const char *text, int state)
{
    return NULL;
}

static char *
command_generator(const char *text, int state)
{
    static int list_index;

    if (state == 0) {
	list_index = 0;
    }

    const char *name;

    while (cmds[list_index].name) {
	name = cmds[list_index].name;
	list_index++;
	if (strncmp(name, text, strlen(text)) == 0) {
	    char *s;
	    asprintf(&s, "%s ", name);
	    return s;
	}
    }

    return NULL;
}

static char **
get_completion(const char *text, int start, int end)
{
    int ret;
    int argc;
    char **argv;
    char *line = strdup(rl_line_buffer);
    char **matches = NULL;

    ret = sl_make_argv(line, &argc, &argv);
    if (ret) {
	free(line);
	return NULL;
    }

    int argno = -1;
    int i;
    for (i = 0; i < argc; i++) {
	if (argv[i] - line == start) {
	    argno = i;
	    break;
	}
#if 0
	fprintf(stderr, "get_completion: arg %d(%d): %s\n",
		i, argv[i] - line, argv[i]);
#endif
    }

    char *command;
    if (argc > 0) {
	command = argv[0];
    } else {
	command = "";
    }

    if (start == 0) {
	matches = completion_matches(text, command_generator);
    } else if (strcmp(command, "cd") == 0) {
	matches = completion_matches(text, afs_directory_generator);
    } else if (strcmp(command, "ls") == 0) {
	matches = completion_matches(text, afs_file_generator);
    } else if (strcmp(command, "cat") == 0) {
	matches = completion_matches(text, afs_file_generator);
    }

    if (completion_names != NULL) {
        free(completion_names);
	completion_names = NULL;
    }

#if 0
    fprintf(stderr, "get_completion: %s %d\n", command, argno);
#endif

    free(line);
    free(argv);

#if 0
    fprintf(stderr, "get_completion: %s %d %d\n", text, start, end);
#endif
    return matches;
}

static void
arla_start (char *device_file, const char *cache_dir, int argc, char **argv)
{
    int error;

#if 0
    {
	struct cred_rxkad cred;
	CREDENTIALS c;
	int ret;
	char *realm;
	const char *this_cell = cell_getthiscell ();
	const char *db_server = cell_findnamedbbyname (this_cell);
	
	if (db_server == NULL)
	    arla_errx (1, ADEBERROR,
		       "no db server for cell %s", this_cell);
	realm = krb_realmofhost (db_server);
	
	ret = get_cred("afs", this_cell, realm, &c);
	if (ret)
	    ret = get_cred("afs", "", realm, &c);
	
	if (ret) {
	    arla_warnx (ADEBWARN,
			"getting ticket for %s: %s",
			this_cell,
			krb_get_err_text (ret));
	    return;
	} 
	
	memset(&cred, 0, sizeof(cred));

	memcpy(&cred.ct.HandShakeKey, c.session, sizeof(cred.ct.AuthHandle));
	cred.ct.AuthHandle = c.kvno;
	cred.ct.ViceId = getuid();
	cred.ct.BeginTimestamp = c.issue_date + 1;
	cred.ct.EndTimestamp = krb_life_to_time(c.issue_date, c.lifetime);
	
	cred.ticket_len = c.ticket_st.length;
	if (cred.ticket_len > sizeof(cred.ticket))
	    arla_errx (1, ADEBERROR, "ticket too large");
	memcpy(cred.ticket, c.ticket_st.dat, cred.ticket_len);

	cred_add (getuid(), CRED_KRB4, 2, cell_name2num(cell_getthiscell()), 
		  2, &cred, sizeof(cred), getuid());
	
    }
#endif

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
    arla_warnx(ADEBINIT, "arla loop started");
    error = 0;
    rl_attempted_completion_function = get_completion;
    rl_completion_entry_function = null_generator;
    rl_completion_append_character = '\0';
    if (argc > 0) {
	error = sl_command(cmds, argc, argv);
	if (error == -1)
	    errx (1, "%s: Unknown command\n", argv[0]); 
    } else {
	sl_loop(cmds, "arla> ");
    }
    store_state();
    fcache_giveup_all_callbacks();
    if (error)
	exit(1);
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
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "[command]");
    exit (ret);
}

int
main (int argc, char **argv)
{
    int optind = 0;
    int ret;

    setprogname (argv[0]);
    tzset();
    srand(time(NULL));

    if (getarg (args, sizeof(args)/sizeof(*args), argc, argv, &optind))
	usage (1);

    argc -= optind;
    argv += optind;

    if (help_flag)
	usage (0);

    if (version_flag) {
	print_version (NULL);
	exit (0);
    }
    
    default_log_file = "/dev/stderr";

    ret = arla_init();
    if (ret)
	return ret;

    {
	struct timeval tv = { 0, 10000} ;
	IOMGR_Select(0, NULL, NULL, NULL, &tv);
    }

    arla_start (NULL, cache_dir, argc, argv);
    
    return 0;
}
