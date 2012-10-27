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

/*
 * This is the cache for files.
 * The hash-table is keyed with (cell, volume, fid).
 */

#include "arla_local.h"
RCSID("$Id: fcache.c,v 1.455 2007/01/24 17:12:06 tol Exp $") ;

#include <nnpfs/nnpfs_queue.h>

#ifdef __CYGWIN32__
#include <windows.h>
#endif

/*
 * Prototypes
 */

static int get_attr_bulk (FCacheEntry *parent_entry, 
			  FCacheEntry *prefered_entry,
			  VenusFid *prefered_fid,
			  const char *prefered_name,
			  CredCacheEntry *ce);

static int
resolve_mp(FCacheEntry *e, VenusFid *ret_fid, CredCacheEntry **ce);

static int
fcache_want_bytes(uint64_t wanted);

static int
fcache_need_bytes(uint64_t needed);
 
static int
fcache_verify_data(FCacheEntry *e, CredCacheEntry *ce,
		   uint64_t offset, uint64_t end);

static void
setbusy_block(struct block *b, Bool val);

static void
throw_block(struct block *b, Bool usagep);

static int
fcache_update_usage(FCacheEntry *e, int nblocks);

/*
 * Local data for this module.
 */

/*
 * Hash table for all the nodes known by the cache manager keyed by
 * (cell, volume, vnode, unique).
 */

static Hashtab *hashtab;

/*
 * LRU lists, sorted sorted in LRU-order.  The head is the MRU and the
 * tail the LRU, which is from where we get entries when we have no
 * free ones left.
 */

/*
 * List of all nodes known to kernel.
 */

static List *kernel_node_lru;

/*
 * List of all nodes in hashtab that are not known to kernel.
 */

static List *node_lru;

/*
 * Pool of all nodes not in `hashtab'.
 */

static List *free_nodes;

/*
 * List of all data blocks known to kernel.
 */

static List *kernel_block_lru;

/*
 * List of all data blocks not known to kernel.
 */

static List *block_lru;


/*
 * Heap of entries to be invalidated.
 */

static Heap *invalid_heap;

/* low and high-water marks for vnodes and space */

static u_long highvnodes, lowvnodes, current_vnodes;
static int64_t highbytes, lowbytes;


/* block size used in cache */

static uint64_t blocksize;

/* current values */

static int64_t usedbytes, needbytes, wantbytes;
static u_long usedvnodes;

static int64_t appendquota, appendquota_used;

/* Map with recovered nodes */

static uint32_t maxrecovered;

static char *recovered_map;


/* Handling fair lock queue */

struct lock_waiter {
    FCacheEntry *entry;		/* NULL for empty slots */
    NNPQUEUE_ENTRY(lock_waiter) queue;
    struct {
	unsigned gcp : 1;	/* Accepts gc-flagged entry? */
    } flags;
};

NNPQUEUE_HEAD(locks_head, lock_waiter);
static struct locks_head *lockwaiters;
static unsigned num_locks;

static const AFSCallBack broken_callback = {0, 0, CBDROPPED};

static void
set_recovered(uint32_t index)
{
    char *p;
    u_long oldmax;

    if (index >= maxrecovered) {
	oldmax = maxrecovered;
	maxrecovered = (index + 16) * 2;
	p = realloc(recovered_map, maxrecovered);
	if (p == NULL) {
	    arla_errx(1, ADEBERROR, "fcache: realloc %lu recovered_map failed",
		      (unsigned long)maxrecovered);
	}
	recovered_map = p;
	memset(recovered_map + oldmax, 0, maxrecovered - oldmax);
    }
    recovered_map[index] = 1;
}

#define IS_RECOVERED(index) (recovered_map[(index)])

/* 
 * This is how far the cleaner will go to clean out entries.
 * The higher this is, the higher the risk is that you will
 * lose any file that you feel is important to disconnected
 * operation. 
 */

Bool fprioritylevel = arla_FPRIO_DEFAULT;

static uint32_t node_count = NNPFS_NO_INDEX; /* XXX */

/*
 * This is set to non-zero when we want to use bulkstatus().  2 means
 * that the nodes should be installed into the kernel.
 */

static int fcache_enable_bulkstatus = 1;
static int fcache_bulkstatus_num = 14; /* XXX should use the [P]MTU */

#define FCHASHSIZE 997

/*
 * The cleaner
 */

#define CLEANER_SLEEP 10

static PROCESS cleaner_pid;

#define CLEANER_MARKER   (void*)4711

/*
 * The creator of nodes.
 */

static PROCESS create_nodes_pid;

/*
 * The invalidator
 */

static PROCESS invalidator_pid;

/*
 * Smalltalk emulation
 */

int64_t
fcache_highbytes(void)
{
    return highbytes;
}

int64_t
fcache_usedbytes(void)
{
    return usedbytes - appendquota + appendquota_used;
}

int64_t
fcache_lowbytes(void)
{
    return lowbytes;
}

u_long
fcache_highvnodes(void)
{
    return highvnodes;
}

u_long
fcache_usedvnodes(void)
{
    return usedvnodes;
}

u_long
fcache_lowvnodes(void)
{
    return lowvnodes;
}


uint64_t
fcache_getblocksize(void)
{
    return blocksize;
}

void
fcache_setblocksize(uint64_t newsize)
{
    blocksize = newsize;
}


/*
 * Fair lock handling:
 * locked nodes are flagged with `locked'
 * nodes with lock queue are flagged with `lockwait'
 */

static struct locks_head *
find_lock_head(FCacheEntry *node)
{
    int i;
    if (node->flags.lockwait) {
	for (i = 0; i < num_locks; i++) {
	    struct lock_waiter *w = NNPQUEUE_FIRST(&lockwaiters[i]);
	    if (w && w->entry == node)
		return &lockwaiters[i];
	}
	assert(0);
    }
    for (i = 0; i < num_locks; i++)
	if (NNPQUEUE_EMPTY(&lockwaiters[i]))
	    return &lockwaiters[i];
    
    assert(0); /* XXX overflow */
    return NULL;
}

static void
take_lock(FCacheEntry *node)
{
    assert(CheckLock(&node->lock) == 0);
    ObtainWriteLock(&node->lock);
    node->flags.locked = TRUE;
}

static Bool
fcache_islocked(FCacheEntry *e)
{
    return e->flags.locked;
}

/*
 * Lock `node'
 *
 * Caller accepts lock on a gcp-flagged node iff `gcp' is TRUE.
 */

static void
fcache_lock(FCacheEntry *node, Bool gcp)
{
    struct locks_head *head;
    struct lock_waiter me;

    /* grab the lock if we can */
    if (!node->flags.locked && (!node->flags.gcp || gcp))
	return take_lock(node);
    
    NNPQUEUE_INIT_ENTRY(&me, queue);
    me.entry = node;
    me.flags.gcp = gcp;
    head = find_lock_head(node);

    /* worker_setdebuginfo("lockwait"); */

    node->flags.lockwait = TRUE;
    NNPQUEUE_INSERT_TAIL(head, &me, queue);
    LWP_WaitProcess(&me);
    
    assert(node->flags.locked);
    assert(gcp || !node->flags.gcp);

    NNPQUEUE_REMOVE(&me, head, queue);
    if (NNPQUEUE_EMPTY(head))
	node->flags.lockwait = FALSE;
    
    return take_lock(node);
}

static void
fcache_unlock(FCacheEntry *node)
{
    struct locks_head *head;
    struct lock_waiter *next = NULL;
    struct lock_waiter *w;

    assert(node->flags.locked);
    AssertExclLocked(&node->lock);
    ReleaseWriteLock(&node->lock);
    
    if (!node->flags.lockwait) {
	node->flags.locked = FALSE;
	return;
    }

    head = find_lock_head(node);
    if (node->flags.gcp) {
	NNPQUEUE_FOREACH(w, head, queue) {
	    if (w->flags.gcp) {
		next = w;
		break;
	    }
	}
    } else {
	next = NNPQUEUE_FIRST(head);
	assert(next);
    }

    if (next)
	LWP_NoYieldSignal(next);
    else
	node->flags.locked = FALSE;
}

/*
 * Allocate some appropriate append quota for nnpfs and return the
 * value.  Should be called only once.
 *
 * XXX config option, better defaults.
 */

int64_t
fcache_set_appendquota(void)
{
    int64_t newquota, diff;

    assert(num_workers > 2);

    newquota = (num_workers - 2) * blocksize;
    assert(lowbytes > newquota);

    if (newquota > lowbytes/2)
	newquota = block_offset(lowbytes/3);

    (void)fcache_need_bytes(newquota); /* XXX best effort */

    diff = newquota - appendquota;
    appendquota = newquota;
    usedbytes += diff;
    
    /* appendquota_used may now be larger than quota.  That's ok. */

    return diff;
}

/*
 * Counters
 */

static struct {
    unsigned long fetch_attr;
    unsigned long fetch_attr_cached;
    unsigned long fetch_attr_bulk;
    unsigned long fetch_data;
    unsigned long fetch_data_cached;
    unsigned long store_attr;
    unsigned long store_data;
} fcache_counter;

/*
 * Compare two entries. Return 0 if and only if the same.
 */

static int
fcachecmp (void *a, void *b)
{
    FCacheEntry *f1 = (FCacheEntry*)a;
    FCacheEntry *f2 = (FCacheEntry*)b;

    return VenusFid_cmp(&f1->fid, &f2->fid);
}

/*
 * Hash the value of an entry.
 */

static unsigned
fcachehash (void *e)
{
    FCacheEntry *f = (FCacheEntry*)e;

    return f->fid.Cell + f->fid.fid.Volume + f->fid.fid.Vnode 
	+ f->fid.fid.Unique;
}

/*
 * Compare expiration times.
 */

static int
expiration_time_cmp (const void *a, const void *b)
{
    const FCacheEntry *f1 = (const FCacheEntry *)a;
    const FCacheEntry *f2 = (const FCacheEntry *)b;

    return f1->callback.ExpirationTime - f2->callback.ExpirationTime;
}

void
recon_hashtabadd(FCacheEntry *entry)
{
    hashtabadd(hashtab,entry);
}
 
void
recon_hashtabdel(FCacheEntry *entry)
{
    hashtabdel(hashtab,entry);
}

/*
 * Globalnames 
 */

char **sysnamelist = NULL;
int sysnamenum = 0;

/*
 *
 */

static void
fcache_poller_unref(FCacheEntry *e)
{
    AssertExclLocked(&e->lock);

    if (e->poll) {
	poller_remove(e->poll);
	e->poll = NULL;
    }
}

static void
fcache_poller_reref(FCacheEntry *e, ConnCacheEntry *conn)
{
    PollerEntry *pe = e->poll;
    AssertExclLocked(&e->lock);

    e->poll = poller_add_conn(conn);
    if (pe)
	poller_remove(pe);
}


/*
 * true if nobody is working on the entry
 */

static Bool
unreferenced(FCacheEntry *e)
{
    if (!fcache_islocked(e) && e->refcount == 0)
	return TRUE;
    
    return FALSE;
}

/*
 *
 */

const char *
fcache_getdefsysname (void)
{
    if (sysnamenum == 0)
	return "fool-dont-remove-all-sysnames";
    return sysnamelist[0];
}

/*
 *
 */

int
fcache_setdefsysname (const char *sysname)
{
    if (sysnamenum == 0)
	return fcache_addsysname (sysname);
    free (sysnamelist[0]);
    sysnamelist[0] = estrdup (sysname);
    return 0;
}

/*
 *
 */

int
fcache_addsysname (const char *sysname)
{
    sysnamenum += 1;
    sysnamelist = erealloc (sysnamelist, 
			    sysnamenum * sizeof(char *));
    sysnamelist[sysnamenum - 1] = estrdup(sysname);
    return 0;
}

/*
 *
 */

int
fcache_removesysname (const char *sysname)
{
    int i;
    for (i = 0; i < sysnamenum; i++)
	if (strcmp (sysnamelist[i], sysname) == 0)
	    break;
    if (i == sysnamenum)
	return 1;
    free (sysnamelist[i]);
    for (;i < sysnamenum; i++)
	sysnamelist[i] = sysnamelist[i + 1];
    sysnamenum--;
    sysnamelist = erealloc (sysnamelist, 
			    sysnamenum * sizeof(char *));
    return 0;
}

/*
 * The node is busy, flag it and wait for signal so we can retry our
 * operation.
 */

static void
wait_busy(FCacheEntry *entry)
{
    entry->flags.waiters = TRUE;
    fcache_unlock(entry);
    LWP_WaitProcess(entry);
    fcache_lock(entry, FALSE);
}

/*
 * Wake any waiters for node and clear flag.
 */

static void
wake_waiters(FCacheEntry *e)
{
    if (e->flags.waiters) {
	e->flags.waiters = FALSE;
	LWP_NoYieldSignal(e);
    }
}

/*
 * Check the wanted data range's presence in cache, return first block
 * not already cached in *offset and *end
 *
 * Needed blocks found         -> BLOCK_GOT
 * No additional blocks needed -> BLOCK_NONE
 * Only busy blocks needed     -> BLOCK_BUSY
 */

static BlockState
first_wanted_range(FCacheEntry *entry,
		   uint64_t wanted_offset, uint64_t wanted_end,
		   uint64_t *offset, uint64_t *end)
{
    int busyp = 0;
    uint64_t i;

    AssertExclLocked(&entry->lock);

    assert(wanted_offset <= wanted_end);

    /* find first block that's not in cache */
    for (i = block_offset(wanted_offset); i < wanted_end; i += blocksize) {
	struct block *block = block_get(entry, i);
	if (!block) {
	    *offset = i;
	    break;
	}
	if (block->flags.busy)
	    busyp = 1;
    }

    if (i >= wanted_end) {
	if (busyp)
	    return BLOCK_BUSY;
	else
	    return BLOCK_NONE; /* entire wanted range is already in cache */
    }

    /* find first block present in cache after that one */
    for (i += blocksize; i < wanted_end; i += blocksize) {
	if (block_get(entry, i))
	    break;
    }
    *end = i;

    return BLOCK_GOT;
}

/*
 * Check the wanted data range's presence in cache.
 * Only block presence is considered.
 */

static Bool
fcache_have_wanted(FCacheEntry *entry, uint64_t offset, uint64_t end)
{
    uint64_t i;

    AssertExclLocked(&entry->lock);

    assert(offset <= end);

    for (i = block_offset(offset); i < end; i += blocksize) {
	struct block *block = block_get(entry, i);
	if (!block || block->flags.busy)
	    return FALSE;
    }

    return TRUE;
}

/*
 * return the first directory name of the cached file for `entry'
 */

int
fcache_dir_name (FCacheEntry *entry, char *s, size_t len)
{
    return snprintf (s, len, NNPFS_CACHE_FILE_DIR1, entry->index / 0x100);
}

/*
 * return the second directory name of the cached file for `entry'.
 */

static int
fcache_file_name (FCacheEntry *entry, char *s, size_t len)
{
    return snprintf (s, len, NNPFS_CACHE_FILE_DIR_PATH,
		     entry->index / 0x100, entry->index % 0x100);
}

/*
 * return the file name of the cached file for `entry' and  `offset'.
 */

static int
fcache_block_name (FCacheEntry *entry, uint64_t offset, char *s, size_t len)
{
    uint64_t index = offset / blocksize;
    return snprintf (s, len, NNPFS_CACHE_FILE_PATH, /* XXX windows */
		     entry->index / 0x100, entry->index % 0x100,
		     (unsigned long long)index);
}

/*
 * the filename for the extra (converted) directory
 * XXX no blocks here for now
 */

static int
real_extra_file_name (FCacheEntry *entry, char *s, size_t len)
{
    return snprintf(s, len, NNPFS_CACHE_DIR_PATH, /* XXX windows */
		    entry->index / 0x100, entry->index % 0x100);
}

/*
 * return the file name of the converted directory for `entry'.
 */

int
fcache_extra_file_name (FCacheEntry *entry, char *s, size_t len)
{
    assert (entry->flags.extradirp &&
	    entry->status.FileType == TYPE_DIR);

    return real_extra_file_name (entry, s, len);
}

#if 0

static int fhopen_working;

/*
 * open file by handle
 */

static int
fcache_fhopen (fcache_cache_handle *handle, int flags)
{
    if (!handle->valid) {
	errno = EINVAL;
	return -1;
    }

#if defined(HAVE_GETFH) && defined(HAVE_FHOPEN)
    {
	int ret;
	fhandle_t fh;

	memcpy (&fh, &handle->nnpfs_handle, sizeof(fh));
	ret = fhopen (&fh, flags);
	if (ret >= 0)
	    return ret;
    }
#endif

    errno = EINVAL;
    return -1;
}
#endif

/*
 * get the handle of `filename'
 */

int
fcache_fhget (char *filename, fcache_cache_handle *handle)
{
    handle->valid = 0;
    errno = EINVAL;
    return -1;

#if 0 /* block cache */
#ifdef __CYGWIN32__
    {
	int ret, a, b;
	char buf[1024];

	ret = sscanf(filename, "%02X/%02X", &a, &b);
	if (ret != 2)
	    return EINVAL;

	GetCurrentDirectory(sizeof(buf)-1, buf);
	buf[sizeof(buf) - 1] = '\0';
	
	ret = snprintf((char *)handle->nnpfs_handle, 
		       sizeof(handle->nnpfs_handle),
		       "%s\\%02X\\%02X", buf, a, b);

	if (ret > 0 && ret < sizeof(handle->nnpfs_handle))
	    handle->valid = 1;

	return ret;
    }
#endif

#if 0
#if defined(HAVE_GETFH) && defined(HAVE_FHOPEN)
    {
	int ret;
	fhandle_t fh;

	ret = getfh (filename, &fh);
	if (ret == 0) {
	    memcpy (&handle->nnpfs_handle, &fh, sizeof(fh));
	    handle->valid = 1;
	}

	return ret;
    }
#endif
#endif

#ifdef KERBEROS
    {
	struct arlaViceIoctl vice_ioctl;
	int ret;
	
	if (!fhopen_working)
	    return 0;
	
	vice_ioctl.in      = NULL;
	vice_ioctl.in_size = 0;
	
	vice_ioctl.out      = (caddr_t)&handle->nnpfs_handle;
	vice_ioctl.out_size = sizeof(handle->nnpfs_handle);
	
	ret = k_pioctl (filename, ARLA_VIOC_FHGET, (void *)&vice_ioctl, 0);
	if (ret == 0)
	    handle->valid = 1;

	return ret;
    }
#else
    errno = EINVAL;
    return -1;
#endif
#endif
}

static void
make_dir(FCacheEntry *entry, const char *dirname)
{
    int bits = 0700;
    int ret;
    (void)unlink(dirname); /* old implementation used files, remove if so */

    ret = mkdir(dirname, bits);
    if (ret < 0 && errno != EEXIST) {
	if (errno == ENOENT) {
	    char parent[MAXPATHLEN];
	    
	    fcache_dir_name(entry, parent, sizeof(parent));
	    ret = mkdir(parent, bits);
	    if (ret < 0)
		arla_err (1, ADEBERROR, errno, "mkdir %s", parent);
	    ret = mkdir(dirname, bits);
	    if (ret < 0)
		arla_err (1, ADEBERROR, errno, "mkdir %s", dirname);
	} else {
	    arla_err (1, ADEBERROR, errno, "mkdir %s", dirname);
	}
    }
}

/*
 * Get ourselves a clean cache dir, creating it if necessary.
 *
 * We always keep the first block as arlad/nnpfs traditionally
 * depended on there being a cache file for every node, for
 * attributes and data length, maybe more.
 *
 * XXX It may be time to remove this oddity.  Would it add or
 * remove special cases?
 */

static void
make_clean_dir(FCacheEntry *entry)
{
    char name[MAXPATHLEN];
    char dirname[MAXPATHLEN];
    struct dirent *dp;
    DIR *dir;
    int ret;

    fcache_file_name (entry, dirname, sizeof(dirname));

    dir = opendir(dirname);
    if (dir == NULL) {
	make_dir(entry, dirname);
	return;
    }

    while ((dp = readdir(dir)) != NULL) {
	if (strcmp(dp->d_name, ".") == 0
	    || strcmp(dp->d_name, "..") == 0
	    || strcmp(dp->d_name, "00") == 0)
	    continue;

	ret = snprintf(name, sizeof(name), "%s/%s", dirname, dp->d_name);
	if (ret <= 0 || ret >= sizeof(name))
	    err (1, "dirname %s/%s", dirname, dp->d_name);
	
	ret = unlink(name);
	if (ret)
	    err (1, "unlink %s", name);
    }
    closedir(dir);
}

/*
 * create a new cache vnode, assume the entry is locked or private
 */

static int
fcache_create_file (FCacheEntry *entry, int create)
{
    char bname[MAXPATHLEN];
    char extra_fname[MAXPATHLEN];
    int fd;

    if (create) {
	int flags = O_RDWR | O_BINARY | O_CREAT | O_TRUNC;
	
	if (use_o_largefile)
	    flags |= O_LARGEFILE;

	make_clean_dir(entry);

	fcache_block_name (entry, 0, bname, sizeof(bname));
	fd = open(bname, flags, 0600);
	if (fd < 0)
	    arla_err (1, ADEBERROR, errno, "open %s", bname);
	if (close (fd) < 0)
	    arla_err (1, ADEBERROR, errno, "close %s", bname);
    }

    real_extra_file_name (entry, extra_fname, sizeof(extra_fname));
    unlink (extra_fname);
    return 0;
}

/*
 * Transfer used append quota to ordinary usage.  `e' will be flagged
 * with gcp and unlocked temporarily, this is to keep it from being
 * locked by other operations while we may need to gc blocks from it.
 *
 * Give back quota to kernel, if any, and return error code.
 */

int
fcache_update_appendquota(FCacheEntry *e)
{
    int64_t diff;
    static int nthreads;
    int ret = 0;

    AssertExclLocked(&e->lock);
    assert(appendquota_used >= 0);

    if (!appendquota_used)
	return 0;

    worker_setdebuginfo("gc");
    assert(!e->flags.gcp);

    e->flags.gcp = TRUE;
    fcache_unlock(e);

    do {
	if (!nthreads) {
	    diff = appendquota_used;
	    if (!diff)
		return 0;
	} else {
	    diff = blocksize;
	}

	nthreads++;
	ret = fcache_want_bytes(diff);
	nthreads--;
    } while (ret && !nthreads);
    
    fcache_lock(e, TRUE);
    e->flags.gcp = FALSE;
    
    LWP_NoYieldSignal(e);
    
    worker_setdebuginfo("not gc");
    
    if (ret)
	return 0;

    assert(appendquota_used >= 0);

    if (appendquota_used < diff)
	diff = appendquota_used;
    appendquota_used -= diff;
    usedbytes += diff;
    
    assert(appendquota_used >= 0);
    /* assert(appendquota_used <= appendquota); not on cache size change */

    return install_appendquota(diff);
}

/*
 * Create a block and set kernelp.
 */

int
fcache_append_block(FCacheEntry *e, uint64_t offset)
{
    struct block *b;
    assert(block_offset(offset) == offset);
    
    appendquota_used += blocksize;
    e->usage += blocksize;
    /* assert(appendquota_used <= appendquota); not on cache size change */
    
    b = block_add(e, offset);
    b->flags.kernelp = TRUE;
    b->lru_le = listaddhead(kernel_block_lru, b);
    assert(b->lru_le);

    return 0;
}

/*
 * Create a block, setting kernelp as indicated.
 */

static int
create_block(FCacheEntry *e, uint64_t offset)
{
    struct block *b;
    int ret;
    assert(block_offset(offset) == offset);
    
    worker_setdebuginfo("gc");

    ret = fcache_update_usage(e, 1);

    worker_setdebuginfo("not gc");

    if (ret)
	return ret;
    
    b = block_add(e, offset);
    b->flags.kernelp = FALSE;
    b->lru_le = listaddhead(block_lru, b);
    
    assert(b->lru_le);

    return ret;
}

/*
 * Return true if the node exists.
 */

Bool
fcache_block_exists(FCacheEntry *entry, uint64_t offset)
{
    struct block *block = block_get(entry, offset);
    if (!block)
	return FALSE;

    return TRUE;
}

/*
 * return a fd to the cache file of `entry' or -1 on failure
 */

int
fcache_open_block(FCacheEntry *entry, uint64_t offset, Bool writep)
{
    char fname[MAXPATHLEN];
    int flags = O_BINARY;
    Bool exists;

    if (use_o_largefile)
        flags |= O_LARGEFILE;

    if (writep)
	flags |= O_RDWR;
    else
	flags |= O_RDONLY;

    exists = fcache_block_exists(entry, offset);
    if (writep) {
	if (!exists) {
	    int ret = create_block(entry, offset);
	    if (ret) {
		errno = ret;
		return -1;
	    }

	    flags |= O_CREAT;
	}
    } else {
	if (!exists) {
	    arla_warnx (ADEBWARN, "Tried to read nonexistent block");
	    assert(0);
	    errno = EIO;
	    return -1;
	}
    }

#if 0
    if (fhopen_working) {
	ret = fcache_fhopen (&entry->handle, flags);
	if (ret < 0 && (errno == EINVAL || errno == EPERM))
	    fhopen_working = 0;
	else
	    return ret;
    }
#endif

    fcache_block_name(entry, offset, fname, sizeof(fname));
    return open(fname, flags, 0600);
}

/*
 * Create blocks for a new range without accounting, mark them busy.
 * Returns the number of blocks created (for future accounting).
 */

static int
create_busy_blocks(FCacheEntry *entry, uint64_t offset, uint64_t end)
{
    char fname[MAXPATHLEN];
    struct block *b;
    uint64_t off;
    int fd;
    int i = 0;

    AssertExclLocked(&entry->lock);
 
    for (off = offset; off < end; off += blocksize) {
	fcache_block_name(entry, off, fname, sizeof(fname));
	fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd < 0) {
	    fd = errno;
	    arla_warnx(ADEBWARN, "create_busy_blocks: "
		       "creat failed at offset 0x%llx\n",
		       (unsigned long long)off);
	    errno = fd;
	    return -1;
	}
	close(fd);
	b = block_add(entry, off);
	b->lru_le = listaddhead(block_lru, b);
	b->flags.busy = TRUE;
	i++;
    }

    return i;
}

/*
 * Clean up after create_busy_blocks(), removing any blocks beyond
 * what was actually received.  Iff `usagep' is set, update cache
 * usage.
 */

static void
delete_unbusy_blocks(FCacheEntry *entry, uint64_t offset,
		     uint64_t end, uint64_t guessed_end, Bool usagep)
{
    uint64_t off;
    
    fcache_data_setbusy(entry, offset, end, FALSE);
	
    for (off = end; off < guessed_end; off += blocksize) {
	struct block *b = block_get(entry, off);
	setbusy_block(b, FALSE);
	throw_block(b, usagep);
    }
    wake_waiters(entry);
}

/*
 * return a fd to the converted directory for `entry'
 */

int
fcache_open_extra_dir (FCacheEntry *entry, int flag, mode_t mode)
{
    char fname[MAXPATHLEN];

    assert (entry->flags.extradirp &&
	    entry->status.FileType == TYPE_DIR);

    fcache_extra_file_name (entry, fname, sizeof(fname));
    return open (fname, flag | O_BINARY, mode);
}

/*
 *
 */

uint64_t
fcache_get_status_length(const AFSFetchStatus *status)
{
    return status->Length | ((uint64_t)status->LengthHigh << 32);
}

void
fcache_set_status_length(AFSFetchStatus *status, int64_t length)
{
    status->Length = length & 0xffffffff;
    status->LengthHigh = length >> 32;
}

/*
 * Discard a cached data block for `entry'.
 */

static void
throw_block(struct block *b, Bool usagep)
{
    FCacheEntry *entry = b->node;
    char fname[MAXPATHLEN];
    uint64_t offset = b->offset;

    AssertExclLocked(&entry->lock);
    assert(!b->flags.busy);
    
    if (b->flags.kernelp)
	listdel(kernel_block_lru, b->lru_le);
    else
	listdel(block_lru, b->lru_le);

    block_free(b);
    fcache_block_name(entry, offset, fname, sizeof(fname));

    if (offset == 0)
	truncate(fname, 0);
    else
	unlink(fname);

    if (usagep)
	(void)fcache_update_usage(entry, -1);
}

/*
 * Discard a cached data block for `entry' and update accounting.
 */

void
fcache_throw_block(struct block *b)
{
    throw_block(b, TRUE);
}

/*
 * Discard the data cached for `entry'.
 */

static void
throw_data (FCacheEntry *entry)
{
    int ret;

    AssertExclLocked(&entry->lock);
    assert (entry->flags.usedp);
    assert(usedbytes >= entry->usage);

    entry->flags.stale = FALSE;
    entry->flags.dirtied = FALSE;
    
    arla_log(ADEBVLOG, "throw_data(%d, %u, %u, %u): usage %llu",
	     entry->fid.Cell, entry->fid.fid.Volume,
	     entry->fid.fid.Vnode, entry->fid.fid.Unique,
	     (unsigned long long)entry->usage);

    if (block_emptyp(entry)) {
	assert(entry->usage == 0);
	return;
    }

    ret = abuf_purge(entry);
    if (ret) {
	/* XXX set dirtied/stale again? */
	arla_warn (ADEBFCACHE, ret, "abuf_purge");
	goto out;
    }

    assert(block_emptyp(entry));

    if (entry->flags.extradirp) {
	char fname[MAXPATHLEN];
 
	fcache_extra_file_name (entry, fname, sizeof(fname));
	unlink (fname);
	entry->flags.extradirp = FALSE;
    }

    assert(entry->usage == 0);

 out:
    cm_check_consistency();
}

/*
 * A probe function for a file server.
 */

int
fs_probe (struct rx_connection *conn)
{
    uint32_t sec, usec;

    return RXAFS_GetTime (conn, &sec, &usec);
}

/*
 * Clean a locked node.
 *
 * The caller must not touch the node afterwards.
 * This function may yield.
 */

static void
throw_entry (FCacheEntry *entry)
{
    CredCacheEntry *ce;
    ConnCacheEntry *conn;
    AFSCBFids fids;
    AFSCBs cbs;
    int ret;

    assert (entry->flags.usedp);
    assert (!entry->flags.kernelp);

    AssertExclLocked(&entry->lock);
    assert(LockWaiters(&entry->lock) == 0);
    assert(entry->refcount == 0);

    hashtabdel (hashtab, entry);
    listdel(node_lru, entry->lru_le);

    throw_data (entry);

    if (entry->invalid_ptr != -1) {
	heap_remove (invalid_heap, entry->invalid_ptr);
	entry->invalid_ptr = -1;
    }

    fcache_poller_unref(entry);

    if (entry->flags.attrp && !entry->flags.silly && entry->host) {
	ce = cred_get (entry->fid.Cell, 0, CRED_NONE);
	assert (ce != NULL);
	
	conn = conn_get (entry->fid.Cell, entry->host, afsport,
			 FS_SERVICE_ID, fs_probe, ce);
	cred_free (ce);
	
	fids.len = cbs.len = 1;
	fids.val = &entry->fid.fid;
	cbs.val  = &entry->callback;

	if (conn_isalivep (conn)) {
	    ret = RXAFS_GiveUpCallBacks(conn->connection, &fids, &cbs);
	    if (host_downp(ret)) {
		conn_dead (conn);
		ret = ENETDOWN;
	    }
	} else
	    ret = ENETDOWN;
	conn_free (conn);
	if (ret)
	    arla_warn (ADEBFCACHE, ret, "RXAFS_GiveUpCallBacks");
    }
    if (entry->volume) {
	volcache_free (entry->volume);
	entry->volume = NULL;
    }
    assert_not_flag(entry,kernelp);
    entry->flags.attrp = FALSE;
    entry->flags.usedp = FALSE;
    entry->lru_le = listaddtail(free_nodes, entry);
    assert(entry->lru_le);
    --usedvnodes;
    fcache_unlock(entry);
    LWP_NoYieldSignal(free_nodes);
}

/*
 * Return the next cache node number.
 */

static uint32_t
next_cache_index (void)
{
    do {
	node_count++;
    } while ((node_count < maxrecovered)
	     && IS_RECOVERED(node_count));
    
    return node_count;
}

/*
 * Pre-create cache nodes up to the limit highvnodes.  If you want to
 * create more increase highnodes and signal create_nodes.
 */

static void
create_nodes (char *arg)
{
    FCacheEntry *entries;
    unsigned count = 0;
    struct timeval tv;

    while (1) {
       	unsigned int n, i, j;

	while (highvnodes <= current_vnodes)
	    LWP_WaitProcess (create_nodes);

	n = highvnodes - current_vnodes;

	count = 0;
	
	arla_warnx (ADEBFCACHE,
		    "pre-creating nodes");
	
	entries = calloc (n, sizeof(FCacheEntry));
	if (n != 0 && entries == NULL)
	    arla_errx (1, ADEBERROR, "fcache: calloc failed");
	
	for (i = 0; i < n; ++i) {
	    entries[i].invalid_ptr = -1;
	    entries[i].volume      = NULL;
	    entries[i].refcount    = 0;
	    entries[i].anonaccess  = 0;
	    entries[i].poll = NULL;
	    for (j = 0; j < NACCESS; j++) {
		entries[i].acccache[j].cred = ARLA_NO_AUTH_CRED;
		entries[i].acccache[j].access = 0;
	    }
	    entries[i].usage       = 0;
	    entries[i].blocks      = listnew();
	    assert(entries[i].blocks);

	    Lock_Init(&entries[i].lock);
	    entries[i].index = next_cache_index ();
	    fcache_create_file (&entries[i], 1);

	    current_vnodes++;

	    ++count;
	    tv.tv_sec = 0;
	    tv.tv_usec = 1000;

	    entries[i].lru_le      = listaddhead(free_nodes, &entries[i]);
	    assert (entries[i].lru_le);

	    LWP_NoYieldSignal (free_nodes);
	    IOMGR_Select(0, NULL, NULL, NULL, &tv);
	}

	arla_warnx (ADEBFCACHE,
		    "pre-created %u nodes", count);
    }
}

/*
 * This is the almighty cleaner loop
 */

static Bool cleaner_working = FALSE;
static Bool cleaner_force = FALSE;
static int cleaner_npending;

/*
 * manage count of pending gc ops.
 */

void
fcache_cleaner_ref(void)
{
    cleaner_npending++;
}

void
fcache_cleaner_deref(void)
{
    cleaner_npending--;
    assert(cleaner_npending >= 0);
    if (!cleaner_npending)
	LWP_NoYieldSignal(&cleaner_npending);
}

/*
 * make sure we wait until all ops triggered by the gc message have
 * been processed. putdata does take some time, should be batched.
 */

static void
cleaner_gc_wait(void)
{
    IOMGR_Poll();
    while (cleaner_npending)
	LWP_WaitProcess(&cleaner_npending);
}

/*
 * Try to trim nodes off the node LRU:s until we reach the low water
 * mark.
 */

static void
cleaner_gc_nodes(void)
{
    struct nnpfs_message_gc msg;
    Listitem *item, *prev;
    FCacheEntry *entry;
    Listitem *kmarker;

    int numnodes = NNPFS_GC_MAX_HANDLE;
    int cnt = 0;
    Bool found_kmarker = FALSE;
    
    kmarker = listaddhead(kernel_node_lru, CLEANER_MARKER);
    assert(kmarker);

    /*
     * XXX it would be better if kernel handled this
     */
    for (item = listtail(kernel_node_lru);
	 item && item != kmarker;
	 item = prev) {
	prev = listprev(kernel_node_lru, item);
	entry = (FCacheEntry *)listdata(item);
	
	if (entry->flags.silly && unreferenced(entry)) {
	    memcpy(&msg.handle[cnt].node, &entry->fid,
		   sizeof(msg.handle[0].node));
	    msg.handle[cnt].offset = NNPFS_NO_OFFSET;
	    cnt++;
	    
	    if (cnt >= numnodes) {
		nnpfs_send_message_gc(kernel_fd, &msg, cnt);
		cnt = 0;
	    }
	}
    }
    
    if (cnt > 0) {
	nnpfs_send_message_gc(kernel_fd, &msg, cnt);
	cleaner_gc_wait();
	cnt = 0;
    }


    while (usedvnodes > lowvnodes) {
	Listitem *nmarker = listaddhead(node_lru, CLEANER_MARKER);
	assert(nmarker);

	while ((item = listtail(node_lru)) != NULL
	       && item != nmarker
	       && usedvnodes > lowvnodes) {
	    entry = (FCacheEntry *)listdata(item);
	    
	    if (unreferenced(entry)) {
		/* if (this_is_a_good_node_to_gc(entry,state)) */
		/* XXX fprio */
		
		fcache_lock(entry, FALSE); /* should be clean */
		throw_entry(entry); /* releases lock and sleeps */
	    } else {
		fcache_node_lru(entry);
	    }
	}
	listdel(node_lru, nmarker);
	
	if (found_kmarker)
	    break;

	for (item = listtail(kernel_node_lru);
	     item && item != kmarker && usedvnodes > lowvnodes;
	     item = prev) {
	    prev = listprev(kernel_node_lru, item);
	    entry = (FCacheEntry *)listdata(item);
	    
	    if (unreferenced(entry)) {
		/* if (this_is_a_good_node_to_gc(entry,state)) */
		/* XXX fprio */
		
		fcache_node_lru(entry);

		memcpy(&msg.handle[cnt].node, &entry->fid,
		       sizeof(msg.handle[0].node));
		msg.handle[cnt].offset = NNPFS_NO_OFFSET;
		cnt++;

		if (cnt >= numnodes)
		    break;
	    }
	}
	
	if (cnt > 0) {
	    nnpfs_send_message_gc(kernel_fd, &msg, cnt);
	    cleaner_gc_wait();	    
	    cnt = 0;
	}

	/* We've traversed the entire kernel node list, time to bail out. */
	if (item == kmarker)
	    found_kmarker = TRUE;
    }

    listdel(kernel_node_lru, kmarker);
}

/*
 * Return true if this looks like a good block to gc.
 */

static Bool
good_block_to_gc(struct block *b)
{
    FCacheEntry *entry = b->node;

    if (fcache_islocked(entry))
	return FALSE;

    if (b->flags.busy) {
#if 0
	arla_warnx(ADEBWARN, "busy block (%ld.%lu.%lu.%lu) @%llu",
		   (long)entry->fid.Cell,
		   (unsigned long)entry->fid.fid.Volume,
		   (unsigned long)entry->fid.fid.Vnode,
		   (unsigned long)entry->fid.fid.Unique,
		   (unsigned long long)b->offset);
#endif
	return FALSE;
    }
    
    if (entry->flags.silly && entry->flags.kernelp)
	return FALSE;
    
    if (entry->status.FileType != TYPE_DIR)
	return TRUE;

    if (!entry->flags.datausedp)
	return TRUE;
    
    if (cleaner_force)
	return TRUE;
    
    return FALSE;
}

/*
 * GC block if it's possible and looks like a good idea.
 *
 * Return true if the block is gone.
 */

static Bool
gc_block_maybe(struct block *b)
{
    if (good_block_to_gc(b)) {
	FCacheEntry *entry = b->node;
	
	/* For directories, throw all or nothing */
	if (entry->status.FileType == TYPE_DIR) {
	    if (unreferenced(entry)) {
		fcache_lock(entry, FALSE); /* should be clean */
		throw_data(entry);
		fcache_unlock(entry);
	    }
	} else {
	    Bool locked = fcache_islocked(entry);
	    if (!locked)
		fcache_lock(entry, TRUE);

	    throw_block(b, TRUE);

	    if (!locked)
		fcache_unlock(entry);
	}
	return TRUE;
    }
    return FALSE;
}

/*
 * Return target value for usedbytes.
 */

static int64_t
target_usedbytes(void) {
    return min(lowbytes, highbytes - needbytes - wantbytes);
}

/*
 * Get more space by evicting blocks off of the block LRU lists. 
 *
 * XXX don't loop forever
 */

static void
cleaner_gc_blocks(void)
{
    struct nnpfs_message_gc msg;
    struct block *entry;
    Listitem *item, *prev;
    Listitem *marker;
    int64_t usedtarget = target_usedbytes();

    int numblocks = NNPFS_GC_MAX_HANDLE;
    int cnt = 0;
    Bool found_marker = FALSE;

    marker = listaddhead(kernel_block_lru, CLEANER_MARKER);
    assert(marker);

    while (usedbytes > usedtarget) {
	Listitem *last = NULL;

	/*
	 * First, release non-kernel blocks.  No context switching in
	 * this loop.  Directory blocks may be thrown several at a
	 * time, so we need to take extra care.  Fortunately, blocks
	 * we've already passed and not thrown can be trusted as long
	 * as we avoid context switches.
	 */
	while (usedbytes > usedtarget) {
	    if (last)
		item = listprev(block_lru, last);
	    else
		item = listtail(block_lru);
	    
	    if (!item)
		break;

	    entry = (struct block *)listdata(item);
	    
	    if (!gc_block_maybe(entry))
		last = item;
	}
	
	if (found_marker)
	    break;

	for (item = listtail(kernel_block_lru);
	     item && item != marker && usedbytes > usedtarget;
	     item = prev) {
	    prev = listprev(kernel_block_lru, item);
	    entry = (struct block *)listdata(item);
	    
	    if (good_block_to_gc(entry)) { 
		listdel(kernel_block_lru, item);
		entry->lru_le = listaddhead(kernel_block_lru, entry);

		memcpy(&msg.handle[cnt].node, &entry->node->fid,
		       sizeof(msg.handle[0].node));
		
		/*
		 * XXX overkill to gc entire node for dirs. invalidnode?
		 */
		if (entry->node->status.FileType == TYPE_DIR)
		    msg.handle[cnt].offset = NNPFS_NO_OFFSET;
		else
 		    msg.handle[cnt].offset = entry->offset;
		
		cnt++;
		if (cnt >= numblocks)
		    break;
	    }
	}
	
	if (cnt > 0) {
	    nnpfs_send_message_gc(kernel_fd, &msg, cnt);
	    cleaner_gc_wait();	    
	    usedtarget = target_usedbytes();
	    cnt = 0;
	}

	/* We've traversed the entire kernel node list, time to bail out. */
	if (item == marker)
	    found_marker = TRUE;
    }

    listdel(kernel_block_lru, marker);
}

static void
cleaner (char *arg)
{
    while (TRUE) {
	int i;
	arla_warnx (ADEBCLEANER,
		    "running cleaner: "
		    "%lu (%lu-(%lu)-%lu) files, "
		    "%lu (%lu-%lu) bytes "
		    "%lu needed bytes "
		    "%lu wanted bytes",
		    usedvnodes, lowvnodes, current_vnodes, highvnodes,
		    (long)usedbytes, (long)lowbytes, (long)highbytes,
		    (long)needbytes, (long)wantbytes);
	cleaner_working = TRUE;

	for (i = 0; i < 3; i++) {
	    /*
	     * Releasing nodes may give us data space as a side effect, so we
	     * check the nodes first.
	     */
	    cm_check_consistency();

	    if (i == 1)
		cleaner_force = TRUE;
	    else
		cleaner_force = FALSE;

	    cleaner_gc_nodes();
	    cm_check_consistency();
	    cleaner_gc_blocks();
	    
	    if (target_usedbytes() >= usedbytes)
		break;
	}

	arla_warnx(ADEBCLEANER,
		   "cleaner done: "
		   "%lu (%lu-(%lu)-%lu) files, "
		   "%ld (%ld-%ld) bytes "
		   "%ld needed bytes "
		   "%lu wanted bytes",
		   usedvnodes, lowvnodes, current_vnodes, highvnodes,
		   (long)usedbytes, (long)lowbytes, (long)highbytes,
		   (long)needbytes, (long)wantbytes);
	
	cm_check_consistency();
	if (needbytes || wantbytes)
	    LWP_NoYieldSignal(fcache_need_bytes);
	cleaner_working = FALSE;
	IOMGR_Sleep (CLEANER_SLEEP);
    }
}

static void
fcache_wakeup_cleaner (void *wait)
{
    worker_setdebuginfo("wake cleaner");
    if (cleaner_working == FALSE)
	IOMGR_Cancel (cleaner_pid);
    worker_setdebuginfo("wait cleaner");
    LWP_WaitProcess (wait);
    worker_setdebuginfo("waited cleaner");
}

/*
 * Try to allocate 'wanted' bytes of space. May trigger GC.
 */

static int
fcache_want_bytes(uint64_t wanted)
{
    int ret = 0;
    wantbytes += wanted;

    assert(wantbytes >= 0);

    if (usedbytes + needbytes + wantbytes > highbytes)
	fcache_wakeup_cleaner(fcache_need_bytes);
    
    if (usedbytes + needbytes + wantbytes > highbytes)
	ret = ENOSPC;

    wantbytes -= wanted;
    return ret;
}

/*
 * Reserve 'needed' bytes of space. May trigger GC.
 */

static int
fcache_need_bytes(uint64_t needed)
{
    int ret = 0;
    needbytes += needed;

    assert(needbytes >= 0);

    if (usedbytes + needbytes > highbytes)
	fcache_wakeup_cleaner(fcache_need_bytes);

    if (usedbytes + needbytes > highbytes) {
	arla_warnx(ADEBWARN, 
		   "Out of space, couldn't get needed bytes after cleaner "
		   "(%lu bytes missing, %lu used, %lu highbytes)",
		   (long)(needbytes - (highbytes - usedbytes)), 
		   (long)usedbytes, (long)highbytes);
	ret = ENOSPC;
    }
    
    needbytes -= needed;

    return ret;
}

/*
 * Run through the heap of objects to be invalidated and throw them away
 * when their expirationtime arrive.
 */

static void
invalidator (char *arg)
{
    for (;;) {
	const void *head;
	struct timeval tv;

	arla_warnx(ADEBINVALIDATOR,
		   "running invalidator");

	while ((head = heap_head (invalid_heap)) == NULL)
	    LWP_WaitProcess (invalid_heap);

	gettimeofday (&tv, NULL);

	while ((head = heap_head (invalid_heap)) != NULL) {
	    FCacheEntry *entry = (FCacheEntry *)head;

	    if (tv.tv_sec < entry->callback.ExpirationTime) {
		unsigned long t = entry->callback.ExpirationTime - tv.tv_sec;

		arla_warnx (ADEBINVALIDATOR,
			    "invalidator: sleeping for %lu second(s)", t);
		IOMGR_Sleep (t);
		break;
	    }

	    fcache_lock(entry, FALSE);
	    if (head == heap_head (invalid_heap)) {
		heap_remove_head (invalid_heap);
		entry->invalid_ptr = -1;
		if (entry->flags.kernelp)
		    break_callback (entry);
		fcache_poller_unref(entry);
	    }
	    fcache_unlock(entry);
	}
    }
}

/*
 * Add `entry' to the list of entries to invalidate when its time is
 * up.
 */

static void
add_to_invalidate (FCacheEntry *e)
{
    if (e->invalid_ptr != -1)
	heap_remove (invalid_heap, e->invalid_ptr);
    heap_insert (invalid_heap, (const void *)e, &e->invalid_ptr);
    LWP_NoYieldSignal (invalid_heap);
    IOMGR_Cancel(invalidator_pid);
}

/*
 * Return a usable locked entry.
 * If there are no free entries, sleep until there is.
 */

static FCacheEntry *
find_free_entry (void)
{
    FCacheEntry *entry = NULL;
    Listitem *item;

    while ((item = listtail(free_nodes)) == NULL) {
	arla_warnx (ADEBFCACHE, "find_free_entry: sleeping");
	fcache_wakeup_cleaner(free_nodes);
    }
    
    /* Entries on the freelist should not be locked. */
    entry = (FCacheEntry *)listdata(item);
    assert_not_flag(entry,usedp);
    fcache_lock(entry, FALSE); /* should be clean */
    listdel(free_nodes, entry->lru_le);
    entry->lru_le = NULL;

    ++usedvnodes;

    return entry;
}

/*
 *
 */

struct fstore_context {
    Listitem *item;
    unsigned n;
};

static int
fcache_store_entry (struct fcache_store *st, void *ptr)
{
    struct fstore_context *c;
    FCacheEntry *entry;

    c = (struct fstore_context *)ptr;
    if (c->item == NULL)		/* check if done ? */
	return STORE_DONE;

    entry = (FCacheEntry *)listdata (c->item);
    c->item = listprev (node_lru, c->item);

    if (!entry->flags.usedp)
	return STORE_SKIP;
    
    strlcpy(st->cell, cell_num2name(entry->fid.Cell), sizeof(st->cell));
    st->fid		= entry->fid.fid;
    st->refcount	= entry->refcount;
    st->length		= entry->usage;
    st->fetched_length	= 0; /* XXX */
    st->volsync		= entry->volsync;
    st->status		= entry->status;
    st->anonaccess	= entry->anonaccess;
    st->index		= entry->index;
    st->flags.attrp	= entry->flags.attrp;
    st->flags.datap	= entry->usage ? TRUE : FALSE;
    st->flags.extradirp = entry->flags.extradirp;
    st->flags.mountp    = entry->flags.mountp;
    st->flags.fake_mp   = entry->flags.fake_mp;
    st->flags.vol_root  = entry->flags.vol_root;
    strlcpy(st->parentcell, cell_num2name(entry->parent.Cell), 
	    sizeof(st->parentcell));
    st->parent		= entry->parent.fid;
    st->priority	= entry->priority;
    
    c->n++;
    return STORE_NEXT;
}

/*
 *
 */

int
fcache_store_state (void)
{
    struct fstore_context c;
    int ret;

    if (node_lru == NULL) {
	arla_warnx (ADEBFCACHE, "store_state: node_lru is NULL\n");
	return 0;
    }

    c.item = listtail(node_lru);
    c.n = 0;

    ret = state_store_fcache("fcache", fcache_store_entry, &c);
    if (ret)
	arla_warn(ADEBWARN, ret, "failed to write fcache state");
    else
	arla_warnx (ADEBFCACHE, "wrote %u entries to fcache", c.n);

    return 0;
}

/*
 *
 */

static int
fcache_recover_entry (struct fcache_store *st, void *ptr)
{
    unsigned *n = (unsigned *)ptr;

    CredCacheEntry *ce;
    FCacheEntry *e;
    int i;
    VolCacheEntry *vol;
    int res;
    int32_t cellid;

    cellid = cell_name2num(st->cell);
    assert (cellid != -1);
    
    ce = cred_get (cellid, 0, 0);
    assert (ce != NULL);
    
    res = volcache_getbyid (st->fid.Volume, cellid, ce, &vol, NULL);
    cred_free (ce);
    if (res)
	return 0;
    assert(vol);
    
    e = calloc(1, sizeof(FCacheEntry));
    e->invalid_ptr = -1;
    Lock_Init(&e->lock);
    fcache_lock(e, FALSE);
    

    e->fid.Cell = cellid;
    e->fid.fid  = st->fid;
    e->host     = 0;
    e->status   = st->status;
    e->usage   = st->length;
    /* e->fetched_length = st->fetched_length; */
    e->callback = broken_callback;
    e->volsync  = st->volsync;
    e->refcount = st->refcount;
    
    /* Better not restore the rights. pags don't have to be the same */
    for (i = 0; i < NACCESS; ++i) {
	e->acccache[i].cred = ARLA_NO_AUTH_CRED;
	e->acccache[i].access = ANONE;
    }
    
    e->anonaccess = st->anonaccess;
    e->index      = st->index;
    fcache_create_file(e, 0);
    set_recovered(e->index);
    e->flags.usedp = TRUE;
    e->flags.attrp = st->flags.attrp;
    /* st->flags.datap */
    e->flags.attrusedp = FALSE;
    e->flags.datausedp = FALSE;
    e->flags.kernelp   = FALSE;
    e->flags.extradirp = st->flags.extradirp;
    e->flags.mountp    = st->flags.mountp;
    e->flags.fake_mp   = st->flags.fake_mp;
    e->flags.vol_root  = st->flags.vol_root;
    e->flags.sentenced = FALSE;
    e->flags.stale 	   = FALSE;
    e->flags.dirtied 	   = FALSE;
    e->flags.silly 	   = FALSE;
    e->flags.waiters 	   = FALSE;
    e->flags.gcp 	   = FALSE;
    e->flags.appended	   = FALSE;
    e->tokens	       = 0;
    e->parent.Cell = cell_name2num(st->parentcell);
    assert(e->parent.Cell != -1);
    e->parent.fid = st->parent;
    e->priority = st->priority;
    e->hits = 0;
    e->lru_le = listaddhead (node_lru, e);
    assert(e->lru_le);
    e->volume = vol;
    hashtabadd (hashtab, e);
    if (e->usage)
	usedbytes += e->usage;
    fcache_unlock(e);
    
    (*n)++;

    return 0;
}

/*
 *
 */

static void
fcache_recover_state (void)
{
    unsigned n;

    n = 0;
    state_recover_fcache("fcache", fcache_recover_entry, &n);

    arla_warnx (ADEBFCACHE, "recovered %u entries to fcache", n);
    current_vnodes = n;
}

/*
 * Search for `cred' in `ae' and return a pointer in `pos'.  If it
 * already exists return TRUE, else return FALSE and set pos to a
 * random slot.
 */

Bool
findaccess (nnpfs_pag_t cred, AccessEntry *ae, AccessEntry **pos)
{
    int i;

    for(i = 0; i < NACCESS ; ++i)
	if(ae[i].cred == cred) {
	    *pos = &ae[i];
	    return TRUE;
	}

    i = rand() % NACCESS;
    *pos = &ae[i];
    return FALSE;
}

/*
 *
 */


static int
fs_rtt_cmp (const void *v1, const void *v2)
{
    struct fs_server_entry *e1 = (struct fs_server_entry *)v1;
    struct fs_server_entry *e2 = (struct fs_server_entry *)v2;
    
    return conn_rtt_cmp(&e1->conn, &e2->conn);
}

/*
 * Initialize a `fs_server_context'.
 */

static void
init_fs_server_context (fs_server_context *context)
{
    context->num_conns = 0;
}

static long
find_partition (fs_server_context *context)
{
    int i = context->conns[context->i - 1].ve_ent;

    if (i < 0 || i >= context->ve->entry.nServers)
	return 0;
    return context->ve->entry.serverPartition[i];
}

/*
 * Find the next fileserver for the request in `context'.
 * Returns a ConnCacheEntry or NULL.
 */

ConnCacheEntry *
find_next_fs (fs_server_context *context,
	      ConnCacheEntry *prev_conn,
	      int error)
{
    if (error) {
	if (host_downp(error))
	    conn_dead (prev_conn);
	if (volume_downp(error))
	    volcache_mark_down (context->ve, 
				context->conns[context->i - 1].ve_ent,
				error);
    } else if (prev_conn) {
	assert(prev_conn == context->conns[context->i - 1].conn);
	volcache_reliable_el(context->ve, context->conns[context->i - 1].ve_ent);
    }

    if (context->i < context->num_conns)
	return context->conns[context->i++].conn;
    else
	return NULL;
}

/*
 * Clean up a `fs_server_context'
 */

void
free_fs_server_context (fs_server_context *context)
{
    int i;

    for (i = 0; i < context->num_conns; ++i)
	conn_free (context->conns[i].conn);

    if (context->ve)
	volcache_process_marks(context->ve);
}

/*
 * Find the the file servers housing the volume for `e' and store it
 * in the `context'.
 */

int
init_fs_context (FCacheEntry *e,
		 CredCacheEntry *ce,
		 fs_server_context *context)
{
    VolCacheEntry  *ve = e->volume;
    int i;
    int bit;
    int num_clones;
    int cell = e->fid.Cell;
    int ret;

    memset(context, 0, sizeof(*context));

    if (ve == NULL) {
	ret = volcache_getbyid (e->fid.fid.Volume, e->fid.Cell,
				ce, &e->volume, NULL);
	if (ret)
	    return ret;
	ve = e->volume;
    }

    ret = volume_make_uptodate (ve, ce);
    if (ret)
	return ret;

    bit = volcache_volid2bit (ve, e->fid.fid.Volume);

    if (bit == -1) {
	/* the volume entry is inconsistent. */
	volcache_invalidate_ve (ve);
	return ENOENT;
    }

    num_clones = 0;
    for (i = 0; i < min(NMAXNSERVERS,ve->entry.nServers); ++i) {
	u_long addr = htonl(ve->entry.serverNumber[i]);

	if (ve->entry.serverFlags[i] & bit
	    && addr != 0
	    && (ve->entry.serverFlags[i] & VLSF_DONTUSE) == 0) {
	    ConnCacheEntry *conn;

	    conn = conn_get (cell, addr, afsport,
			     FS_SERVICE_ID, fs_probe, ce);
	    if (!conn_isalivep (conn))
		conn->rtt = INT_MAX/2 ;
	    else if (!volcache_reliablep_el(ve, i))
		conn->rtt = INT_MAX/4;
	    else
		conn->rtt = rx_PeerOf(conn->connection)->srtt
		    + rand() % RTT_FUZZ - RTT_FUZZ / 2;
	    context->conns[num_clones].conn = conn;
	    context->conns[num_clones].ve_ent = i;
	    ++num_clones;
	}
    }

    if (num_clones == 0)
	return ENOENT;
    
    context->ve = ve;

    qsort (context->conns, num_clones, sizeof(*context->conns),
	   fs_rtt_cmp);

    context->num_conns = num_clones;
    context->i	       = 0;

    return 0;
}

/*
 * Find the first file server housing the volume for `e'.
 */

ConnCacheEntry *
find_first_fs (fs_server_context *context)
{
    return find_next_fs (context, NULL, 0);
}

/*
 * Initialize the file cache in `cachedir', with these values for high
 * and low-water marks.
 */

void
fcache_init (u_long alowvnodes,
	     u_long ahighvnodes,
	     int64_t alowbytes,
	     int64_t ahighbytes,
	     uint64_t ablocksize,
	     Bool recover)
{
    /*
     * Initialize all variables.
     */

    int i;

#if 0
#ifdef KERBEROS
    fhopen_working = k_hasafs ();
#else
    fhopen_working = 0;
#endif
#endif

    collectstats_init ();

    node_count     = 0;
    lowvnodes      = alowvnodes;
    highvnodes     = ahighvnodes;
    lowbytes       = alowbytes;
    highbytes      = ahighbytes;
    highbytes      = ahighbytes;
    blocksize      = ablocksize;

    if (cache_dir == NULL)
	cache_dir = getcwd(NULL, 0);

    if (cache_dir == NULL)
	arla_errx (1, ADEBERROR, "fcache: getcwd failed");

    hashtab      = hashtabnew (FCHASHSIZE, fcachecmp, fcachehash);
    if (hashtab == NULL)
	arla_errx (1, ADEBERROR, "fcache: hashtabnew failed");

    kernel_node_lru  = listnew();
    node_lru         = listnew();
    free_nodes       = listnew();
    kernel_block_lru = listnew();
    block_lru        = listnew();
    if (kernel_node_lru == NULL
	|| node_lru == NULL
	|| free_nodes == NULL
	|| kernel_block_lru == NULL
	|| block_lru == NULL)
	arla_errx (1, ADEBERROR, "fcache: listnew failed");

    invalid_heap = heap_new (ahighvnodes, expiration_time_cmp);
    if (invalid_heap == NULL)
	arla_errx (1, ADEBERROR, "fcache: heap_new failed");

    num_locks = num_workers + 8; /* a few for other threads */
    lockwaiters = malloc(num_locks * sizeof(*lockwaiters));
    if (lockwaiters == NULL)
	arla_errx(1, ADEBERROR, "fcache: malloc failed");

    for (i = 0; i < num_locks; i++)
	NNPQUEUE_INIT(&lockwaiters[i]);

    if (recover)
	fcache_recover_state ();

    if (LWP_CreateProcess (create_nodes, 0, 1, NULL, "fcache-create-nodes",
 			   &create_nodes_pid))
 	arla_errx (1, ADEBERROR,
 		   "fcache: cannot create create-nodes thread");

    if (LWP_CreateProcess (cleaner, 0, 1, NULL, "fcache-cleaner",
			   &cleaner_pid))
	arla_errx (1, ADEBERROR,
		   "fcache: cannot create cleaner thread");

    if (LWP_CreateProcess (invalidator, 0, 1, NULL, "fcache-invalidator",
			   &invalidator_pid))
	arla_errx (1, ADEBERROR,
		   "fcache: cannot create invalidator thread");
}

/*
 * set new values for those of lowvnodes, highvnodes that are not zero.
 * do some sanity checks
 * return 0 or an error code
 */

static int
fcache_setvnodes(u_long alowvnodes, 
		 u_long ahighvnodes)
{
    int64_t high = highvnodes;
    int64_t low = lowvnodes;

    arla_warnx (ADEBFCACHE, "fcache_setvnodes");
    
    if (ahighvnodes != 0)
	high = ahighvnodes;

    if (alowvnodes != 0)
	low = alowvnodes;

    if (high < low)
	return EINVAL;

    if (high > highvnodes)
	LWP_NoYieldSignal (create_nodes);

    highvnodes = high;
    lowvnodes = low;
	
    return 0;
}

/*
 * set new values for those of lowvnodes, highvnodes that are not zero.
 * do some sanity checks
 * return 0 or an error code
 */

static int
fcache_setbytes(int64_t alowbytes,
		int64_t ahighbytes)
{
    int64_t high = highbytes;
    int64_t low = lowbytes;
    int64_t quotadiff;

    arla_warnx (ADEBFCACHE, "fcache_setbytes");

    if (alowbytes != 0)
	low = alowbytes;

    if (ahighbytes != 0)
	high = ahighbytes;
    
    if (high < low)
	return EINVAL;

    highbytes = high;
    lowbytes = low;
    
    quotadiff = fcache_set_appendquota();
    return install_appendquota(quotadiff);
}

/*
 * set new high/low values for vnodes and bytes.
 * return 0 or an error code
 */

int
fcache_reinit(u_long alowvnodes,
	      u_long ahighvnodes,
	      int64_t alowbytes,
	      int64_t ahighbytes)
{
    int error = fcache_setvnodes(alowvnodes, ahighvnodes);
    if (error)
	return error;

    return fcache_setbytes(alowbytes, ahighbytes);
}

/*
 * Node has been touched, move to head of LRU list.
 */

void
fcache_node_lru(FCacheEntry *e)
{
    if (e->flags.kernelp) {
	listdel(kernel_node_lru, e->lru_le);
	e->lru_le = listaddhead(kernel_node_lru, e);
    } else {
	listdel(node_lru, e->lru_le);
	e->lru_le = listaddhead(node_lru, e);
    }

    assert(e->lru_le);
}

/*
 * Block has been touched, move it to head of LRU list.
 */

void
fcache_block_lru(struct block *b)
{
    if (b->flags.kernelp) {
	listdel(kernel_block_lru, b->lru_le);
	b->lru_le = listaddhead(kernel_block_lru, b);
    } else {
	listdel(block_lru, b->lru_le);
	b->lru_le = listaddhead(block_lru, b);
    }

    assert(b->lru_le);

    /* fcache_node_lru(b->node); XXX hopefully happens anyway */
}

static void
data_unkernel_callback(struct block *block, void *data)
{
    if (!block->flags.kernelp)
	return;

    block->flags.kernelp = FALSE;
    listdel(kernel_block_lru, block->lru_le);
    block->lru_le = listaddhead(block_lru, block);

    assert(block->lru_le);
}

/*
 * Node's kernelp is to be set to indicated value.
 *
 * XXX kernelp implies things about attrused, dataused, etc which we
 * should take care of here, too...  but what?
 */

void
fcache_node_setkernelp(FCacheEntry *e, Bool val)
{
    assert(val == TRUE || val == FALSE);

    if (e->flags.kernelp == val)
	return;
    
    if (!val)
	block_foreach(e, data_unkernel_callback, NULL);

    e->flags.kernelp = val;
    
    if (val) {
	listdel(node_lru, e->lru_le);
	e->lru_le = listaddhead(kernel_node_lru, e);
    } else {
	listdel(kernel_node_lru, e->lru_le);
	e->lru_le = listaddhead(node_lru, e);
    }

    assert(e->lru_le);
}

/*
 * Set a block's busy flag to `val'.
 */

static void
setbusy_block(struct block *b, Bool val)
{
    assert(b->flags.busy != val);
    b->flags.busy = val;
}

/*
 * Set busy flag to `val' for a range of blocks, wake any waiters.
 */

void
fcache_data_setbusy(FCacheEntry *e, uint64_t offset, uint64_t end,
		    Bool val)
{ 
    uint64_t off;

    assert(block_offset(offset) == offset);
    
    for (off = offset; off < end; off += blocksize) {
	struct block *b = block_get(e, off);
	setbusy_block(b, val);
    }
    wake_waiters(e);
}

/*
 * Block's kernelp is to be set to indicated value.
 */

void
fcache_data_setkernelp(FCacheEntry *e, uint64_t offset, Bool val, Bool unbusy)
{
    struct block *b;

    assert(block_offset(offset) == offset);
    
    AssertExclLocked(&e->lock);

    b = block_get(e, offset);
    if (!b) {
	assert(!val);
	assert(!unbusy);
	return;
    }

    if (unbusy) {
	setbusy_block(b, FALSE);
	wake_waiters(e);
    }

    if (b->flags.kernelp == val)
	return;
    
    b->flags.kernelp = val;
    
    if (val) {
	listdel(block_lru, b->lru_le);
	b->lru_le = listaddhead(kernel_block_lru, b);
    } else {
	listdel(kernel_block_lru, b->lru_le);
	b->lru_le = listaddhead(block_lru, b);
    }

    assert(b->lru_le);
}

/*
 * Find the entry for `fid' in the hash table.
 * If it's found, move it to the front of `node_lru' as well.
 */

static FCacheEntry *
find_entry_nolock (VenusFid fid)
{
    FCacheEntry key;
    FCacheEntry *e;

    if (hashtab == NULL)
	return NULL;

    key.fid = fid;
    e = (FCacheEntry *)hashtabsearch (hashtab, (void *)&key);
    if (e != NULL)
	fcache_node_lru(e);

    return e;
}

/*
 * Mark `e' as having `callback' and notify the kernel.
 * This might be overly harsh to opened files.
 */

static void
stale (FCacheEntry *e, AFSCallBack callback)
{
    if (callback.CallBackType == CBDROPPED &&
	e->callback.CallBackType == CBDROPPED)
	return;

    if (fcache_islocked(e) || e->refcount > 0)
	e->flags.sentenced = TRUE;
    else {
	fcache_lock(e, FALSE);
	fcache_poller_unref(e);
	e->callback = callback;

	if (e->flags.kernelp)
	    break_callback (e);
	else
	    e->tokens = 0;

	if (e->status.FileType == TYPE_DIR)
	    throw_data(e);
	fcache_unlock(e);
    }
}

struct stale_arg {
    VenusFid fid;
    AFSCallBack callback;
};

/*
 * Iterate over all entries until we find an entry that matches in
 * only fid (without cell) and stale it.
 */

static Bool
stale_unknown_cell (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;
    struct stale_arg *sa = (struct stale_arg *)arg;

    if (e->fid.fid.Volume    == sa->fid.fid.Volume
	&& e->fid.fid.Vnode  == sa->fid.fid.Vnode
	&& e->fid.fid.Unique == sa->fid.fid.Unique)
	stale (e, sa->callback);

    return FALSE;
}

/*
 * Call stale on the entry corresponding to `fid', if any.
 */

void
fcache_stale_entry (VenusFid fid, AFSCallBack callback)
{
    FCacheEntry *e;

    if (fid.Cell == -1) {
	struct stale_arg arg;

	arg.fid = fid;
	arg.callback = callback;

	hashtabforeach (hashtab, stale_unknown_cell, &arg);
	return;
    }

    e = find_entry_nolock (fid);
    if (e == NULL) {
	arla_warnx (ADEBFCACHE,
		    "callback for non-existing file (%d, %u, %u, %u)",
		    fid.Cell, fid.fid.Volume, fid.fid.Vnode, fid.fid.Unique);
	return;
    }
    stale (e, callback);
}

typedef struct {
    nnpfs_pag_t pag;
    int32_t cell;
} fc_purgecred;

/*
 * If ptr has cred arg, set it invalid
 */

static Bool
purge_cred (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;
    fc_purgecred *cred = (fc_purgecred *) arg;
    AccessEntry *ae = e->acccache;
    int i;

    if (e->fid.Cell == cred->cell ||  cred->cell == -1) {

	for(i = 0; i < NACCESS ; ++i)
	    if(ae[i].cred == cred->pag) {
		ae[i].cred = ARLA_NO_AUTH_CRED;
		ae[i].access = ANONE;
		if (e->flags.kernelp)
		    install_attr (e, FCACHE2NNPFSNODE_NO_LENGTH);
		break;
	    }
    }
    return FALSE;
}
    

/*
 * Mark cred as stale in kernel and all fcache-entries,
 * When cell == -1, flush all creds in this pag.
 */

void
fcache_purge_cred (nnpfs_pag_t pag, int32_t cell)
{
    fc_purgecred cred;

    cred.pag = pag;
    cred.cell = cell;

    hashtabforeach(hashtab, purge_cred, &cred);
}

/*
 * If ptr was retrieved from cell - volume , try to mark stale
 */

static Bool
purge_volume (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;
    VenusFid *fid = (VenusFid *) arg;

    if ((e->fid.Cell == fid->Cell || fid->Cell == -1)
	&& e->fid.fid.Volume == fid->fid.Volume) {
	stale (e, broken_callback);
    }
    return FALSE;
}

/*
 * Mark all entries from cell.volume as stale
 */

void
fcache_purge_volume (VenusFid fid)
{
    hashtabforeach(hashtab, purge_volume, &fid);
}

/*
 * If `ptr' was retrieved from `host', mark it as stale.
 */

static Bool
purge_host (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;
    u_long *host = (u_long *)arg;

    assert (*host);
    if (e->host == *host)
	stale (e, broken_callback);
    return FALSE;
}

/*
 * Mark all entries from the host `host' as stale.
 */

void
fcache_purge_host (u_long host)
{
    hashtabforeach (hashtab, purge_host, &host);
}


/*
 * If `ptr' is a mountpoint, mark it as stale.
 */

static Bool
invalidate_mp (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;
    if (e->flags.mountp)
	stale (e, broken_callback);
    return FALSE;
}

/*
 * Invalidate all mountpoints to force them to be reread.
 */

void
fcache_invalidate_mp (void)
{
    hashtabforeach (hashtab, invalidate_mp, NULL);
}

/*
 * Mark `entry' as not being used.
 */

void
fcache_unused (FCacheEntry *entry)
{
    AssertExclLocked(&entry->lock);

    assert(!entry->flags.appended || entry->flags.dirtied);
    assert(!entry->flags.kernelp);

    entry->flags.datausedp = entry->flags.attrusedp = FALSE;
    entry->tokens &= ~NNPFS_DATA_MASK;

    /* 
     * we don't signal free_nodes here since we never
     * free the node (usedvnode--);
     */

    /* throw stale and deleted-and-unreachable data */
    if (entry->flags.stale || entry->flags.dirtied || entry->flags.silly) {
	throw_data(entry); /* XXX overkill for volume callbacks etc */

	/* make sure we get fresh attrs. unnecessary for "stale" entries? */
	entry->flags.attrp = FALSE;
    }
}

/*
 * make up some status that might be valid for a mount-point
 */

static void
fake_mp_status (FCacheEntry *e)
{
    AFSFetchStatus *status = &e->status;

    status->FileType      = TYPE_DIR;
    status->LinkCount     = 100;
    status->UnixModeBits  = 0777;
    status->ClientModTime = 0;
    status->ServerModTime = 0;
    status->Owner         = 0;
    status->Group         = 0;
}

/*
 * Return true if `entry' is a mountpoint
 */

static Bool
mountpointp (FCacheEntry *entry)
{
    if (entry->status.FileType == TYPE_LINK
	&& fcache_get_status_length(&entry->status) != 0
	&& entry->status.UnixModeBits == 0644)
	return TRUE;
    return FALSE;
}

/*
 * Mark `entry' as mountpoint or a fake mountpoint depending on
 * fake_mp is used or not.
 */

void
fcache_mark_as_mountpoint (FCacheEntry *entry)
{
    if (fake_mp) {
	entry->flags.fake_mp = TRUE;
	fake_mp_status (entry);
    } else {
	entry->flags.mountp = TRUE;
    }
}

/*
 * Update all the relevant parts of `entry' after having received new
 * data from the file server.
 */

static void
update_entry (FCacheEntry *entry,
	      AFSFetchStatus *status,
	      AFSCallBack *callback,
	      AFSVolSync *volsync,
	      ConnCacheEntry *conn,
	      nnpfs_pag_t cred)
{
    struct timeval tv;
    AccessEntry *ae;
    unsigned long bitmask = 0141777; /* REG, DIR, STICKY, USR, GRP, OTH */

    if (entry->volume && cell_issuid_by_num (entry->volume->cell))
	bitmask |= 0006000; /* SUID, SGID */

    gettimeofday (&tv, NULL);

    entry->status   = *status;
    entry->status.UnixModeBits &= bitmask;
    if (callback) {
	entry->callback = *callback;
	entry->callback.ExpirationTime += tv.tv_sec;
	add_to_invalidate (entry);
    }
    if (volsync) {
	entry->volsync  = *volsync;
	if (entry->volume)
	    volcache_update_volsync (entry->volume, *volsync);
    }

    if (conn) {
	fcache_poller_reref(entry, conn);
	entry->host     = rx_HostOf(rx_PeerOf(conn->connection));
    } else {
	fcache_poller_unref(entry);
	entry->host = 0;
    }

    entry->anonaccess = status->AnonymousAccess;
    findaccess (cred, entry->acccache, &ae);
    ae->cred   = cred;
    ae->access = status->CallerAccess;
    if (!entry->flags.mountp && mountpointp (entry))
	fcache_mark_as_mountpoint (entry);
}

/*
 * Update entry, common code for do_read_attr and get_attr_bulk
 */

static void
update_attr_entry (FCacheEntry *entry,
		   AFSFetchStatus *status,
		   AFSCallBack *callback,
		   AFSVolSync *volsync,
		   ConnCacheEntry *conn,
		   nnpfs_pag_t cred)
{
    if (block_any(entry) != BLOCK_NONE
	&& entry->status.DataVersion != status->DataVersion) {

	if (entry->flags.datausedp) {
	    /* we need to mark entry as stale, or we won't be able to
	     * detect that once DataVersion has been updated
	     */
	    
	    /* actually, what we do need is to get rid of old
	     * data. there are two ways to do that. for us to get rid
	     * of all data we need kernel to drop the node. the other
	     * way is to send gc messages until the all data is out of
	     * kernel, but that's probably tricky to get right.
	     */

	    entry->flags.stale = TRUE;
	    arla_log(ADEBVLOG, "update_attr_entry(%d, %u, %u, %u): usage %llu",
		     entry->fid.Cell, entry->fid.fid.Volume,
		     entry->fid.fid.Vnode, entry->fid.fid.Unique,
		     (unsigned long long)entry->usage);
	    stale(entry, broken_callback);
	} else {
	    entry->tokens &= ~NNPFS_DATA_MASK;
	    throw_data(entry);
	}
    }
    
    update_entry (entry, status, callback, volsync,
		  conn, cred);
    
    entry->tokens |= NNPFS_ATTR_R;
    entry->flags.attrp = TRUE;
}

/*
 * We're about to update entry, if we have valid data we'll update
 * length ourselves when modifying the local cache. If data is stale,
 * throw it so we can get fresh.
 *
 * This depends on 
 * 1. Following code to do the actual update if all is well
 * 2. Following code to get new data if we have stale data
 *    (maybe we should do that here)
 */

static void
update_modify_dir(FCacheEntry *entry,
		  AFSFetchStatus *status,
		  AFSCallBack *callback,
		  AFSVolSync *volsync,
		  ConnCacheEntry *conn,
		  nnpfs_pag_t cred)
{
    entry->status.DataVersion++;
    
    if (block_any(entry) != BLOCK_NONE
	&& entry->status.DataVersion != status->DataVersion)
    {
	arla_warnx(ADEBWARN, "DataVersion mismatch, refreshing directory");
	
	throw_data(entry); /* XXX installed in kernel, but should be locked */
	entry->tokens &= ~NNPFS_DATA_MASK;

	/* XXX entry->flags.datausedp = FALSE; perhaps? */

	/* keep server's length so we know how much data to fetch */
    } else {
	uint64_t len = fcache_get_status_length(&entry->status);
	fcache_set_status_length(status, len);
    }

    update_entry(entry, status, callback, volsync, conn, cred);
}


/*
 * Give up all callbacks.
 */

static int
giveup_all_callbacks (uint32_t cell, uint32_t host, void *arg)
{
    CredCacheEntry *ce;	
    ConnCacheEntry *conn;
    int ret;

    ce = cred_get (cell, 0, CRED_ANY);
    assert (ce != NULL);
    
    conn = conn_get (cell, host, afsport, FS_SERVICE_ID, fs_probe, ce);
    cred_free (ce);

    if (conn_isalivep (conn)) {

	ret = RXAFS_GiveUpAllCallBacks(conn->connection);
	if (ret != 0 && ret != RXGEN_OPCODE) {
	    struct in_addr in_addr;
	
	    in_addr.s_addr = rx_HostOf(rx_PeerOf(conn->connection));
	    arla_warn (ADEBWARN, ret, "GiveUpAllCallBacks %s",
		       inet_ntoa (in_addr));
	    if (host_downp(ret)) {
		conn_dead (conn);
		ret = ENETDOWN;
	    }
	}
    }    

    conn_free (conn);

    return 0;
}

int
fcache_giveup_all_callbacks (void)
{
    Listitem *item;

    poller_foreach(giveup_all_callbacks, NULL);

    for (item = listtail(node_lru);
	 item != NULL;
	 item = listprev(node_lru, item)) {
	FCacheEntry *entry = (FCacheEntry *)listdata(item);

	if (entry->flags.attrp && 
	    entry->flags.silly == FALSE &&
	    entry->host != 0) {

	    CredCacheEntry *ce;	
	    ConnCacheEntry *conn;
	    AFSCBFids fids;
	    AFSCBs cbs;
	    int ret;

	    ce = cred_get (entry->fid.Cell, 0, CRED_ANY);
	    assert (ce != NULL);

	    conn = conn_get (entry->fid.Cell, entry->host, afsport,
			     FS_SERVICE_ID, fs_probe, ce);
	    cred_free (ce);

	    fids.len = cbs.len = 1;
	    fids.val = &entry->fid.fid;
	    cbs.val  = &entry->callback;
		
	    if (conn_isalivep (conn)) {
		ret = RXAFS_GiveUpCallBacks (conn->connection, &fids, &cbs);
		if (ret) {
		    struct in_addr in_addr;
		    
		    in_addr.s_addr = rx_HostOf(rx_PeerOf(conn->connection));
		    arla_warn (ADEBFCACHE, ret, "RXAFS_GiveUpCallBacks %s",
			       inet_ntoa (in_addr));
		}
	    }
	    conn_free (conn);
	}
    }
    return 0;			/* XXX */
}

/*
 * discard all cached attrs to force revalidation of entries
 * intended for reconnect after disconnected mode.
 */

void
fcache_discard_attrs(void)
{
    Listitem *item;
    
    for (item = listtail(node_lru);
	 item != NULL;
	 item = listprev(node_lru, item)) {
	FCacheEntry *entry = (FCacheEntry *)listdata(item);
	
	if (entry->flags.attrp && 
	    entry->flags.silly == FALSE)
	    entry->flags.attrp = FALSE;
    }
}

/*
 * Obtain new callbacks for all entries in the cache.
 */

int
fcache_reobtain_callbacks (struct nnpfs_cred *cred)
{
    Listitem *item;
    int ret;

    for (item = listtail(node_lru);
	 item != NULL;
	 item = listprev(node_lru, item)) {
	FCacheEntry *entry = (FCacheEntry *)listdata(item);

	fcache_lock(entry, FALSE);
	if (entry->flags.usedp && 
	    entry->flags.silly == FALSE &&
	    entry->host != 0) {

	    CredCacheEntry *ce;	
	    ConnCacheEntry *conn;
	    AFSFetchStatus status;
	    AFSCallBack callback;
	    AFSVolSync volsync;
	    VolCacheEntry *vol;

	    ce = cred_get (entry->fid.Cell, cred->pag, CRED_ANY);
	    assert (ce != NULL);

	    conn = conn_get (entry->fid.Cell, entry->host, afsport,
			     FS_SERVICE_ID, fs_probe, ce);
	    if (!conn_isalivep(conn))
		goto out;
	    /*
	     * does this belong here?
	     */

	    ret = volcache_getbyid (entry->fid.fid.Volume,
				    entry->fid.Cell, ce, &vol, NULL);
	    if (ret == 0)
		entry->volume = vol;

	    ret = RXAFS_FetchStatus (conn->connection,
				     &entry->fid.fid,
				     &status,
				     &callback,
				     &volsync);
	    if (ret)
		arla_warn (ADEBFCACHE, ret, "RXAFS_FetchStatus");
	    else {
		update_attr_entry (entry, &status, &callback, &volsync,
				   conn, ce->cred);
		if (entry->flags.kernelp)
		    break_callback (entry);
	    }
	    fcache_counter.fetch_attr++;
	out:
	    if (conn)
		conn_free (conn);
	    cred_free (ce);
	}
	fcache_unlock(entry);
    }
    return 0;			/* XXX */
}

/*
 * Return true iff there's any point in trying the next fs.
 *
 * XXX perhaps ut would be better reverse this and default to TRUE?
 */

static Bool
try_next_fs (int error, const VenusFid *fid)
{
    switch (error) {
#ifdef KERBEROS
    case RXKADUNKNOWNKEY:
#endif
    case ARLA_CALL_DEAD :
    case ARLA_INVALID_OPERATION :
    case ARLA_CALL_TIMEOUT :
    case ARLA_EOF :
    case ARLA_PROTOCOL_ERROR :
    case ARLA_USER_ABORT :
    case ARLA_ADDRINUSE :
    case ARLA_MSGSIZE :
    case ARLA_VSALVAGE :
    case ARLA_VNOSERVICE :
    case ARLA_VOFFLINE :
    case ARLA_VBUSY :
    case ARLA_VIO :
    case ECONNABORTED :
	return TRUE;
    case ARLA_VNOVOL :
    case ARLA_VMOVED :
	if (fid && !volcache_reliablep (fid->fid.Volume, fid->Cell))
	    volcache_invalidate (fid->fid.Volume, fid->Cell);
	return TRUE;
    case 0 :
	return FALSE;
    default :
	return FALSE;
    }
}

/*
 * Fetch the attributes for the file in `entry' from the file_server,
 * using the credentials in `ce' and returning the connection in
 * `ret_conn'
 *
 * `entry' must be write-locked.
 *
 * If an error code is returned `fs_server_context' is already freed.
 * If everything is ok, `fs_server_context' must be freed by the caller.
 */

static int
do_read_attr (FCacheEntry *entry,
	      CredCacheEntry *ce,
	      ConnCacheEntry **ret_conn,
	      fs_server_context *ret_context)
{
    ConnCacheEntry *conn;
    AFSFetchStatus status;
    AFSCallBack callback;
    AFSVolSync volsync;
    struct collect_stat collectstat;
    int ret;

    AssertExclLocked(&entry->lock);

    *ret_conn = NULL;

    ret = init_fs_context(entry, ce, ret_context);
    if (ret)
	return ret;

    for (conn = find_first_fs (ret_context);
	 conn != NULL;
	 conn = find_next_fs (ret_context, conn, ret)) {

	collectstats_start(&collectstat);
	ret = RXAFS_FetchStatus (conn->connection,
				 &entry->fid.fid,
				 &status,
				 &callback,
				 &volsync);
	collectstats_stop(&collectstat, entry, conn,
			  find_partition(ret_context),
			  arla_STATISTICS_REQTYPE_FETCHSTATUS, 1);
	arla_warnx (ADEBFCACHE, "trying to fetch status: %d", ret);
	if (!try_next_fs (ret, &entry->fid))
	    break;
    }
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fetch-status");
	if (host_downp(ret))
	    ret = ENETDOWN;
	free_fs_server_context (ret_context);
	return ret;
    }

    fcache_counter.fetch_attr++;

    update_attr_entry (entry, &status, &callback, &volsync,
		       conn, ce->cred);
    
    AssertExclLocked(&entry->lock);

    *ret_conn = conn;
    return 0;
}


/*
 * Read the attributes of `entry' from the file server and store them.
 * `e' must be write-locked.
 */

int
read_attr (FCacheEntry *entry, CredCacheEntry *ce)
{
    int ret;
    ConnCacheEntry *conn;
    fs_server_context context;

    AssertExclLocked(&entry->lock);

    init_fs_server_context (&context);
    ret = do_read_attr (entry, ce, &conn, &context);
    if (ret)
	return ret;
    free_fs_server_context (&context);
    return 0;
}

/*
 * Read the contents of `entry' from the file server and store it.
 *
 * If the wanted data is busy, try waiting for it.
 */

static int
read_data (FCacheEntry *entry, ConnCacheEntry *conn, CredCacheEntry *ce,
	   long partition, uint64_t wanted_offset, uint64_t wanted_end)
{
    struct rx_call *call;
    int ret = 0;
    int nblocks;
    uint64_t end, nbytes = 0;
    int64_t sizefs = 0;
    AFSFetchStatus status;
    AFSCallBack callback;
    AFSVolSync volsync;
    struct collect_stat collectstat;
    uint32_t sizefs4;
    uint64_t offset;
    BlockState state;
    Bool unlocked = FALSE;

    arla_warnx (ADEBMISC, "read_data");

    AssertExclLocked(&entry->lock);

    if (connected_mode == DISCONNECTED)
	return ENETDOWN;

    state = first_wanted_range(entry, wanted_offset, wanted_end,
			       &offset, &end);
    switch (state) {
    case BLOCK_GOT:  /* got block to fetch, process below */
	break;
    case BLOCK_BUSY: /* already fetching block, wait for them and retry */
	wait_busy(entry);
	return 0;
    case BLOCK_NONE:
	return 0;    /* already cached, no blocks to fetch */
    }
    
    /* figure out how much more then we need we want to fetch */
    /* XXX end = stats_fetch_round(conn, partition, end); */
    if (end > fcache_get_status_length(&entry->status))
	end = fcache_get_status_length(&entry->status);

    nbytes = end - offset;

    nblocks = create_busy_blocks(entry, offset, end);
    if (nblocks < 0) {
	ret = errno;
	arla_warn(ADEBFCACHE, ret, "read_data blocks");
	delete_unbusy_blocks(entry, offset, offset, end, FALSE);
	return ret;
    }

    /*
     * Release lock on ordinary nodes during rpc, it's still
     * referenced.
     */

    fcache_unlock(entry);
    unlocked = TRUE;

    ret = fcache_update_usage(entry, nblocks);
    if (ret) {
	arla_warn(ADEBFCACHE, ret, "read_data usage");
	fcache_lock(entry, FALSE);
	delete_unbusy_blocks(entry, offset, offset, end, FALSE);
	return ret;
    }
    
 again:
    /* now go talk to the world */
    call = rx_NewCall (conn->connection);
    if (call == NULL) {
	arla_warnx (ADEBMISC, "rx_NewCall failed");
	ret = ENOMEM;
	goto out;
    }

    arla_warnx(ADEBFCACHE, "read_data: from %#llx to %#llx",
	       offset, end);

    collectstats_start(&collectstat);
    if (conn_get_fs_support64(conn)) {
	ret = StartRXAFS_FetchData64 (call,
				      &entry->fid.fid,
				      offset,
				      nbytes);
	if (ret == RXGEN_OPCODE) {
	    rx_EndCall(call,ret);
	    conn_set_fs_support64(conn, FALSE);
	    goto again;
	}
    } else if (end >> 32)
	ret = EFBIG;
    else
	ret = StartRXAFS_FetchData (call,
				    &entry->fid.fid,
				    offset,
				    nbytes);
    
    if(ret) {
	arla_warn (ADEBFCACHE, ret, "fetch-data");
	rx_EndCall(call,ret);
	goto out;
    }

    if (conn_get_fs_support64(conn)) {
	ret = rx_Read (call, &sizefs4, sizeof(sizefs4));
	if (ret != sizeof(sizefs4)) {
	    ret = rx_GetCallError(call);
	    if (ret == RXGEN_OPCODE && conn_get_fs_support64(conn)) {
		rx_EndCall(call,0);
		conn_set_fs_support64(conn, FALSE);
		goto again;
	    }
	    ret = conv_to_arla_errno(ret);
	    arla_warn (ADEBFCACHE, ret, "Error reading length");
	    rx_EndCall(call, 0);
	    goto out;
	}
	sizefs = (int64_t)ntohl(sizefs4) << 32;
    } else
	sizefs = 0;

    ret = rx_Read (call, &sizefs4, sizeof(sizefs4));
    if (ret != sizeof(sizefs4)) {
	ret = conv_to_arla_errno(rx_GetCallError(call));
	arla_warn (ADEBFCACHE, ret, "Error reading length");
	rx_EndCall(call, 0);
	goto out;
    }

    sizefs |= ntohl (sizefs4);
    if (sizefs < 0)
	sizefs = 0;

    /* get node lock again, now that we're about to change things */
    fcache_lock(entry, FALSE);
    unlocked = FALSE;

    ret = copyrx2cache(call, entry, offset, sizefs);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "copyrx2cache");
	rx_EndCall(call, ret);
	goto out;
    }

    if (conn_get_fs_support64(conn)) {
	ret = EndRXAFS_FetchData64 (call,
				    &status,
				    &callback,
				    &volsync);
    } else {
	ret = EndRXAFS_FetchData (call,
				  &status,
				  &callback,
				  &volsync);
    }
    if (ret)
	arla_warn (ADEBWARN, ret, "EndRXAFS_FetchData");
    ret = rx_EndCall (call, ret);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "rx_EndCall");
	goto out;
    }
    collectstats_stop(&collectstat, entry, conn,
		      partition, arla_STATISTICS_REQTYPE_FETCHDATA, sizefs);

    fcache_counter.fetch_data++;
    
    update_entry (entry, &status, &callback, &volsync, conn, ce->cred);
    
 out:
    if (unlocked)
	fcache_lock(entry, FALSE);

    /*
     * Unbusy blocks.  If we didn't get all created blocks, the rest
     * should be removed.
     */
    if (ret)
	sizefs = 0;
    delete_unbusy_blocks(entry, offset,
			 block_next_offset(offset + sizefs), end,
			 TRUE);
    
    AssertExclLocked(&entry->lock);

    return ret;
}

/*
 * Write the contents of the cache file back to the file server.
 */

int
write_data(FCacheEntry *entry, FCacheEntry *data_entry,
	   uint64_t offset, uint64_t length,
	   AFSStoreStatus *storestatus, CredCacheEntry *ce)
{
    FCacheEntry *fd_entry = entry;
    ConnCacheEntry *conn;
    struct rx_call *call;
    int ret;
    uint64_t sizefs;
    AFSFetchStatus status;
    AFSVolSync volsync;
    fs_server_context context;
    struct collect_stat collectstat;

    AssertExclLocked(&entry->lock);

    if (data_entry) {
	AssertExclLocked(&data_entry->lock);
	fd_entry = data_entry;
    }

    if (connected_mode != CONNECTED || entry->flags.silly)
	return 0;

    sizefs = fcache_get_status_length(&fd_entry->status);

    /* avoid gc */
    fcache_data_setbusy(fd_entry, offset, offset + length, TRUE);
	
    /* keep node lock for now, perhaps unnecessary */

    ret = init_fs_context(entry, ce, &context);
    if (ret) {
	fcache_data_setbusy(fd_entry, offset, offset + length, FALSE);
	return ret;
    }

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

    again:
	call = rx_NewCall (conn->connection);
	if (call == NULL) {
	    arla_warnx (ADEBMISC, "rx_NewCall failed");
	    ret = ENOMEM;
	    break;
	}

	collectstats_start(&collectstat);
	if (conn_get_fs_support64(conn)) {
	    ret = StartRXAFS_StoreData64 (call, &entry->fid.fid,
					  storestatus,
					  offset,
					  length,
					  sizefs);
	    if (ret == RXGEN_OPCODE) {
		rx_EndCall(call,ret);
		conn_set_fs_support64(conn, FALSE);
		goto again;
	    }
	} else if ((uint64_t)sizefs >> 32) {
	    ret = EFBIG;
	} else {
	    ret = StartRXAFS_StoreData (call, &entry->fid.fid,
					storestatus,
					offset,
					length,
					sizefs);

	}
	if (host_downp(ret)) {
	    rx_EndCall(call, ret);
	    continue;
	} else if (ret) {
	    arla_warn (ADEBFCACHE, ret, "store-data");
	    rx_EndCall(call, 0);
	    break;
	}

	ret = copycache2rx(fd_entry, call, offset, length);
	if (ret == RXGEN_OPCODE && conn_get_fs_support64(conn)) {
	    rx_EndCall(call,ret);
	    conn_set_fs_support64(conn, FALSE);
	    goto again;
	} else if (ret) {
	    rx_EndCall(call, ret);
	    arla_warn (ADEBFCACHE, ret, "copycache2rx");
	    break;
	}

	if (conn_get_fs_support64(conn)) {
	    ret = EndRXAFS_StoreData64 (call,
					&status,
					&volsync);
	    if (ret == RXGEN_OPCODE) {
		rx_EndCall(call, 0);
		conn_set_fs_support64(conn, FALSE);
		goto again;
	    }
	} else {
	    ret = EndRXAFS_StoreData (call,
				      &status,
				      &volsync);
	}
	if (ret) {
	    rx_EndCall (call, ret);
	    arla_warnx (ADEBFCACHE, "EndRXAFS_StoreData");
	    break;
	}

	ret = rx_EndCall (call, 0);
	if (ret) {
	    arla_warn (ADEBFCACHE, ret, "rx_EndCall");
	}
	collectstats_stop(&collectstat, entry, conn,
			  find_partition(&context),
			  arla_STATISTICS_REQTYPE_STOREDATA, sizefs);
	break;
    }

    if (conn != NULL) {
	if (ret == 0) {
	    fcache_counter.store_data++;
	    update_entry (entry, &status, NULL, &volsync,
			  conn, ce->cred);
	} else {
#if 0
	    /*
	     * We can't do this, it will corrupt the cache since nnpfs
	     * will still think it have the data, and then when we
	     * write back the file to the fileserver, it will be
	     * filled with zeros. Happens if you are unlucky so store
	     * a file at the same moment as your credentials expire.
	     */
	    ftruncate (fd, 0);
	    usedbytes -= entry->usage; 
	    entry->usage = 0;
#endif
	}
    }
    fcache_data_setbusy(fd_entry, offset, offset + length, FALSE);

    if (host_downp(ret))
	ret = ENETDOWN;

    free_fs_server_context (&context);
    AssertExclLocked(&entry->lock);
    if (data_entry) {
	AssertExclLocked(&data_entry->lock);

	/* make sure data is up to date, copy it or just throw */
	throw_data(entry);
    }

    return ret;
}

/*
 * Truncate the file in `entry' to `size' bytes.
 */

int
truncate_file (FCacheEntry *entry, uint64_t size, 
	       AFSStoreStatus *storestatus, CredCacheEntry *ce)
{
    fs_server_context context;
    ConnCacheEntry *conn;
    struct rx_call *call;
    AFSFetchStatus status;
    AFSVolSync volsync;
    int ret;

    AssertExclLocked(&entry->lock);

    if (connected_mode != CONNECTED)
	return 0;

    /* XXX needed? */
    if (size) {
	ret = fcache_verify_data(entry, ce, 0, 0);
	if (ret)
	    return ret;
    }

    ret = init_fs_context(entry, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

    again:
	call = rx_NewCall (conn->connection);
	if (call == NULL) {
	    arla_warnx (ADEBMISC, "rx_NewCall failed");
	    ret = ENOMEM;
	    break;
	}

	if (conn_get_fs_support64(conn)) {
	    ret = StartRXAFS_StoreData64 (call,
					  &entry->fid.fid, 
					  storestatus,
					  size,
					  0,
					  size);
	    if (ret == RXGEN_OPCODE) {
		rx_EndCall(call, ret);
		conn_set_fs_support64(conn, FALSE);
		goto again;
	    }
	} else if (size >> 32)
	    ret = EFBIG;
	else
	    ret = StartRXAFS_StoreData (call,
					&entry->fid.fid, 
					storestatus,
					size,
					0,
					size);
	if (host_downp(ret)) {
	    rx_EndCall(call, ret);
	    continue;
	} else if(ret) {
	    arla_warn (ADEBFCACHE, ret, "store-data");
	    rx_EndCall(call, 0);
	    break;
	}

	if (conn_get_fs_support64(conn)) {
	    ret = EndRXAFS_StoreData64 (call,
					&status,
					&volsync);
	    if (ret == RXGEN_OPCODE) {
		rx_EndCall(call, 0);
		conn_set_fs_support64(conn, FALSE);
		goto again;
	    }
	} else {
	    ret = EndRXAFS_StoreData (call,
				      &status,
				      &volsync);
	}
	if (ret) {
	    rx_EndCall (call, ret);
	    arla_warnx (ADEBFCACHE, "EndRXAFS_StoreData");
	    break;
	}

	ret = rx_EndCall (call, 0);
	if (ret)
	    arla_warn (ADEBFCACHE, ret, "rx_EndCall");

	break;
    }

    if (ret == 0) {
	ret = abuf_truncate(entry, size);
	if (ret) {
	    arla_warn (ADEBFCACHE, ret, "abuf_truncate %ld", (long)size);
	    free_fs_server_context (&context);
	    return ret;
	}
	
	fcache_counter.store_data++;
	update_entry (entry, &status, NULL, &volsync,
		      conn, ce->cred);
    }

    free_fs_server_context (&context);

    if (host_downp(ret))
	ret = ENETDOWN;

    AssertExclLocked(&entry->lock);
    return ret;
}

/*
 * Set the attributes of the file in `entry' to `status'.
 */

int
write_attr (FCacheEntry *entry,
	    const AFSStoreStatus *store_status,
	    CredCacheEntry *ce)
{
    ConnCacheEntry *conn = NULL;
    int ret;
    AFSFetchStatus status;
    AFSVolSync volsync;

    AssertExclLocked(&entry->lock);

    /* Don't write attributes to deleted files */
    if (entry->flags.silly)
	return 0;

    if (connected_mode == CONNECTED) {
	fs_server_context context;
	struct collect_stat collectstat;

	ret = init_fs_context(entry, ce, &context);
	if (ret)
	    return ret;

	for (conn = find_first_fs (&context);
	     conn != NULL;
	     conn = find_next_fs (&context, conn, ret)) {

	    collectstats_start(&collectstat);
	    ret = RXAFS_StoreStatus (conn->connection,
				     &entry->fid.fid,
				     store_status,
				     &status,
				     &volsync);
	    if (host_downp(ret)) {
		continue;
	    } else if (ret) {
		arla_warn (ADEBFCACHE, ret, "store-status");
		free_fs_server_context (&context);
		conn = NULL;
		goto out;
	    }
	    conn_ref(conn);
	    break;
	}

	if (ret == 0)
	    collectstats_stop(&collectstat, entry, conn,
			      find_partition(&context),
			      arla_STATISTICS_REQTYPE_STORESTATUS, 1);


	free_fs_server_context (&context);

	if (host_downp(ret)) {
	    ret = ENETDOWN;
	    goto out;
	}
	update_entry (entry, &status, NULL, &volsync, conn, ce->cred);

    } else {
	assert (conn == NULL);

	fcache_counter.store_attr++;
	if (store_status->Mask & SS_MODTIME) {
	    entry->status.ClientModTime = store_status->ClientModTime;
	    entry->status.ServerModTime = store_status->ClientModTime;
	}
	if (store_status->Mask & SS_OWNER)
	    entry->status.Owner = store_status->Owner;
	if (store_status->Mask & SS_GROUP)
	    entry->status.Group = store_status->Group;
	if (store_status->Mask & SS_MODEBITS)
	    entry->status.UnixModeBits = store_status->UnixModeBits;
	ret = 0;
    }

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&entry->lock);

    return ret;
}

/*
 * Create a file.  The new node is returned locked in `ret_entry'.
 */

int
create_file (FCacheEntry *dir_entry,
	     const char *name, AFSStoreStatus *store_attr,
	     FCacheEntry **ret_entry, CredCacheEntry *ce)
{
    ConnCacheEntry *conn = NULL;
    int ret;
    FCacheEntry *child_entry;
    AFSFetchStatus fetch_attr;
    VenusFid child_fid;
    AFSFetchStatus status;
    AFSCallBack callback;
    AFSVolSync volsync;

    AssertExclLocked(&dir_entry->lock);

    *ret_entry = NULL;

    if (connected_mode == CONNECTED) {
	fs_server_context context;

	ret = init_fs_context(dir_entry, ce, &context);
	if (ret)
	    return ret;

	for (conn = find_first_fs (&context);
	     conn != NULL;
	     conn = find_next_fs (&context, conn, ret)) {

	    ret = RXAFS_CreateFile (conn->connection,
				    &dir_entry->fid.fid,
				    name,
				    store_attr,
				    &child_fid.fid,
				    &fetch_attr,
				    &status,
				    &callback,
				    &volsync);
	    if (host_downp(ret)) {
		continue;
	    } else if (ret) {
		free_fs_server_context (&context);
		arla_warn (ADEBFCACHE, ret, "CreateFile");
		conn = NULL;
		goto out;
	    }
	    conn_ref(conn);
	    break;
	}

	free_fs_server_context (&context);

	if (host_downp(ret)) {
	    ret = ENETDOWN;
	    goto out;
	}

	fetch_attr.CallerAccess |= AADMIN;

	update_modify_dir(dir_entry, &status, &callback,
			  &volsync, conn, ce->cred);
    } else {
	static int fakefid = 1001;

	assert(conn == NULL);

	ret = 0;

	child_fid.fid.Volume = dir_entry->fid.fid.Volume;
	child_fid.fid.Vnode  = fakefid;
	child_fid.fid.Unique = fakefid;
	fakefid += 2;

	fetch_attr.InterfaceVersion = 1;
	fetch_attr.FileType         = TYPE_FILE;
	fetch_attr.LinkCount        = 1;
	fetch_attr.Length	    = 0;
	fetch_attr.DataVersion      = 1;
	fetch_attr.Author           = store_attr->Owner;
	fetch_attr.Owner            = store_attr->Owner;
	fetch_attr.CallerAccess     = dir_entry->status.CallerAccess;
	fetch_attr.AnonymousAccess  = dir_entry->status.AnonymousAccess;
	fetch_attr.UnixModeBits     = store_attr->UnixModeBits;
	fetch_attr.ParentVnode      = dir_entry->fid.fid.Vnode;
	fetch_attr.ParentUnique     = dir_entry->fid.fid.Unique;
	fetch_attr.ResidencyMask    = 1;
	fetch_attr.ClientModTime    = store_attr->ClientModTime;
	fetch_attr.ServerModTime    = store_attr->ClientModTime;
	fetch_attr.Group            = store_attr->Group;
	fetch_attr.SyncCounter      = 0;
	fetch_attr.DataVersionHigh  = 0;
	fetch_attr.LockCount        = 0;
	fetch_attr.LengthHigh       = 0;
	fetch_attr.ErrorCode        = 0;
    }

    child_fid.Cell = dir_entry->fid.Cell;

    ret = fcache_get(&child_entry, child_fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	goto out;
    }

    update_entry(child_entry, &fetch_attr, NULL, NULL,
		 conn, ce->cred);

    throw_data(child_entry);
    ret = create_block(child_entry, 0);
    if (ret) {
	arla_warn(ADEBFCACHE, ret, "create cache file %u",
		  (unsigned)child_entry->index);
	fcache_release(child_entry);
	goto out;
    }

    child_entry->tokens |= NNPFS_ATTR_R | NNPFS_DATA_R | NNPFS_DATA_W;
    child_entry->flags.attrp = TRUE;
	
    *ret_entry = child_entry;

 out:
    if (conn)
	conn_free(conn);

    AssertExclLocked(&dir_entry->lock);

    return ret;
}

/*
 * Create a directory.
 */

int
create_directory (FCacheEntry *dir_entry,
		  const char *name, AFSStoreStatus *store_attr,
		  VenusFid *child_fid, AFSFetchStatus *fetch_attr,
		  CredCacheEntry *ce)
{
    ConnCacheEntry *conn = NULL;
    int ret;
    AFSFid OutFid;
    FCacheEntry *child_entry;
    AFSFetchStatus status;
    AFSCallBack callback;
    AFSVolSync volsync;


    AssertExclLocked(&dir_entry->lock);

    if (connected_mode == CONNECTED) {
	fs_server_context context;

	ret = init_fs_context(dir_entry, ce, &context);
	if (ret)
	    return ret;

	for (conn = find_first_fs (&context);
	     conn != NULL;
	     conn = find_next_fs (&context, conn, ret)) {

	    ret = RXAFS_MakeDir (conn->connection,
				 &dir_entry->fid.fid,
				 name,
				 store_attr,
				 &OutFid,
				 fetch_attr,
				 &status,
				 &callback,
				 &volsync);

	    if (host_downp(ret)) {
		continue;
	    } else if (ret) {
		free_fs_server_context (&context);
		arla_warn (ADEBFCACHE, ret, "MakeDir");
		conn = NULL;
		goto out;
	    }
	    conn_ref(conn);
	    break;
	}
	free_fs_server_context (&context);

	if (host_downp(ret)) {
	    ret = ENETDOWN;
	    goto out;
	}

	update_modify_dir(dir_entry, &status, &callback, &volsync,
			  conn, ce->cred);
    } else {
	static int fakedir = 1000;

	ret = 0;

	assert(conn == NULL);

	OutFid.Volume = dir_entry->fid.fid.Volume;
	OutFid.Vnode  = fakedir;
	OutFid.Unique = fakedir;
	fakedir += 2;

	fetch_attr->InterfaceVersion = 1;
	fetch_attr->FileType         = TYPE_DIR;
	fetch_attr->LinkCount        = 2;
	fetch_attr->Length           = AFSDIR_PAGESIZE;
	fetch_attr->DataVersion      = 1;
	fetch_attr->Author           = store_attr->Owner;
	fetch_attr->Owner            = store_attr->Owner;
	fetch_attr->CallerAccess     = dir_entry->status.CallerAccess;
	fetch_attr->AnonymousAccess  = dir_entry->status.AnonymousAccess;
	fetch_attr->UnixModeBits     = store_attr->UnixModeBits;
	fetch_attr->ParentVnode      = dir_entry->fid.fid.Vnode;
	fetch_attr->ParentUnique     = dir_entry->fid.fid.Unique;
	fetch_attr->ResidencyMask    = 1;
	fetch_attr->ClientModTime    = store_attr->ClientModTime;
	fetch_attr->ServerModTime    = store_attr->ClientModTime;
	fetch_attr->Group            = store_attr->Group;
	fetch_attr->SyncCounter      = 0;
	fetch_attr->DataVersionHigh  = 0;
	fetch_attr->LockCount        = 0;
	fetch_attr->LengthHigh       = 0;
	fetch_attr->ErrorCode        = 0;
    }

    child_fid->Cell = dir_entry->fid.Cell;
    child_fid->fid  = OutFid;

    ret = fcache_get (&child_entry, *child_fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	goto out;
    }

    assert(child_entry->usage == 0);

    update_entry (child_entry, fetch_attr, NULL, NULL,
		  conn, ce->cred);

    child_entry->flags.attrp = TRUE;

    ret = adir_mkdir (child_entry, child_fid->fid, dir_entry->fid.fid);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "adir_mkdir");
	fcache_release(child_entry);
	goto out;
    }

    child_entry->tokens |= NNPFS_ATTR_R | NNPFS_DATA_R | NNPFS_DATA_W;
	
    fcache_release(child_entry);

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&dir_entry->lock);
    return ret;
}

/*
 * Create a symbolic link.
 *
 * Note: create_symlink->flags.kernelp is not set on success
 * and that must be done by the caller.
 */

int
create_symlink (FCacheEntry *dir_entry,
		const char *name, AFSStoreStatus *store_attr,
		VenusFid *child_fid, AFSFetchStatus *fetch_attr,
		const char *contents,
		CredCacheEntry *ce)
{
    int ret;
    ConnCacheEntry *conn;
    AFSFid OutFid;
    FCacheEntry *child_entry;
    AFSVolSync volsync;
    AFSFetchStatus new_status;
    fs_server_context context;

    AssertExclLocked(&dir_entry->lock);

    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = init_fs_context(dir_entry, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	ret = RXAFS_Symlink (conn->connection,
			     &dir_entry->fid.fid,
			     name,
			     contents,
			     store_attr,
			     &OutFid,
			     fetch_attr,
			     &new_status,
			     &volsync);
	if (host_downp(ret)) {
	    continue;
	} else if (ret) {
	    arla_warn (ADEBFCACHE, ret, "Symlink");
	    free_fs_server_context (&context);
	    conn = NULL;
	    goto out;
	}
	conn_ref(conn);
	break;
    }
    free_fs_server_context (&context);

    if (host_downp(ret)) {
	ret = ENETDOWN;
	goto out;
    }

    update_modify_dir(dir_entry, &new_status, NULL, &volsync,
		      conn, ce->cred);

    child_fid->Cell = dir_entry->fid.Cell;
    child_fid->fid  = OutFid;

    ret = fcache_get (&child_entry, *child_fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	goto out;
    }

    update_entry (child_entry, fetch_attr, NULL, NULL,
		  conn, ce->cred);

    /* 
     * flags.kernelp is set in cm_symlink since the symlink
     * might be a mountpoint and this entry is never install
     * into the kernel.
     */

    child_entry->flags.attrp = TRUE;
    child_entry->tokens |= NNPFS_ATTR_R;
	
    fcache_release(child_entry);

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&dir_entry->lock);
    return ret;
}

/*
 * Create a hard link.
 */

int
create_link (FCacheEntry *dir_entry,
	     const char *name,
	     FCacheEntry *existing_entry,
	     CredCacheEntry *ce)
{
    ConnCacheEntry *conn = NULL;
    int ret;
    AFSFetchStatus new_status;
    AFSFetchStatus status;
    AFSVolSync volsync;
    fs_server_context context;

    AssertExclLocked(&dir_entry->lock);

    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = init_fs_context(dir_entry, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	ret = RXAFS_Link (conn->connection,
			  &dir_entry->fid.fid,
			  name,
			  &existing_entry->fid.fid,
			  &new_status,
			  &status,
			  &volsync);
	if (host_downp(ret)) {
	    continue;
	} else if (ret) {
	    free_fs_server_context (&context);
	    arla_warn (ADEBFCACHE, ret, "Link");
	    conn = NULL;
	    goto out;
	}
	conn_ref(conn);
	break;
    }
    free_fs_server_context (&context);

    if (host_downp(ret)) {
	ret = ENETDOWN;
	goto out;
    }

    update_modify_dir(dir_entry, &status, NULL, &volsync,
		      conn, ce->cred);

    update_entry (existing_entry, &new_status, NULL, NULL,
		  conn, ce->cred);

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&dir_entry->lock);
    return ret;
}

/*
 * Remove a file from a directory.
 */

int
remove_file(FCacheEntry *dir_entry, const char *name,
	    FCacheEntry *child_entry, CredCacheEntry *ce)
{
    int ret;
    ConnCacheEntry *conn = NULL;
    AFSFetchStatus status;
    AFSVolSync volsync;
    fs_server_context context;

    AssertExclLocked(&dir_entry->lock);
    AssertExclLocked(&child_entry->lock);

    if (connected_mode == CONNECTED) {

	ret = init_fs_context(dir_entry, ce, &context);
	if (ret)
	    return ret;

	for (conn = find_first_fs (&context);
	     conn != NULL;
	     conn = find_next_fs (&context, conn, ret)) {
	    
	    ret = RXAFS_RemoveFile (conn->connection,
				    &dir_entry->fid.fid,
				    name,
				    &status,
				    &volsync);
	    if (host_downp(ret)) {
		continue;
	    } else if (ret) {
		free_fs_server_context (&context);
		arla_warn (ADEBFCACHE, ret, "RemoveFile");
		conn = NULL;
		goto out;
	    }
	    conn_ref(conn);
	    break;
	}
	free_fs_server_context (&context);
	
	if (host_downp(ret))
	    ret = ENETDOWN;

    } else {
#if 0
	fbuf the_fbuf;
	VenusFid child_fid;

	status = dir_entry->status;
	
	ret = fcache_get_fbuf(dir_entry, &the_fbuf, FBUF_READ);
	if (ret)
	    goto out;
	
	ret = fdir_lookup(&the_fbuf, &dir_entry->fid, name, &child_fid);
	if (ret == 0) {
	    FCacheEntry *child_entry = NULL;
	    uint32_t disco_id = 0;

	    child_entry = fcache_find(child_fid);
	    if (child_entry)
		disco_id = child_entry->disco_id;

	    disco_id = disco_unlink(&dir_entry->fid, &child_fid,
				    name, disco_id);

	    if (child_entry) {
		child_entry->disco_id = disco_id;
		fcache_release(child_entry);
	    }
	}
	    
	abuf_end (&the_fbuf);
#else
	ret = EINVAL; /* XXX */
#endif
    }

    if (ret == 0) {
	update_modify_dir(dir_entry, &status, NULL, &volsync,
			  conn, ce->cred);
	child_entry->status.LinkCount--;
	if (child_entry->status.LinkCount == 0)
	    child_entry->flags.silly = TRUE;
    }

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&dir_entry->lock);
    return ret;
}

/*
 * Remove a directory from a directory.
 */

int
remove_directory(FCacheEntry *dir_entry,
		 const char *name,
		 FCacheEntry *child_entry,
		 CredCacheEntry *ce)
{
    int ret;
    ConnCacheEntry *conn;
    AFSFetchStatus status;
    AFSVolSync volsync;
    fs_server_context context;

    AssertExclLocked(&dir_entry->lock);

    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = init_fs_context(dir_entry, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	ret = RXAFS_RemoveDir (conn->connection,
			       &dir_entry->fid.fid,
			       name,
			       &status,
			       &volsync);
	if (host_downp(ret)) {
	    continue;
	} else if (ret) {
	    free_fs_server_context (&context);
	    arla_warn (ADEBFCACHE, ret, "RemoveDir");
	    conn = NULL;
	    goto out;
	}
	conn_ref(conn);
	break;
    }
    free_fs_server_context (&context);

    if (host_downp(ret)) {
	ret = ENETDOWN;
	goto out;
    }

    update_modify_dir(dir_entry, &status, NULL, &volsync,
		      conn, ce->cred);

    if (child_entry->status.LinkCount == 2) {
	child_entry->status.LinkCount = 0;
	child_entry->flags.silly = TRUE;
    }

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&dir_entry->lock);
    return ret;
}

/*
 * Rename a file
 */

int
rename_file (FCacheEntry *old_dir,
	     const char *old_name,
	     FCacheEntry *new_dir,
	     const char *new_name,
	     CredCacheEntry *ce)
{
    int ret = ARLA_CALL_DEAD;
    ConnCacheEntry *conn;
    AFSFetchStatus orig_status, new_status;
    AFSVolSync volsync;
    fs_server_context context;

    AssertExclLocked(&old_dir->lock);
    AssertExclLocked(&new_dir->lock);

    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = init_fs_context(old_dir, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	ret = RXAFS_Rename (conn->connection,
			    &old_dir->fid.fid,
			    old_name,
			    &new_dir->fid.fid,
			    new_name,
			    &orig_status,
			    &new_status,
			    &volsync);
	if (host_downp(ret)) {
	    continue;
	} else if (ret) {
	    free_fs_server_context (&context);
	    arla_warn (ADEBFCACHE, ret, "Rename");
	    conn = NULL;
	    goto out;
	}
	conn_ref(conn);
	break;
    }
    free_fs_server_context (&context);

    if (host_downp(ret)) {
	ret = ENETDOWN;
	goto out;
    }

   
    if (old_dir != new_dir)
	update_modify_dir(old_dir, &orig_status, NULL, &volsync,
			  conn, ce->cred);
    
    update_modify_dir(new_dir, &new_status, NULL, &volsync,
		      conn, ce->cred);

 out:
    if (conn)
	conn_free(conn);
    AssertExclLocked(&old_dir->lock);
    AssertExclLocked(&new_dir->lock);
    return ret;
}

/*
 * Return the fid to the root.
 */

int
getroot (VenusFid *res, CredCacheEntry *ce)
{
    VolCacheEntry *ve;
    VenusFid fid;
    const char *root_volume = volcache_get_rootvolume ();
    int ret;
    const char *this_cell = cell_getthiscell ();
    int32_t this_cell_id;

    if (dynroot_enablep()) {
	this_cell = "dynroot";
	this_cell_id = dynroot_cellid();
    } else {
	this_cell_id = cell_name2num (this_cell);
	if (this_cell_id == -1)
	    arla_errx (1, ADEBERROR, "cell %s does not exist", this_cell);
    }

    ret = volcache_getbyname (root_volume, this_cell_id, ce, &ve, NULL);
    if (ret) {
	arla_warn (ADEBWARN, ret,
		   "Cannot find the root volume (%s) in cell %s",
		   root_volume, this_cell);
	return ret;
    }

    fid.Cell = this_cell_id;
    if (ve->entry.flags & VLF_ROEXISTS) {
	fid.fid.Volume = ve->entry.volumeId[ROVOL];
    } else if (ve->entry.flags & VLF_RWEXISTS) {
	arla_warnx(ADEBERROR,
		   "getroot: %s in cell %s is missing a RO clone, not good",
		   root_volume, this_cell);
	fid.fid.Volume = ve->entry.volumeId[RWVOL];
    } else {
	arla_errx(1, ADEBERROR,
		  "getroot: %s in cell %s has no RW or RO clone?",
		  root_volume, this_cell);
    }
    fid.fid.Vnode = fid.fid.Unique = 1;

    volcache_free (ve);

    *res = fid;
    return 0;
}

/*
 * Return the type for this volume.
 */

long
getvoltype(int32_t volid, const VolCacheEntry *ve)
{
    int i;

    for (i = RWVOL; i <= BACKVOL; ++i)
	if (ve->entry.volumeId[i] == volid)
	    return i;
    assert (FALSE);
    return -1; /* NOT REACHED */
}

/*
 * Return locked entry for `fid' or NULL.  If `gcp' is set the
 * returned node may be under gc.
 */

FCacheEntry *
fcache_find_gcp(VenusFid fid, Bool gcp)
{
    FCacheEntry *res = find_entry_nolock(fid);
    if (res == NULL)
	return res;

    res->refcount++;
    assert(res->refcount > 0);
    
    fcache_lock(res, gcp);
    if (!gcp)
	assert(!res->flags.gcp);

    return res;
}

/*
 * Return locked entry for `fid' or NULL.
 */

FCacheEntry *
fcache_find(VenusFid fid)
{
    return fcache_find_gcp(fid, FALSE);
}

/*
 * Return the entry for `fid'.  If it's not cached, add it.
 */

static int
fcache_get_int(FCacheEntry **res, VenusFid fid, CredCacheEntry *ce, Bool gcp)
{
    FCacheEntry *old;
    FCacheEntry *e;
    VolCacheEntry *vol;
    int i, error;

    *res = NULL;

    old = fcache_find_gcp(fid, gcp);
    if (old) {
	assert (old->flags.usedp);
	*res = old;
	return 0;
    }

    error = volcache_getbyid (fid.fid.Volume, fid.Cell, ce, &vol, NULL);
    if (error) {
	if (connected_mode == DISCONNECTED && error == ENOENT)
	    return ENETDOWN;
	return error;
    }

    e = find_free_entry ();
    assert (e != NULL);

    old = fcache_find_gcp(fid, gcp);
    if (old) {
	AssertExclLocked(&e->lock);
	fcache_unlock(e);

	e->lru_le = listaddtail(free_nodes, e);
	assert(e->lru_le);

	assert (old->flags.usedp);
	*res = old;
	return 0;
    }


    assert(e->blocks);
    assert(listemptyp(e->blocks));

    e->fid     	       = fid;
    e->refcount        = 1;
    e->host	       = 0;
    e->usage           = 0;
    memset (&e->status,   0, sizeof(e->status));
    memset (&e->callback, 0, sizeof(e->callback));
    memset (&e->volsync,  0, sizeof(e->volsync));
    for (i = 0; i < NACCESS; i++) {
	e->acccache[i].cred = ARLA_NO_AUTH_CRED;
	e->acccache[i].access = 0;
    }
    e->anonaccess      = 0;
    e->flags.usedp     = TRUE;
    e->flags.attrp     = FALSE;
    e->flags.attrusedp = FALSE;
    e->flags.datausedp = FALSE;
    e->flags.extradirp = FALSE;
    e->flags.mountp    = FALSE;
    e->flags.fake_mp   = FALSE;
    e->flags.vol_root  = FALSE;
    e->flags.kernelp   = FALSE;
    e->flags.sentenced = FALSE;
    e->flags.stale     = FALSE;
    e->flags.dirtied   = FALSE;
    e->flags.silly     = FALSE;
    e->flags.waiters   = FALSE;
    e->flags.gcp       = FALSE;
    e->flags.appended  = FALSE;
    e->tokens          = 0;
    memset (&e->parent, 0, sizeof(e->parent));
    e->lru_le = listaddhead (node_lru, e);
    assert(e->lru_le);
    e->invalid_ptr     = -1;
    e->volume	       = vol;
    e->priority	       = fprio_get(fid);
    e->hits	       = 0;
    
    hashtabadd (hashtab, e);

    *res = e;
    return 0;
}

/*
 * Return the entry for `fid'.  If it's not cached, add it.
 */

int
fcache_get(FCacheEntry **res, VenusFid fid, CredCacheEntry *ce)
{
    return fcache_get_int(res, fid, ce, FALSE);
}

/*
 * Return the entry for `fid'.  If it's not cached, add it.
 */

int
fcache_get_gc(FCacheEntry **res, VenusFid fid, CredCacheEntry *ce)
{
    return fcache_get_int(res, fid, ce, TRUE);
}

/*
 * Release the lock on `e' and mark it as stale if it has been sentenced.
 */

void
fcache_release(FCacheEntry *e)
{
    AssertExclLocked(&e->lock);

    e->refcount--;

    assert(e->refcount >= 0);

    fcache_unlock(e);

    if (e->flags.sentenced) {
	e->flags.sentenced = FALSE;
	stale(e, broken_callback);
    }
}

/*
 *
 */

static Bool
uptodatep (FCacheEntry *e)
{
    struct timeval tv;
    assert (e->flags.usedp);

    if (connected_mode != CONNECTED && 
	connected_mode != FETCH_ONLY)
	return TRUE;

    gettimeofday(&tv, NULL);
    
    if (tv.tv_sec < e->callback.ExpirationTime &&
	e->callback.CallBackType != CBDROPPED &&
	(e->callback.CallBackType != 0
	 || e->volume->volsync.spare1 != e->volsync.spare1))
        return TRUE;
    
    return FALSE;
}

/*
 * The idea is that we start to stat everything after the prefered
 * entry, everything before that is probably not useful to get, the
 * user is probably trying to stat() everything _after_ that node.
 * This might be somewhat bogus, but we dont care (for now).
 */

struct bulkstat {
    int 		len;		   /* used entries in fids and names */
    AFSFid		fids[AFSCBMAX];    /* fids to fetch */
    char		*names[AFSCBMAX];  /* names it install */
    AFSFid		*used;		   /* do we have a prefered node */
    CredCacheEntry	*ce;		   /* cred to use */
};

typedef union {
    struct nnpfs_message_installnode node;
    struct nnpfs_message_installattr attr;
} nnpfs_message_install_node_attr;

static int
bulkstat_help_func (VenusFid *fid, const char *name, void *ptr)
{
    struct bulkstat *bs = (struct bulkstat *) ptr;
    AccessEntry *ae;
    FCacheEntry key;
    FCacheEntry *e;

    /* Is bs full ? */
    if (bs->len > fcache_bulkstatus_num)
	return 0;

    /* Ignore . and .. */
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
	return 0;

    /* 
     * Do we have a prefered node, and is this the one. If we don't know
     * the name of the node (ie bs.names[0] == NULL), fill it in.
     * Set bs->used to NULL it indicate that we should start stat stuff
     * from here, remeber that bs->len == 1 if bs->used is set.
     */
    if (bs->used) { 
	if (memcmp(bs->used, &fid->fid, sizeof(fid->fid)) == 0) {
	    if (bs->names[0] == NULL)
		bs->names[0] = strdup (name);
	    bs->used = NULL; /* stat everything after this */
	}
	return 0;
    }

    /*
     * Already cached for this pag ?
     */
    key.fid = *fid;
    e = (FCacheEntry *)hashtabsearch (hashtab, (void *)&key);
    if (e 
	&& e->flags.usedp
	&& e->flags.attrp
	&& uptodatep (e)
	&& findaccess (bs->ce->cred, e->acccache, &ae) == TRUE) {
	arla_warnx (ADEBFCACHE, 
		    "bulkstat_help_func: already cached "
		    "(%d.%d.%d.%d) name: %s",
		    fid->Cell, fid->fid.Volume, fid->fid.Vnode, 
		    fid->fid.Unique, name);
	return 0;
    }

    if (fcache_enable_bulkstatus == 2) {
	/* cache the name for the installnode */
	bs->names[bs->len] = strdup (name);
	if (bs->names[bs->len] == NULL)
	    return 0;
    } else {
	bs->names[bs->len] = NULL;
    }
    

    bs->fids[bs->len] = fid->fid;
    bs->len++;

    return 0;
}

/*
 * Do bulkstat for ``parent_entry''. Make sure that ``prefered_entry''
 * is in the list of fids it not NULL, and it ``prefered_name'' is NULL
 * try to find it in the list files in the directory.
 *
 * 			Entry		Success		Failure
 * parent_entry		locked		locked		locked
 * prefered_entry	locked		locked		locked
 *   or if NULL		if set to NULL must not be locked
 * prefered_fid		related fcache-entry must not be locked
 * ce			not NULL
 */

static int
get_attr_bulk (FCacheEntry *parent_entry, 
	       FCacheEntry *prefered_entry,
	       VenusFid *prefered_fid, 
	       const char *prefered_name,
	       CredCacheEntry *ce)
{
    fs_server_context context;
    ConnCacheEntry *conn = NULL;
    struct bulkstat bs;
    AFSBulkStats stats;
    AFSVolSync sync;
    AFSCBFids fids;
    fbuf the_fbuf;
    int ret;
    AFSCBs cbs;
    int i;
    int len;
    struct collect_stat collectstat;

    arla_warnx (ADEBFCACHE, "get_attr_bulk");

    AssertExclLocked(&parent_entry->lock);
    if (prefered_entry)
	AssertExclLocked(&prefered_entry->lock);

    if (fcache_enable_bulkstatus == 0)
	return -1;

    if (parent_entry->usage == 0) {
	arla_warnx (ADEBFCACHE, "get_attr_bulk: parent doesn't have data");
	return -1;
    }
    
    fids.val = bs.fids;

    memset (bs.names, 0, sizeof(bs.names));
    memset (bs.fids,  0, sizeof(bs.fids));
    bs.len	= 0;
    bs.ce	= ce;
    bs.used	= NULL;
    
    /*
     * If we have a prefered_entry, and that to the first entry in the
     * array. This is used later. If we find the prefered_entry in the
     * directory-structure its ignored.
     */

    if (prefered_fid) {
	arla_warnx (ADEBFCACHE, "get_attr_bulk: using prefered_entry");
	bs.used			= &prefered_fid->fid;
	fids.val[bs.len]	= prefered_fid->fid;
	if (prefered_name != NULL) {
	    bs.names[bs.len]	= strdup(prefered_name);
	    if (bs.names[bs.len] == NULL)
		return ENOMEM;
	} else {
	    bs.names[bs.len]    = NULL;
	}
	bs.len++;
    }

    ret = fcache_get_fbuf (parent_entry, &the_fbuf, FBUF_READ);
    if (ret)
	return ret;

    ret = fdir_readdir (&the_fbuf,
			bulkstat_help_func,
			&bs,
			parent_entry->fid,
			NULL);
    abuf_end (&the_fbuf);
    if (ret)
	goto out_names;
    
    fids.len = bs.len;

    /*
     * Don't do BulkStatus when fids.len == 0 since we should never do it.
     * There should at least be the node that we want in the BulkStatus.
     */

    if (fids.len == 0) {
	if (prefered_fid)
	    arla_warnx (ADEBERROR, 
			"get_attr_bulk: "
			"prefered_fid not found in dir");
	/* XXX MAGIC send it back so we don't do it again soon */
	parent_entry->hits -= 64;
	ret = EINVAL;
	goto out_names;
    }

    /*
     * XXX if there is a prefered fid, and and we didn't find the name for it
     * return an error.
     */

    if (prefered_fid && bs.names[0] == NULL) {
	arla_warnx (ADEBFCACHE, 
		    "get_attr_bulk: didn't find prefered_fid's name");
	ret = EINVAL;
	goto out_names;
    }
    
    ret = ARLA_CALL_DEAD;

    ret = init_fs_context(parent_entry, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	stats.val = NULL;
	cbs.val   = NULL;
	stats.len = cbs.len = 0;

	collectstats_start(&collectstat);
	ret = RXAFS_BulkStatus (conn->connection, &fids, &stats, &cbs, &sync);
	collectstats_stop(&collectstat, parent_entry, conn,
			  find_partition(&context),
			  arla_STATISTICS_REQTYPE_BULKSTATUS, fids.len);
	if (ret) {
	    free (stats.val);
	    free (cbs.val);
	}

	if (host_downp(ret)) {
	    continue;
	} else if (ret) {
	    free_fs_server_context(&context);
	    arla_warn(ADEBFCACHE, ret, "BulkStatus");
	    conn = NULL;
	    goto out_names;
	}
	conn_ref(conn);
	break;
    }

    free_fs_server_context (&context);

    if (ret) {
	ret = ENETDOWN;
	goto out_names;
    }

    arla_warnx (ADEBFCACHE,"get_attr_bulk: BulkStatus returned %d",ret);
    
    len = min(fids.len, min(stats.len, cbs.len));

    /*
     * Save results of bulkstatus
     */

    if (ret == 0) {
	FCacheEntry *e;
	VenusFid fid;

	fcache_counter.fetch_attr_bulk += len;

	fid.Cell = parent_entry->fid.Cell;
	for (i = 0; i < len && ret == 0; i++) {

	    fid.fid = fids.val[i];
	    
	    if (VenusFid_cmp(prefered_fid, &fid) == 0) {
		e = prefered_entry;
	    } else {
		e = find_entry_nolock (fid);
		if (e != NULL && fcache_islocked(e))
		    continue;

		ret = fcache_get (&e, fid, ce);
		if (ret)
		    break;
	    }
	    update_attr_entry (e,
			       &stats.val[i],
			       &cbs.val[i],
			       &sync,
			       conn,
			       ce->cred);
	    e->parent		= parent_entry->fid;
	    if (prefered_entry != e) {
		fcache_release(e);
	    }
	}
    }

    /*
     * Insert result into kernel
     */

    if (fcache_enable_bulkstatus == 2 && ret == 0)  {
	nnpfs_message_install_node_attr msg[AFSCBMAX];
	struct nnpfs_msg_node *node;
	nnpfs_handle *parent;
	FCacheEntry *e;
	VenusFid fid;
	int j;

	fid.Cell = parent_entry->fid.Cell;
	for (i = 0 , j = 0; i < len && ret == 0; i++) {
	    u_int tokens;

	    fid.fid = fids.val[i];
	    
	    if (VenusFid_cmp(prefered_fid, &fid) == 0) {
		e = prefered_entry;
	    } else {
		e = find_entry_nolock (fid);
		if (e != NULL && fcache_islocked(e))
		    continue;

		ret = fcache_get (&e, fid, ce);
		if (ret)
		    break;
	    }


	    arla_warnx (ADEBFCACHE, "installing %d.%d.%d\n",
			e->fid.fid.Volume,
			e->fid.fid.Vnode,
			e->fid.fid.Unique);
	    assert_flag(e,kernelp);
	    e->flags.attrusedp 	= TRUE;
	    
	    /*
	     * Its its already installed, just update with installattr
	     */
	    
	    e->tokens			|= NNPFS_ATTR_R;
	    tokens				= e->tokens;
	    if (!e->flags.kernelp || !e->flags.datausedp)
		tokens			&= ~NNPFS_DATA_MASK;
	    
	    if (e->flags.kernelp) {
		msg[j].attr.header.opcode	= NNPFS_MSG_INSTALLATTR;
		node			= &msg[j].attr.node;
		parent			= NULL;
	    } else {
		msg[j].node.header.opcode	= NNPFS_MSG_INSTALLNODE;
		node			= &msg[j].node.node;
		parent			= &msg[j].node.parent_handle;
		e->flags.kernelp		= TRUE;
		strlcpy (msg[j].node.name, bs.names[i],
			 sizeof(msg[j].node.name));
	    }
	    node->tokens = tokens;
	    
	    /*
	     * Don't install symlink since they might be
	     * mount-points.
	     */
	    
	    if (e->status.FileType != TYPE_LINK) {
		fcacheentry2nnpfsnode (&e->fid,
				       &e->fid,
				       &stats.val[i],
				       node, 
				       parent_entry->acccache,
				       FCACHE2NNPFSNODE_ALL);
		
		if (parent)
		    *parent = *(struct nnpfs_handle*) &parent_entry->fid;
		msg[j].attr.flag = 0;
		j++;
	    }
	    if (prefered_entry != e)
		fcache_release(e);
	}

	/*
	 * Install if there is no error and we have something to install
	 */
	
	if (ret == 0 && j != 0)
	    ret = nnpfs_send_message_multiple_list (kernel_fd,
						    (struct nnpfs_message_header *) msg,
						    sizeof (msg[0]),
						    j);
	/* We have what we wanted, ignore errors */
  	if (ret && i > 0 && prefered_entry)
	    ret = 0;
    }
    
    free (stats.val);
    free (cbs.val);

 out_names:
    for (i = 0 ; i < bs.len && ret == 0; i++)
	free (bs.names[i]);

    if (conn)
	conn_free(conn);

    arla_warnx (ADEBFCACHE, "get_attr_bulk: returned %d", ret);

    return ret;
}


/*
 * fetch attributes for the note `entry' with the rights `ce'.  If
 * `parent_entry' is not NULL, it is used for doing bulkstatus when
 * guess is necessary. If there is a named associated with `entry' it
 * should be filled into `prefered_name' as that will be used for
 * guessing that nodes should be bulkstat:ed.
 *
 * If there is no bulkstatus done, a plain FetchStatus is done.
 */

int
fcache_verify_attr (FCacheEntry *entry, FCacheEntry *parent,
		    const char *prefered_name, CredCacheEntry* ce)
{
    AccessEntry *ae;

    if (dynroot_is_dynrootp (entry))
	return dynroot_get_attr (entry, ce);

    if (entry->flags.usedp
	&& entry->flags.attrp
	&& uptodatep(entry)
	&& findaccess (ce->cred, entry->acccache, &ae) == TRUE)
    {
	arla_warnx (ADEBFCACHE, "fcache_get_attr: have attr");
	fcache_counter.fetch_attr_cached++;
	return 0;
    }

    /* 
     * XXX is this right ?
     * Dont ask fileserver if this file is deleted
     */
    if (entry->flags.silly) {
	entry->tokens |= NNPFS_ATTR_R;
	entry->flags.attrp = TRUE;
	return 0;
    }

    if (connected_mode == DISCONNECTED) {
	if (entry->flags.attrp) {
	    AccessEntry *ae;
	    findaccess(ce->cred, entry->acccache, &ae);
	    ae->cred = ce->cred;
	    ae->access = 0x7f; /* XXXDISCO */
	    return 0;
	}
	else
	    return ENETDOWN;
    }

    /*
     * If there is no parent, `entry' is a root-node, or the parent is
     * un-initialized, don't bother bulkstatus.
     */
    if (parent			    != NULL
	&& entry->fid.fid.Vnode     != 1
	&& entry->fid.fid.Unique    != 1
	&& !entry->flags.mountp
	&& !entry->flags.fake_mp
	&& entry->parent.Cell       != 0
	&& entry->parent.fid.Volume != 0
	&& entry->parent.fid.Vnode  != 0
	&& entry->parent.fid.Unique != 0)
    {
	/*
	 * Check if the entry is used, that means that
	 * there is greater chance that we we'll succeed
	 * when doing bulkstatus.
	 */

	if (parent->hits++ > fcache_bulkstatus_num &&
	    parent->flags.datausedp) {
	    int error;
	
	    arla_warnx (ADEBFCACHE, "fcache_get_attr: doing bulk get_attr");

	    error = get_attr_bulk (parent,
				   entry, &entry->fid,
				   prefered_name, ce);
	    /* magic calculation when we are going to do next bulkstat */
	    parent->hits = 0;

	    if (error == 0)
		return 0;
	}
    }

    /*
     * We got here because the bulkstatus failed, didn't want to do a
     * bulkstatus or we didn't get a parent for the entry
     */

    arla_warnx (ADEBFCACHE, "fcache_get_attr: doing read_attr");

    return read_attr (entry, ce);
}



/*
 * Make sure that `e' has attributes and that they are up-to-date.
 * `e' must be write-locked.
 */

static int
do_read_data(FCacheEntry *e, CredCacheEntry *ce, 
	     uint64_t offset, uint64_t end)
{
    int ret = ARLA_CALL_DEAD;
    fs_server_context context;
    ConnCacheEntry *conn;

    if (connected_mode == DISCONNECTED)
	return ENETDOWN;

    ret = init_fs_context(e, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {
	do {
	    ret = read_data(e, conn, ce, find_partition(&context), 
			    offset, end);
	} while (!ret && !fcache_have_wanted(e, offset, end));
	if (!try_next_fs (ret, &e->fid))
	    break;
    }
    free_fs_server_context (&context);

    if (host_downp(ret))
	ret = ENETDOWN;
    return ret;
}

/*
 * Make sure that `e' has file data and is up-to-date.
 */

static int
fcache_verify_data(FCacheEntry *e, CredCacheEntry *ce,
		   uint64_t offset, uint64_t end)
{
    ConnCacheEntry *conn = NULL;
    int ret;
    fs_server_context context;

    assert (e->flags.usedp);
    AssertExclLocked(&e->lock);

    if (dynroot_is_dynrootp (e))
	return dynroot_get_data (e, ce);

    /* Don't get data for deleted files */
    if (e->flags.silly) {
	if (fcache_have_wanted(e, offset, end))
	    return 0;

	return EIO;
    }

    if (e->flags.attrp && uptodatep(e)) {

	/* For directories we have all data or no data at all */
	if (e->status.FileType == TYPE_DIR
	    && block_any(e) != BLOCK_NONE) /* XXX */
	    return 0;

	if (fcache_have_wanted(e, offset, end)) {
	    fcache_counter.fetch_data_cached++;
	    return 0;
	} else
	    return do_read_data(e, ce, offset, end);
    }

    ret = do_read_attr (e, ce, &conn, &context);
    if (ret)
	return ret;

    if (fcache_have_wanted(e, offset, end)) {
	fcache_counter.fetch_data_cached++;
	free_fs_server_context (&context);
	return 0;
    }

    do {
	ret = read_data(e, conn, ce, find_partition(&context),
			offset, end);
    } while (!ret && !fcache_have_wanted(e, offset, end));

    free_fs_server_context (&context);
    return ret;
}

/*
 * Fetch `fid' with data, returning the cache entry in `res'.
 * note that `fid' might change.
 */

int
fcache_get_data(FCacheEntry **e, CredCacheEntry **ce,
		uint64_t wanted_offset, uint64_t wanted_end)
{
    int ret;

    if ((*e)->flags.fake_mp) {
	VenusFid new_fid;
	FCacheEntry *new_root;

	ret = resolve_mp(*e, &new_fid, ce);
	if (ret) {
	    return ret;
	}
	ret = fcache_get (&new_root, new_fid, *ce);
	if (ret) {
	    return ret;
	}
	ret = fcache_verify_attr (new_root, NULL, NULL, *ce);
	if (ret) {
	    fcache_release (new_root);
	    return ret;
	}
	(*e)->flags.fake_mp   = FALSE;
	(*e)->flags.mountp    = TRUE;
	(*e)->status.FileType = TYPE_LINK;
	update_fid ((*e)->fid, *e, new_fid, new_root);
	fcache_release (*e);
	*e  = new_root;
	install_attr (*e, FCACHE2NNPFSNODE_ALL);
    }

    if (wanted_end == 0) {
	/*
	 * XXX remove this case, attr should either be known already
	 * here, or we should just fetch `whole file'/next block.
	 */

        ret = fcache_verify_attr (*e, NULL, NULL, *ce);
        if (ret)
            return ret;

        /* if ((*e)->usage == 0 || !uptodatep(*e)) */
	wanted_end = fcache_get_status_length(&(*e)->status);
    }
	
    ret = fcache_verify_data(*e, *ce, wanted_offset, wanted_end);
    return ret;
}

/*
 * Helper function for followmountpoint.
 * Given the contents of a mount-point, figure out the cell and volume name.
 *
 * ``mp'' must be writeable and should not be used afterwards.
 * ``*volname'' is a pointer to somewhere in the mp string.
 * ``cell'' should be set before function is called to default cell.
 */

static int
parse_mountpoint (char *mp, size_t len, int32_t *cell, char **volname)
{
    char *colon;
    
    mp[len - 1] = '\0';
    colon = strchr (mp, ':');
    if (colon != NULL) {
	*colon++ = '\0';
	*cell    = cell_name2num (mp + 1);
	if (*cell == -1)
	    return ENOENT;
	*volname = colon;
    } else {
	*volname = mp + 1;
    }
    return 0;
}

/*
 * Used by followmountpoint to figure out what clone of a volume
 * should be used.
 *
 * Given a `volname', `cell', it uses the given `ce', `mount_symbol'
 * and `parent_type' to return a volume id in `volume'.
 *
 * The rules are:
 *
 * "readonly" -> RO
 * BK + "backup" -> fail
 * "backup" -> BK
 * BK + "" + # -> RO
 * RO + "" + # -> RO
 * * -> RW
 *
 * this_type = "" | "readonly" | "backup"
 * parent_type = RW | RO | BK
 * mount_symbol = "#" | "%"
 */

static int
find_volume (const char *volname, int32_t cell, 
	     CredCacheEntry *ce, char mount_symbol, int parent_type,
	     uint32_t *volid, VolCacheEntry **ve)
{
    int result_type;
    int this_type;
    int res;

    res = volcache_getbyname (volname, cell, ce, ve, &this_type);
    if (res)
	return res;

    assert (this_type == RWVOL ||
	    this_type == ROVOL ||
	    this_type == BACKVOL);

    if (this_type == ROVOL) {
	if (!((*ve)->entry.flags & VLF_ROEXISTS)) {
	    volcache_free (*ve);
	    return ENOENT;
	}
	result_type = ROVOL;
    } else if (this_type == BACKVOL && parent_type == BACKVOL) {
	volcache_free (*ve);
	return ENOENT;
    } else if (this_type == BACKVOL) {
	if (!((*ve)->entry.flags & VLF_BOEXISTS)) {
	    volcache_free (*ve);
	    return ENOENT;
	}
	result_type = BACKVOL;
    } else if (this_type == RWVOL &&
	       parent_type != RWVOL &&
	       mount_symbol == '#') {
	if ((*ve)->entry.flags & VLF_ROEXISTS)
	    result_type = ROVOL;
	else if ((*ve)->entry.flags & VLF_RWEXISTS)
	    result_type = RWVOL;
	else {
	    volcache_free (*ve);
	    return ENOENT;
	}
    } else {
	if ((*ve)->entry.flags & VLF_RWEXISTS)
	    result_type = RWVOL;
	else if ((*ve)->entry.flags & VLF_ROEXISTS)
	    result_type = ROVOL;
	else {
	    volcache_free (*ve);
	    return ENOENT;
	}
    }
    *volid = (*ve)->entry.volumeId[result_type];
    return 0;
}

/*
 * Set `fid' to point to the root of the volume pointed to by the
 * mount-point in (buf, len).
 *
 * If succesful, `fid' will be updated to the root of the volume, and
 * `ce' will point to a cred in the new cell.
 */

static int
get_root_of_volume (VenusFid *fid, const VenusFid *parent,
		    VolCacheEntry *volume,
		    CredCacheEntry **ce,
		    char *buf, size_t len)
{
    VenusFid oldfid = *fid;
    char *volname;
    int32_t cell;
    uint32_t volid;
    int res;
    long parent_type, voltype;
    char mount_symbol;
    VolCacheEntry *ve;
    FCacheEntry *e;

    cell = fid->Cell;

    res = parse_mountpoint (buf, len, &cell, &volname);
    if (res)
	return res;

    /*
     * If this is a cross-cell mountpoint we need new credentials. 
     */

    if ((*ce)->cell != cell) {
	CredCacheEntry *new_ce;

	new_ce = cred_get(cell, (*ce)->cred, CRED_ANY);
	if (new_ce == NULL)
	    return ENOMEM;
	cred_free (*ce);
	*ce = new_ce;
    }

    parent_type = getvoltype (fid->fid.Volume, volume);
    mount_symbol = *buf;

    res = find_volume (volname, cell, *ce, mount_symbol,
		       parent_type, &volid, &ve);
    if (res)
	return res;

    /*
     * Create the new fid. The root of a volume always has
     * (Vnode, Unique) = (1,1)
     */

    fid->Cell = cell;
    fid->fid.Volume = volid;
    fid->fid.Vnode = fid->fid.Unique = 1;

    /*
     * Check if we are looking up ourself, if we are, just return.
     */

    if (VenusFid_cmp(fid, parent) == 0) {
	volcache_free (ve);
	return 0;
    }

    res = fcache_get (&e, *fid, *ce);
    if (res) {
	volcache_free (ve);
	return res;
    }

    /*
     * Root nodes are a little bit special.  We keep track of
     * their parent in `parent' so that `..' can be handled
     * properly.
     */

    e->flags.vol_root  = TRUE;
    e->parent          = *parent;

    voltype = getvoltype (fid->fid.Volume, ve);
    if (ve->parent[voltype].volume == NULL) {
	ve->parent[voltype].fid = *parent;
	ve->parent[voltype].mp_fid = oldfid;
    }
    volcache_volref (ve, volume, voltype);
    fcache_release (e);
    volcache_free (ve);
    return 0;
}

/*
 * If this entry is a mount point, set the fid data to
 * the root directory of the volume it's pointing at,
 * otherwise just leave it.
 *
 * Mount points are symbol links with the following contents:
 *
 * '#' | '%' [ cell ':' ] volume-name [ '.' ]
 *
 * This function tries to do a minimal amount of work.  It always has
 * to fetch the attributes of `fid' and if it's a symbolic link, the
 * contents as well.
 */

int
followmountpoint (VenusFid *fid, const VenusFid *parent, FCacheEntry *parent_e,
		  CredCacheEntry **ce)
{
    FCacheEntry *e;
    int ret;

    /*
     * Get the node for `fid' and verify that it's a symbolic link
     * with the correct bits.  Otherwise, just return the old
     * `fid' without any change.
     */

    ret = fcache_get (&e, *fid, *ce);
    if (ret)
	return ret;

    e->parent = *parent;
    ret = fcache_verify_attr (e, parent_e, NULL, *ce);
    if (ret) {
	fcache_release(e);
	return ret;
    }

    if (e->flags.mountp)
	ret = resolve_mp(e, fid, ce);
     
    fcache_release(e);
    return ret;
}

/*
 * actually resolve a mount-point
 */

static int
resolve_mp(FCacheEntry *e, VenusFid *ret_fid, CredCacheEntry **ce)
{
    VenusFid fid = e->fid;
    int ret;
    fbuf the_fbuf;
    char *buf;
    uint32_t length;

    assert(e->flags.fake_mp || e->flags.mountp);
    AssertExclLocked(&e->lock);

    ret = fcache_verify_data(e, *ce, 0,
			     fcache_get_status_length(&e->status));
    if (ret)
	return ret;

    length = fcache_get_status_length(&e->status);

    ret = abuf_create (&the_fbuf, e, length, FBUF_READ);
    if (ret)
	return ret;

    buf = fbuf_buf (&the_fbuf);

    ret = get_root_of_volume (&fid, &e->parent, e->volume, 
			      ce, buf, length);

    abuf_end (&the_fbuf);
    if (ret) 
	return ret;
    *ret_fid = fid;
    return 0;
}

/*
 *
 */

static Bool
print_entry (void *ptr, void *arg)
{
    FCacheEntry *e = (FCacheEntry *)ptr;

    arla_log(ADEBVLOG, "(%d, %u, %u, %u)" "%s%s%s%s"
	     "%s%s%s%s" "%s%s%s%s" "%s%s%s%s" "%s%s%s usage: %llu",
	     e->fid.Cell,
	     e->fid.fid.Volume, e->fid.fid.Vnode, e->fid.fid.Unique,

	     e->flags.usedp?" used":"",
	     e->flags.attrp?" attr":"",
	     e->usage != 0 ?" data":"",
	     e->flags.attrusedp?" attrused":"",

	     e->flags.datausedp?" dataused":"",
	     e->flags.extradirp?" extradir":"",
	     e->flags.mountp?" mount":"",
	     e->flags.kernelp?" kernel":"",

	     e->flags.sentenced?" sentenced":"",
	     e->flags.stale?" stale":"",
	     e->flags.dirtied?" dirtied":"",
	     e->flags.silly?" silly":"",

	     e->flags.fake_mp ? " fake mp" : "",
	     e->flags.vol_root ? " vol root" : "",
	     e->flags.waiters ? " waiters" : "",
	     e->flags.gcp ? " gc" : "",

	     e->flags.locked ? " locked" : "",
	     e->flags.lockwait ? " lockwait" : "",
	     e->flags.appended ? " appended" : "",
	     (unsigned long long)e->usage);
    return FALSE;
}


/*
 *
 */

void
fcache_status (void)
{
    arla_log(ADEBVLOG, "%lu (%lu-/%lu)-%lu) files"
	     "%lu (%lu-%lu) bytes\n",
	     usedvnodes, lowvnodes, current_vnodes, highvnodes,
	     (long)usedbytes, (long)lowbytes, (long)highbytes);
    hashtabforeach (hashtab, print_entry, NULL);
}

/*
 * Update cache usage of entry by adding `nblocks' times blocksize and
 * update accounting accordingly.
 */

static int
fcache_update_usage(FCacheEntry *e, int nblocks)
{
    int64_t diff = ((int64_t)blocksize) * nblocks;
    int ret = 0;

    /* AssertExclLocked(&e->lock); */

    if (nblocks > 0)
	ret = fcache_need_bytes(diff);
    if (!ret) {
	usedbytes += diff;
	e->usage  += diff;
	
	assert(e->usage <= usedbytes);
	assert(e->usage >= 0);
    }

    return ret;
}

/*
 * Mark the data range's presence in cache according to 'have'
 * Cache usage is updated, this may cause gc.
 */

int
fcache_set_have(FCacheEntry *entry, uint64_t offset, uint64_t end)
{
    uint64_t off;

    AssertExclLocked(&entry->lock);

    assert(offset <= end);

    off = block_offset(offset);
    do {
	if (!fcache_block_exists(entry, off)) {
	    int ret = create_block(entry, off);
	    if (ret)
		return ret;
	}
	off += blocksize;
    } while (off < end);

    return 0;
}

/*
 * Set new length of entry, and note it's all in cache
 */

void
fcache_set_have_all(FCacheEntry *e, uint64_t len)
{
    AssertExclLocked(&e->lock);
    fcache_set_status_length(&e->status, len);
}

/*
 * Request an ACL and put it in opaque
 */

int
getacl(VenusFid fid,
       CredCacheEntry *ce,
       AFSOpaque *opaque)
{
    FCacheEntry *dire;
    ConnCacheEntry *conn;
    AFSFetchStatus status;
    AFSVolSync volsync;
    int ret;
    fs_server_context context;
  
    opaque->val = NULL;
    opaque->len = 0;

    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = fcache_get (&dire, fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	return ret;
    }

    ret = init_fs_context(dire, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {

	ret = RXAFS_FetchACL (conn->connection, &fid.fid,
			      opaque, &status, &volsync);
	if (ret) {
	    free(opaque->val);
	    opaque->val = NULL;
	    opaque->len = 0;
	}

	if (!try_next_fs (ret, &fid))
	    break;
    }
    if (ret)
	arla_warn (ADEBFCACHE, ret, "FetchACL");

    if (ret == 0)
	update_entry (dire, &status, NULL, &volsync,
		      conn, ce->cred);
    else if (host_downp(ret))
	ret = ENETDOWN;

    free_fs_server_context (&context);
    fcache_release (dire);
    return ret;
}

/*
 * Store the ACL read from opaque
 *
 * If the function return 0, ret_e is set to the dir-entry and must
 * be fcache_released().
 */

int
setacl(VenusFid fid,
       CredCacheEntry *ce,
       AFSOpaque *opaque,
       FCacheEntry **ret_e)
{
    FCacheEntry *dire;
    ConnCacheEntry *conn;
    AFSFetchStatus status;
    AFSVolSync volsync;
    int ret;
    fs_server_context context;
  
    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = fcache_get (&dire, fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	return EINVAL;
    }

    ret = init_fs_context(dire, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {
	ret = RXAFS_StoreACL (conn->connection, &fid.fid,
			      opaque, &status, &volsync);
	if (!try_next_fs (ret, &fid))
	    break;
    }
    if (ret)
	arla_warn (ADEBFCACHE, ret, "StoreACL");

    if (ret == 0)
	update_entry (dire, &status, NULL, &volsync,
		      conn, ce->cred);
    else if (host_downp(ret))
	ret = ENETDOWN;

    free_fs_server_context (&context);

    if (ret == 0) {
	*ret_e = dire;
    } else {
	*ret_e = NULL;
	fcache_release (dire);
    }
    return ret;
}

/*
 * Request volume status
 */

int
getvolstat(VenusFid fid, CredCacheEntry *ce,
	   AFSFetchVolumeStatus *volstat,
	   char *volumename, size_t volumenamesz,
	   char *offlinemsg,
	   char *motd)
{
    FCacheEntry *dire;
    ConnCacheEntry *conn;
    int ret;
    fs_server_context context;
  
    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = fcache_get (&dire, fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	return EINVAL;
    }

    ret = init_fs_context(dire, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {
	ret = RXAFS_GetVolumeStatus (conn->connection, fid.fid.Volume,
				     volstat, volumename, offlinemsg,
				     motd);
	if (!try_next_fs (ret, &fid))
	    break;
    }
    if (ret)
	arla_warn (ADEBFCACHE, ret, "GetVolumeStatus");
    free_fs_server_context (&context);
    if (host_downp(ret))
	ret = ENETDOWN;
    if (ret == 0 && volumename[0] == '\0') {
	if (volcache_getname (fid.fid.Volume, fid.Cell,
			      volumename, volumenamesz) == -1)
	    strlcpy(volumename, "<unknown>", volumenamesz);
    }

    fcache_release (dire);
    return ret;
}

/*
 * Store volume status
 */

int
setvolstat(VenusFid fid, CredCacheEntry *ce,
	   AFSStoreVolumeStatus *volstat,
	   char *volumename,
	   char *offlinemsg,
	   char *motd)
{
    FCacheEntry *dire;
    ConnCacheEntry *conn;
    int ret;
    fs_server_context context;
  
    if (connected_mode != CONNECTED)
	return EINVAL;

    ret = fcache_get (&dire, fid, ce);
    if (ret) {
	arla_warn (ADEBFCACHE, ret, "fcache_get");
	return EINVAL;
    }

    ret = init_fs_context(dire, ce, &context);
    if (ret)
	return ret;

    for (conn = find_first_fs (&context);
	 conn != NULL;
	 conn = find_next_fs (&context, conn, ret)) {
	ret = RXAFS_SetVolumeStatus (conn->connection, fid.fid.Volume,
				     volstat, volumename, offlinemsg,
				     motd);
	if (!try_next_fs (ret, &fid))
	    break;
    }
    if (ret) {
	if (host_downp(ret))
	    ret = ENETDOWN;
	arla_warn (ADEBFCACHE, ret, "SetVolumeStatus");
    }
    free_fs_server_context (&context);

    fcache_release (dire);
    return ret;
}

/*
 * Get `fbuf' from `centry'
 *
 * Assume that data is valid and `centry' is exclusive locked.
 */

int
fcache_get_fbuf (FCacheEntry *centry, fbuf *fbuf, int fbuf_flags)
{
    uint64_t len;

    AssertExclLocked(&centry->lock);

    len = fcache_get_status_length(&centry->status);
    return abuf_create(fbuf, centry, len, fbuf_flags);
}

/*
 *
 */

static Bool 
sum_node (List *list, Listitem *li, void *arg)
{
    int64_t *a = arg;
    FCacheEntry *e = listdata (li);

    if (e != CLEANER_MARKER)
	*a += e->usage;
    
    return FALSE;
}


int64_t
fcache_calculate_usage (void)
{
    int64_t size = 0;

    listiter (kernel_node_lru, sum_node, &size);
    listiter (node_lru, sum_node, &size);

    return size;
}

/*
 *
 */

const VenusFid *
fcache_realfid (const FCacheEntry *entry)
{
    if (entry->flags.vol_root
	|| (entry->fid.fid.Vnode == 1 && entry->fid.fid.Unique == 1)) {
	long voltype = getvoltype(entry->fid.fid.Volume, entry->volume);
    	return &entry->volume->parent[voltype].mp_fid;
    } else {
	return &entry->fid;
    }
}

/*
 *
 */

static Bool 
check_dir (List *list, Listitem *li, void *arg)
{
    FCacheEntry *e = listdata (li);
    fbuf the_fbuf;
    uint64_t len;
    int ret;

    if (e == CLEANER_MARKER)
	return FALSE;

    if (fcache_islocked(e))
	return FALSE;

    fcache_lock(e, TRUE);

    len = fcache_get_status_length(&e->status);
    if (!fcache_have_wanted(e, 0, len))
	goto out;

    ret = fcache_get_fbuf(e, &the_fbuf, FBUF_READ);
    if (ret)
	goto out;
    
    ret = fdir_dirp(&the_fbuf);

    abuf_end (&the_fbuf);

    if (e->status.FileType == TYPE_DIR)
	assert(ret);
    else
	assert(!ret);

 out:
    fcache_unlock(e);
    
    return FALSE;
}

/*
 * Verifies that directories seems to be directories and files doesn't
 * seems to be directories, note that false positives are
 * possible in the latter of these cases, so this should not be turned on
 * default.
 */

void
fcache_check_dirs(void)
{
    listiter (node_lru, check_dir, NULL);
    listiter (kernel_node_lru, check_dir, NULL);
}

struct check_block_arg {
    Listitem *prev;
};

/*
 * As much paranoia as possible.
 */

static Bool 
check_block(List *list, Listitem *li, void *arg)
{
    struct check_block_arg *cba = (struct check_block_arg *)arg;
    struct block *b = (struct block *)listdata(li);

    if (b != CLEANER_MARKER) {
	assert(b->lru_le == li);
	assert(listprev(list, li) == cba->prev);
	assert(block_offset(b->offset) == b->offset);
	assert(b->node->flags.usedp);
	assert(!block_emptyp(b->node));

	if (list == kernel_block_lru) {
	    assert(b->flags.kernelp);
	    assert(b->node->flags.kernelp);
	} else if (list == block_lru) {
	    assert(!b->flags.kernelp);
	} else {
	    assert(0);
	}
    }

    cba->prev = li;

    return FALSE;
}

/*
 * Verify that the block lists are consistent.
 */

void
fcache_check_blocks(void)
{
    struct check_block_arg arg;

    arg.prev = NULL;
    listiter(block_lru, check_block, &arg);

    arg.prev = NULL;
    listiter(kernel_block_lru, check_block, &arg);
}
