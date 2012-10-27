/*
 * Copyright (c) 1995-2006 Kungliga Tekniska Högskolan
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
 * The interface for the file-cache.
 */

/* $Id: fcache.h,v 1.106 2006/12/11 16:20:38 tol Exp $ */

#ifndef _FCACHE_H_
#define _FCACHE_H_

#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_blocks.h>
#include <fcntl.h>
#include <cred.h>
#include <heap.h>

/*
 * For each entry in the filecache we save the rights of NACCESS users.
 * The value should be the same as NNPFS_MAXRIGHTS from nnpfs_message.h
 * If it isn't you can get some very strange behavior from nnpfs, so don't
 * even try. XXX
 */ 

#define NACCESS NNPFS_MAXRIGHTS

typedef struct {
     nnpfs_pag_t cred;
     u_long access;
} AccessEntry;

/* these must match PRSFS_* from rxdef/common.h */
enum Access { ANONE   = 0x0,
              AREAD   = 0x01,
	      AWRITE  = 0x02,
	      AINSERT = 0x04,
	      ALIST   = 0x08,
	      ADELETE = 0x10,
	      ALOCK   = 0x20,
	      AADMIN  = 0x40 };

typedef struct {
    Bool valid;
#if 0
     struct nnpfs_cache_handle nnpfs_handle;
#endif
} fcache_cache_handle;

struct block; /* fwd */

typedef struct FCacheEntry {
    struct Lock lock;		/* locking information for this entry */
    VenusFid fid;		/* The fid of the file for this entry */
    unsigned refcount;		/* reference count */
    uint32_t host;		/* the source of this entry */
    int64_t usage;		/* the cache usage size */
    AFSFetchStatus status;	/* Removed unused stuff later */
    AFSCallBack callback;	/* Callback to the AFS-server */
    AFSVolSync volsync;		/* Sync info for ro-volumes */
    AccessEntry acccache[NACCESS]; /* cache for the access rights */
    uint32_t anonaccess;	/* the access mask for system:anyuser */
    uint32_t index;		/* this is V%u */
/*x*/    fcache_cache_handle handle;	/* handle */
    List *blocks;
    struct {
	unsigned usedp : 1;	/* Is this entry used? */
	unsigned attrp : 1;	/* Are the attributes in status valid? */
	unsigned attrusedp : 1;	/* Attr is used in the kernel */
/*x*/	unsigned datausedp : 1;	/* Data is used in the kernel */
	unsigned extradirp : 1;	/* Has this directory been "converted"? */
	unsigned mountp : 1;	/* Is this an AFS mount point? */
	unsigned kernelp : 1;	/* Does this entry exist in the kernel? */
	unsigned sentenced : 1;	/* This entry should die */
	unsigned dirtied : 1;	/* Putdata failed. */
	unsigned stale : 1;	/* Data isn't valid. */
	unsigned silly : 1;	/* Instead of silly-rename */
	unsigned fake_mp : 1;	/* a `fake' mount point */
	unsigned vol_root : 1;	/* root of a volume */
	unsigned waiters : 1;	/* Are threads waiting for I/O to complete? */
	unsigned gcp : 1;	/* Allow gc of blocks while node is locked? */
	unsigned locked : 1;	/* Is this node locked? */
	unsigned lockwait : 1;	/* Are threads waiting to lock? */
	unsigned appended : 1;	/* Has kernel sent 'appenddata' for node? */
    } flags;
    u_int tokens;		/* read/write tokens for the kernel */
    VenusFid parent;
    Listitem *lru_le;		/* lru */
    heap_ptr invalid_ptr;	/* pointer into the heap */
    VolCacheEntry *volume;	/* pointer to the volume entry */
    Bool priority;		/* is the file worth keeping */
    int hits;			/* number of lookups */
    PollerEntry *poll;		/* poller entry */
    uint32_t disco_id;		/* id in disconncted log */
} FCacheEntry;

/*
 * The fileservers to ask for a particular volume.
 */

struct fs_server_context {
    int i;			/* current number being probed */
    int num_conns;		/* number in `conns' */
    VolCacheEntry *ve;		/*  */
    struct fs_server_entry {
	ConnCacheEntry *conn;	/* rx connection to server */
	int ve_ent;		/* entry in `ve' */
    } conns[NMAXNSERVERS];
};

typedef struct fs_server_context fs_server_context;

/*
 * How far the cleaner will go went cleaning things up.
 */

extern Bool fprioritylevel;

void
fcache_init (u_long alowvnodes,
	     u_long ahighvnodes,
	     int64_t alowbytes,
	     int64_t ahighbytes,
	     uint64_t blocksize,
	     Bool recover);

int
fcache_reinit(u_long alowvnodes,
	      u_long ahighvnodes,
	      int64_t alowbytes,
	      int64_t ahighbytes);

void
fcache_purge_volume (VenusFid fid);

void
fcache_purge_host (u_long host);

void
fcache_purge_cred (nnpfs_pag_t cred, int32_t cell);

void
fcache_stale_entry (VenusFid fid, AFSCallBack callback);

void
fcache_invalidate_mp (void);

int
fcache_dir_name (FCacheEntry *entry, char *s, size_t len);

int
fcache_extra_file_name (FCacheEntry *entry, char *s, size_t len);

int
fcache_open_block (FCacheEntry *entry, uint64_t offset, Bool writep);

void
fcache_throw_block (struct block *b);

int
fcache_append_block(FCacheEntry *entry, uint64_t offset);

Bool
fcache_block_exists(FCacheEntry *entry, uint64_t offset);

void
fcache_block_lru(struct block *b);

void
fcache_node_lru(FCacheEntry *e);

void
fcache_node_setkernelp(FCacheEntry *e, Bool val);

void
fcache_data_setkernelp(FCacheEntry *e, uint64_t offset, Bool val, Bool unbusy);

void
fcache_data_setbusy(FCacheEntry *e, uint64_t offset, uint64_t end, Bool val);

int
fcache_open_extra_dir (FCacheEntry *entry, int flag, mode_t mode);

int
fcache_fhget (char *filename, fcache_cache_handle *handle);

int
write_data(FCacheEntry *entry, FCacheEntry *data_entry,
	   uint64_t offset, uint64_t length,
	   AFSStoreStatus *storestatus, CredCacheEntry *ce);

int
truncate_file (FCacheEntry *entry, uint64_t size,
	       AFSStoreStatus *status, CredCacheEntry *ce);

int
write_attr (FCacheEntry *entry, const AFSStoreStatus *status,
	    CredCacheEntry *ce);

int
create_file (FCacheEntry *dir_entry,
	     const char *name, AFSStoreStatus *store_attr,
	     FCacheEntry **ret_entry, CredCacheEntry *ce);

int
create_directory (FCacheEntry *dir_entry,
		  const char *name, AFSStoreStatus *store_attr,
		  VenusFid *child_fid, AFSFetchStatus *fetch_attr,
		  CredCacheEntry *ce);

int
create_symlink (FCacheEntry *dir_entry,
		const char *name, AFSStoreStatus *store_attr,
		VenusFid *child_fid, AFSFetchStatus *fetch_attr,
		const char *contents,
		CredCacheEntry *ce);

int
create_link (FCacheEntry *dir_entry,
	     const char *name,
	     FCacheEntry *existing_entry,
	     CredCacheEntry *ce);

int
remove_file(FCacheEntry *dir_entry, const char *name,
	    FCacheEntry *child_entry, CredCacheEntry *ce);

int
remove_directory(FCacheEntry *dir_entry, const char *name,
		 FCacheEntry *child_entry, CredCacheEntry *ce);

int
rename_file (FCacheEntry *old_dir,
	     const char *old_name,
	     FCacheEntry *new_dir,
	     const char *new_name,
	     CredCacheEntry *ce);

int
getroot (VenusFid *res, CredCacheEntry *ce);

int
fcache_get (FCacheEntry **res, VenusFid fid, CredCacheEntry *ce);

int
fcache_get_gc (FCacheEntry **res, VenusFid fid, CredCacheEntry *ce);

void
fcache_release (FCacheEntry *e);

FCacheEntry *
fcache_find(VenusFid fid);

FCacheEntry *
fcache_find_gcp(VenusFid fid, Bool gcp);

int
fcache_get_data (FCacheEntry **e, CredCacheEntry **ce,
		 uint64_t wanted_offset, uint64_t wanted_end);

int
fcache_verify_attr (FCacheEntry *entry, FCacheEntry *parent_entry,
		    const char *prefered_name, CredCacheEntry* ce);

int
followmountpoint (VenusFid *fid, const VenusFid *parent, FCacheEntry *parent_e,
		  CredCacheEntry **ce);

void
fcache_status (void);

int
fcache_store_state (void);

long
getvoltype(int32_t volid, const VolCacheEntry *ve);

int
getacl(VenusFid fid, CredCacheEntry *ce,
       AFSOpaque *opaque);

int
setacl(VenusFid fid, CredCacheEntry *ce,
       AFSOpaque *opaque, FCacheEntry **ret);

int
getvolstat(VenusFid fid, CredCacheEntry *ce,
	   AFSFetchVolumeStatus *volstat,
	   char *volumename, size_t volumenamesz,
	   char *offlinemsg,
	   char *motd);

int
setvolstat(VenusFid fid, CredCacheEntry *ce,
	   AFSStoreVolumeStatus *volstat,
	   char *volumename,
	   char *offlinemsg,
	   char *motd);

int64_t
fcache_highbytes(void);

int64_t
fcache_usedbytes(void);

int64_t
fcache_lowbytes(void);

u_long
fcache_highvnodes(void);

u_long
fcache_usedvnodes(void);

u_long
fcache_lowvnodes(void);

uint64_t
fcache_getblocksize(void);

void
fcache_setblocksize(uint64_t newsize);

int64_t
fcache_set_appendquota(void);

int
fcache_update_appendquota(FCacheEntry *e);

int
fcache_giveup_all_callbacks (void);

uint64_t
fcache_get_status_length(const AFSFetchStatus *status);

void
fcache_set_status_length(AFSFetchStatus *status, int64_t length);

void
fcache_discard_attrs(void);

int
fcache_reobtain_callbacks (struct nnpfs_cred *cred);

/* XXX - this shouldn't be public, but getrights in inter.c needs it */
int
read_attr (FCacheEntry *, CredCacheEntry *);

Bool
findaccess (nnpfs_pag_t cred, AccessEntry *ae, AccessEntry **pos);

void
fcache_unused(FCacheEntry *entry);

int
fcache_set_have(FCacheEntry *entry, uint64_t offset, uint64_t length);

void
fcache_set_have_all(FCacheEntry *e, uint64_t len);


int
init_fs_context (FCacheEntry *e,
		 CredCacheEntry *ce,
		 fs_server_context *context);

ConnCacheEntry *
find_first_fs (fs_server_context *context);

ConnCacheEntry *
find_next_fs (fs_server_context *context,
	      ConnCacheEntry *prev_conn,
	      int mark_as_dead);

void
free_fs_server_context (fs_server_context *context);

void
recon_hashtabadd(FCacheEntry *entry);
 
void
recon_hashtabdel(FCacheEntry *entry);

int
fcache_get_fbuf (FCacheEntry *centry, fbuf *fbuf, int fbuf_flags);

int64_t
fcache_calculate_usage (void);

const VenusFid *
fcache_realfid (const FCacheEntry *entry);

void
fcache_mark_as_mountpoint (FCacheEntry *entry);

const char *
fcache_getdefsysname (void);

int
fcache_addsysname (const char *sysname);

int
fcache_removesysname (const char *sysname);

int
fcache_setdefsysname (const char *sysname);

int
fs_probe (struct rx_connection *conn);

void
fcache_check_dirs(void);

void
fcache_check_blocks(void);

void
fcache_cleaner_ref(void);
void
fcache_cleaner_deref(void);

#endif /* _FCACHE_H_ */
