/*
 * Copyright (c) 1995 - 2002, 2005 - 2006 Kungliga Tekniska Högskolan
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
 * Interface to the cache manager.
 */

#include "arla_local.h"
RCSID("$Id: inter.c,v 1.155 2007/11/25 20:09:37 map Exp $") ;

#include <nnpfs/nnpfs_message.h>

#ifdef BLOCKS_PARANOIA
Bool cm_consistencyp = TRUE;
#else
Bool cm_consistencyp = FALSE;
#endif

/*
 * Return the rights for user cred and entry e.
 * If the rights are not existant fill in the entry.
 * The locking of e is up to the caller.
 */

static u_long
getrights (FCacheEntry *e, CredCacheEntry *ce)
{
     AccessEntry *ae;
     int error;

     while (findaccess (ce->cred, e->acccache, &ae) == FALSE) {
	 if ((error = read_attr(e, ce)) != 0)
	     return 0; /* XXXX  we want to return errno */
     }
     return ae->access;
}

/*
 * Check to see if the operation(s) mask are allowed to user cred on
 * file e.
 *
 * Return 0 on success, else a suitable error code.
 */

int
cm_checkright (FCacheEntry *e, u_long mask, CredCacheEntry *ce)
{
    uint32_t modify = AWRITE | AINSERT | ADELETE | ALOCK | AADMIN;
    long voltype = getvoltype(e->fid.fid.Volume, e->volume);
    u_long rights;

    /* We won't be able to modify readonly volumes */
    if (voltype != RWVOL && (mask & modify) != 0)
	return EROFS;

    if (e->status.FileType == TYPE_LINK &&
	e->anonaccess & ALIST)
	return 0;

    if ((e->anonaccess & mask) == mask)
	return 0;

    rights = getrights (e, ce);
    if (e->status.FileType != TYPE_DIR && (rights & AADMIN))
	rights |= AREAD | AWRITE;

    if (e->status.FileType == TYPE_LINK &&
	rights & ALIST)
	return 0;

    if ((rights & mask) == mask)
	return 0;

    return EACCES;
}

/*
 * Check whether to modify cache or not. If we have stale data, get
 * fresh data and return FALSE, else return TRUE to indicate that
 * cache modification is the way to go.
 */

static Bool
should_modify_locally(FCacheEntry **e, CredCacheEntry **ce, int *error)
{
    if (block_any(*e) != BLOCK_NONE)
	return TRUE;
    
    *error = fcache_get_data(e, ce, 0,
			     fcache_get_status_length(&(*e)->status));
    return FALSE;
}

static int log_fd;
static FILE *log_fp;

/*
 *
 */

void
cm_init (void)
{
    log_fd = open ("log", O_WRONLY | O_APPEND | O_CREAT | O_BINARY, 0666);
    if (log_fd < 0)
	arla_err (1, ADEBERROR, errno, "open log");
    log_fp = fdopen (log_fd, "a");
    if (log_fp == NULL)
	arla_err (1, ADEBERROR, errno, "fdopen");
}

/*
 *
 */

void
cm_store_state (void)
{
    fclose (log_fp);
}

/*
 *
 */

static void
log_operation (const char *fmt, ...)
{
    va_list args;
    struct timeval now;

    if(connected_mode == CONNECTED && cm_consistencyp == FALSE)
	return;

    va_start (args, fmt);
    gettimeofday (&now, NULL);
    fprintf (log_fp, "%lu.%lu ",
	     (unsigned long)now.tv_sec,
	     (unsigned long)now.tv_usec);
    vfprintf (log_fp, fmt, args);
    va_end (args);
}

/*
 *
 *
 */

void
cm_turn_on_consistency_check(void)
{
    cm_consistencyp = TRUE;
}

/*
 * Check consistency of the fcache.
 * Will break the log-file.
 */

void
cm_check_consistency (void)
{
    static unsigned int log_times = 0;
    static unsigned int file_times = 0;
    int64_t calc_size, real_size;
    char newname[MAXPATHLEN];

    if (cm_consistencyp == FALSE)
	return;
    
    fcache_check_dirs();
    fcache_check_blocks();

    calc_size = fcache_calculate_usage();
    real_size = fcache_usedbytes ();

    if (calc_size != real_size) {
	    log_operation ("consistency check not guaranteed "
			   "(calc: %d, real: %d, diff %d), aborting\n", 
			   (int) calc_size, (int) real_size,
			   (int)(calc_size - real_size));
	    cm_store_state ();
	    abort();
    }
    if (log_times % 100000 == 0) {
	log_operation ("consistency check ok, rotating logs\n");
	cm_store_state ();
	snprintf (newname, sizeof(newname), "log.%d", file_times++);
	rename ("log", newname);
	cm_init ();	
	log_operation ("brave new world\n");
    }
    log_times++;
}

/*
 * These functions often take a FID as an argument to be general, but
 * they are intended to be called from a vnode-type of layer.
 */

/*
 * The interface to the open-routine.
 */

int
cm_open (FCacheEntry *entry, CredCacheEntry *ce, u_int tokens)
{
     u_long mask;
     int error = 0;

     switch(tokens) {
     case NNPFS_DATA_R:
	  mask = AREAD;
	  break;
     case NNPFS_OPEN_NR:
#if 0
     case NNPFS_OPEN_SR:
#endif
	  mask = AREAD;
	  tokens |= NNPFS_DATA_R;
	  break;
     case NNPFS_DATA_W:
	  mask = AWRITE;
	  break;
     case NNPFS_OPEN_NW:
	  mask = AREAD | AWRITE;
	  tokens |= NNPFS_DATA_R | NNPFS_DATA_W | NNPFS_OPEN_NR;
	  break;
     default:
	 arla_warnx (ADEBCM, "cm_open(): unknown token: %d, assuming AREAD",
		     tokens);
	 mask = AREAD;
	 tokens |= NNPFS_DATA_R;
#if 1
	 assert(FALSE);
#endif
     }

     error = cm_checkright(entry, mask, ce);
     if (!error) {
	  assert(entry->flags.attrusedp);
	  entry->flags.datausedp = TRUE;
	  entry->tokens |= tokens;
	  
	  log_operation ("open (%ld,%lu,%lu,%lu) %u\n",
			 entry->fid.Cell,
			 entry->fid.fid.Volume,
			 entry->fid.fid.Vnode,
			 entry->fid.fid.Unique,
			 mask);
     }

     cm_check_consistency();
 
     return error;
}

/*
 * write ("close"). Set flags and if we opened the file for writing,
 * write it back to the server.
 */

int
cm_write(FCacheEntry *entry, int flag,  uint64_t offset, uint64_t length, 
	 AFSStoreStatus *status, CredCacheEntry* ce)
{
    int error = 0;

    if (flag & NNPFS_WRITE) {
	if (flag & NNPFS_FSYNC)
	    status->Mask |= SS_FSYNC;

	error = write_data(entry, NULL, offset, length, status, ce);

	if (error) {
	    arla_warn (ADEBCM, error, "writing back file");
	    return error;
	}
    }

    log_operation ("write (%ld,%lu,%lu,%lu) %d\n",
		   entry->fid.Cell,
		   entry->fid.fid.Volume,
		   entry->fid.fid.Vnode,
		   entry->fid.fid.Unique,
		   flag);

    cm_check_consistency();

    return error;
}

/*
 * getattr - read the attributes from this file.
 */

int
cm_getattr (FCacheEntry *entry,
	    CredCacheEntry *ce)
{
     int error = 0;

     arla_warnx (ADEBCM, "cm_getattr");

     AssertExclLocked(&entry->lock);

     error = fcache_verify_attr (entry, NULL, NULL, ce);
     if (error)
	 return error;

     arla_warnx (ADEBCM, "cm_getattr: done get attr");

     error = cm_checkright(entry,
			   entry->status.FileType == TYPE_FILE ? AREAD : 0,
			   ce);
     if (!error) {
	 entry->flags.attrusedp = TRUE;
	 fcache_node_setkernelp(entry, TRUE);
	 
	 log_operation ("getattr (%ld,%lu,%lu,%lu)\n",
			entry->fid.Cell,
			entry->fid.fid.Volume,
			entry->fid.fid.Vnode,
			entry->fid.fid.Unique);
     }

     if (!entry->flags.datausedp)
	 entry->tokens &= ~(NNPFS_DATA_MASK | NNPFS_OPEN_MASK);
     
     arla_warnx (ADEBCM, "cm_getattr: return: %d", error);
     cm_check_consistency();

     return error;
}

/*
 * setattr - set the attributes of this file. These are immediately
 * sent to the FS.
 */

int
cm_setattr (FCacheEntry *entry, AFSStoreStatus *attr, CredCacheEntry* ce)
{
     int error = fcache_verify_attr (entry, NULL, NULL, ce);
     if (error)
	 return error;

     error = cm_checkright(entry, AWRITE, ce);
     if (!error) {
	  arla_warnx (ADEBCM, "cm_setattr: Writing status");
	  error = write_attr (entry, attr, ce);

	  log_operation ("setattr (%ld,%lu,%lu,%lu)\n",
			 entry->fid.Cell,
			 entry->fid.fid.Volume,
			 entry->fid.fid.Vnode,
			 entry->fid.fid.Unique);
     }

     cm_check_consistency();
     return error;
}

/*
 * ftruncate - make the specified file have a specified size
 */

int
cm_ftruncate (FCacheEntry *entry, off_t size,
	      AFSStoreStatus *storestatus, CredCacheEntry* ce)
{
     int error = 0;

     error = fcache_verify_attr (entry, NULL, NULL, ce);
     if (error)
	 return error;

     error = cm_checkright(entry, AWRITE, ce);
     if (!error) {
	  error = truncate_file (entry, size, storestatus, ce);

	  log_operation ("ftruncate (%ld,%lu,%lu,%lu) %lu\n",
			 entry->fid.Cell,
			 entry->fid.fid.Volume,
			 entry->fid.fid.Vnode,
			 entry->fid.fid.Unique,
			 (unsigned long)size);
}

     cm_check_consistency();
     return error;
}

/*
 * Expand `src' into `dest' (of size `dst_sz'), expanding `str' to
 * `replacement'. Return number of characters written to `dest'
 * (excluding terminating zero) or `dst_sz' if there's not enough
 * room.
 */

static int
expand_sys (char *dest, size_t dst_sz, const char *src,
	    const char *str, const char *rep)
{
    char *destp = dest;
    const char *srcp = src;
    char *s;
    int n = 0;
    int len;
    size_t str_len = strlen(str);
    size_t rep_len = strlen(rep);
    size_t src_len = strlen(src);
    
    while ((s = strstr (srcp, str)) != NULL) {
	len = s - srcp;

	if (dst_sz <= n + len + rep_len)
	    return dst_sz;

	memcpy (destp, srcp, len);
	memcpy (destp + len, rep, rep_len);
	n += len + rep_len;
	destp += len + rep_len;
	srcp = s + str_len;
    }
    len = src_len - (srcp - src);
    if (dst_sz <= n + len)
	return dst_sz;
    memcpy (destp, srcp, len);
    n += len;
    destp[len] = '\0';
    return n;
}

/*
 * Find this entry in the directory. If the entry happens to point to
 * a mount point, then we follow that and return the root directory of
 * the volume. Hopefully this is the only place where we need to think
 * about mount points (which are followed iff follow_mount_point).
 */

int
cm_lookup (FCacheEntry **entry,
	   const char *name,
	   VenusFid *res,
	   CredCacheEntry** ce,
	   int follow_mount_point)
{
     char tmp_name[MAXPATHLEN];
     int error = 0;

     error = fcache_get_data(entry, ce, 0, 0);
     if (error)
	 return error;

     if (strstr (name, "@sys") != NULL) {
	 int i;

	 for (i = 0; i < sysnamenum; i++) {
	     int size = expand_sys (tmp_name, sizeof(tmp_name), name,
				    "@sys", sysnamelist[i]);
	     if (size >= sizeof(tmp_name))
		 continue;
	     error = adir_lookup (*entry, tmp_name, res);
	     if (error == 0)
		 break;
	 }
	 if (i == sysnamenum)
	     error = ENOENT;

     } else
	 error = adir_lookup (*entry, name, res);

     if (error) 
	 return error;

     /* 
      *
      * Or 
      */

     if (strcmp(".", name) == 0) {

	 /*
	  * If we are looking up "." we don't want to follow the
	  * mountpoint, do fcache_verify_attr to force resolving of
	  * fake mountpoints.
	  */

	 error = fcache_verify_attr (*entry, NULL, NULL, *ce);
	 if (error)
	     goto out;

	 *res = (*entry)->fid;
     } else if (strcmp("..", name) == 0) {

	 /* 
	  * First make sure we don't following mountpoints for ".."
	  * First, We are sure, its not a mountpoint. Second since
	  * following mountpoints lock both parent and child, and
	  * mountpoints breaks the tree that usully filesystem enforce
	  * (non-directed graph) we can deadlock one thread looks up
	  * from "root" -> "directory" and a second from "directory"
	  * -> "..".
	  */

	 /*
	  * The ".." at the top of a volume just points to the volume
	  * root itself, so try to get the real ".." from the volume
	  * cache instead.
	  */

	 if (VenusFid_cmp(&(*entry)->fid, res) == 0) {
	     long voltype;

	     error = fcache_verify_attr (*entry, NULL, NULL, *ce);
	     if (error)
		 goto out;
	     
	     voltype = getvoltype((*entry)->fid.fid.Volume, (*entry)->volume);
	     *res = (*entry)->volume->parent[voltype].fid; /* entry->parent */
	 }

     } else if (follow_mount_point) {
	 error = followmountpoint (res, &(*entry)->fid, *entry, ce);
	 if (error)
	     goto out;
     }
out:
     log_operation ("lookup (%ld,%lu,%lu,%lu) %s\n",
		    (*entry)->fid.Cell,
		    (*entry)->fid.fid.Volume,
		    (*entry)->fid.fid.Vnode,
		    (*entry)->fid.fid.Unique,
		    name);

     cm_check_consistency();
     return error;
}

/*
 * Create this file and more.
 */

int
cm_create (FCacheEntry **dir, const char *name, AFSStoreStatus *store_attr,
	   FCacheEntry **res, CredCacheEntry **ce)
{
     int error = 0;

     error = fcache_get_data (dir, ce, 0, 0);
     if (error)
	 return error;

     error = cm_checkright(*dir, AINSERT, *ce);
     if (!error) {
	 error = create_file (*dir, name, store_attr, res, *ce);
	 if (error == 0 && should_modify_locally(dir, ce, &error))
	     error = adir_creat (*dir, name, (*res)->fid.fid);
     }

     log_operation ("create (%ld,%lu,%lu,%lu) %s\n",
		    (*dir)->fid.Cell,
		    (*dir)->fid.fid.Volume,
		    (*dir)->fid.fid.Vnode,
		    (*dir)->fid.fid.Unique,
		    name);

     cm_check_consistency();
     return error;
}

/*
 * Create a new directory
 */

int
cm_mkdir (FCacheEntry **dir, const char *name,
	  AFSStoreStatus *store_attr,
	  VenusFid *res, AFSFetchStatus *fetch_attr,
	  CredCacheEntry **ce)
{
     int error = 0;

     error = fcache_get_data (dir, ce, 0, 0);
     if (error)
	 return error;

     error = cm_checkright(*dir, AINSERT, *ce);
     if (!error) {
	 error = create_directory (*dir, name, store_attr,
				   res, fetch_attr, *ce);
	 if (error == 0 && should_modify_locally(dir, ce, &error))
	     error = adir_creat (*dir, name, res->fid);
	 
     }

     log_operation ("mkdir (%ld,%lu,%lu,%lu) %s\n",
		    (*dir)->fid.Cell,
		    (*dir)->fid.fid.Volume,
		    (*dir)->fid.fid.Vnode,
		    (*dir)->fid.fid.Unique,
	      name);

     cm_check_consistency();
     return error;
}

/*
 * Create a symlink
 *
 * If realfid is non-NULL, we mark the symlink with kernelp flag and
 * return its fid in realfid.
 *
 */

int
cm_symlink (FCacheEntry **dir,
	    const char *name, AFSStoreStatus *store_attr,
	    VenusFid *res, VenusFid *realfid,
	    AFSFetchStatus *fetch_attr,
	    const char *contents,
	    CredCacheEntry **ce)
{
     FCacheEntry *symlink_entry;
     int error = 0;

     error = fcache_get_data (dir, ce, 0, 0);
     if (error)
	 return error;

     error = cm_checkright(*dir, AINSERT, *ce);
     if (error)
	 return error;

     /* It seems Transarc insists on mount points having mode bits 0644 */

     if (contents[0] == '%' || contents[0] == '#') {
	 store_attr->UnixModeBits = 0644;
	 store_attr->Mask |= SS_MODEBITS;
     } else if (store_attr->Mask & SS_MODEBITS
		&& store_attr->UnixModeBits == 0644)
	 store_attr->UnixModeBits = 0755;

     error = create_symlink (*dir, name, store_attr,
			     res, fetch_attr,
			     contents, *ce);

     if (error == 0 && should_modify_locally(dir, ce, &error))
	 error = adir_creat (*dir, name, res->fid);

     if (error)
	 goto out;

     error = followmountpoint(res, &(*dir)->fid, NULL, ce);
     if (error)
	 goto out;
     
     /*
      * If the new symlink is a mountpoint and it points
      * to dir_fid we will deadlock if we look it up.
      */

     if (realfid == NULL) {
	 /*
	  * Caller doesn't care, don't bother.
	  * ...and don't mark the symlink with kernelp
	  */
     } else if (VenusFid_cmp (res, &(*dir)->fid) != 0) {

	 error = fcache_get (&symlink_entry, *res, *ce);
	 if (error)
	     goto out;
	 
	 error = fcache_verify_attr (symlink_entry, *dir, name, *ce);
	 if (error) {
	     fcache_release (symlink_entry);
	     goto out;
	 }
	 
	 fcache_node_setkernelp(symlink_entry, TRUE);

	 *fetch_attr = symlink_entry->status;
	 *realfid = *fcache_realfid (symlink_entry);

	 fcache_release (symlink_entry);
     } else {
	 *fetch_attr = (*dir)->status;
	 *realfid = *fcache_realfid (*dir);
     }
     
     log_operation ("symlink (%ld,%lu,%lu,%lu) %s %s\n",
		    (*dir)->fid.Cell,
		    (*dir)->fid.fid.Volume,
		    (*dir)->fid.fid.Vnode,
		    (*dir)->fid.fid.Unique,
		    name,
		    contents);
     
 out:
     cm_check_consistency();
     return error;
}

/*
 * Create a hard link.
 */

int
cm_link (FCacheEntry **dir,
	 const char *name,
	 FCacheEntry *file,
	 CredCacheEntry **ce)
{
     int error = 0;

     error = fcache_get_data (dir, ce, 0, 0);
     if (error)
	 return error;

     error = fcache_verify_attr (file, *dir, NULL, *ce);
     if (error)
	 goto out;

     error = cm_checkright(*dir, AINSERT, *ce);
     if (!error) {
	 error = create_link (*dir, name, file, *ce);
	 if (error == 0) {
	     if (should_modify_locally(dir, ce, &error))
		 error = adir_creat (*dir, name, file->fid.fid);
	 }
     }

     log_operation ("link (%ld,%lu,%lu,%lu) (%ld,%lu,%lu,%lu) %s\n",
		    (*dir)->fid.Cell,
		    (*dir)->fid.fid.Volume,
		    (*dir)->fid.fid.Vnode,
		    (*dir)->fid.fid.Unique,
		    file->fid.Cell,
		    file->fid.fid.Volume,
		    file->fid.fid.Vnode,
		    file->fid.fid.Unique,
		    name);

out:
     cm_check_consistency();
     return error;
}

/*
 * generic function for both remove and rmdir
 */

static int
sub_remove(FCacheEntry **dir, const char *name, FCacheEntry **child,
	   CredCacheEntry **ce,
	   const char *operation,
	   int (*func)(FCacheEntry *dir,
		       const char *name,
		       FCacheEntry *child,
		       CredCacheEntry *ce))
{
     int error = 0;

     error = fcache_get_data (dir, ce, 0, 0);
     if (error)
	 return error;

     error = cm_checkright(*dir, ADELETE, *ce);
     if (!error) {
	 error = (*func) (*dir, name, *child, *ce);
	 if (error == 0 && should_modify_locally(dir, ce, &error))
	     error = adir_remove (*dir, name);
     }
     
     log_operation ("%s (%ld,%lu,%lu,%lu) %s\n",
		    operation,
		    (*dir)->fid.Cell,
		    (*dir)->fid.fid.Volume,
		    (*dir)->fid.fid.Vnode,
		    (*dir)->fid.fid.Unique,
		    name);

     cm_check_consistency();
     return error;
}

/*
 * Remove the file named `name' in the directory `dir'.
 */

int
cm_remove(FCacheEntry **dir, const char *name,
	  FCacheEntry **child, CredCacheEntry **ce)
{
    return sub_remove(dir, name, child, ce, "remove", remove_file);
}

/*
 * Remove the directory named `name' in the directory `dir'.
 */

int
cm_rmdir(FCacheEntry **dir, const char *name,
	 FCacheEntry **child, CredCacheEntry **ce)
{
    return sub_remove(dir, name, child, ce, "rmdir", remove_directory);
}

/*
 * Read a symlink and null-terminate
 */

static int
read_symlink(FCacheEntry *entry, char *buf, size_t bufsize)
{
    int error;
    int len;
    fbuf f;
    
    error = fcache_get_fbuf(entry, &f, FBUF_READ);
    if (error) {
	arla_warn (ADEBWARN, errno, "fcache_get_fbuf");
	return error;
    }
    
    len = fbuf_len(&f);
    if (len >= bufsize || len <= 0) {
	abuf_end(&f);
	arla_warnx(ADEBWARN, "symlink with bad length: %d", len);
	return EIO;
    }
    
    memcpy(buf, fbuf_buf(&f), len);
    buf[len] = '\0';
    
    abuf_end(&f);
    
    return 0;
}


/*
 * Apple's Finder doesn't understand EXDEV within a "Volume", so we do
 * a copy+remove.
 *
 * XXX verify hardlink handling and cross cell renames
 */

#define RENAME_MAX_DEPTH 10

/*
 * Arguments struct for rename_remove_node().
 */

typedef struct remove_node_args {
    CredCacheEntry *ce;
    FCacheEntry *dir;
    int depth;
    int error;
} remove_node_args;

/*
 * Remove a node or tree to given destination.
 *
 * We assume that relevant checks have been performed.
 * Meant as a fdir_readdir_func.
 */

static int
rename_remove_node(VenusFid *fid, const char *name, void *a)
{
    remove_node_args *args = (remove_node_args *)a;
    CredCacheEntry *ce = args->ce;
    FCacheEntry *entry;
    uint64_t len;
    int error;

    if (strcmp(".", name) == 0 || strcmp("..", name) == 0)
	return 0;
    
    error = fcache_get(&entry, *fid, ce);
    if (!error)
	error = fcache_verify_attr(entry, NULL, NULL, ce);
    
    if (error)
	return error;

    len = fcache_get_status_length(&args->dir->status);

    if (entry->status.FileType == TYPE_DIR) {
	remove_node_args args2 = *args;
	args2.dir = entry;
	args2.depth++;
	
	if (args2.depth >= RENAME_MAX_DEPTH)
	    error = EXDEV; /* restore original error */
	else 
	    error = adir_readdir(&entry,
				 rename_remove_node,
				 (void *)&args2,
				 &ce);
	if (!error)
	    error = args2.error;

	if (!error)
	    error = cm_rmdir(&args->dir, name, &entry, &ce);
	
	fcache_release(entry);
    } else {
	error = cm_remove(&args->dir, name, &entry, &ce);
	fcache_release(entry);
    }
    
    if (error)
	args->error = error;

    /*
     * When last entry is removed, dir may be truncated. If so, abort
     * readdir so it doesn't try to read nonexistent directory pages.
     *
     * A more traditional approach would be
     * 1) readdir -> name list
     * 2) foreach(list) {unlink();}
     */
    if (fcache_get_status_length(&args->dir->status) < len)
	return 1;

    return error;
}

/*
 * Remove a node or tree to given destination, usable version.
 */

static int
rename_remove_tree(FCacheEntry *dir, VenusFid *fid,
		   const char *name, CredCacheEntry *ce)
{
    remove_node_args args;

    args.ce = ce;
    args.depth = 0;
    args.error = 0;
    args.dir = dir;

    return rename_remove_node(fid, name, (void*)&args);
}

typedef struct rename_fid_pair {
    VenusFid old;
    VenusFid new;
} rename_fid_pair;

/*
 * Arguments struct for rename_copy_node().
 */

typedef struct copy_node_args {
    CredCacheEntry *ce;
    CredCacheEntry *ce2;
    FCacheEntry *target;
    rename_fid_pair *hardlinks;
    int nlinks;
    int depth;
    int error;
} copy_node_args;

/* Forward */
static int rename_readdir_copy(VenusFid *fid, const char *name, void *a);

/*
 * Copy a node or tree to given destination.
 *
 * We assume that relevant checks have been performed and that
 * `old_entry' has valid data.
 */

static int
rename_copy_node(FCacheEntry *old_entry, const char *name,
		 copy_node_args *args)
{
    AFSFetchStatus fetch_attr;
    CredCacheEntry *ce = args->ce;
    CredCacheEntry *ce2 = args->ce2;
    AFSStoreStatus status;
    FCacheEntry *new_entry = NULL;
    VenusFid new_fid;
    int error = 0;
    
    arla_warnx(ADEBCM, "rename_copy_node(%s)", name);

    afsstatus2afsstorestatus(&old_entry->status, &status);
    
    if (old_entry->status.FileType == TYPE_DIR) {
	error = cm_mkdir(&args->target, name, &status, &new_fid,
			 &fetch_attr, &ce2);
	if (!error)
	    error = fcache_get(&new_entry, new_fid, ce2);
	
	if (!error) {
	    copy_node_args args2 = *args;
	    args2.target = new_entry;
	    args2.hardlinks = NULL;
	    args2.nlinks = 0;
	    args2.depth++;

	    if (args2.depth >= RENAME_MAX_DEPTH)
		error = EXDEV; /* restore original error */
	    else 
		error = adir_readdir(&old_entry, rename_readdir_copy,
				     (void *)&args2, &ce);
	    if (args2.nlinks)
		free(args2.hardlinks);

	    if (!error)
		error = args2.error;
	}
    } else if (old_entry->status.FileType == TYPE_FILE) {
	int linkp = 0;
	int createp = 1;

	if (old_entry->status.LinkCount > 1) {
	    int i;

	    linkp = 1;

	    for (i = 0; i < args->nlinks; i++)
		if (VenusFid_cmp(&args->hardlinks[i].old, &old_entry->fid) == 0)
		    break;
	    
	    if (i < args->nlinks) {
		/* we've already copied this fid */
		
		error = fcache_get(&new_entry, args->hardlinks[i].new, ce2);
		if (!error) {
		    /* XXX hope it's still the same one */
		    error = cm_link(&args->target, name,
				    new_entry,
				    &ce2);
		}
		createp = 0;
	    }
	}
	
	if (!error && createp)
	    error = cm_create(&args->target, name, &status,
			      &new_entry, &ce2);
    
	/* copy file data */
	if (!error)
	    error = write_data(new_entry, old_entry,
			       0, fcache_get_status_length(&old_entry->status),
			       &status, ce2);

	if (linkp && createp && !error) {
	    /* hard linked, add to list and copy the data */
	    int n = args->nlinks + 1;
	    if (n < 0) {
		error = EXDEV;
	    } else {
		rename_fid_pair *tmp;
		tmp = realloc(args->hardlinks, n * sizeof(rename_fid_pair));
		if (tmp) {
		    tmp[args->nlinks].old = old_entry->fid;
		    tmp[args->nlinks].new = new_entry->fid;
		    args->hardlinks = tmp;
		    args->nlinks = n;
		} else {
		    error = errno;
		}
	    }
	}
    } else if (old_entry->status.FileType == TYPE_LINK) {
	char buf[MAXPATHLEN];
	error = read_symlink(old_entry, buf, sizeof(buf));
	if (!error) {
	    error = cm_symlink(&args->target, name,
			       &status, &new_fid,
			       NULL, &fetch_attr,
			       buf, &ce2);
	}
    } else {
	arla_warnx(ADEBWARN, "rename_copy_node: bad node type");
    }
    
    if (new_entry)
	fcache_release(new_entry);

    return error;
}

/*
 * Copy a node or tree to given destination.
 *
 * fdir_readdir_func version.
 */

static int
rename_readdir_copy(VenusFid *fid, const char *name, void *a)
{
    copy_node_args *args = (copy_node_args *)a;
    FCacheEntry *old_entry;
    int error;

    if (strcmp(".", name) == 0 || strcmp("..", name) == 0)
	return 0;

    error = fcache_get(&old_entry, *fid, args->ce);
    if (error)
	return error;
    
    error = fcache_get_data(&old_entry, &args->ce, 0, 0);
    if (!error) {
	error = rename_copy_node(old_entry, name, args);
	if (error)
	    args->error = error;
    }

    fcache_release(old_entry);

    return error;
}

/*
 * Copy a node or tree to given destination, usable version.
 *
 * Assumes that `old_entry' has valid data.
 */

static int
rename_copy_tree(FCacheEntry *old_entry, FCacheEntry *target,
		 const char *new_name, CredCacheEntry *ce, CredCacheEntry *ce2)
{
    copy_node_args args;
    int ret;

    args.ce = ce;
    args.ce2 = ce2;
    args.depth = 0;
    args.error = 0;
    args.target = target;
    args.hardlinks = NULL;
    args.nlinks = 0;

    ret = rename_copy_node(old_entry, new_name, &args);

    if (args.nlinks)
	free(args.hardlinks);

    return ret;
}

/*
 * Arguments struct for rename_source_access().
 */

typedef struct source_access_args {
    CredCacheEntry *ce;
    int depth;
    int error;
} source_access_args;

/*
 * Check access rights for source node and recurse.
 *
 * Meant as a fdir_readdir_func.
 */

static int
rename_source_access(VenusFid *fid, const char *name, void *a)
{
    source_access_args *args = (source_access_args *)a;
    CredCacheEntry *ce = args->ce;
    FCacheEntry *entry;
    int error;

    if (strcmp(".", name) == 0 || strcmp("..", name) == 0)
	return 0;
    
    error = fcache_get(&entry, *fid, ce);
    if (!error)
	error = fcache_verify_attr (entry, NULL, NULL, ce);

    if (!error) {
	if (entry->status.FileType == TYPE_DIR) {
	    error = cm_checkright(entry, ADELETE|AREAD, ce);
	    if (!error) {
		/* Let's recurse */
		args->depth++;

		if (args->depth >= RENAME_MAX_DEPTH)
		    error = EXDEV; /* restore original error */
		else 
		    error = adir_readdir(&entry, rename_source_access,
					 a, &ce);
		args->depth--;
		if (!error)
		    error = args->error;
	    }
	} else if (entry->status.FileType != TYPE_FILE
		   && entry->status.FileType != TYPE_LINK) {
	    error = EACCES;
	}

	fcache_release(entry);
    }
    
    if (error)
	args->error = error;
    
    return error;
}

/*
 * Do some checks to be reasonably sure the operation won't fail.
 *
 * XXX check size vs quota.
 */

static int
rename_check_tree(FCacheEntry *oldnode, CredCacheEntry *ce)
{
    source_access_args args;
    int error;
    
    args.error = 0;
    args.depth = 0;
    args.ce = ce;
    
    error = adir_readdir(&oldnode, 
			 rename_source_access,
			 (void *)&args,
			 &ce);
    if (!error)
	error = args.error;

    return error;
}

static int
copy_remove_entry(FCacheEntry *old_dir, const char *old_name,
		  FCacheEntry *new_dir, const char *new_name,
		  VenusFid *new_fid, CredCacheEntry *ce, CredCacheEntry *ce2)
{
    VenusFid existing_fid, old_fid;
    FCacheEntry *old_entry = NULL;
    FCacheEntry *existing_entry = NULL;

    int dirp = 0;
    int error;

    error = adir_lookup(new_dir, new_name, &existing_fid);
    if (!error) {
	error = fcache_get(&existing_entry, existing_fid, ce2);
	if (error)
	    return error;
    }

    error = adir_lookup(old_dir, old_name, &old_fid);
    if (error)
	return error;

    /* check permissions (and hope they don't change) */
    error = cm_checkright(old_dir, ADELETE|AREAD, ce);
    if (!error)
	error = cm_checkright(new_dir, AINSERT, ce2);
    if (existing_entry && !error)
	error = cm_checkright(new_dir, ADELETE, ce2);
    if (error)
	return error;
    
    error = fcache_get(&old_entry, old_fid, ce);
    if (error)
	return error;

    if (old_entry->status.FileType != TYPE_FILE
	&& old_entry->status.FileType != TYPE_DIR
	&& old_entry->status.FileType != TYPE_LINK) {
	fcache_release(old_entry);
	return EXDEV;
    }
    
    if (old_entry->status.FileType == TYPE_DIR)
	dirp = 1;
    
    error = fcache_get_data(&old_entry, &ce, 0, 0);

    if (dirp && !error) {
	if (!adir_emptyp(&old_entry, &ce))
	    error = rename_check_tree(old_entry, ce);
    }
    
    if (!error && existing_entry) {
	/* 1. we might be able to do a truncate+write. but not today */
	/* 2. rmdir fails if not empty. that's correct and well. */

	if (dirp)
	    error = cm_rmdir(&new_dir, new_name, &existing_entry, &ce2);
	else
	    error = cm_remove(&new_dir, new_name, &existing_entry, &ce2);
    }

    if (!error) {
	error = rename_copy_tree(old_entry, new_dir, new_name, ce, ce2);

	if (error) {
	    /*
	     * Roll back changes as best we can. Unfortunately, existing
	     * targets are already removed and permanently lost.
	     */
	    
	    VenusFid created_fid;
	    int error2 = adir_lookup(new_dir, new_name, &created_fid);
	    if (!error2)
		rename_remove_tree(new_dir, &created_fid, new_name, ce2);
	}
    }

    fcache_release(old_entry);

    if (!error)
	error = rename_remove_tree(old_dir, &old_fid, old_name, ce);

    return error;
}

/*
 * Called when the object is being moved to a new directory, to be
 * able to update .. when required.
 */

static int
potential_update_dir(FCacheEntry *child_entry,
		     const VenusFid *new_parent_fid,
		     FCacheEntry *parent_entry,
		     int *update_child,
		     CredCacheEntry **ce)
{
    int error;

    error = fcache_verify_attr (child_entry, parent_entry, NULL, *ce);
    if (error) 
	return error;

    /*
     * if we're moving a directory.
     */

    if (child_entry->status.FileType == TYPE_DIR) {
	fbuf the_fbuf;

	error = fcache_get_data(&child_entry, ce, 0, 0); /* XXX - check fake_mp */
	if (error)
	    return error;

	error = fcache_get_fbuf(child_entry, &the_fbuf,	FBUF_READ|FBUF_WRITE);
	if (error)
	    return error;

	error = fdir_changefid (&the_fbuf, "..", new_parent_fid);
	abuf_end(&the_fbuf);
	if (error)
	    return error;

	*update_child = 1;
    }
    return 0;
}

/*
 * Rename (old_parent_fid, old_name) -> (new_parent_fid, new_name)
 * update the `child' in the new directory if update_child.
 * set child_fid to the fid of the moved object.
 */

int
cm_rename(FCacheEntry **old_dir, const char *old_name,
	  FCacheEntry **new_dir, const char *new_name,
	  VenusFid *child_fid,
	  int *update_child,
	  CredCacheEntry **ce, CredCacheEntry **ce2)
{
    int error = 0;
    VenusFid new_fid, old_fid;
    Bool modify_old, modify_new;
    
    *update_child = 0;

    /* old parent dir */

    error = fcache_get_data (old_dir, ce, 0, 0);
    if (error)
	return error;

    /* new parent dir */

    error = fcache_get_data (new_dir, ce2, 0, 0);
    if (error)
	return error;

    error = cm_checkright(*old_dir, ADELETE, *ce);
    if (!error)
	error = cm_checkright(*new_dir, AINSERT, *ce2);
    if (error)
	goto out;
	
    error = rename_file (*old_dir, old_name, *new_dir, new_name, *ce);
    if (error == EXDEV) {
	/*
	 * copy_remove_entry() only does normal operations (mkdir,
	 * remove, etc) and thus gets correct parent/child fids, so we
	 * can leave update_child unchanged (zero).
	 */
	error = copy_remove_entry(*old_dir, old_name, *new_dir,
				  new_name, child_fid, *ce, *ce2);
	goto out;
    }

    if (error)
	goto out;

    modify_old = should_modify_locally(old_dir, ce, &error);
    if (error)
	goto out;

    modify_new = should_modify_locally(new_dir, ce2, &error);
    if (error)
	goto out;

    /*
     * Lookup the old name (to get the fid of the new name)
     */
    
    error = adir_lookup (*old_dir, old_name, &new_fid);
    
    if (error)
	goto out;
    
    *child_fid = new_fid;
    
    if (VenusFid_cmp (&(*old_dir)->fid, &(*new_dir)->fid)) {
	FCacheEntry *child_entry;
	
	error = fcache_get (&child_entry, *child_fid, *ce2);
	if (error)
	    goto out;
	
	child_entry->parent = (*new_dir)->fid;
	
	error = potential_update_dir (child_entry, &(*new_dir)->fid,
				      *new_dir, update_child, ce2);
	fcache_release (child_entry);
	if (error)
	    goto out;
    }
    
    /*
     * Lookup the new name, if it exists we need to silly
     * rename it was just killed on the fileserver.
     * XXXDISCO remember mark this node as dead
     */

    error = adir_lookup (*new_dir, new_name, &old_fid);
    if (error == 0) {
	FCacheEntry *old_entry = fcache_find(old_fid);
	if (old_entry) {
	    old_entry->flags.silly = TRUE;
	    fcache_release (old_entry);

	    if (modify_new)
		adir_remove (*new_dir, new_name);
	}
    }
    
    error = 0;

    /*
     * Now do the rename, ie create the new name and remove
     * the old name.
     */
    
    if (modify_new)
	error = adir_creat (*new_dir, new_name,  new_fid.fid);
    
    if (modify_old)
	error = adir_remove (*old_dir, old_name);
    
 out:
    if (!error)
	log_operation ("rename (%ld,%lu,%lu,%lu) (%ld,%lu,%lu,%lu) %s %s\n",
		       (*old_dir)->fid.Cell,
		       (*old_dir)->fid.fid.Volume,
		       (*old_dir)->fid.fid.Vnode,
		       (*old_dir)->fid.fid.Unique,
		       (*new_dir)->fid.Cell,
		       (*new_dir)->fid.fid.Volume,
		       (*new_dir)->fid.fid.Vnode,
		       (*new_dir)->fid.fid.Unique,
		       old_name, new_name);
    
    cm_check_consistency();
    return error;
}

/* 
 * An emulation of kernel lookup, convert (fid, name) into
 * (res).  Strips away leading /afs, removes double slashes,
 * and resolves symlinks.
 * Return 0 for success, otherwise -1.
 */

int
cm_walk (VenusFid fid,
	 const char *name,
	 VenusFid *res)
{
    VenusFid cwd = fid;
    char *base;
    VenusFid file;
    FCacheEntry *entry;
    FCacheEntry *dentry;
    int error;
    char symlink[MAXPATHLEN];
    char store_name[MAXPATHLEN];
    char *fname;
    CredCacheEntry *ce;

    ce = cred_get (fid.Cell, getuid(), CRED_ANY);
    
    strlcpy(store_name, name, sizeof(store_name));
    fname = store_name;
    
    do {
        /* set things up so that fname points to the remainder of the path,
         * whereas base points to the whatever preceeds the first /
         */
        base = fname;
        fname = strchr(fname, '/');
        if (fname) {
            /* deal with repeated adjacent / chars by eliminating the
             * duplicates. 
             */
            while (*fname == '/') {
                *fname = '\0';
                fname++;
            }
        }
	
        /* deal with absolute pathnames first. */
        if (*base == '\0') {
	    error = getroot(&cwd, ce);
	    if (error) {
		arla_warn(ADEBWARN, error, "getroot");
		cred_free(ce);
		return error;
	    }
	    
	    if (fname) {
		if (strncmp("afs",fname,3) == 0) {
		    fname += 3;
		    }
		continue;
	    } else {
		break;
	    }
	}
	error = fcache_get(&dentry, cwd, ce);
	if (error) {
	    arla_warn (ADEBWARN, error, "fcache_get");
	    cred_free(ce);
	    return error;
	}
	error = cm_lookup (&dentry, base, &file, &ce, TRUE);
	fcache_release(dentry);
	if (error) {
	    arla_warn (ADEBWARN, error, "lookup(%s)", base);
	    cred_free(ce);
	    return error;
	}

	error = fcache_get(&entry, file, ce);
	if (error) {
	    arla_warn (ADEBWARN, error, "fcache_get");
	    cred_free(ce);
	    return error;
	}
		
	/* handle symlinks here */
	if (entry->status.FileType == TYPE_LINK) {
	    error = fcache_get_data (&entry, &ce, 0, 0);
	    if (error) {
		fcache_release(entry);
		arla_warn (ADEBWARN, error, "fcache_get_data");
		cred_free(ce);
		return error;
	    }

	    error = read_symlink(entry, symlink, sizeof(symlink));
	    if (error) {
		fcache_release(entry);
		arla_warn(ADEBWARN, error, "read_symlink");
		cred_free(ce);
		return error;
	    }

	    /* if we're not at the end (i.e. fname is not null), take
	     * the expansion of the symlink and append fname to it.
	     */
	    if (fname != NULL) {
		strcat (symlink, "/");
		strcat (symlink, fname);
	    }
	    strlcpy(store_name, symlink, sizeof(store_name));
	    fname = store_name;
	} else {
	    /* if not a symlink, just update cwd */
	    cwd = entry->fid;
	}
	fcache_release(entry);
	
	/* the *fname condition below deals with a trailing / in a
	 * path-name */
    } while (fname != NULL && *fname);
    *res = cwd;
    cred_free(ce);
    return 0;
}
