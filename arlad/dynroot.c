/*
 * Copyright (c) 1999 - 2003, 2005-2007 Kungliga Tekniska Högskolan
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
 * Keep our own root.afs
 *
 * uses cell DYNROOTCELL as cell number.
 */

#include <arla_local.h>

RCSID("$Id: dynroot.c,v 1.33 2007/01/12 17:35:06 tol Exp $");

struct create_entry {
    fbuf *thedir;	/* pointer to the fbuf that contains the dir */
    AFSFid fid;		/* the current fid */
    int len;		/* num of links in the dir */
    int type;
};

#define DYNROOT_ROOTVOLUME 1		/* make sure that these */
#define DYNROOT_ROOTVOLUME_STR "1"	/* two are the same */
#define DYNROOT_ROOTDIR 1
#define DYNROOT_UNIQUE 1

static Bool dynroot_enabled  = 0;		/* is dynroot enabled ? */
static unsigned long last_celldb_version = 0;	/* last version of celldb */

/*
 * Magic glue wrt afsvnode#
 */

static int32_t
cellnum2afs (int cellno, int rw)
{
    if (rw)
	return (cellno << 2) + 0x2;
    else
	return (cellno << 2) + 0x1;
}

static int
afs2cellnum (int32_t afsvnode, int *rw)
{
    if (afsvnode & 0x2)
	*rw = 1;
    else
	*rw = 0;
    return afsvnode >> 2;
}

/*
 * helper functions for dynroot_create_root that for
 * each `cell' with 'cellid' a entry in the root directory.
 */

static int
create_entry_func (const char *name, uint32_t cellid, int type, void *arg)
{
    struct create_entry *entry = (struct create_entry *) arg;
    int ret;

    entry->fid.Vnode = cellnum2afs (cellid, type & DYNROOT_ALIAS_READWRITE);

    ret = fdir_creat (entry->thedir, name, NULL, entry->fid);
    if (ret == 0) {
	entry->len++;
    } else if (ret == EEXIST) {
	arla_warnx (ADEBWARN, "duplicate entry in dynroot: %s", name);
	ret = 0;
    }
    
    return ret;
}

/*
 * Wrapper function for cell_foreach that takes a `cell' instead of a
 * string and a cellid.
 */

static int
create_cell_entry_func (const cell_entry *cell, void *arg)
{
    char *rwname = NULL;
    int ret;

    if (!cell_dynroot(cell))
	return 0;

    ret = create_entry_func(cell->name, cell->id, DYNROOT_ALIAS_READONLY, arg);
    if (ret)
	return ret;

    asprintf(&rwname, ".%s", cell->name);
    if (rwname == NULL)
	return 0;

    ret = create_entry_func(rwname, cell->id, DYNROOT_ALIAS_READWRITE, arg);
    free(rwname);
    return ret;
}

/*
 *
 */

static int
create_alias_entry_func (const char *cellname, const char *alias, 
			 int type, void *arg)
{
    cell_entry *cell;

    cell = cell_get_by_name (cellname);
    if (cell == NULL)
	return 0;
    return create_entry_func(alias, cell->id, type, arg);

}


/*
 * create the dynroot root directory in `fbuf', return number
 * of entries in `len'.
 */

static int
dynroot_create_root (fbuf *fbuf, size_t *len)
{
    int ret;
    AFSFid dot = { DYNROOT_ROOTVOLUME,
		   DYNROOT_ROOTDIR,
		   DYNROOT_UNIQUE};
    struct create_entry entry;

    ret = fdir_mkdir (fbuf, dot, dot, 0);
    if (ret)
	return ret;

    entry.thedir	= fbuf;

    entry.fid.Volume	= DYNROOT_ROOTVOLUME;
    entry.fid.Vnode	= DYNROOT_ROOTDIR + 2;
    entry.fid.Unique	= DYNROOT_UNIQUE;
    entry.len = 0;
    
    ret = cell_foreach (create_cell_entry_func, &entry);
    if (ret)
	return ret;

    ret = cell_alias_foreach(create_alias_entry_func, &entry);
    if (ret)
	return ret;

    *len = entry.len;

    return 0;
}

/*
 * for the `vnode' create apropriate symlink in `fbuf'
 */

static int
dynroot_create_symlink (fbuf *fbuf, int32_t vnode)
{
    char *name;
    cell_entry *cell;
    int len, ret, rw = 0;

    cell = cell_get_by_id (afs2cellnum (vnode, &rw));
    if (cell == NULL)
	return ENOENT;

    len = asprintf (&name, "%c%s:root.cell.", rw ? '%' : '#', cell->name);
    if (len == -1)
	return ENOMEM;

    ret = fbuf_truncate (fbuf, len);
    if (ret == 0)
	memmove (fbuf_buf(fbuf), name, len);
    
    free(name);
    return ret;
}

/*
 * Return TRUE if the combination `cell' and `volume' is
 * in the dynroot.
 */

Bool
dynroot_isvolumep (int cell, const char *volume)
{
    assert (volume);
    
    if (cell == 0 &&
	(strcmp (volume, "root.afs") == 0
	 || strcmp (volume, DYNROOT_ROOTVOLUME_STR) == 0))
	return TRUE;

    return FALSE;
}

/*
 * Create a dummy nvldbentry in `entry'
 */

int
dynroot_fetch_root_vldbN (nvldbentry *entry)
{
    memset (entry, 0, sizeof(*entry));

    strlcpy(entry->name, "root.afs", sizeof(entry->name));
    entry->nServers = 0;
    entry->volumeId[ROVOL] = DYNROOT_ROOTVOLUME;
    entry->flags = VLF_ROEXISTS;

    return 0;
}

/*
 * make sure `cred' is present in `entry'
 */
static void
dynroot_set_access(FCacheEntry *entry, nnpfs_pag_t cred)
{
    AccessEntry *ae;
    if (findaccess(cred, entry->acccache, &ae) == FALSE) {
	ae->cred = cred;
	ae->access = entry->status.CallerAccess;
    }
}

/*
 * Update `entry' to contain the correct information
 * Note: doesn't update status.Length and status.LinkCount
 */

static void
dynroot_update_entry (FCacheEntry *entry, int32_t filetype,
		      nnpfs_pag_t cred)
{
    struct timeval tv;

    assert (entry);
    entry->status.InterfaceVersion = 1;
    entry->status.FileType	= filetype;
    entry->status.DataVersion	= 1;
    entry->status.Author	= 0;
    entry->status.Owner		= 0;
    entry->status.CallerAccess 	= ALIST | AREAD;
    entry->status.AnonymousAccess = ALIST | AREAD;
    switch (filetype) {
    case TYPE_DIR: 
	entry->status.UnixModeBits = 0755;
	break;
    case TYPE_LINK:
	entry->status.UnixModeBits = 0644;
	break;
    default:
	abort();
    }
    entry->status.ParentVnode	= DYNROOT_ROOTDIR;
    entry->status.ParentUnique	= DYNROOT_UNIQUE;
    entry->status.ResidencyMask	= 1;
    entry->status.ClientModTime	= 0;
    entry->status.ServerModTime	= 0;
    entry->status.Group		= 0;
    entry->status.SyncCounter	= 0;
    entry->status.DataVersionHigh= 0;
    entry->status.LockCount	= 0;
    entry->status.LengthHigh	= 0;
    entry->status.ErrorCode	= 0;

    gettimeofday (&tv, NULL);

    memset (&entry->volsync, 0, sizeof (entry->volsync));

    entry->callback.CallBackVersion = 1;
    entry->callback.ExpirationTime = tv.tv_sec + 3600 * 24 * 7;
    entry->callback.CallBackType = CBSHARED;

    entry->anonaccess = entry->status.AnonymousAccess;
    dynroot_set_access(entry, cred);
}

/*
 * Fetch data and attr for `entry'
 */

static int
dynroot_get_node (FCacheEntry *entry, CredCacheEntry *ce)
{
    int ret, rootnode;
    size_t len;
    fbuf dir;

    rootnode = entry->fid.fid.Vnode == DYNROOT_ROOTDIR ? 1 : 0;

    if (entry->usage != 0 &&
	(!rootnode || last_celldb_version == cell_get_version())) {
	dynroot_set_access(entry, ce->cred); /* kernel may want access info */	
	return 0;
    }

    ret = abuf_create(&dir, entry, 0, FBUF_READ | FBUF_WRITE);
    if (ret)
	return ret;
    
    if (rootnode) {
	size_t nentries = 0;
	ret = dynroot_create_root(&dir, &nentries);
	entry->status.LinkCount = nentries;
    } else {
	ret = dynroot_create_symlink (&dir, entry->fid.fid.Vnode);
	entry->status.LinkCount = 1;
    }

    if (ret) {
	abuf_end(&dir);
	return ret;
    }

    entry->flags.attrp = TRUE;

    dynroot_update_entry (entry, rootnode ? TYPE_DIR : TYPE_LINK,
			  ce->cred);

    if (!rootnode)
	fcache_mark_as_mountpoint (entry);
    
    len = fbuf_len(&dir);
    fcache_set_have_all(entry, len);

    ret = abuf_end(&dir);
    if (ret)
	return ret;

    entry->tokens |= NNPFS_ATTR_R|NNPFS_DATA_R;

    last_celldb_version = cell_get_version();

    return 0;
}

/*
 * Fetch attr for `entry'
 */

int
dynroot_get_attr (FCacheEntry *entry, CredCacheEntry *ce)
{
    return dynroot_get_node (entry, ce);
}


/*
 * Fetch data for `entry'
 */

int
dynroot_get_data (FCacheEntry *entry, CredCacheEntry *ce)
{
    return dynroot_get_node (entry, ce);
}

/*
 * returns TRUE if `entry' is a dynroot entry.
 */

Bool
dynroot_is_dynrootp (FCacheEntry *entry)
{
    assert (entry);

    if (dynroot_enabled &&
	entry->fid.Cell == DYNROOT_CELLID &&
	entry->fid.fid.Volume == DYNROOT_ROOTVOLUME)
	return TRUE;

    return FALSE;
}

/*
 * Return what status the dynroot is in.
 */

Bool
dynroot_enablep (void)
{
    return dynroot_enabled;
}

/*
 * Enable/Disable the dynroot depending on `enable', returns previous state.
 */

Bool
dynroot_setenable (Bool enable)
{
    Bool was = dynroot_enabled;
    dynroot_enabled = enable;
    return was;
}

/*
 * Returns the dynroot_cellid.
 */

int32_t dynroot_cellid (void)
{
    return DYNROOT_CELLID;
}

/*
 * Return the dynroot volumeid.
 */

int32_t dynroot_volumeid (void)
{
    return DYNROOT_ROOTVOLUME;
}
