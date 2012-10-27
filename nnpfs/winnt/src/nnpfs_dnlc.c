/*
 * Copyright (c) 2000, 2002, 2003 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_dnlc.c,v 1.9 2003/07/01 14:05:06 tol Exp $ */

#include <nnpfs_locl.h>

/*
 * hmm, debug XLIST
 */

void
xlist_dnlc_debug(nnpfs_dnlc *dnlc, unsigned hashval) {
#if 0
    nnpfs_dnlc_entry *prev = NULL;
    nnpfs_dnlc_entry *curr = NULL;
    XLIST_FOREACH(&dnlc->nc_hash[hashval], curr, hash_entry) {
	ASSERT(prev == XLIST_PREV(curr, hash_entry));
	prev = curr;
    }
    ASSERT(prev == XLIST_TAIL(&dnlc->nc_hash[hashval]));
#endif
}

/*
 * init cache
 */

void
nnpfs_dnlc_init(nnpfs_dnlc *dnlc)
{
    int i, RC;
    RC = ExInitializeResourceLite(&dnlc->dnlc_lock);
    ASSERT(NT_SUCCESS(RC));
    
    for (i=0; i < NNPFS_DNLC_HSIZE; i++)
	XLIST_LISTHEAD_INIT(&dnlc->nc_hash[i]);
    XLIST_LISTHEAD_INIT(&dnlc->nc_lru);

    for (i = 0; i < NNPFS_DNLC_CSIZE; i++) {
	nnpfs_dnlc_entry *e = &dnlc->entries[i];
	e->flags = 0;
	XLIST_ADD_TAIL(&dnlc->nc_lru, e, lru_entry);
    }
}

/*
 * prepare for unload
 */

void
nnpfs_dnlc_shutdown(nnpfs_dnlc *dnlc)
{
    nnpfs_dnlc_entry *e;
    NTSTATUS status = ExDeleteResourceLite(&dnlc->dnlc_lock);
}

unsigned
nnpfs_dnlc_hash(nnpfs_handle *dir, const char *name, int len)
{
    int i;
    unsigned res = dir->a + dir->b + dir->c + dir->d;
    for (i=0; i<len; i++)
	res = res * 33 + name[i];
    res = (res + (res >> 5)) % NNPFS_DNLC_HSIZE;
    return res;
}

struct nnpfs_dnlc_entry *
nnpfs_dnlc_find_entry (struct nnpfs_node *dir, const char *name,
		     unsigned hashval)
{
    nnpfs_dnlc *dnlc;
    nnpfs_dnlc_entry *e;
    int len;

    assert(dir && name);

    dnlc = dir->chan->dnlc;
    len = strlen(name);
    hashval = nnpfs_dnlc_hash(&dir->handle, name, len);

    FsRtlEnterFileSystem();
    if (!ExAcquireResourceExclusiveLite(&dnlc->dnlc_lock, TRUE)) {
	FsRtlExitFileSystem();
	return NULL;
    }
    
    XLIST_FOREACH(&dnlc->nc_hash[hashval], e, hash_entry)
	if (nnpfs_handle_eq(&e->dir, &dir->handle)
	    && e->namelen == len
	    && !strncmp(name, e->name, e->namelen)) {

	    ASSERT(e->flags & NNPFS_DNLC_USED);

	    XLIST_REMOVE(&dnlc->nc_lru, e, lru_entry);
	    XLIST_ADD_HEAD(&dnlc->nc_lru, e, lru_entry);
	    
	    goto done;
	}

    e = NULL;

 done:
    xlist_dnlc_debug(dnlc, hashval);
    ExReleaseResourceLite(&dnlc->dnlc_lock);
    FsRtlExitFileSystem();

    return e;
}

/*
 *
 */

void
nnpfs_dnlc_enter (struct nnpfs_node *dir,
		const char *name,
		struct nnpfs_node *node)
{
    nnpfs_dnlc *dnlc = dir->chan->dnlc;
    nnpfs_node *n;
    NTSTATUS status; 
    int len = strlen(name);
    nnpfs_dnlc_entry *e;

    unsigned hashval = nnpfs_dnlc_hash(&dir->handle, name, len);

    if (len > NNPFS_MAX_NAME) {
	nnpfs_debug(XDEBDNLC, "nnpfs_dnlc_enter: name %s is too long!\n", name);
	return; /* XXX */
    }

    xlist_dnlc_debug(dnlc, hashval);
    e = nnpfs_dnlc_find_entry(dir, name, hashval);
    if (e) {
	if (node == NULL)
	    /* negative entry */
	    e->flags |= NNPFS_DNLC_NEGATIVE;
	return;
    }

    FsRtlEnterFileSystem();
    if (!ExAcquireResourceExclusiveLite(&dnlc->dnlc_lock, TRUE)) {
	FsRtlExitFileSystem();
	return;
    }

    xlist_dnlc_debug(dnlc, hashval);
    XLIST_REMOVE_TAIL(&dnlc->nc_lru, e, lru_entry);
    xlist_dnlc_debug(dnlc, hashval);
    if (e->flags & NNPFS_DNLC_USED) {
	unsigned tmp = nnpfs_dnlc_hash(&e->dir, e->name, e->namelen);
	xlist_dnlc_debug(dnlc, tmp);
	XLIST_REMOVE(&dnlc->nc_hash[tmp], e, hash_entry);
	xlist_dnlc_debug(dnlc, tmp);
    }

    e->dir = dir->handle;
    e->node = node;
    e->namelen = (char) len;

    if (node == NULL)
	e->flags = NNPFS_DNLC_USED | NNPFS_DNLC_NEGATIVE;
    else
	e->flags = NNPFS_DNLC_USED;
    strcpy(e->name, name); /* already checked length */

    XLIST_ADD_HEAD(&dnlc->nc_hash[hashval], e, hash_entry);
    xlist_dnlc_debug(dnlc, hashval);
    XLIST_ADD_HEAD(&dnlc->nc_lru, e, lru_entry);
    ExReleaseResourceLite(&dnlc->dnlc_lock);
    FsRtlExitFileSystem();

    nnpfs_debug(XDEBDNLC, "nnpfs_dnlc_enter_name: added %s!\n", name);
    
    return;
}

/*
 * drop entry
 */

void
nnpfs_dnlc_drop_entry (nnpfs_dnlc *dnlc, nnpfs_dnlc_entry *e, unsigned hashval)
{
    XLIST_REMOVE(&dnlc->nc_hash[hashval], e, hash_entry);
    e->flags = 0; /* XXX */
    xlist_dnlc_debug(dnlc, hashval);
    XLIST_REMOVE(&dnlc->nc_lru, e, lru_entry);
    XLIST_ADD_HEAD(&dnlc->nc_lru, e, lru_entry);
}

void
nnpfs_dnlc_drop_children (nnpfs_node *dir)
{
    nnpfs_dnlc *dnlc;
    nnpfs_dnlc_entry *e;
    int i;
    
    ASSERT(dir && dir->attr.xa_type == NNPFS_FILE_DIR);
    dnlc = dir->chan->dnlc;
    
    nnpfs_debug(XDEBDNLC, "nnpfs_dnlc_drop_children(%X)\n", dir);

    /* drop all entries in dir from cache (state unknown) */
    for (i = 0; i < NNPFS_DNLC_HSIZE; i++) {
	XLIST_FOREACH(&dnlc->nc_hash[i], e, hash_entry)
	    if (nnpfs_handle_eq(&e->dir, &dir->handle))
		nnpfs_dnlc_drop_entry(dnlc, e, i);
	xlist_dnlc_debug(dnlc, i);
    }
}

/*
 * drop node from cache
 */

void
nnpfs_dnlc_drop (nnpfs_node *node)
{
    nnpfs_dnlc *dnlc;
    nnpfs_dnlc_entry *e;
    int i;

    ASSERT(node);
    dnlc = node->chan->dnlc;
    
    nnpfs_debug(XDEBDNLC, "nnpfs_dnlc_drop(%X)\n", node);
    
    /* the dir itself gets dropped if the parent changes, right? */
    for (i = 0; i < NNPFS_DNLC_HSIZE; i++) {
	XLIST_FOREACH(&dnlc->nc_hash[i], e, hash_entry)
	    if (e->node == node)
		nnpfs_dnlc_drop_entry(dnlc, e, i);
	xlist_dnlc_debug(dnlc, i);
    }
}

/*
 * drop deleted node from cache, mark as negative entry?
 */

void
nnpfs_dnlc_uncache (struct nnpfs_node *node)
{
    nnpfs_dnlc_drop(node);
    if (node->attr.xa_type == NNPFS_FILE_DIR)
	nnpfs_dnlc_drop_children(node);
    /* mark as bad? */
}

/*
 *
 */

NTSTATUS
nnpfs_dnlc_lookup (struct nnpfs_node *dir, const char *name, nnpfs_node **n)
{
    *n = NULL;

    if (dir && name) {
	nnpfs_dnlc_entry *e;
	ExAcquireFastMutex(&dir->chan->NodeListMutex);
	e = nnpfs_dnlc_find_entry(dir, name,
				nnpfs_dnlc_hash(&dir->handle, name,
					      strlen(name)));
	
	if (e) {
	    if (e->flags & NNPFS_DNLC_NEGATIVE)
		return STATUS_NO_SUCH_FILE; /* XXX path invalid? */
	    *n = e->node;
	    nnpfs_vref(*n);
	}
	ExReleaseFastMutex(&dir->chan->NodeListMutex);

	return STATUS_SUCCESS;
    }

    return STATUS_OBJECT_PATH_INVALID;
}
