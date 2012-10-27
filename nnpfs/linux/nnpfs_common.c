/*
 * Copyright (c) 1995-2004, 2006 Kungliga Tekniska Högskolan
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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

#define __NO_VERSION__

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_common.h>

#ifdef RCSID
RCSID("$Id: nnpfs_common.c,v 1.40 2006/12/11 16:31:46 tol Exp $");
#endif

#ifdef DEBUG
#define NNPFS_MALLOC_CNT 10
static u_int nnpfs_allocs[NNPFS_MALLOC_CNT]={0,0,0,0,0,0,0,0,0,0};
static u_int nnpfs_frees[NNPFS_MALLOC_CNT]={0,0,0,0,0,0,0,0,0,0};
#endif

#ifdef GFP_FS
#define NNPFS_ALLOC_FLAGS	(GFP_KERNEL|GFP_FS)
#else
#define NNPFS_ALLOC_FLAGS	(GFP_KERNEL)
#endif

void *
nnpfs_alloc(u_int size, unsigned int service)
{
    void *p = kmalloc(size, NNPFS_ALLOC_FLAGS); /* What kind? */
#ifdef DEBUG
    if (p) {
	if (service < NNPFS_MALLOC_CNT)
	    nnpfs_allocs[service]++;
	else
	    printk ("nnpfs_alloc: bad service\n");
    }
#endif
    return p;
}

void
nnpfs_tell_alloc(void)
{
#ifdef DEBUG
    int i;
    printk ("nnpfs_alloc: nnpfs_allocs - nnpfs_frees =");
    for (i = 0; i < NNPFS_MALLOC_CNT; i++)
	printk(" %d", nnpfs_allocs[i] - nnpfs_frees[i]);
    printk ("\n");
#endif
}

void
nnpfs_free(void *ptr, unsigned int service)
{
#ifdef DEBUG
    if (ptr) {
	if (service < NNPFS_MALLOC_CNT)
	    nnpfs_frees[service]++;
	else
	    printk ("nnpfs_free: bad service\n");
    }
#endif
    kfree (ptr);
}

void
nnpfs_print_dentry(const struct dentry *dentry)
{
    NNPFSDEB(XDEBVFOPS, ("%p: count %d\n", dentry, nnpfs_dcount(dentry)));
}

void
nnpfs_print_aliases(const struct inode *inode)
{
    if (NNPFSDEB_P(XDEBVFOPS))
	nnpfs_print_aliases_real(inode);
}

void
nnpfs_print_aliases_real(const struct inode *inode)
{
    struct list_head *alias;
    struct dentry *dentry;
    int bailout = 100;

    alias = inode->i_dentry.next;
    while (alias != &inode->i_dentry) {
	if (--bailout < 0) {
	    printk(" ...");
	    break;
	}
	dentry = list_entry(alias, struct dentry, d_alias);
	if (dentry) {
	    printk(" %.*s(%p)", (int)dentry->d_name.len,
		   dentry->d_name.name, dentry);
	    if (nnpfs_d_entry_unhashed(&dentry->d_hash))
		printk("(unhashed)");
	}
	alias = alias->next;
    }
    printk("\n");
}

void
nnpfs_print_children(const struct dentry *dentry)
{
    struct list_head *subdirs;

    if (!NNPFSDEB_P(XDEBVFOPS))
	return;

    subdirs = dentry->d_subdirs.next;

    while (subdirs != &dentry->d_subdirs) {
	struct list_head *tmp = subdirs;
	struct dentry *child = list_entry(tmp, struct dentry, d_u.d_child);

	printk(" %.*s(%p)", (int)child->d_name.len,
	       child->d_name.name, child);
	
	subdirs = tmp->next;
    }
    
    printk("\n");
}
