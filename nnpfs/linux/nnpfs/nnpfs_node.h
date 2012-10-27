/*
 * Copyright (c) 1995 - 2002, 2004-2006 Kungliga Tekniska Högskolan
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

#ifndef _nnpfs_node_h
#define _nnpfs_node_h

#include <linux/types.h>
#include <linux/time.h>
#include <nnpfs/nnpfs_attr.h>
#include <nnpfs/nnpfs_message.h>

extern uint64_t nnpfs_blocksize;
extern uint32_t nnpfs_blocksizebits;

#include <nnpfs/nnpfs_blocks.h>
#include <nnpfs/nnpfs_blocks_locl.h>

/* nnpfs_node.flags
 * The lower 16 bit flags are reserved for common nnpfs flags
 * The upper 16 bit flags are reserved for operating system dependent
 * flags.
 */

#define NNPFS_NODE_IPUT	0x00010000   /* node is in iput(), avoid deadlock. Can be removed? */

#define XN_HASHSIZE 1009
#define XN_CLEANUP_ITERS 129

struct nnpfs_node {
    uint32_t index;			/* node's cache slot */
    struct nnpfs_cache_handle data;	/* keep track of installed blocks */
    uint64_t daemon_length;		/* how large daemon thinks it is */
    u_int flags;			/* status of data (dirty), etc */
    u_int tokens;			/* what attr|data we have */
    nnpfs_handle handle;			/* the handle of the node */
    struct nnpfs *nnpfsp;		/* our fs */

    nnpfs_pag_t id[NNPFS_MAXRIGHTS];		/* cached rights for pags */
    nnpfs_rights rights[NNPFS_MAXRIGHTS];
    nnpfs_rights anonrights;			/* anonymous rights */

    int pending_writes;
    int async_error;

#if 0
    unsigned int mmapcount;
    nnpfs_cred rd_cred; /* cached creds for indirect reads */
#endif
    nnpfs_cred wr_cred; /* cached creds for indirect writes */
    
    struct list_head inactive_list;	/* put here when inactivated,
					 * to avoid kmalloc */
    struct inode vfs_inode;
};

struct nnpfs;

void nnpfs_print_nodestats(struct nnpfs *nnpfsp);

/*
 * useful macros
 */
#define XNODE_TO_VNODE(xn) (&(xn)->vfs_inode)
#define VNODE_TO_XNODE(inode) container_of((inode), struct nnpfs_node, vfs_inode)

static inline unsigned long
nnpfs_hash(nnpfs_handle *handle)
{
    return handle->a ^ handle->b ^ handle->c ^ handle->d;
}

#endif /* _nnpfs_node_h */
