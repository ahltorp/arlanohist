/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_fs.h,v 1.11 2002/09/07 10:48:00 lha Exp $ */

#ifndef _nnpfs_h
#define _nnpfs_h

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_attr.h>

/*
 * Filesystem struct.
 *
 * LOCKS: `nodes_iter' protects so that there are only one user of the
 * next_node struct, so that only one can iterate the list (this can
 * be changed to a list of `next_nodes':s).
 *
 * `nodes_modify' need to be hold when `nodes', `next_node' and
 * `nnodes' are update/read to make sure they are atomicly
 * updated/read.
 */

struct nnpfs {
    u_int status;			/* Inited, opened or mounted */
#define NNPFS_MOUNTED	0x1
    struct vfs *vfsp;
    struct nnpfs_node *root;
    u_int nnodes;
    
    struct nnpfs_node *nodes;		/* replace with hash table */
    struct nnpfs_node *next_node;		/* next node in iter */
    kmutex_t nodes_iter;		/* iterating over list */
    kmutex_t nodes_modify;		/* modifing/reading nodes/next_node */
    int fd;
};

#define VFS_TO_NNPFS(v)      ((struct nnpfs *) ((v)->vfs_data))
#define NNPFS_TO_VFS(x)      ((x)->vfsp)

#define NNPFS_FROM_VNODE(vp) VFS_TO_NNPFS((vp)->v_vfsp)
#define NNPFS_FROM_XNODE(xp) NNPFS_FROM_VNODE(XNODE_TO_VNODE(xp))

extern struct nnpfs nnpfs[];

extern struct vnodeops nnpfs_vnodeops;

int nnpfs_unloadable (void);
void nnpfs_init_nnpfs (int instance);
void nnpfs_destroy_nnpfs (int instance);

struct nnpfs_node *nnpfs_node_find (struct nnpfs *, struct nnpfs_handle *);
struct nnpfs_node *new_nnpfs_node (struct nnpfs *, struct nnpfs_node *,
			       struct nnpfs_msg_node *);
void free_nnpfs_node (struct nnpfs_node *);
void free_all_nnpfs_nodes (struct nnpfs *nnpfsp);
struct nnpfs_node *nnpfs_node_iter_start (struct nnpfs *nnpfsp);
struct nnpfs_node *nnpfs_node_iter_next (struct nnpfs *nnpfsp);
void nnpfs_node_iter_stop (struct nnpfs *nnpfsp);

int 
nnpfs_dnlc_enter (struct vnode *, char *, struct vnode *);

struct vnode *
nnpfs_dnlc_lookup (struct vnode *, char *);

void
nnpfs_dnlc_remove(vnode_t *dvp, char *name);

void
nnpfs_attr2vattr (const struct nnpfs_attr *xa, struct vattr *va, int clear_node);

void
vattr2nnpfs_attr (const struct vattr *va, struct nnpfs_attr *xa);

int nnpfs_has_pag(const struct nnpfs_node *xn, nnpfs_pag_t);

#endif /* _nnpfs_h */
