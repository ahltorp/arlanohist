/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_fs.h,v 1.33 2007/03/14 16:44:30 tol Exp $ */

#ifndef _nnpfs_h
#define _nnpfs_h

#include <sys/types.h>

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_attr.h>

#include <nnpfs/nnpfs.h>

#ifdef __APPLE__
#define VFS_SET_NNPFS(v,n)   vfs_setfsprivate((v), (void *)(n));
#else
#define VFS_SET_NNPFS(v,n)   ((v)->mnt_data = (void *)(n))
#endif
#define NNPFS_TO_VFS(x)      ((x)->mp)

#ifdef __APPLE__
#define VFS_TO_NNPFS(mp)     ((struct nnpfs *)(vfs_fsprivate(mp)))
#define NNPFS_FROM_VNODE(vp) VFS_TO_NNPFS(vnode_mount(vp))
#else
#define VFS_TO_NNPFS(mp)      ((struct nnpfs *) ((mp)->mnt_data))
#define NNPFS_FROM_VNODE(vp) VFS_TO_NNPFS((vp)->v_mount)
#endif

#define NNPFS_FROM_XNODE(xp) NNPFS_FROM_VNODE(XNODE_TO_VNODE(xp))

#ifdef __FreeBSD__
extern struct vop_vector nnpfs_vnodeops;
#else
extern struct vnodeops nnpfs_vnodeops;
extern vop_t **nnpfs_vnodeop_p;
#endif

int nnpfs_new_node(struct nnpfs *, struct nnpfs_msg_node *, char *,
		   struct nnpfs_node **, d_thread_t *, int);
void nnpfs_free_node(struct nnpfs *nnpfsp, struct nnpfs_node *node);
int nnpfs_free_all_nodes(struct nnpfs *, int, int);
void nnpfs_release_cachevn(struct nnpfs_node *node);
void nnpfs_release_data(struct nnpfs_node *node);

int nnpfs_dnlc_enter(struct vnode *, nnpfs_componentname *, struct vnode *);
int nnpfs_dnlc_enter_name(struct vnode *, char *, struct vnode *);
void nnpfs_dnlc_purge_mp(struct mount *);
void nnpfs_dnlc_purge(struct vnode *);
int nnpfs_dnlc_lookup(struct vnode *, nnpfs_componentname *, struct vnode **);
int nnpfs_dnlc_lookup_name(struct vnode *, const char *, struct vnode **);

void vattr2nnpfs_attr(const struct nnpfs_vfs_vattr *, struct nnpfs_attr *);
void nnpfs_store_attr(const struct nnpfs_attr *, struct nnpfs_node *, int);
void nnpfs_setsize(struct nnpfs_node *xn, uint64_t size);

int nnpfs_has_pag(const struct nnpfs_node *, nnpfs_pag_t);

#endif				       /* _nnpfs_h */
