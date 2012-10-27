/*
 * Copyright (c) 1995 - 2001 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_vfsops-bsd.h,v 1.27 2010/06/16 19:58:53 tol Exp $ */

#ifndef _nnpfs_vfsops_bsd_h
#define _nnpfs_vfsops_bsd_h

#ifdef __APPLE__
int
nnpfs_mount_context(struct mount *mp, vnode_t devvp, user_addr_t data,
		    nnpfs_vfs_context ctx);
int
nnpfs_start(struct mount *mp, int flags, nnpfs_vfs_context ctx);

int
nnpfs_unmount(struct mount *mp, int mntflags, nnpfs_vfs_context ctx);

int
nnpfs_root(struct mount *mp, struct vnode **vpp, nnpfs_vfs_context ctx);

int
nnpfs_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t arg,
	       nnpfs_vfs_context ctx);

/* vfs_getattr really */
int
nnpfs_statfs(struct mount *mp, nnpfs_statvfs *sbp, nnpfs_vfs_context ctx);

int
nnpfs_sync(struct mount *mp, int waitfor, nnpfs_vfs_context ctx);

int
nnpfs_dead_lookup(struct vnop_lookup_args *ap);

#else /* !__APPLE__*/

int
nnpfs_mount_caddr(struct mount *mp, const char *user_path, caddr_t user_data,
		struct nameidata *ndp, d_thread_t *p);

int
nnpfs_start(struct mount * mp, int flags, d_thread_t * p);

int
nnpfs_unmount(struct mount * mp, int mntflags, d_thread_t *p);

int
nnpfs_root(struct mount *mp, struct vnode **vpp);

int
#if (defined(HAVE_VFS_QUOTACTL_CADDR) || (defined (__OpenBSD__) && OpenBSD >= 200805))
nnpfs_quotactl(struct mount *mp, int cmd, uid_t uid, caddr_t arg, d_thread_t *p);
#else
nnpfs_quotactl(struct mount *mp, int cmd, uid_t uid, void *arg, d_thread_t *p);
#endif

int
nnpfs_statfs(struct mount *mp, nnpfs_statvfs *sbp, d_thread_t *p);

#if defined(__DragonFly__) || (defined(__FreeBSD_version) && __FreeBSD_version > 600006)
int
nnpfs_sync(struct mount *mp, int waitfor, d_thread_t *p);
#else
int
nnpfs_sync(struct mount *mp, int waitfor, nnpfs_kernel_cred cred, d_thread_t *p);
#endif

int
nnpfs_vget(struct mount * mp, ino_t ino, struct vnode ** vpp);


struct mbuf;
struct fid;

#ifdef HAVE_THREE_ARGUMENT_FHTOVP
int
nnpfs_fhtovp(struct mount * mp,
	     struct fid * fhp,
	     struct vnode ** vpp);
#else
int
nnpfs_fhtovp(struct mount * mp,
	     struct fid * fhp,
	     struct mbuf * nam,
	     struct vnode ** vpp,
	     int *exflagsp,
	     struct ucred ** credanonp);
#endif

#ifndef HAVE_VOP_VPTOFH
int
nnpfs_vptofh(struct vnode * vp,
	     struct fid * fhp
#if defined(__NetBSD__) && __NetBSD_Version__ >= 399002200 /* 3.99.22 */
	     ,size_t * fidsz
#endif
	     );
#endif

int
nnpfs_dead_lookup(struct vop_lookup_args *ap);

int
nnpfs_snapshot(struct mount *, struct vnode *, struct timespec *);

int
nnpfs_checkexp (struct mount *mp,
#if  defined(__FreeBSD__) || defined(__DragonFly__)
	      struct sockaddr *nam,
#else
	      struct mbuf *nam,
#endif
	      int *exflagsp,
	      struct ucred **credanonp);

#endif /* !__APPLE__*/

#ifdef HAVE_VOP_PUTPAGES
int
nnpfs_dead_putpages(struct vop_putpages_args *ap);
#endif

#endif /* _nnpfs_vfsops_bsd_h */
