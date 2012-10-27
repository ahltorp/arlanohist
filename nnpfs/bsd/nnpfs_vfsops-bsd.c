/*
 * Copyright (c) 1995-2002, 2004-2007 Kungliga Tekniska Högskolan
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

#include <nnpfs/nnpfs_locl.h>

RCSID("$Id: nnpfs_vfsops-bsd.c,v 1.107 2010/06/16 19:58:51 tol Exp $");

/*
 * NNPFS vfs operations.
 */

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_vfsops-bsd.h>
#include <nnpfs/nnpfs_vnodeops.h>

#ifndef __APPLE__
int
nnpfs_mount_caddr(struct mount *mp,
		const char *user_path,
		caddr_t user_data,
		struct nameidata *ndp,
		d_thread_t *p)
{
    return nnpfs_mount_common(mp, user_path, user_data, ndp, p);
}

int
nnpfs_start(struct mount * mp, int flags, d_thread_t * p)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_start mp = %lx, flags = %d, proc = %lx\n", 
		       (unsigned long)mp, flags, (unsigned long)p));
    return 0;
}

int
nnpfs_unmount(struct mount * mp, int mntflags, d_thread_t *p)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_umount: mp = %lx, mntflags = %d, proc = %lx\n", 
		       (unsigned long)mp, mntflags, (unsigned long)p));
    return nnpfs_unmount_common(mp, mntflags);
}

int
nnpfs_root(struct mount *mp, struct vnode **vpp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_root mp = %lx\n", (unsigned long)mp));

    return nnpfs_root_common(mp, vpp, nnpfs_curproc());
}

int
#if (defined(HAVE_VFS_QUOTACTL_CADDR) || (defined (__OpenBSD__) && OpenBSD >= 200805))
nnpfs_quotactl(struct mount *mp, int cmd, uid_t uid, caddr_t arg, d_thread_t *p)
#else
nnpfs_quotactl(struct mount *mp, int cmd, uid_t uid, void *arg, d_thread_t *p)
#endif
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_quotactl: mp = %lx, cmd = %d, uid = %u, "
		       "arg = %lx, proc = %lx\n", 
		       (unsigned long)mp, cmd, uid,
		       (unsigned long)arg, (unsigned long)p));
    return EOPNOTSUPP;
}

int
nnpfs_statfs(struct mount *mp, nnpfs_statvfs *sbp, d_thread_t *p)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_statfs: mp = %lx, sbp = %lx, proc = %lx\n", 
		       (unsigned long)mp,
		       (unsigned long)sbp,
		       (unsigned long)p));
    bcopy(&mp->mnt_stat, sbp, sizeof(*sbp));
    return 0;
}

#if defined(__DragonFly__) || (defined(__FreeBSD_version) && __FreeBSD_version > 600006)
int
nnpfs_sync(struct mount *mp, int waitfor, d_thread_t *p)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_sync: mp = %lx, waitfor = %d, "
		       "proc = %lx\n",
		       (unsigned long)mp,
		       waitfor,
		       (unsigned long)p));
    return 0;
}
#else
int
nnpfs_sync(struct mount *mp, int waitfor, nnpfs_kernel_cred cred, d_thread_t *p)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_sync: mp = %lx, waitfor = %d, "
		       "cred = %lx, proc = %lx\n",
		       (unsigned long)mp,
		       waitfor,
		       (unsigned long)cred,
		       (unsigned long)p));
    return 0;
}
#endif

int
nnpfs_snapshot(struct mount *mp, struct vnode *vp, struct timespec *ts)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_snapshot: mp = %lx\n", 
			 (unsigned long)mp));
    return EOPNOTSUPP;
}

int
nnpfs_vget(struct mount * mp, ino_t ino, struct vnode ** vpp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
    return EOPNOTSUPP;
}

static int
common_fhtovp(struct mount * mp,
	      struct fid * fhp,
	      struct vnode ** vpp)
{
    return EOPNOTSUPP;
}

/* new style fhtovp */

#ifdef HAVE_THREE_ARGUMENT_FHTOVP
int
nnpfs_fhtovp(struct mount * mp,
	   struct fid * fhp,
	   struct vnode ** vpp)
{
    return common_fhtovp (mp, fhp, vpp);
}

#else /* !HAVE_THREE_ARGUMENT_FHTOVP */

/* old style fhtovp */

int
nnpfs_fhtovp(struct mount * mp,
	   struct fid * fhp,
	   struct mbuf * nam,
	   struct vnode ** vpp,
	   int *exflagsp,
	   struct ucred ** credanonp)
{
    static struct ucred fhtovpcred;
    int error;

    /* XXX: Should see if we is exported to this client */
#if 0
    np = vfs_export_lookup(mp, &ump->um_export, nam);
    if (np == NULL)
       return EACCES;
#endif
    error = common_fhtovp(mp, fhp, vpp);
    if (error == 0) {
       fhtovpcred.cr_uid = 0;
       fhtovpcred.cr_gid = 0;
       fhtovpcred.cr_ngroups = 0;
      
#ifdef MNT_EXPUBLIC
       *exflagsp = MNT_EXPUBLIC;
#else
       *exflagsp = 0;
#endif
       *credanonp = &fhtovpcred;
    }
    return error;
}
#endif /* !HAVE_THREE_ARGUMENT_FHTOVP */

int
nnpfs_checkexp (struct mount *mp,
#if defined(__FreeBSD__) || defined(__DragonFly__)
	      struct sockaddr *nam,
#else
	      struct mbuf *nam,
#endif
	      int *exflagsp,
	      struct ucred **credanonp)
{
#if 0
    struct netcred *np;
#endif

    NNPFSDEB(XDEBVFOPS, ("nnpfs_checkexp\n"));

#if 0
    np = vfs_export_lookup(mp, &ump->um_export, nam);
    if (np == NULL)
	return EACCES;
#endif
    return 0;
}

#ifndef HAVE_VOP_VPTOFH
int
nnpfs_vptofh(struct vnode * vp,
	     struct fid * fhp
#if defined(__NetBSD__) && __NetBSD_Version__ >= 399002200 /* 3.99.22 */
	     ,size_t * fidsz
#endif
	   )
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vptofh\n"));
    return EOPNOTSUPP;
}
#endif

#endif /* !__APPLE__ */

/* 
 * nnpfs complete dead vnodes implementation.
 *
 * this is because the dead_vnodeops_p is _not_ filesystem, but rather
 * a part of the vfs-layer.  
 */

#ifdef __APPLE__
int
nnpfs_dead_lookup(struct vnop_lookup_args * ap)
#else
int
nnpfs_dead_lookup(struct vop_lookup_args * ap)
     /* struct vop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
}; */
#endif
{
    *ap->a_vpp = NULL;
    return ENOTDIR;
}

/*
 *
 */

#ifdef HAVE_VOP_PUTPAGES
int
nnpfs_dead_putpages (struct vop_putpages_args *ap)
{
    struct vnode *vp = ap->a_vp;
#ifdef __FreeBSD__
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dead_putpages %s\n", ap->a_gen.a_desc->vdesc_name));
#else
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dead_putpages %s\n", ap->a_desc->vdesc_name));
#endif
#ifndef __DragonFly__
    nnpfs_interlock_unlock(&vp->v_interlock)
#endif
    return 0;
}
#endif
