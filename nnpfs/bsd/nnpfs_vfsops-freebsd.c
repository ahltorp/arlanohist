/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vfsops-freebsd.c,v 1.38 2008/02/26 21:59:12 tol Exp $");

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_vfsops-bsd.h>
#include <nnpfs/nnpfs_vnodeops.h>
#include <nnpfs/nnpfs_node.h>

const char *VT_AFS = "afs";
static const char *VT_NON = "dead-afs";

static int
nnpfs_dead_reclaim(struct vop_reclaim_args *ap)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dead_reclaim(%p)\n", ap->a_vp));
    cache_purge(ap->a_vp);
    return 0;
}

static struct vop_vector nnpfs_dead_vops = {
    .vop_default = &default_vnodeops,
    .vop_lookup = nnpfs_dead_lookup,
    .vop_reclaim = nnpfs_dead_reclaim,
#ifdef HAVE_VOP_LOCK1
    .vop_lock1 = vop_stdlock,
#endif
#ifdef HAVE_VOP_LOCK
    .vop_lock = vop_stdlock,
#endif
    .vop_unlock = vop_stdunlock,
    .vop_islocked = vop_stdislocked,
};

int
nnpfs_make_dead_vnode(struct mount *mp, int isrootp, struct vnode **vpp)
{
    int error;
    NNPFSDEB(XDEBNODE, ("make_dead_vnode mp = %lx\n",
		      (unsigned long)mp));

    error = getnewvnode(VT_NON, mp, &nnpfs_dead_vops, vpp);
    if (error == 0)
	NNPFS_MAKE_VROOT(*vpp);

#ifdef HAVE_KERNEL_INSMNTQUE
    /* XXX: Possibly should lock with lockmgr here. */
    error = insmntque(*vpp, mp);
    if (error) {
      *vpp = NULL;
      return error;
    }
#endif

    nnpfs_vfs_writelock(*vpp, nnpfs_curproc());

    return error;
}

static int
nnpfs_init(struct vfsconf *conf)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_init\n"));
#if defined(HAVE_KERNEL_VFS_OPV_INIT)
    vfs_opv_init(&nnpfs_vnodeop_opv_desc);
    vfs_opv_init(&nnpfs_dead_vnodeop_opv_desc);
#elif defined(HAVE_KERNEL_VFS_ADD_VNODEOPS) && !defined(KLD_MODULE)
    vfs_add_vnodeops (&nnpfs_vnodeop_opv_desc);
    vfs_add_vnodeops (&nnpfs_dead_vnodeop_opv_desc);
#endif
    return 0;
}

static const char *nnpfs_opts[] = { "from", "fspath", NULL };

static int
nnpfs_mount_freebsd(struct mount *mp, d_thread_t *p)
{
    char *path, *data;
    int pathlen, datalen, error;
    struct nameidata ndp;
    nnpfs_vfs_context ctx;
    nnpfs_vfs_context_init(ctx, p, nnpfs_proc_to_cred(p));

    if (vfs_filteropt(mp->mnt_optnew, nnpfs_opts))
	return EINVAL;

    error = vfs_getopt(mp->mnt_optnew, "fspath", (void**)&path, &pathlen);
    if (error || '\0' != path[pathlen - 1])
	return EINVAL;
    error = vfs_getopt(mp->mnt_optnew, "from", (void**)&data, &datalen);
    if (error || '\0' != data[datalen - 1])
	return EDOOFUS;		// not EINVAL cuz this comes from mount(2)
    error = nnpfs_mount_common_sys(mp, NULL, path, data, &ndp, ctx);
    if (error)
	return error;

    MNT_ILOCK(mp);
    mp->mnt_kern_flag |= MNTK_MPSAFE;
    MNT_IUNLOCK(mp);

    /* vfs_mountedfrom(mp, data); see _mount_common_sys() */

    return 0;
}

static int
nnpfs_cmount_freebsd(struct mntarg *ma, void *data, int flags, struct thread *td)
{
    ma = mount_argsu(ma, "from", data, MAXPATHLEN);
    return kernel_mount(ma, flags);
}

static int
nnpfs_vget_freebsd(struct mount *mp,
		   ino_t ino,
		   int flags,
		   struct vnode ** vpp)
{
    return nnpfs_vget(mp, ino, vpp);
}

static int
nnpfs_root_freebsd(struct mount *mp, int flags, struct vnode **vpp,
		struct thread *td)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_root mp = %lx\n", (unsigned long)mp));
    return nnpfs_root_common(mp, vpp, td);
}

struct vfsops nnpfs_vfsops = {
    .vfs_cmount = nnpfs_cmount_freebsd,
    .vfs_mount = nnpfs_mount_freebsd,
    .vfs_unmount = nnpfs_unmount,
    .vfs_root = nnpfs_root_freebsd,
    .vfs_quotactl = nnpfs_quotactl,
    .vfs_statfs = nnpfs_statfs,
    .vfs_sync = nnpfs_sync,
    .vfs_vget = nnpfs_vget_freebsd,
    .vfs_fhtovp = nnpfs_fhtovp,
    .vfs_checkexp = nnpfs_checkexp,
#ifndef HAVE_VOP_VPTOFH
    .vfs_vptofh = nnpfs_vptofh,
#endif
    .vfs_init = nnpfs_init
};
/*VFS_SET(nnpfs_vfsops, arlannpfsdev, 0);*/

#if !KLD_MODULE

#if __FreeBSD_version > 502123
static struct vfsconf nnpfs_vfc = {
    .vfs_ops = &nnpfs_vfsops,    
    .vfs_name = "nnpfs",
    .vfs_flags = 0,
    .vfs_refcount = 0
};
#else
static struct vfsconf nnpfs_vfc = {
    &nnpfs_vfsops,
    "nnpfs",
    0,
    0,
    0
};
#endif

#ifndef HAVE_KERNEL_VFS_REGISTER

static int
vfs_register (struct vfsconf *vfs)
{
    int i;

    for (i = 0; i < MOUNT_MAXTYPE; i++)
	if (strcmp(vfsconf[i]->vfc_name, vfs->vfc_name) == 0)
	    return EEXIST;

    for (i = MOUNT_MAXTYPE - 1; i >= 0; --i)
	if (vfsconf[i] == &void_vfsconf)
	    break;

    if (i < 0) {
	NNPFSDEB(XDEBVFOPS, ("failed to find free VFS slot\n"));
	return EINVAL;
    }

    vfs->vfc_index = i;
    vfsconf[i] = vfs;

    vfssw[i] = vfs->vfc_vfsops;
    (*(vfssw[i]->vfs_init)) ();
    return 0;
}

static int
vfs_unregister (struct vfsconf *vfs)
{
    int i = vfs->vfc_index;

    if (vfs->vfc_refcount)
	return EBUSY;

    vfsconf[i] = &void_vfsconf;
    vfssw[i]   = NULL;
    return 0;
}

#endif
#endif /* !KLD_MODULE */

#if KLD_MODULE

int
nnpfs_install_filesys(void)
{
    return 0;
}

int
nnpfs_uninstall_filesys(void)
{
    return 0;
}

int
nnpfs_stat_filesys (void)
{
    return 0;
}

#else

int
nnpfs_install_filesys(void)
{
    
    NNPFSDEB(XDEBVFOPS, ("nnpfs_install_filesys vfc_name = %s\n",
			 nnpfs_vfc.vfc_name));
    return vfs_register(&nnpfs_vfc);
}

int
nnpfs_uninstall_filesys(void)
{
    return vfs_unregister(&nnpfs_vfc);
}

int
nnpfs_stat_filesys (void)
{
    return 0;
}

#endif /* KLD_MODULE */
