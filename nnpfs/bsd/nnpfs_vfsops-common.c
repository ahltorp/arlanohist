/*
 * Copyright (c) 1995 - 2009 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vfsops-common.c,v 1.68 2009/02/24 21:00:39 tol Exp $");

/*
 * NNPFS vfs operations.
 */

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>

#if defined(HAVE_KERNEL_FINDCDEV)
#define VA_RDEV_TO_DEV(x) findcdev(x)
#elif defined(HAVE_KERNEL_UDEV2DEV)
#define VA_RDEV_TO_DEV(x) udev2dev(x, 0) /* XXX what is the 0 */
#else
#define VA_RDEV_TO_DEV(x) x
#endif

/*
 * path and data is in system memory
 */

int
nnpfs_mount_common_sys(struct mount *mp,
		       struct vnode *devvp_in,
		       const char *path,
		       void *data,
		       struct nameidata *ndp,
		       nnpfs_vfs_context ctx)
{
    struct vnode *devvp = devvp_in;
    struct nnpfs_vfs_vattr vat;
    nnpfs_dev_t dev;
    struct nnpfs *nnpfs;
    int error;
#ifdef __FreeBSD__
    int unit;
#endif
    
    NNPFSDEB(XDEBVFOPS, ("nnpfs_mount: "
			 "struct mount mp = %lx path = '%s' data = '%s'\n",
			 (unsigned long)mp,
			 path == NULL ? "-" : path, (char *)data));

#ifdef ARLA_KNFS
    NNPFSDEB(XDEBVFOPS, ("nnpfs_mount: mount flags = %x\n", mp->mnt_flag));

    /*
     * mountd(8) flushes all export entries when it starts
     * right now we ignore it (but should not)
     */

    if (mp->mnt_flag & MNT_UPDATE ||
	mp->mnt_flag & MNT_DELEXPORT) {

	NNPFSDEB(XDEBVFOPS, 
	       ("nnpfs_mount: ignoring MNT_UPDATE or MNT_DELEXPORT\n"));
	return 0;
    }
#endif

#ifdef __APPLE__
    if (devvp == NULL)
	panic("nnpfs_mount_common_sys: NULL devvp"); /* XXX */
#else
    if (devvp == NULL) {
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF | NNPFS_MPSAFE, UIO_SYSSPACE, data,
	       nnpfs_vfs_context_proc(ctx));

	error = namei(ndp);
	if (error) {
	    NNPFSDEB(XDEBVFOPS, ("namei failed, errno = %d\n", error));
	    return error;
	}
	
	devvp = ndp->ni_vp;
    }
#endif

    if (!nnpfs_vnode_ischr(devvp)) {
        nnpfs_vput(devvp);
	NNPFSDEB(XDEBVFOPS, ("not VCHR\n"));
	return ENXIO;
    }

#ifdef __APPLE__
    VATTR_INIT(&vat);
    VATTR_WANTED(&vat, va_rdev);
#endif

    nnpfs_vop_getattr(devvp, &vat, ctx, error);
    nnpfs_vput(devvp);
    if (error) {
	NNPFSDEB(XDEBVFOPS, ("VOP_GETATTR failed, error = %d\n", error));
	return error;
    }

#ifdef __FreeBSD__
    for (unit = 0; unit < NNNPFS; unit++) {
	nnpfs = nnpfs_dev + unit;
	dev = nnpfs->dev;
	if (dev2udev(dev) == vat.va_rdev) {
	    NNPFSDEB(XDEBVFOPS, ("dev = .%d\n", unit));
	    break;
	}
    }
    if (unit >= NNNPFS) {
	NNPFSDEB(XDEBVFOPS, ("%s is not a nnpfs device\n", (char *)data));
	return ENXIO;
    }
#else
    dev = VA_RDEV_TO_DEV(vat.va_rdev);
    nnpfs = &nnpfs_dev[minor(dev)];
    NNPFSDEB(XDEBVFOPS, ("dev = %d.%d\n", major(dev), minor(dev)));
    
    if (!nnpfs_is_nnpfs_dev (dev)) {
	NNPFSDEB(XDEBVFOPS, ("%s is not a nnpfs device\n", (char *)data));
	return ENXIO;
    }
#endif

    nnpfs_dev_lock(nnpfs);

    if (nnpfs->status & NNPFS_MOUNTED) {
	nnpfs_dev_unlock(nnpfs);
	return EBUSY;
    }

    nnpfs->status |= NNPFS_MOUNTED;
    nnpfs->mp = mp;
    nnpfs->root = 0;

    nnpfs_init_head(&nnpfs->nodehead);
    NNPQUEUE_INIT(&nnpfs->freehead);

    VFS_SET_NNPFS(mp, nnpfs);
#if defined(HAVE_KERNEL_VFS_GETNEWFSID)
#if defined(HAVE_TWO_ARGUMENT_VFS_GETNEWFSID)
    vfs_getnewfsid(mp, MOUNT_AFS);
#else
    vfs_getnewfsid(mp);
#endif /* HAVE_TWO_ARGUMENT_VFS_GETNEWFSID */
#endif /* HAVE_KERNEL_VFS_GETNEWFSID */

#ifdef __APPLE__
    {
	struct vfsstatfs *vfsstats = vfs_statfs(mp);
	char *mntfrom = vfsstats->f_mntfromname;
	strncpy(mntfrom, (char *)data, MNAMELEN);
	mntfrom[MNAMELEN - 1] = '\0';

	nnpfs_typenum = vfs_typenum(mp);
	vfs_setauthopaque(mp);
	vfs_setauthopaqueaccess(mp);

	/*
	 * Here we should do vfs_setlocklocal(mp), but it is not
	 * exported, so we emulate. Sort of. Ignore mp locking and
	 * iterating over all vnodes, hoping that we're in a safe
	 * enough state as it is...
	 */
	{
	    int *mount_struct_contents = (int *)mp;
	    
	    /* mp->mnt_kern_flag |= MNTK_LOCK_LOCAL; */
	    mount_struct_contents[16] |= 0x00100000; /* XXX _BAD_ with 64 bits */
	}
	
	/* vfs_name(mp, vfsstats->f_fstypename); */
	
	vfsstats->f_bsize = DEV_BSIZE;
	vfsstats->f_iosize = DEV_BSIZE;
	vfsstats->f_owner = 0;
	vfsstats->f_blocks = 4711 * 4711;
	vfsstats->f_bfree = 4711 * 4711;
	vfsstats->f_bavail = 4711 * 4711;
	vfsstats->f_bused = 0;
	vfsstats->f_files = 4711;
	vfsstats->f_ffree = 4711;
	vfsstats->f_fssubtype = 0;
	vfsstats->f_fsid.val[0] = nnpfs_typenum;
	vfsstats->f_fsid.val[1] = 0;
    }
#else
    mp->mnt_stat.f_bsize = DEV_BSIZE;
    mp->mnt_stat.f_iosize = DEV_BSIZE;
    mp->mnt_stat.f_owner = 0;
    mp->mnt_stat.f_blocks = 4711 * 4711;
    mp->mnt_stat.f_bfree = 4711 * 4711;
    mp->mnt_stat.f_bavail = 4711 * 4711;
    mp->mnt_stat.f_files = 4711;
    mp->mnt_stat.f_ffree = 4711;
#if defined(__NetBSD_Version__) && __NetBSD_Version__ > 299000900 /* really statvfs */
    mp->mnt_stat.f_flag = mp->mnt_flag;
#else
    mp->mnt_stat.f_flags = mp->mnt_flag;
#endif

    strncpy(mp->mnt_stat.f_mntonname,
	    path,
	    sizeof(mp->mnt_stat.f_mntonname));

    strncpy(mp->mnt_stat.f_mntfromname,
	    "arla",
	    sizeof(mp->mnt_stat.f_mntfromname));

    strncpy(mp->mnt_stat.f_fstypename,
	    "nnpfs",
	    sizeof(mp->mnt_stat.f_fstypename));
#endif

    nnpfs_dev_unlock(nnpfs);
    return 0;
}

#ifndef __APPLE__
int
nnpfs_mount_common(struct mount *mp,
		   const char *user_path,
		   void *user_data,
		   struct nameidata *ndp,
		   d_thread_t *p)
{
    char *path = NULL;
    char *data = NULL;
    nnpfs_vfs_context ctx;
    size_t count;
    int error;

    data = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
    path = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);

    error = copyinstr(user_path, path, MAXPATHLEN, &count);
    if (error)
        goto done;

    error = copyinstr(user_data, data, MAXPATHLEN, &count);
    if (error)
        goto done;

    nnpfs_vfs_context_init(ctx, p, nnpfs_proc_to_cred(p));
    error = nnpfs_mount_common_sys(mp, NULL, path, data, ndp, ctx);
 done:
    free(data, M_TEMP);
    free(path, M_TEMP);
    return error;
}
#endif

#ifdef HAVE_KERNEL_DOFORCE
extern int doforce;
#endif

int
nnpfs_unmount_common(struct mount *mp, int mntflags)
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(mp);
    int flags = 0;
    int error;

    if (mntflags & MNT_FORCE) {
#ifdef HAVE_KERNEL_DOFORCE
	if (!doforce)
	    return EINVAL;
#endif
	flags |= FORCECLOSE;
    }

    nnpfs_dev_lock(nnpfsp);

#ifdef __APPLE__
    if ((nnpfsp->status & CHANNEL_OPENED) && (flags & FORCECLOSE) == 0) {
	nnpfs_dev_unlock(nnpfsp);
	NNPFSDEB(XDEBVFOPS, ("nnpfs_umount: busy and not forced\n"));
	return EBUSY;
    }
#endif

    error = nnpfs_free_all_nodes(nnpfsp, flags, 1);
    if (error)
	return error;

    nnpfsp->status &= ~NNPFS_MOUNTED;
    NNPFS_TO_VFS(nnpfsp) = NULL;

    nnpfs_dev_unlock(nnpfsp);
    return 0;
}

int
nnpfs_root_common(struct mount *mp, struct vnode **vpp,
		  d_thread_t *proc)
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(mp);
    struct nnpfs_message_getroot msg;
    nnpfs_kernel_cred cred = nnpfs_proc_to_cred(proc);
    int error;

    nnpfs_dev_lock(nnpfsp);
    
    do {
	if (nnpfsp->root != NULL) {
	    *vpp = XNODE_TO_VNODE(nnpfsp->root);
	    nnpfs_dev_unlock(nnpfsp);
	    nnpfs_do_vget(*vpp, LK_EXCLUSIVE, proc);
	    return 0;
	}
	msg.header.opcode = NNPFS_MSG_GETROOT;
	msg.cred.uid = nnpfs_cred_get_uid(cred);
	msg.cred.pag = nnpfs_get_pag(cred);
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), proc);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    } while (error == 0);
    /*
     * Failed to get message through, need to pretend that all went well
     * and return a fake dead vnode to be able to unmount.
     */

    NNPFSDEB(XDEBVFOPS, ("did not get root, making dead\n"));

    error = nnpfs_make_dead_vnode(mp, 1, vpp);
    nnpfs_dev_unlock(nnpfsp);
    return error;
}
