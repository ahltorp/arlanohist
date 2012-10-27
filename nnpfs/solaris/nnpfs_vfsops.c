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

#include <nnpfs/nnpfs_locl.h>

RCSID("$Id: nnpfs_vfsops.c,v 1.20 2002/09/07 10:47:43 lha Exp $");

/*
 * NNPFS vfs operations.
 */

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>
#include <nnpfs/nnpfs_vfsops.h>

extern int nchrdev;

static struct vnode *make_dead_vnode (struct vfs *vfsp);

struct nnpfs nnpfs[NNNPFS];

static int nnpfsfstype;

/*
 * Returns 0 if the module is unloadable
 */

int
nnpfs_unloadable(void)
{
    int i;
    
    for (i = 0; i < NNNPFS ; i++) {
	if (nnpfs[i].nnodes)
	    return 1;
    }
    return 0;
}

/*
 *
 */

static int
nnpfs_mount(struct vfs *vfsp,
	  struct vnode *mvp,
	  struct mounta *uap,
	  struct cred *cred)
{
    struct vnode *devvp;
    struct nnpfs *nnpfsp;
    dev_t dev;
    int error;
  
#ifdef DEBUG
    char dir[MAXPATHLEN], spec[MAXPATHLEN];

    if (copyinstr(uap->dir, dir, sizeof(dir), NULL) ||
	copyinstr(uap->spec, spec, sizeof(spec), NULL))
	return EFAULT;
    NNPFSDEB(XDEBVFOPS, ("nnpfs_mount vfsp = 0x%x path = '%s' args = '%s'\n",
		       (u_int) vfsp, dir, spec));
#endif

    /*
     * This is something that should be done before calling this
     * function, but it's not, so we do it here.
     */

    if (mvp->v_type != VDIR)
	return ENOTDIR;
    mutex_enter(&mvp->v_lock);
    if (mvp->v_count != 1 || (mvp->v_flag & VROOT)) {
	mutex_exit(&mvp->v_lock);
	return EBUSY;
    }
    mutex_exit(&mvp->v_lock);

    error = lookupname(uap->spec, UIO_USERSPACE, FOLLOW, 0, &devvp);
    if (error != 0)
	return error;

    if (devvp->v_type != VCHR) {
	VN_RELE(devvp);
	return ENXIO;
    }
    dev = devvp->v_rdev;
    VN_RELE(devvp);

    /* Check that this device really is an nnpfs_dev */

    /* I'm not sure how to test this under solaris */
#if 0
    if (getmajor(dev) < 0 || nchrdev < getmajor(dev))
	return ENXIO;
#endif

    NNPFSDEB(XDEBVFOPS, ("nnpfs_mount dev = %x, minor = %x, major = %x,"
		       "ops = %x, "
		       "cb_ops = %x, "
		       "open = %x, "
		       "(nnpfs_devopen = %x)\n",
		       (unsigned)dev,
		       (unsigned)getminor(dev),
		       (unsigned)getmajor(dev),
		       (unsigned)devopsp[getmajor(dev)],
		       (unsigned) (devopsp[getmajor(dev)] ? 
				   devopsp[getmajor(dev)]->devo_cb_ops :
				   0),
		       (unsigned) ((devopsp[getmajor(dev)] 
				    && devopsp[getmajor(dev)]->devo_cb_ops) ?
				   devopsp[getmajor(dev)]->devo_cb_ops->cb_open :
				   0),
		       (unsigned) nnpfs_devopen));

    if (getminor(dev) < 0 || NNNPFS < getminor(dev))
	return ENXIO;
    if (devopsp[getmajor(dev)] == NULL ||
	devopsp[getmajor(dev)]->devo_cb_ops == NULL ||
	devopsp[getmajor(dev)]->devo_cb_ops->cb_open != nnpfs_devopen)
	return ENXIO;

    nnpfsp = &nnpfs[getminor(dev)];

    if (nnpfsp->status & NNPFS_MOUNTED)
	return EBUSY;

    mutex_init(&nnpfsp->nodes_iter, "nnpfs:iter", MUTEX_DRIVER, NULL);
    mutex_init(&nnpfsp->nodes_modify, "nnpfs:modify", MUTEX_DRIVER, NULL);

    nnpfsp->status = NNPFS_MOUNTED;
    nnpfsp->vfsp = vfsp;
    nnpfsp->root = 0;
    nnpfsp->nnodes = 0;
    nnpfsp->nodes = 0;
    nnpfsp->fd = getminor(dev);

    VFS_TO_NNPFS(vfsp) = nnpfsp;
    vfsp->vfs_fstype = nnpfsfstype;
    vfsp->vfs_dev    = getminor(dev);
    vfsp->vfs_bsize  = PAGESIZE;
    vfsp->vfs_flag  |= VFS_NOTRUNC;
    vfsp->vfs_fsid.val[0] = getminor(dev);
    vfsp->vfs_fsid.val[1] = getmajor(dev); /* What is this good for */

    return 0;
}

static int
nnpfs_unmount(struct vfs *vfsp, struct cred *cred)
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);

    NNPFSDEB(XDEBVFOPS, ("nnpfs_umount vfsp = 0x%x\n", (u_int) vfsp));

    free_all_nnpfs_nodes(nnpfsp);

    mutex_destroy(&nnpfsp->nodes_iter);
    mutex_destroy(&nnpfsp->nodes_modify);

    nnpfsp->status = 0;
    return 0;			/* Always allow umount to succed */
}

static int
nnpfs_root(struct vfs *vfsp,
	 struct vnode **vpp)     
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);
    struct nnpfs_message_getroot msg;
    int error;
  
    NNPFSDEB(XDEBVFOPS, ("nnpfs_root vfsp = 0x%x\n", (u_int) vfsp));

    do {
	if (nnpfsp->root != 0) {
	    *vpp = XNODE_TO_VNODE(nnpfsp->root);
	    VN_HOLD(*vpp);
	    NNPFSDEB(XDEBVFOPS, ("nnpfs_root: returning real vnode\n"));
	    return 0;
	}

	msg.header.opcode = NNPFS_MSG_GETROOT;
	msg.cred.uid = CRED()->cr_uid;
	msg.cred.pag = 0;		/* XXX */
	error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	    error = ((struct nnpfs_message_wakeup *) &msg)->error;
    } while (error == 0);

    NNPFSDEB(XDEBVFOPS, ("nnpfs_root: returning dead vnode\n"));

    /*
     * Failed to get message through, need to pretend that all went well
     * and return a fake dead vnode to be able to unmount.
     */
    *vpp = make_dead_vnode(vfsp);
    VN_HOLD(*vpp);
    return 0;
}

static int
nnpfs_statvfs(struct vfs *vfsp,
#ifdef _LARGEFILE64_SOURCE
	    struct statvfs64 *sbp
#else
	    struct statvfs *sbp
#endif
    )
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_statvfs\n"));

    sbp->f_bsize = 8192;
    sbp->f_frsize = 1024;
    sbp->f_blocks = 4711*4711;
    sbp->f_bfree = 4711*4711;
    sbp->f_bavail = 4711*4711;
    sbp->f_files = 4711;
    sbp->f_ffree = 4711;
    sbp->f_favail = 4711;
    sbp->f_fsid = 0x47114711;
    strcpy(sbp->f_basetype, "nnpfs");
    sbp->f_flag = ST_NOTRUNC;
    sbp->f_namemax = 256;
    sbp->f_fstr[0] = 0;

    return 0;
}

static int
nnpfs_sync(struct vfs *vfsp, short flag, struct cred *cred)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_sync\n"));
    return 0;
}

static int
nnpfs_vget(struct vfs *vfsp,
	 struct vnode **vpp,
	 struct fid *fidp)     
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
    return ENOSYS;
}

static int
nnpfs_mountroot(struct vfs *vfsp,
	      enum whymountroot reason)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_mountroot\n"));
    return ENOSYS;
}

static int
nnpfs_swapvp(struct vfs *vfsp,
	   struct vnode **vpp,
	   char *path)     
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_swapvp\n"));
    return ENOSYS;
}

/*
 * To be able to unmount when the NNPFS daemon is not
 * responding we need a root vnode, use a dead vnode!
 */

static void
dead_vnode_inactive(struct vnode *vp, struct cred *cred)
{
    NNPFSDEB(XDEBVFOPS, ("dead_vnode_inactive\n"));
    nnpfs_free(vp, sizeof(*vp));
}

struct vnodeops dead_vnodeops = {
    nodev,			/* nnpfs_open */
    nodev,			/* nnpfs_close */
    nodev,			/* nnpfs_read */
    nodev,			/* nnpfs_write */
    nodev,			/* nnpfs_ioctl */
    nodev,			/* nnpfs_setfl */
    nodev,			/* nnpfs_getattr */
    nodev,			/* nnpfs_setattr */
    nodev,			/* nnpfs_access */
    nodev,			/* nnpfs_lookup */
    nodev,			/* nnpfs_create */
    nodev,			/* nnpfs_remove */
    nodev,			/* nnpfs_link */
    nodev,			/* nnpfs_rename */
    nodev,			/* nnpfs_mkdir */
    nodev,			/* nnpfs_rmdir */
    nodev,			/* nnpfs_readdir */
    nodev,			/* nnpfs_symlink */
    nodev,			/* nnpfs_readlink */
    nodev,			/* nnpfs_fsync */
    dead_vnode_inactive,	/* nnpfs_inactive */
    nodev,			/* nnpfs_fid */
    (void*) nodev,		/* nnpfs_rwlock */
    (void*) nodev,		/* nnpfs_rwunlock */
    nodev,			/* nnpfs_seek */
    nodev,			/* nnpfs_cmp */
    nodev,			/* nnpfs_frlock */
    nodev,			/* nnpfs_space */
    nodev,			/* nnpfs_realvp */
    nodev,			/* nnpfs_getpage */
    nodev,			/* nnpfs_putpage */
    (void*) nodev,		/* nnpfs_map */
    (void*) nodev,		/* nnpfs_addmap */
    nodev,			/* nnpfs_delmap */
    (void*) nodev,		/* nnpfs_poll */
    nodev,			/* nnpfs_dump */
    nodev,			/* nnpfs_pathconf */
    nodev,			/* nnpfs_pageio */
    nodev,			/* nnpfs_dumpctl */
    (void*) nodev,		/* nnpfs_dispose */
    nodev,			/* nnpfs_setsecattr */
    nodev			/* nnpfs_getsecattr */
};

static struct vnode *
make_dead_vnode(struct vfs *vfsp)
{
    struct vnode *dead;

    NNPFSDEB(XDEBNODE, ("make_dead_vnode vfsp = 0x%x\n", (u_int) vfsp));

    dead = nnpfs_alloc(sizeof(*dead));
    bzero((caddr_t)dead, sizeof(*dead));
    VN_INIT(dead, vfsp, VDIR, 0);
    dead->v_flag = VROOT;
    dead->v_op = &dead_vnodeops;
    dead->v_count = 0;
    return dead;
}

int
nnpfs_uprintf_filsys(void)
{
#if 0
    {
	struct vfssw *fs;
	uprintf("Currently loaded filesystems are:\n");
	for (fs = vfssw; fs < vfsNVFS; fs++)
	    uprintf("vfssw[%d] == { \"%s\", 0x%x}\n",
		    fs - vfssw, fs->vsw_name, fs->vsw_ops);
    }
#endif
#if 1
    {
	int i;
	struct nnpfs_node *t;
	for (i = 0; i < NNNPFS; i++)
	    if (nnpfs[i].nodes) {
		uprintf("Current nnpfs_nodes on nnpfs[%d] are:\n", i);
		for (t = nnpfs_node_iter_start(&nnpfs[i]); t;
		     t = nnpfs_node_iter_next(&nnpfs[i]))
		    uprintf("%d.%d.%d.%d(%d) ",
			    t->handle.a,
			    t->handle.b,
			    t->handle.c,
			    t->handle.d,
			    t->vn.v_count);
		uprintf(" !\n");
		nnpfs_node_iter_stop(&nnpfs[i]);
	    }
	
    }
#endif
    return 0;
}

/*
 *
 */

int
nnpfs_fhlookup (fsid_t fsid,
	      fid_t fid,
	      struct vnode **vpp)
{
    int error;
    struct vfs *vfs;

    if (!suser(CRED()))
	return EPERM;

    vfs = getvfs (&fsid);
    if (vfs == NULL)
	return ENXIO;

    error = VFS_VGET(vfs, vpp, &fid);
    return error;
}

/*
 *
 */

int
nnpfs_fhopen (fsid_t fsid,
	    fid_t fid,
	    int flags)
{
    int error;
    struct vnode *vp;
    int fmode = flags - FOPEN;
    struct file *fp;
    int fd;

    error = nnpfs_fhlookup (fsid, fid, &vp);
    if (error)
	return set_errno(error);

    error = VOP_OPEN(&vp, fmode, CRED());
    if (error)
	goto rele;

    NNPFSDEB(XDEBSYS, ("nnpfs_fhopen: falloc fmode = %d\n", fmode & FMASK));

    error = falloc(vp, fmode & FMASK, &fp, &fd);
    if (error)
	goto rele;

    mutex_exit(&fp->f_tlock);

    setf(fd, fp);

    NNPFSDEB(XDEBSYS, ("nnpfs_fhopen: returning fd = %d\n", fd));

    return fd;

 rele:
    VN_RELE(vp);
    return set_errno(error);
}

/*
 * file system
 */

static int
nnpfs_vfs_init (struct vfssw *vfssw, int offset)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vfs_init: offset = %d\n", offset));
    nnpfsfstype = offset;
    return 0;
}

#ifdef HAVE_STRUCT_VFSOPS_VFS_FREEVFS
static void
nnpfs_freevfs(struct vfs *vfsp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_freevfs\n"));
}
#endif

static struct vfsops nnpfs_vfsops = {
    nnpfs_mount,			/* mount */
    nnpfs_unmount,		/* unmount */
    nnpfs_root,			/* root */
    nnpfs_statvfs,		/* statvfs */
    nnpfs_sync,			/* sync */
    nnpfs_vget,			/* vget */
    nnpfs_mountroot,		/* mountroot */
    nnpfs_swapvp			/* swapvp */
#if HAVE_STRUCT_VFSOPS_VFS_FREEVFS
    ,
    nnpfs_freevfs			/* freevfs */
#endif
};

static struct vfssw nnpfs_vfssw = {
    "nnpfs",			/* name */
    nnpfs_vfs_init,		/* init */
    &nnpfs_vfsops,		/* vfsops */
    0				/* flags */
};

struct modlfs nnpfs_modlfs = {
    &mod_fsops,
    "nnpfs filesystem",
    &nnpfs_vfssw
};
