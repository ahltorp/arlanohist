/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vfsops.c,v 1.10 2002/09/07 11:09:08 lha Exp $");

/*
 * NNPFS vfs operations.
 */

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

extern int nchrdev;

static struct vnode *make_dead_vnode (struct vfs *vfsp);

struct nnpfs nnpfs[NNNPFS];

static int nnpfsfstype;

static int
nnpfs_root_common(struct nnpfs *nnpfsp, struct vnode **vpp)     
{
  struct nnpfs_message_getroot msg;
  int error;
  
  NNPFSDEB(XDEBVFOPS, ("nnpfs_root nnpfsp = 0x%x\n", (u_int) nnpfsp));

  do {
    if (nnpfsp->root != 0) {
	*vpp = XNODE_TO_VNODE(nnpfsp->root);
	VN_HOLD(*vpp);
	NNPFSDEB(XDEBVFOPS, ("nnpfs_root: returning real vnode\n"));
	return 0;
    }

    msg.header.opcode = NNPFS_MSG_GETROOT;
    msg.cred.uid = curprocp->p_cred->cr_uid;
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
  *vpp = make_dead_vnode(NNPFS_TO_VFS(nnpfsp));
  return 0;
}

static int
nnpfs_unmount_common(struct nnpfs *nnpfsp, int flags, struct cred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_umount nnpfsp = 0x%x\n", (u_int) nnpfsp));

  free_all_nnpfs_nodes(nnpfsp);
  nnpfsp->status = 0;
  return 0;			/* Always allow umount to succed */
}


static int
nnpfs_statvfs_common(struct nnpfs *nnpfsp,
		   struct statvfs *sbp,
		   struct vnode *vp)	/* XXX ? */
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
nnpfs_sync_common(struct nnpfs *nnpfsp, short flag, struct cred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_sync\n"));
  return 0;
}

static int
nnpfs_vget_common(struct nnpfs *nnpfsp,
		struct vnode **vpp,
		struct fid *fidp)     
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
  return ENOSYS;
}

static int
nnpfs_mountroot_common(struct nnpfs *nnpfsp,
		     enum whymountroot reason)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_mountroot\n"));
  return ENOSYS;
}

static int
nnpfs_swapvp_common(struct nnpfs *nnpfsp,
		  struct vnode **vpp,
		  char *path)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_swapvp\n"));
  return ENOSYS;
}

#if IRIX_64

static int nnpfs_mount(struct vfs *vfsp, struct vnode *mvp,
		     struct mounta *uap, struct cred *cred);

static int nnpfs_rootinit(struct vfs *vfsp);

static int nnpfs_mntupdate(bhv_desc_t *bh, struct vnode *vp,
			 struct mounta *uap, struct cred *cred);

static int nnpfs_dounmount(bhv_desc_t *bh, int flags, struct cred *cred);

static int nnpfs_unmount(bhv_desc_t *bh, int flags, struct cred *cred);

static int nnpfs_root(bhv_desc_t *bh, struct vnode **vpp);

static int nnpfs_statvfs(bhv_desc_t *bh,
		       struct statvfs *sbp,
		       struct vnode *vp);

static int nnpfs_sync(bhv_desc_t *bh, short flag, struct cred *cred);

static int nnpfs_vget(bhv_desc_t *bh,
		    struct vnode **vpp,
		    struct fid *fidp);

static int nnpfs_mountroot(bhv_desc_t *bh, enum whymountroot reason);

static int nnpfs_swapvp(bhv_desc_t *bh,
		      struct vnode **vpp,
		      char *path);

static struct vfsops nnpfs_vfsops = {
    VFS_POSITION_BASE,
    nnpfs_mount,			/* mount */
    nnpfs_rootinit,		/* rootinit */
    nnpfs_mntupdate,		/* mntupdate */
    nnpfs_dounmount,		/* dounmount */
    nnpfs_unmount,		/* unmount */
    nnpfs_root,			/* root */
    nnpfs_statvfs,		/* statvfs */
    nnpfs_sync,			/* sync */
    nnpfs_vget,			/* vget */
    nnpfs_mountroot,		/* mountroot */
    nnpfs_swapvp			/* swapvp */
};

#else /* !IRIX_64 */

static int nnpfs_mount(struct vfs *vfsp, struct vnode *mvp,
		     struct mounta *uap, struct cred *cred);

static int nnpfs_unmount(struct vfs *vfsp, int flags, struct cred *cred);

static int nnpfs_root(struct vfs *vfsp, struct vnode **vpp);

static int nnpfs_statvfs(struct vfs *vfsp,
		       struct statvfs *sbp,
		       struct vnode *vp);

static int nnpfs_sync(struct vfs *vfsp, short flag, struct cred *cred);

static int nnpfs_vget(struct vfs *vfsp,
		    struct vnode **vpp,
		    struct fid *fidp);

static int nnpfs_mountroot(struct vfs *vfsp,
			 enum whymountroot reason);

static int nnpfs_swapvp(struct vfs *vfsp,
		      struct vnode **vpp,
		      char *path);

static struct vfsops nnpfs_vfsops = {
    nnpfs_mount,			/* mount */
    nnpfs_unmount,		/* unmount */
    nnpfs_root,			/* root */
    nnpfs_statvfs,		/* statvfs */
    nnpfs_sync,			/* sync */
    nnpfs_vget,			/* vget */
    nnpfs_mountroot,		/* mountroot */
    nnpfs_swapvp			/* swapvp */
};

#endif /* IRIX_64 */

static int
nnpfs_mount(struct vfs *vfsp,
	  struct vnode *mvp,
	  struct mounta *uap,
	  struct cred *cred)
{
  struct vnode *devvp;
  dev_t dev;
  int error;

  NNPFSDEB(XDEBVFOPS, ("nnpfs_mount vfsp = 0x%x path = %s args = '%s'\n",
		   (u_int) vfsp, uap->dir, uap->spec));

  /*
   * This is something that should be done before calling this
   * function, but it's not, so we do it here.
   */

  if (mvp->v_type != VDIR)
      return ENOTDIR;

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
#if 1
  if (getemajor(dev) < 0 || cdevmax < getemajor(dev))
    return ENXIO;
#endif

  NNPFSDEB(XDEBVFOPS, ("nnpfs_mount dev = %x, minor = %x, major = %x\n",
		     (unsigned)dev,
		     (unsigned)getminor(dev),
		     (unsigned)getemajor(dev)));

  if (getminor(dev) < 0 || NNNPFS < getminor(dev)) {
    NNPFSDEB(XDEBVFOPS, ("nnpfs_mount: bad minor(%u)\n", getminor(dev)));
    return ENXIO;
  }
#if 0				/* XXX */
  if (cdevsw[getemajor(dev)].d_open != nnpfs_devopen) {
      NNPFSDEB(XDEBVFOPS, ("nnpfs_mount: not nnpfs_devopen (%x, %x)\n",
	     cdevsw[getemajor(dev)].d_open, nnpfs_devopen));
      return ENXIO;
  }
#endif

  if (nnpfs[getminor(dev)].status & NNPFS_MOUNTED)
    return EBUSY;

  nnpfs[getminor(dev)].status = NNPFS_MOUNTED;
  nnpfs[getminor(dev)].vfsp = vfsp;
  nnpfs[getminor(dev)].root = 0;
  nnpfs[getminor(dev)].nnodes = 0;
  nnpfs[getminor(dev)].nodes = 0;
  nnpfs[getminor(dev)].fd = getminor(dev);

#if IRIX_64

  bhv_desc_init (&nnpfs[getminor(dev)].bh, &nnpfs[getminor(dev)],
		 vfsp, &nnpfs_vfsops);
  bhv_insert_initial (&vfsp->vfs_bh, &nnpfs[getminor(dev)].bh);

#else

  VFS_TO_NNPFS(vfsp) = &nnpfs[getminor(dev)];

#endif

  vfsp->vfs_fstype = nnpfsfstype;
  vfsp->vfs_dev    = getminor(dev);
  vfsp->vfs_bsize  = 8192;
  vfsp->vfs_flag  |= VFS_NOTRUNC;
  vfsp->vfs_fsid.val[0] = getminor(dev);
  vfsp->vfs_fsid.val[1] = getemajor(dev); /* What is this good for */

  return 0;
}

#if IRIX_64

static int
nnpfs_rootinit(struct vfs *vfsp)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_rootinit vfsp = 0x%x\n", (u_int) vfsp));
  return ENOSYS;
}

static int
nnpfs_mntupdate(bhv_desc_t *bh, struct vnode *vp,
	      struct mounta *uap, struct cred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_mntupdate bh = 0x%x\n", (u_int) bh));
  return ENOSYS;
}

static int
nnpfs_dounmount(bhv_desc_t *bh, int flags, struct cred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_dounmount bh = 0x%x\n", (u_int) bh));
  return ENOSYS;
}

static int
nnpfs_unmount(bhv_desc_t *bh, int flags, struct cred *cred)
{
  return nnpfs_unmount_common (BHV_TO_NNPFS(bh), flags, cred);
}

static int
nnpfs_root(bhv_desc_t *bh, struct vnode **vpp)
{
    return nnpfs_root_common (BHV_TO_NNPFS(bh), vpp);
}

static int
nnpfs_statvfs(bhv_desc_t *bh,
	    struct statvfs *sbp,
	    struct vnode *vp)
{
    return nnpfs_statvfs_common (BHV_TO_NNPFS(bh), sbp, vp);
}

static int
nnpfs_sync(bhv_desc_t *bh, short flag, struct cred *cred)
{
    return nnpfs_sync_common (BHV_TO_NNPFS(bh), flag, cred);
}

static int
nnpfs_vget(bhv_desc_t *bh,
	 struct vnode **vpp,
	 struct fid *fidp)
{
    return nnpfs_vget_common (BHV_TO_NNPFS(bh), vpp, fidp);
}

static int
nnpfs_mountroot(bhv_desc_t *bh, enum whymountroot reason)
{
    return nnpfs_mountroot_common (BHV_TO_NNPFS(bh), reason);
}

static int
nnpfs_swapvp(bhv_desc_t *bh,
	   struct vnode **vpp,
	   char *path)
{
    return nnpfs_swapvp_common (BHV_TO_NNPFS(bh), vpp, path);
}

/*
 * To be able to unmount when the NNPFS daemon is not
 * responding we need a root vnode, use a dead vnode!
 */

static struct vnode *
make_dead_vnode(struct vfs *vfsp)
{
  struct vnode *dead;

  NNPFSDEB(XDEBNODE, ("make_dead_vnode vfsp = 0x%x\n", (u_int) vfsp));

  dead = vn_alloc (vfsp, VDIR, 0);
  dead->v_flag = VROOT;

  return dead;
}

#else /* !IRIX_64 */

static int
nnpfs_unmount(struct vfs *vfsp, int flags, struct cred *cred)
{
    return nnpfs_unmount_common (VFS_TO_NNPFS(vfsp), flags, cred);
}

static int
nnpfs_root(struct vfs *vfsp, struct vnode **vpp)
{
    return nnpfs_root_common (VFS_TO_NNPFS(vfsp), vpp);
}

static int
nnpfs_statvfs(struct vfs *vfsp,
	    struct statvfs *sbp,
	    struct vnode *vp)
{
    return nnpfs_statvfs_common (VFS_TO_NNPFS(vfsp), sbp, vp);
}

static int
nnpfs_sync(struct vfs *vfsp, short flag, struct cred *cred)
{
    return nnpfs_sync_common (VFS_TO_NNPFS(vfsp), flag, cred);
}

static int
nnpfs_vget(struct vfs *vfsp,
	 struct vnode **vpp,
	 struct fid *fidp)
{
    return nnpfs_vget_common (VFS_TO_NNPFS(vfsp), vpp, fidp);
}

static int
nnpfs_mountroot(struct vfs *vfsp, enum whymountroot reason)
{
    return nnpfs_mountroot_common (VFS_TO_NNPFS(vfsp), reason);
}

static int
nnpfs_swapvp(struct vfs *vfsp,
	   struct vnode **vpp,
	   char *path)
{
    return nnpfs_swapvp_common (VFS_TO_NNPFS(vfsp), vpp, path);
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
    (int (*)(vnode_t **, mode_t, struct cred *))nodev,
    (int (*)(vnode_t *, int, lastclose_t, off_t, struct cred *))nodev,
    (int (*)(vnode_t *, struct uio *, int, struct cred *))nodev,
    (int (*)(vnode_t *, struct uio *, int, struct cred *))nodev,
    (int (*)(vnode_t *, int, void *, int, struct cred *, int *))nodev,
    (int (*)(vnode_t *, int, int, struct cred *))nodev,
    (int (*)(vnode_t *, struct vattr *, int, struct cred *))nodev,
    (int (*)(vnode_t *, struct vattr *, int, struct cred *))nodev,
    (int (*)(vnode_t *, int, int, struct cred *))nodev,
    (int (*)(vnode_t *, char *, vnode_t **,
	     struct pathname *, int, vnode_t *, struct cred *))nodev,
    (int (*)(vnode_t *, char *, struct vattr *,
	     enum vcexcl, int, vnode_t **, struct cred *))nodev,
    (int (*)(vnode_t *, char *, struct cred *))nodev,
    (int (*)(vnode_t *, vnode_t *, char *, struct cred *))nodev,
    (int (*)(vnode_t *, char *, vnode_t *, char *,
	     struct pathname *npnp, struct cred *))nodev,
    (int (*)(vnode_t *, char *, struct vattr *,
	     vnode_t **, struct cred *))nodev,
    (int (*)(vnode_t *, char *, vnode_t *, struct cred *))nodev,
    (int (*)(vnode_t *, struct uio *, struct cred *, int *))nodev,
    (int (*)(vnode_t *, char *, struct vattr *, char *,
	     struct cred *))nodev,
    (int (*)(vnode_t *, struct uio *, struct cred *))nodev,
    (int (*)(vnode_t *, int, struct cred *))nodev,
    dead_vnode_inactive,
    (int (*)(struct vnode *, struct fid **))nodev,
    (int (*)(struct vnode *, struct fid *))nodev,
    (void (*)(vnode_t *, vrwlock_t))nodev,
    (void (*)(vnode_t *, vrwlock_t))nodev,
    (int (*)(vnode_t *, off_t, off_t*))nodev,
    (int (*)(vnode_t *, vnode_t *))nodev,
    (int (*)(vnode_t *, int, struct flock *, int, off_t,
	     struct cred *))nodev,
    (int (*)(vnode_t *, vnode_t **))nodev,
    (int (*)(vnode_t *, off_t, ssize_t,
	     int, struct cred *,
	     struct bmapval *, int *))nodev, /* getpage in svr4 */
    (void (*)(vnode_t *, struct buf *))nodev, /* putpage in svr4 */
    (int (*)(vnode_t *, off_t, struct pregion *, char **,
	     size_t, u_int, u_int, u_int, struct cred *))nodev,
    (int (*)(vnode_t *, off_t, struct pregion *, addr_t,
	     size_t, u_int, u_int, u_int, struct cred *))nodev,
    (int (*)(vnode_t *, off_t, struct pregion *, addr_t,
	     size_t, u_int, u_int, u_int, struct cred *))nodev,
    (int (*)(vnode_t *, short, int, short *, struct pollhead **))nodev,
    (int (*)(vnode_t *, caddr_t, daddr_t, u_int))nodev,
    (int (*)(struct vnode *, int, u_long *, struct cred *))nodev,
    (int (*)(struct vnode *, off_t, size_t, struct cred *))nodev,

    (int (*)(vnode_t *, int, void *, int, off_t,
	     struct cred *, union rval *))nodev,
    (int (*)(vnode_t *, int))nodev,
    (int (*)(vnode_t *, char *, char *, int *, int,
	     struct cred *))nodev,
    (int (*)(vnode_t *, char *, char *, int, int,
	     struct cred *))nodev,
    (int (*)(vnode_t *, char *, int, struct cred *))nodev,
    (int (*)(vnode_t *, char *, int, int,
	     struct attrlist_cursor_kern *,
	     struct cred *))nodev,
};

static struct vnode *
make_dead_vnode(struct vfs *vfsp)
{
  struct vnode *dead;

  NNPFSDEB(XDEBNODE, ("make_dead_vnode vfsp = 0x%x\n", (u_int) vfsp));

  dead = vn_alloc (&dead_vnodeops, vfsp, VDIR, 0, NULL);
  dead->v_flag = VROOT;

  return dead;
}

#endif /* IRIX_64 */

static int
nnpfs_uprintf_filsys(void)
{
#if 0
  {
    struct vfssw *fs;
    printf("Currently loaded filesystems are:\n");
    for (fs = vfssw; fs < vfsNVFS; fs++)
      printf("vfssw[%d] == { \"%s\", 0x%x}\n",
	      fs - vfssw, fs->vsw_name, fs->vsw_ops);
  }
#endif
#if 1
  {
    int i;
    struct nnpfs_node *t;
    for (i = 0; i < NNNPFS; i++)
      if (nnpfs[i].nodes)
	{
	  printf("Current nnpfs_nodes on nnpfs[%d] are:\n", i);
	  for (t = nnpfs[i].nodes; t; t = t->next)
	    printf("%d.%d.%d.%d(%d) ",
		    t->handle.a,
		    t->handle.b,
		    t->handle.c,
		    t->handle.d,
		    XNODE_TO_VNODE(t)->v_count);
	  printf(" !\n");
	}
  }
#endif
  return 0;
}

/*
 * file system
 */

static int
nnpfs_vfs_init (struct vfssw *vfssw, int offset)
{
    printf ("nnpfs_vfs_init: offset = %d\n", offset);
    nnpfsfstype = offset;
    return 0;
}

static struct vfssw nnpfs_vfssw = {
    "nnpfs",			/* name */
    nnpfs_vfs_init,		/* init */
    &nnpfs_vfsops,		/* vfsops */
    &nnpfs_vnodeops,		/* vnodeops */
    NULL,			/* fill */
    VFS_NOTRUNC			/* flags */
};

static int nnpfs_vfsindex;

static struct vfssw old_vfssw;

int
nnpfs_install_filesys (void)
{
    int i;

    printf ("nnpfs_install_filesys\n");

    for (i = 0; i < nfstype; ++i)
	if (vfssw[i].vsw_name
	    && strcmp(vfssw[i].vsw_name, nnpfs_vfssw.vsw_name) == 0)
	    return EEXIST;

    for (i = nfstype - 1; i >= 0; --i)
	if (strcmp(vfssw[i].vsw_name, "") == 0)
	    break;
    if (i < 0) {
	printf ("failed to find free VFS slot\n");
	return EINVAL;
    }
    printf ("Using VFS slot %d\n", i);
    
    nnpfs_vfsindex = i;

    old_vfssw = vfssw[i];
    vfssw[i] = nnpfs_vfssw;
    (*(vfssw[nnpfs_vfsindex].vsw_init)) (&vfssw[i], i);
    return 0;
}

int
nnpfs_uninstall_filesys (void)
{
    int i;

    printf ("nnpfs_uninstall_filesys\n");

    /* Check for open, mounted and active vnodes */
    for (i = 0; i < NNNPFS; i++)
	if (nnpfs[i].nnodes)
	    printf("Warning (error really): There are active vnodes!\n");

    vfssw[nnpfs_vfsindex] = old_vfssw;
    return 0;
}
