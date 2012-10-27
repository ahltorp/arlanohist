/*
 * Copyright (c) 1995, 1996, 1997, 1998 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vfsops.c,v 1.5 2002/09/07 10:44:37 lha Exp $");

/*
 * NNPFS vfs operations.
 */

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

static struct vnode *make_dead_vnode (struct vfs *vfsp);

struct nnpfs nnpfs[NNNPFS];

static int nnpfsfstype;

static int
nnpfs_mount(struct vfs *vfsp,
	  struct ucred *cred)
{
  char *devpath;
  struct vnode *devvp;
  dev_t dev;
  int error;
  struct vmount *vmnt;

  NNPFSDEB(XDEBVFOPS, ("nnpfs_mount vfsp = 0x%x\n"));

  vmnt = vfsp->vfs_mdata;

  devpath = (char *)vmnt + vmnt->vmt_data[VMT_OBJECT].vmt_off;

  error = lookupvp (devpath, L_NOFOLLOW, &devvp, U.U_cred);
  if (error)
      return error;

  if (devvp->v_type != VCHR) {
      VNOP_RELE(devvp);
      return ENXIO;
  }
  dev = devvp->v_rdev;
  VNOP_RELE(devvp);

  /* Check that this device really is an nnpfs_dev */

#if 0
  NNPFSDEB(XDEBVFOPS, ("nnpfs_mount dev = %x, minor = %x, major = %x,"
		     "ops = %x, "
		     "cb_ops = %x, "
		     "open = %x, "
		     "(nnpfs_devopen = %x)\n",
		     (unsigned)dev,
		     (unsigned)minor(dev),
		     (unsigned)major(dev),
		     devopsp[major(dev)],
		     devopsp[major(dev)] ? devopsp[major(dev)]->devo_cb_ops : 0,
		     (devopsp[major(dev)] && devopsp[major(dev)]->devo_cb_ops) ? devopsp[major(dev)]->devo_cb_ops->cb_open : 0,
		     nnpfs_devopen));
#endif

  if (minor(dev) < 0 || NNNPFS < minor(dev))
    return ENXIO;

#if 0 /* XXX - It doesn't seem we can perform this test */
  if (devsw[major(dev)].d_open != nnpfs_devopen)
      return ENXIO;
#endif

  if (nnpfs[minor(dev)].status & NNPFS_MOUNTED)
    return EBUSY;

  nnpfs[minor(dev)].status = NNPFS_MOUNTED;
  nnpfs[minor(dev)].vfsp = vfsp;
  nnpfs[minor(dev)].root = 0;
  nnpfs[minor(dev)].nnodes = 0;
  nnpfs[minor(dev)].nodes = 0;
  nnpfs[minor(dev)].fd = minor(dev);

  SET_VFS_TO_NNPFS(vfsp, &nnpfs[minor(dev)]);

  vfsp->vfs_bsize = PAGESIZE;

#if 0
  vfsp->vfs_fstype = nnpfsfstype;
  vfsp->vfs_dev    = minor(dev);
  vfsp->vfs_bsize  = PAGESIZE;
  vfsp->vfs_flag  |= VFS_NOTRUNC;
  vfsp->vfs_fsid.val[0] = minor(dev);
  vfsp->vfs_fsid.val[1] = major(dev); /* What is this good for */
#endif

  return 0;
}

static int
nnpfs_unmount(struct vfs *vfsp,
	    int flag,
	    struct ucred *cred)
{
  struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);

  NNPFSDEB(XDEBVFOPS, ("nnpfs_umount vfsp = 0x%x\n", (u_int) vfsp));

  free_all_nnpfs_nodes(nnpfsp);
  nnpfsp->status = 0;
  return 0;			/* Always allow umount to succed */
}

static int
nnpfs_root(struct vfs *vfsp,
	 struct vnode **vpp,
	 struct ucred *cred)
{
  struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);
  struct nnpfs_message_getroot msg;
  int error;
  
  NNPFSDEB(XDEBVFOPS, ("nnpfs_root vfsp = 0x%x\n", (u_int) vfsp));

  do {
    if (nnpfsp->root != 0) {
	*vpp = XNODE_TO_VNODE(nnpfsp->root);
	VNOP_HOLD(*vpp);
	NNPFSDEB(XDEBVFOPS, ("nnpfs_root: returning real vnode\n"));
	return 0;
    }

    msg.header.opcode = NNPFS_MSG_GETROOT;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = cred->cr_pag;
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
  VNOP_HOLD(*vpp);
  return 0;
}

static int
nnpfs_statfs(struct vfs *vfsp,
	   struct statfs *statfs,
	   struct ucred *cred)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_statvfs\n"));

    statfs->f_version   = 0;
    statfs->f_type      = 0;
    statfs->f_bsize     = 8192;
    statfs->f_blocks    = 4711 * 4711;
    statfs->f_bfree     = 4711 * 4711;
    statfs->f_bavail    = 4711 * 4711;
    statfs->f_files     = 4711;
    statfs->f_ffree     = 4711;
    
    statfs->f_vfstype   = vfsp->vfs_type;
    statfs->f_fsid      = vfsp->vfs_fsid;
    statfs->f_fsize     = 8192;
    statfs->f_vfsnumber = 17;	/* XXX */
    strcpy(statfs->f_fname, "arla");
    strcpy(statfs->f_fpack, "arla");

    return 0;
}

static int
nnpfs_sync(struct gfs *gfsp)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_sync\n"));
  return 0;
}

static int
nnpfs_vget(struct vfs *vfsp,
	 struct vnode **vpp,
	 struct fileid *fidp,
	 struct ucred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
  return ENOSYS;
}

static int
nnpfs_cntl (struct vfs *vfsp,
	  int cmd,
	  caddr_t arg,
	  unsigned long argsize,
	  struct ucred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_cntl\n"));
  return ENOSYS;
}

static int
nnpfs_quotactl (struct vfs *vfsp,
	      int foo,
	      uid_t bar,
	      caddr_t baz,
	      struct ucred *cred)
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_quotactl\n"));
  return ENOSYS;
}

/*
 * To be able to unmount when the NNPFS daemon is not
 * responding we need a root vnode, use a dead vnode!
 */

struct dead_node {
    struct vnode vn;
    struct gnode gn;
};

static int
dead_hold (struct vnode *vp)
{
    NNPFSDEB(XDEBVFOPS, ("dead_hold\n"));
    ++vp->v_count;
    return 0;
}

static int
dead_rele (struct vnode *vp)
{
    NNPFSDEB(XDEBVFOPS, ("dead_rele\n"));
    if (--vp->v_count == 0)
	nnpfs_free(vp, sizeof(*vp));
    return 0;
}

extern int nodev();

struct vnodeops dead_vnodeops = {
    nodev /* link */,
    nodev /* mkdir */,
    nodev /* mknod */,
    nodev /* remove */,
    nodev /* rename */,
    nodev /* rmdir */,
    nodev /* lookup */,
    nodev /* fid */,
    nodev /* open */,
    nodev /* create */,
    dead_hold /* hold */,
    dead_rele /* rele */,
    nodev /* close */,
    nodev /* map */,
    nodev /* unmap */,
    nodev /* access */,
    nodev /* getattr */,
    nodev /* setattr */,
    nodev /* fclear */,
    nodev /* fsync */,
    nodev /* ftrunc */,
    nodev /* rdwr */,
    nodev /* lockctl */,
    nodev /* ioctl */,
    nodev /* readlink */,
    (int (*)(struct vnode *,int,u_short,u_short*,void(*)(),char*,struct ucred* ))nodev /* select */,
    nodev /* symlink */,
    nodev /* readdir */,
    nodev /* strategy */,
    nodev /* revoke */,
    nodev /* getacl */,
    nodev /* setacl */,
    nodev /* getpcl */,
    nodev /* setpcl */,
    nodev /* seek */
};

static struct vnode *
make_dead_vnode(struct vfs *vfsp)
{
  struct dead_node *dead;

  NNPFSDEB(XDEBNODE, ("make_dead_vnode vfsp = 0x%x\n", (u_int) vfsp));

  dead = nnpfs_alloc(sizeof(*dead));
  bzero((caddr_t)dead, sizeof(*dead));

  dead->vn.v_flag    = V_ROOT;
  dead->vn.v_count   = 1;
  dead->vn.v_vfsgen  = 0;
  dead->vn.v_vfsp    = vfsp;
  dead->vn.v_mvfsp   = NULL;
  dead->vn.v_gnode   = &dead->gn;
  dead->vn.v_next    = NULL;
  dead->vn.v_socket  = NULL;
  dead->vn.v_audit   = NULL;

  dead->gn.gn_type   = VDIR;
  dead->gn.gn_flags  = 0;
  dead->gn.gn_seg    = 0;
  dead->gn.gn_mwrcnt = 0;
  dead->gn.gn_mrdcnt = 0;
  dead->gn.gn_rdcnt  = 0;
  dead->gn.gn_wrcnt  = 0;
  dead->gn.gn_excnt  = 0;
  dead->gn.gn_rshcnt = 0;
  dead->gn.gn_ops    = &dead_vnodeops;
  dead->gn.gn_vnode  = &dead->vn;
  dead->gn.gn_rdev   = 0;
  dead->gn.gn_chan   = 0;

  return &dead->vn;
}

static int
nnpfs_init (struct gfs *gfs)
{
  NNPFSDEB(XDEBNODE, ("nnpfs_init\n"));
  return 0;
}

static int
nnpfs_rinit (void)
{
  NNPFSDEB(XDEBNODE, ("nnpfs_rinit\n"));
  return 0;
}

static struct vfsops nnpfs_vfsops = {
    nnpfs_mount,			/* mount */
    nnpfs_unmount,		/* unmount */
    nnpfs_root,			/* root */
    nnpfs_statfs,			/* statfs */
    nnpfs_sync,			/* sync */
    nnpfs_vget,			/* vget */
    nnpfs_cntl,			/* cntl */
    nnpfs_quotactl		/* quoatctl */
};

static struct gfs nnpfs_gfs = {
    &nnpfs_vfsops,		/* gfs_ops */
    &nnpfs_vnodeops,		/* gn_ops */
    MNT_USRVFS,			/* gfs_type */
    "nnpfs",			/* gfs_name */
    nnpfs_init,			/* gfs_init */
    GFS_VERSION4,		/* flags */
    NULL,			/* gfs_data */
    nnpfs_rinit,			/* gfs_rinit */
    0,				/* gfs_hold */
};

int
nnpfs_install_filesys (void)
{
    return gfsadd (MNT_USRVFS, &nnpfs_gfs);
}

int
nnpfs_uninstall_filesys (void)
{
    return gfsdel (MNT_USRVFS);
}
