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

/*
 * NNPFS vfs operations.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/errno.h>

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

#include <sys/conf.h>
extern int nchrdev;
extern struct cdevsw cdevsw[];

static char nnpfs_fsname[] = "nnpfs";
static struct vnode * make_dead_vnode _PARAMS((struct vfs *vfsp));

struct nnpfs nnpfs[NNNPFS];

#if defined(__STDC__)
static int nnpfs_mount(struct vfs *vfsp,
		     char *path,
		     caddr_t args)     
#else
static
int
nnpfs_mount(vfsp, path, args)
     struct vfs *vfsp;
     char *path;
     caddr_t args;
#endif
{
  struct vnode *devvp;
  dev_t dev;
  int error;

  NNPFSDEB(XDEBVFOPS, ("nnpfs_mount vfsp = 0x%x path = %s args = '%s'\n",
		   (u_int) vfsp, path, args));

  error = lookupname(args, UIO_USERSPACE, FOLLOW_LINK, 0, &devvp);
  if (error != 0)
    return error;

  if (devvp->v_type != VCHR)
    {
      VN_RELE(devvp);
      return ENXIO;
    }
  dev = devvp->v_rdev;
  VN_RELE(devvp);

  /* Check that this device really is an nnpfs_dev */
  if (major(dev) < 0 || nchrdev < major(dev))
    return ENXIO;
  if (minor(dev) < 0 || NNNPFS < minor(dev))
    return ENXIO;
  if (cdevsw[major(dev)].d_open != (int (*)()) nnpfs_devopen)
    return ENXIO;

  if (nnpfs[minor(dev)].status & NNPFS_MOUNTED)
    return EBUSY;

  nnpfs[minor(dev)].status = NNPFS_MOUNTED;
  nnpfs[minor(dev)].vfsp = vfsp;
  nnpfs[minor(dev)].root = 0;
  nnpfs[minor(dev)].nnodes = 0;
  nnpfs[minor(dev)].nodes = 0;
  nnpfs[minor(dev)].fd = minor(dev);

  VFS_TO_NNPFS(vfsp) = &nnpfs[minor(dev)];
  vfsp->vfs_fsid.val[0] = minor(dev);
  vfsp->vfs_fsid.val[1] = major(dev); /* What is this good for */

  return 0;
}

#if defined(__STDC__)
static int nnpfs_unmount(struct vfs *vfsp)     
#else
static
int
nnpfs_unmount(vfsp)
     struct vfs *vfsp;
#endif
{
  struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);

  NNPFSDEB(XDEBVFOPS, ("nnpfs_umount vfsp = 0x%x\n", (u_int) vfsp));

  free_all_nnpfs_nodes(nnpfsp);
  nnpfsp->status = 0;
  return 0;			/* Always allow umount to succed */
}

#if defined(__STDC__)
static int nnpfs_root(struct vfs *vfsp,
		    struct vnode **vpp)     
#else
static
int
nnpfs_root(vfsp, vpp)
     struct vfs *vfsp;
     struct vnode **vpp;
#endif
{
  struct nnpfs *nnpfsp = VFS_TO_NNPFS(vfsp);
  struct nnpfs_message_getroot msg;
  int error;
  
  NNPFSDEB(XDEBVFOPS, ("nnpfs_root vfsp = 0x%x\n", (u_int) vfsp));

  do {
    if (nnpfsp->root != 0)
      {
	*vpp = XNODE_TO_VNODE(nnpfsp->root);
	VN_HOLD(*vpp);
	return 0;
      }

    msg.header.opcode = NNPFS_MSG_GETROOT;
    msg.cred.uid = u.u_cred->cr_uid;
    msg.cred.pag = 0;		/* XXX */
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  } while (error == 0);

  /*
   * Failed to get message through, need to pretend that all went well
   * and return a fake dead vnode to be able to unmount.
   */
  *vpp = make_dead_vnode(vfsp);
  VN_HOLD(*vpp);
  return 0;
}

#if defined(__STDC__)
static int nnpfs_statfs(struct vfs *vfsp,
		      struct statfs *sbp)     
#else
static
int
nnpfs_statfs(vfsp, sbp)
     struct vfs *vfsp;
     struct statfs *sbp;
#endif
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_statfs\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_sync(struct vfs *vfsp)     
#else
static
int
nnpfs_sync(vfsp)
     struct vfs *vfsp;
#endif
{
  return 0;
}

#if defined(__STDC__)
static int nnpfs_vget(struct vfs *vfsp,
		    struct vnode **vpp,
		    struct fid *fidp)     
#else
static
int
nnpfs_vget(vfsp, vpp, fidp)
     struct vfs *vfsp;
     struct vnode **vpp;
     struct fid *fidp;
#endif
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_mountroot(struct vfs *vfsp,
			 struct vnode **vpp,
			 char *name)     
#else
static
int
nnpfs_mountroot(vfsp, vpp, name)
     struct vfs *vfsp;
     struct vnode **vpp;
     char *name;
#endif
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_mountroot\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_swapvp(struct vfs *vfsp,
		      struct vnode **vpp,
		      char *path)     
#else
static
int
nnpfs_swapvp(vfsp, vpp, path)
     struct vfs *vfsp;
     struct vnode **vpp;
     char *path;
#endif
{
  NNPFSDEB(XDEBVFOPS, ("nnpfs_swapvp\n"));
  return EINVAL;
}

struct vfsops nnpfs_vfsops = {
        nnpfs_mount,
        nnpfs_unmount,
        nnpfs_root,
        nnpfs_statfs,
        nnpfs_sync,
        nnpfs_vget,
        nnpfs_mountroot,
        nnpfs_swapvp
};

/*
 * To be able to unmount when the NNPFS daemon is not
 * responding we need a root vnode, use a dead vnode!
 */
#if defined(__STDC__)
static int enodev(void)
#else
static int 
enodev()
#endif
{
  return ENODEV;
}

#if defined(__STDC__)
static int dead_vnode_inactive(struct vnode *vp, struct ucred *cred)
#else
static int
dead_vnode_inactive(vp, cred)
     register struct vnode *vp;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVFOPS, ("dead_vnode_inactive\n"));
  nnpfs_free(vp, sizeof(*vp));
  return 0;
}

struct vnodeops dead_vnodeops = {
        enodev,			/* nnpfs_open */
        enodev,			/* nnpfs_close */
        enodev,			/* nnpfs_rdwr */
        enodev,			/* nnpfs_ioctl */
        enodev,			/* nnpfs_select */
        enodev,			/* nnpfs_getattr */
        enodev,			/* nnpfs_setattr */
        enodev,			/* nnpfs_access */
        enodev,			/* nnpfs_lookup */
        enodev,			/* nnpfs_create */
        enodev,			/* nnpfs_remove */
        enodev,			/* nnpfs_link */
        enodev,			/* nnpfs_rename */
        enodev,			/* nnpfs_mkdir */
        enodev,			/* nnpfs_rmdir */
        enodev,			/* nnpfs_readdir */
        enodev,			/* nnpfs_symlink */
        enodev,			/* nnpfs_readlink */
        enodev,			/* nnpfs_fsync */
        dead_vnode_inactive,	/* nnpfs_inactive */
        enodev,			/* nnpfs_lockctl */
        enodev,			/* nnpfs_fid */
        enodev,			/* nnpfs_getpage */
        enodev,			/* nnpfs_putpage */
        enodev,			/* nnpfs_map */
        enodev,			/* nnpfs_dump */
        enodev,			/* nnpfs_cmp */
        enodev,			/* nnpfs_realvp */
        enodev,			/* nnpfs_cntl */
};

#if defined(__STDC__)
static struct vnode * make_dead_vnode(struct vfs *vfsp)
#else
static struct vnode *
make_dead_vnode(vfsp)
     struct vfs *vfsp;
#endif
{
  struct vnode *dead;

  NNPFSDEB(XDEBNODE, ("make_dead_vnode vfsp = 0x%x\n", (u_int) vfsp));

  dead = nnpfs_alloc(sizeof(*dead));
  bzero(dead, sizeof(*dead));
  VN_INIT(dead, vfsp, VDIR, 0);
  dead->v_flag = VROOT;
  dead->v_op = &dead_vnodeops;
  dead->v_count = 0;
  return dead;
}

/*
 *
 */
#if defined(__STDC__)
static int nnpfs_uprintf_filsys(void)
#else
static
int
nnpfs_uprintf_filsys()
#endif
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
      if (nnpfs[i].nodes)
	{
	  uprintf("Current nnpfs_nodes on nnpfs[%d] are:\n", i);
	  for (t = nnpfs[i].nodes; t; t = t->next)
	    uprintf("%d.%d.%d.%d(%d) ",
		    t->handle.a,
		    t->handle.b,
		    t->handle.c,
		    t->handle.d,
		    t->vn.v_count);
	  uprintf(" !\n");
	}
  }
#endif
  return 0;
}

/*
 * Install and uninstall filesystem.
 */
extern struct vfssw vfssw[];
extern struct vfssw *vfsNVFS;

#if defined(__STDC__)
int nnpfs_install_filesys(void)
#else
int
nnpfs_install_filesys()
#endif
{
  struct vfssw *fs;
  
  for (fs = vfssw; fs < vfsNVFS; fs++)
    if (fs->vsw_name == 0 && fs->vsw_ops == 0) /* free slot? */
      {
	fs->vsw_name = nnpfs_fsname;
	fs->vsw_ops = &nnpfs_vfsops;
	break;			/* found a free slot */
      }
  if (fs == vfsNVFS)
    {
      uprintf("Failed to find free VFS slot for %s!\n", nnpfs_fsname);
      nnpfs_uprintf_filsys();
      return EINVAL;
    }
  return 0;
}

#if defined(__STDC__)
int nnpfs_uninstall_filesys(void)
#else
int
nnpfs_uninstall_filesys()
#endif
{
  struct vfssw *fs;
  int i;

  /* Check for open, mounted and active vnodes */
  for (i = 0; i < NNNPFS; i++)
    if (nnpfs[i].nodes)
      printf("Warning (error really): There are active vnodes!\n");
  for (fs = vfssw; fs < vfsNVFS; fs++)
    if (fs->vsw_name == nnpfs_fsname && fs->vsw_ops == &nnpfs_vfsops)
      {
	fs->vsw_name = 0;
	fs->vsw_ops = 0;
      }
  return 0;
}

#if defined(__STDC__)
int nnpfs_vdstat_filesys(void)
#else
int
nnpfs_vdstat_filesys()
#endif
{
  return nnpfs_uprintf_filsys();
}
