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
 * NNPFS operations.
 */

#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/dnlc.h>
#include <sys/uio.h>
#include <sys/pathname.h>
#include <sys/fcntlcom.h>
#include <vm/seg.h>
#include <sys/mman.h>
#include <sys/errno.h>

#if defined(__STDC__)
static int nnpfs_open_valid(struct vnode *vp, struct ucred *cred, u_int tok)
#else
static
int
nnpfs_open_valid(vp, cred, tok)
     struct vnode *vp;
     struct ucred *cred;
     u_int tok;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_open msg;
	msg.header.opcode = NNPFS_MSG_OPEN;
	msg.cred.uid = u.u_cred->cr_uid;
	msg.cred.pag = 0;		/* XXX */
	msg.handle = xn->handle;
	msg.tokens = tok;
	error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) &msg)->error;
      }
    else
      {
	goto done;
      }
  } while (error == 0);

 done:
  return error;
}

#if defined(__STDC__)
static int nnpfs_attr_valid(struct vnode *vp, struct ucred *cred, u_int tok)
#else
static
int
nnpfs_attr_valid(vp, cred, tok)
     struct vnode *vp;
     struct ucred *cred;
     u_int tok;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_getattr msg;
	msg.header.opcode = NNPFS_MSG_GETATTR;
	msg.cred.uid = u.u_cred->cr_uid;
	msg.cred.pag = 0;		/* XXX */
	msg.handle = xn->handle;
	error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) &msg)->error;
      }
    else
      {
	goto done;
      }
  } while (error == 0);

 done:
  return error;
}

#if defined(__STDC__)
static int nnpfs_data_valid(struct vnode *vp, struct ucred *cred, u_int tok)
#else
static
int
nnpfs_data_valid(vp, cred, tok)
     struct vnode *vp;
     struct ucred *cred;
     u_int tok;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_getdata msg;
	msg.header.opcode = NNPFS_MSG_GETDATA;
	msg.cred.uid = u.u_cred->cr_uid;
	msg.cred.pag = 0;		/* XXX */
	msg.handle = xn->handle;
	msg.offset = xn->attr.va_size;
	error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) &msg)->error;
      }
    else
      {
	goto done;
      }
  } while (error == 0);

 done:
  return error;
}

#if defined(__STDC__)
static int nnpfs_open(struct vnode **vpp,
		    int flag,
		    struct ucred *cred)
#else
static
int
nnpfs_open(vpp, flag, cred)
     struct vnode **vpp;
     int flag;
     struct ucred *cred;
#endif
{
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_open\n"));
  
  if (flag & FWRITE)
    error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NW);
  else
    error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NR);
  
  return error;
}

#if defined(__STDC__)
static int nnpfs_fsync(struct vnode *vp,
		     struct ucred *cred)
#else
static
int
nnpfs_fsync(vp, cred)
     struct vnode *vp;
     struct ucred *cred;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync\n"));
  if (VNODE_TO_XNODE(vp)->flags & NNPFS_DATA_DIRTY)
    {
      struct nnpfs_message_putdata msg;
      msg.header.opcode = NNPFS_MSG_PUTDATA;
      msg.cred.uid = u.u_cred->cr_uid;
      msg.cred.pag = 0;		/* XXX */
      msg.handle = xn->handle;
      error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
      if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;
    }
  
  return error;
}

#if defined(__STDC__)
static int nnpfs_close(struct vnode *vp,
		     int flag,
		     int count,
		     struct ucred *cred)
#else
static
int
nnpfs_close(vp, flag, count, cred)
     struct vnode *vp;
     int flag;
     int count;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_close\n"));
  
  if (flag & FWRITE)
    error = nnpfs_fsync(vp, cred);
  
  return error;
}

#if defined(__STDC__)
static int nnpfs_rdwr(struct vnode *vp,
		    struct uio *uio,
		    enum uio_rw rw,
		    int ioflag,
		    struct ucred *cred)
#else
static
int
nnpfs_rdwr(vp, uio, rw, ioflag, cred)
     struct vnode *vp;
     struct uio *uio;
     enum uio_rw rw;
     int ioflag;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_rdwr\n"));

  /* XXX Also handle appending writes. */
  if (rw == UIO_WRITE)
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
  else
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);

  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      VN_HOLD(t);
      error = VOP_RDWR(t, uio, rw, ioflag, cred);
      if (rw == UIO_WRITE)
	VNODE_TO_XNODE(vp)->flags |= NNPFS_DATA_DIRTY;
      VN_RELE(t);
    }

  return error;
}

#if defined(__STDC__)
static int nnpfs_ioctl(struct vnode *vp,
		     int com,
		     caddr_t data,
		     int flag,
		     struct ucred *cred)
#else
static
int
nnpfs_ioctl(vp, com, data, flag, cred)
     struct vnode *vp;
     int com;
     caddr_t data;
     int flag;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_select(struct vnode *vp,
		      int which,
		      struct ucred *cred)
#else
static
int
nnpfs_select(vp, which, cred)
     struct vnode *vp;
     int which;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_select\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_getattr(struct vnode *vp,
		       struct vattr *vap,
		       struct ucred *cred)     
#else
static
int
nnpfs_getattr(vp, vap, cred)
     struct vnode *vp;
     struct vattr *vap;
     struct ucred *cred;
#endif
{
  int error = 0;
  
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr\n"));
  
  error = nnpfs_attr_valid(vp, cred, NNPFS_ATTR_R);
  if (error == 0)
    {
      *vap = xn->attr;
    }
  
  return error;
}

#if defined(__STDC__)
static int nnpfs_setattr(struct vnode *vp,
		       struct vattr *vap,
		       struct ucred *cred)
#else
static
int
nnpfs_setattr(vp, vap, cred)
     struct vnode *vp;
     struct vattr *vap;
     struct ucred *cred;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_setattr\n"));
  if (NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_W))
    {
      /* Update attributes and mark them dirty. */
      VNODE_TO_XNODE(vp)->flags |= NNPFS_ATTR_DIRTY;
      error = EINVAL;		/* XXX not yet implemented */
      goto done;
    }
  else
    {
      struct nnpfs_message_putattr msg;
      msg.header.opcode = NNPFS_MSG_PUTATTR;
      msg.cred.uid = u.u_cred->cr_uid;
      msg.cred.pag = 0;		/* XXX */
      msg.handle = xn->handle;
      vattr2nnpfs_attr (vap, &msg.attr);
      error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
      if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;
    }

 done:
  return error;
}

#if defined(__STDC__)
static int nnpfs_access(struct vnode *vp,
		      int mode,
		      struct ucred *cred)     
#else
static
int
nnpfs_access(vp, mode, cred)
     struct vnode *vp;
     int mode;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_access mode = 0%o\n", mode));

  error = nnpfs_attr_valid(vp, cred, NNPFS_ATTR_R);
  if (error == 0)
    {
      struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
      mode >>= 6;		/* The kernel uses rwx------ */
      if (!((xn->id[0] == NNPFS_ANONYMOUSID)
	    && ((mode & ~xn->rights[0]) == 0)))
	{
	  int i;
	  error = EACCES;	/* Until otherwise proven */
	  for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	    if ((xn->id[i] == cred->cr_uid)
		&& (mode & ~xn->rights[i]))
	      {
		error = 0;
		break;
	      }
	}   
    }

  NNPFSDEB(XDEBVNOPS, ("nnpfs_access(0%o) = %d\n", mode, error));
  return 0;			/* XXX For now! */
  return error;
}

#if defined(__STDC__)
static int nnpfs_lookup(struct vnode *dvp,
		      char *nm,
		      struct vnode **vpp,
		      struct ucred *cred,
		      struct pathname *pnp,
		      int flags)     
#else
static
int
nnpfs_lookup(dvp, nm, vpp, cred, pnp, flags)
     struct vnode *dvp;
     char *nm;
     struct vnode **vpp;
     struct ucred *cred;
     struct pathname *pnp;
     int flags;
#endif
{
  struct nnpfs_message_getnode msg;
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  int error = 0;

  struct nnpfs_node *d = VNODE_TO_XNODE(dvp);
  struct vnode *v;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup\n"));
  
  do {
#ifdef notdef_but_correct
    error = nnpfs_access(dvp, VEXEC, cred);
    if (error != 0)
      goto done;
#endif
    v = nnpfs_dnlc_lookup(dvp, nm);
    if (!v)
      {
	msg.header.opcode = NNPFS_MSG_GETNODE;
	msg.cred.uid = u.u_cred->cr_uid;
	msg.cred.pag = 0;		/* XXX */
	msg.parent_handle = d->handle;
	if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_LEN)
	    error = ENAMETOOLONG;
	else
	    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) &msg)->error;
      }
    else
      {
	*vpp = v;
	VN_HOLD(v);
	goto done;
      }
  } while (error == 0);

 done:
  NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup() = %d\n", error));
  return error;
}

#if defined(__STDC__)
static int nnpfs_create(struct vnode *dvp,
		      char *nm,
		      struct vattr *va,
		      enum vcexcl exclusive,
		      int mode,
		      struct vnode **vpp,
		      struct ucred *cred)     
#else
static
int
nnpfs_create(dvp, nm, va, exclusive, mode, vpp, cred)
     struct vnode *dvp;
     char *nm;
     struct vattr *va;
     enum vcexcl exclusive;
     int mode;
     struct vnode **vpp;
     struct ucred *cred;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_create\n"));
  {
    struct nnpfs_message_create msg;
    msg.header.opcode = NNPFS_MSG_CREATE;
    msg.parent_handle = xn->handle;
    strncpy(msg.name, nm, sizeof(msg.name));
    msg.name[sizeof(msg.name)-1] = '\0';
    vattr2nnpfs_attr (va, &msg.attr);
#if 0
    msg.exclusive = exclusive;
#endif
    msg.mode = mode;
    msg.cred.uid = u.u_cred->cr_uid;
    msg.cred.pag = 0;		/* XXX */
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }

  if (error == 0)
    error = nnpfs_lookup(dvp, nm, vpp, cred, /*pnp*/ NULL, /*flags*/ 0);
  return error;
}

#if defined(__STDC__)
static int nnpfs_remove(struct vnode *dvp, char *nm, struct ucred *cred)
#else
static
int
nnpfs_remove(dvp, nm, cred)
     struct vnode *dvp;
     char *nm;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_remove\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_link(struct vnode *vp,
		    struct vnode *tdvp,
		    char *tnm,
		    struct ucred *cred)     
#else
static
int
nnpfs_link(vp, tdvp, tnm, cred)
     struct vnode *vp;
     struct vnode *tdvp;
     char *tnm;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_link\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_rename(struct vnode *odvp,
		      char *onm,
		      struct vnode *ndvp,
		      char *nnm,
		      struct ucred *cred)     
#else
static
int
nnpfs_rename(odvp, onm, ndvp, nnm, cred)
     struct vnode *odvp;
     char *onm;
     struct vnode *ndvp;
     char *nnm;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_rename\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_mkdir(struct vnode *dvp,
		     char *nm,
		     struct vattr *va,
		     struct vnode **vpp,
		     struct ucred *cred)     
#else
static
int
nnpfs_mkdir(dvp, nm, va, vpp, cred)
     struct vnode *dvp;
     char *nm;
     struct vattr *va;
     struct vnode **vpp;
     struct ucred *cred;
#endif
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir\n"));
  {
    struct nnpfs_message_mkdir msg;
    msg.header.opcode = NNPFS_MSG_CREATE;
    msg.parent_handle = xn->handle;
    strncpy(msg.name, nm, sizeof(msg.name));
    msg.name[sizeof(msg.name)-1] = '\0';
    vattr2nnpfs_attr (va, &msg.attr);
    msg.cred.uid = u.u_cred->cr_uid;
    msg.cred.pag = 0;		/* XXX */
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }

  return error;
}

#if defined(__STDC__)
static int nnpfs_rmdir(struct vnode *dvp,
		     char *nm,
		     struct ucred *cred)     
#else
static
int
nnpfs_rmdir(dvp, nm, cred)
     struct vnode *dvp;
     char *nm;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_readdir(struct vnode *vp,
		       struct uio *uiop,
		       struct ucred *cred)
#else
static
int
nnpfs_readdir(vp, uiop, cred)
     struct vnode *vp;
     struct uio *uiop;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      VN_HOLD(t);
      error = VOP_RDWR(t, uiop, UIO_READ, 0, cred);
      VN_RELE(t);
    }

  return error;
}

#if defined(__STDC__)
static int nnpfs_symlink(struct vnode *dvp,
		       char *lnm,
		       struct vattr *tva,
		       char *tnm,
		       struct ucred *cred)
#else
static
int
nnpfs_symlink(dvp, lnm, tva, tnm, cred)
     struct vnode *dvp;
     char *lnm;
     struct vattr *tva;
     char *tnm;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_symlink\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_readlink(struct vnode *vp,
			struct uio *uiop,
			struct ucred *cred)
#else
static
int
nnpfs_readlink(vp, uiop, cred)
     struct vnode *vp;
     struct uio *uiop;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      VN_HOLD(t);
      error = VOP_RDWR(t, uiop, UIO_READ, 0, cred);
      VN_RELE(t);
    }

  return error;
}

#if defined(__STDC__)
static int nnpfs_inactive(struct vnode *vp,
			struct ucred *cred)
#else
static
int
nnpfs_inactive(vp, cred)
     struct vnode *vp;
     struct ucred *cred;
#endif
{
  struct nnpfs_message_inactivenode msg;
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive\n"));

  msg.header.opcode = NNPFS_MSG_INACTIVENODE;
  msg.handle = xn->handle;
  msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;
  free_nnpfs_node(VNODE_TO_XNODE(vp));
  nnpfs_message_send(nnpfsp->fd, &msg.header, sizeof(msg));
  return 0;
}

#if defined(__STDC__)
static int nnpfs_lockctl(struct vnode *vp,
		       struct flock *ld,
		       int cmd,
		       struct ucred *cred,
		       int clid)
#else
static
int
nnpfs_lockctl(vp, ld, cmd, cred, clid)
     struct vnode *vp;
     struct flock *ld;
     int cmd;
     struct ucred *cred;
     int clid;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_lockctl\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_fid(void)
#else
static
int
nnpfs_fid()
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fid\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_getpage(struct vnode *vp,
		       u_int off,
		       u_int len,
		       u_int *protp,
		       struct page *pl[],
		       u_int plsz,
		       struct seg *seg,
		       addr_t addr,
		       enum seg_rw rw,
		       struct ucred *cred)
#else
static
int
nnpfs_getpage(vp, off, len, protp, pl, plsz, seg, addr, rw, cred)
     struct vnode *vp;
     u_int off, len;
     u_int *protp;
     struct page *pl[];
     u_int plsz;
     struct seg *seg;
     addr_t addr;
     enum seg_rw rw;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_getpage\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_putpage(struct vnode *vp,
		       u_int off,
		       u_int len,
		       int flags,
		       struct ucred *cred)
#else
static
int
nnpfs_putpage(vp, off, len, flags, cred)
     struct vnode *vp;
     u_int off;
     u_int len;
     int flags;
     struct ucred *cred;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_putpage\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_map(struct vnode *vp,
		   u_int off,
		   struct as *as,
		   addr_t *addrp,
		   u_int len,
		   u_int prot,
		   u_int maxprot,
		   u_int flags,
		   struct ucred *cred)
#else
static
int
nnpfs_map(vp, off, as, addrp, len, prot, maxprot, flags, cred)
     struct vnode *vp;
     u_int off;
     struct as *as;
     addr_t *addrp;
     u_int len;
     u_int prot, maxprot;
     u_int flags;
     struct ucred *cred;
#endif
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS,
	 ("nnpfs_map(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n",
	  (int) vp, off, (int) as, (int) addrp, len, prot, maxprot, flags, (int) cred));

  if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
  else
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  
  if (error != 0)
    /* Can't map today */;
  else if (off + len > VNODE_TO_XNODE(vp)->attr.va_size)
    error = EINVAL;
  else if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
    error = EROFS;		/* XXX This is currently not supported */
  else
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      VN_HOLD(t);
      error = VOP_MAP(t, off, as, addrp, len, prot, maxprot, flags, cred);
      /* XXX Patch vnode so that we can intercept get/putpage and inactive. */
      VN_RELE(t);
    }

  return error;
}

#if defined(__STDC__)
static int nnpfs_dump(struct vnode *dumpvp,
		    caddr_t addr,
		    int bn,
		    int count)
#else
static
int
nnpfs_dump(dumpvp, addr, bn, count)
     struct vnode *dumpvp;
     caddr_t addr;
     int bn;
     int count;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_dump\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_cmp(struct vnode *vp1, struct vnode *vp2)
#else
static
int
nnpfs_cmp(vp1, vp2)
     struct vnode *vp1, *vp2;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_cmp\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_realvp(struct vnode *vp,
		      struct vnode **vpp)
#else
static
int
nnpfs_realvp(vp, vpp)
     struct vnode *vp;
     struct vnode **vpp;
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_realvp\n"));
  return EINVAL;
}

#if defined(__STDC__)
static int nnpfs_cntl(struct vnode *vp,
		    int cmd,
		    caddr_t idata,
		    caddr_t odata,
		    int iflag,
		    int oflag)
#else
static
int
nnpfs_cntl(vp, cmd, idata, odata, iflag, oflag)
     struct vnode *vp;
     int cmd, iflag, oflag;
     caddr_t idata, odata;     
#endif
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_cntl\n"));
  return EINVAL;
}

struct vnodeops nnpfs_vnodeops = {
        nnpfs_open,
        nnpfs_close,
        nnpfs_rdwr,
        nnpfs_ioctl,
        nnpfs_select,
        nnpfs_getattr,
        nnpfs_setattr,
        nnpfs_access,
        nnpfs_lookup,
        nnpfs_create,
        nnpfs_remove,
        nnpfs_link,
        nnpfs_rename,
        nnpfs_mkdir,
        nnpfs_rmdir,
        nnpfs_readdir,
        nnpfs_symlink,
        nnpfs_readlink,
        nnpfs_fsync,
        nnpfs_inactive,
        nnpfs_lockctl,
        nnpfs_fid,
        nnpfs_getpage,
        nnpfs_putpage,
        nnpfs_map,
        nnpfs_dump,
        nnpfs_cmp,
        nnpfs_realvp,
        nnpfs_cntl,
};
