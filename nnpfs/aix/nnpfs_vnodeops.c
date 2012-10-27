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

/*
 * NNPFS operations.
 */

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_syscalls.h>

RCSID("$Id: nnpfs_vnodeops.c,v 1.10 2004/06/13 15:03:06 lha Exp $");

static int
nnpfs_open_valid(struct vnode *vp, struct ucred *cred, u_int tok)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  NNPFSDEB(XDEBVFOPS, ("nnpfs_open_valid\n"));

  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_open msg;

	msg.header.opcode = NNPFS_MSG_OPEN;
	msg.cred.uid = cred->cr_uid;
	msg.cred.pag = nnpfs_get_pag(cred);
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

static int
nnpfs_attr_valid(struct vnode *vp, struct ucred *cred, u_int tok)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  nnpfs_pag_t pag = nnpfs_get_pag(cred);

  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_getattr msg;
	msg.header.opcode = NNPFS_MSG_GETATTR;
	msg.cred.uid = cred->cr_uid;
	msg.cred.pag = pag;
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

static int
nnpfs_fetch_rights(struct vnode *vp, struct ucred *cred)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    nnpfs_pag_t pag = nnpfs_get_pag(cred);

    struct nnpfs_message_getattr msg;

    msg.header.opcode = NNPFS_MSG_GETATTR;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = pag;
    msg.handle = xn->handle;
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    return (error);
}

static int
nnpfs_data_valid(struct vnode *vp, struct ucred *cred, u_int tok)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_getdata msg;
	msg.header.opcode = NNPFS_MSG_GETDATA;
	msg.cred.uid = cred->cr_uid;
	msg.cred.pag = nnpfs_get_pag(cred);
	msg.handle = xn->handle;
	msg.tokens = tok;
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

static int
do_fsync(struct nnpfs *nnpfsp,
	 struct nnpfs_node *xn,
	 struct ucred *cred,
	 u_int flag)
{
    int error;
    struct nnpfs_message_putdata msg;

    msg.header.opcode = NNPFS_MSG_PUTDATA;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    msg.handle = xn->handle;

    msg.flag = flag;
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    if (error == 0)
	xn->flags &= ~NNPFS_DATA_DIRTY;

    return error;
}

static int
nnpfs_open(struct vnode *vp,
	 int flag,
	 int ext,
	 caddr_t *vinfop,
	 struct ucred *cred)
{
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_open\n"));
  
  if (flag & _FWRITE)
    error = nnpfs_open_valid(vp, cred, NNPFS_OPEN_NW);
  else
    error = nnpfs_open_valid(vp, cred, NNPFS_OPEN_NR);
  
  return error;
}

static int
nnpfs_close(struct vnode *vp,
	  int flag,
	  caddr_t vinfo,
	  struct ucred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_close\n"));
  
  if (flag & _FWRITE && xn->flags & NNPFS_DATA_DIRTY)
    error = do_fsync (nnpfsp, xn, cred, NNPFS_WRITE);
  
  return error;
}

static int
nnpfs_map (struct vnode *vp,
	 caddr_t addr,
	 uint length,
	 uint offset,
	 uint flags,
	 struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_map\n"));
  return ENOSYS;
}

static int
nnpfs_unmap (struct vnode *vp,
	   int flag,
	   struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_unmap\n"));
  return ENOSYS;
}

static int
nnpfs_rdwr(struct vnode *vp,
	 enum uio_rw op,
	 int flags,
	 struct uio *uio,
	 int ext,
	 caddr_t vinfo,
	 struct vattr *vattr,
	 struct ucred *cred)
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_read\n"));

    if (op == UIO_WRITE)
	error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
    else
	error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);

    if (error == 0) {
	struct vnode *t = DATA_FROM_VNODE(vp);
	ASSERT(t != NULL);
	VNOP_HOLD(t);
	error = VNOP_RDWR(t, op, flags, uio, ext, vinfo, NULL, cred);
	if (op == UIO_WRITE)
	    VNODE_TO_XNODE(vp)->flags |= NNPFS_DATA_DIRTY;
	VNOP_RELE(t);
	/* XXX - vattrp */
    }

    return error;
}

static int
nnpfs_ioctl(struct vnode *vp,
	  int cmd,
	  caddr_t arg,
	  size_t size,
	  int flag,
	  struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));
  return ENOSYS;
}

static int
nnpfs_getattr(struct vnode *vp,
	    struct vattr *vap,
	    struct ucred *cred)     
{
  int error = 0;
  
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr\n"));
  
  error = nnpfs_attr_valid(vp, cred, NNPFS_ATTR_R);
  if (error == 0) {
      *vap = xn->attr;
  }
  
  return error;
}

static int
nnpfs_setattr (struct vnode *vp,
	     int cmd,
	     int arg1,
	     int arg2,
	     int arg3,
	     struct ucred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_setattr\n"));
  if (NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_W)) {
      /* Update attributes and mark them dirty. */
      VNODE_TO_XNODE(vp)->flags |= NNPFS_ATTR_DIRTY;
      error = ENOSYS;		/* XXX not yet implemented */
      goto done;
  } else {
      struct nnpfs_message_putattr msg;
      msg.header.opcode = NNPFS_MSG_PUTATTR;
      msg.cred.uid = cred->cr_uid;
      msg.cred.pag = nnpfs_get_pag(cred);
      msg.handle = xn->handle;

      XA_CLEAR(&msg.attr);

      switch (cmd) {
      case V_OWN:
	  XA_SET_UID(&msg.attr, arg2);
	  XA_SET_GID(&msg.attr, arg3);
	  break;
      case V_UTIME: {
	  struct timeval *atime = (struct timeval *)arg2;
	  struct timeval *mtime = (struct timeval *)arg3;

	  if (arg1 & T_SETTIME) {
	      ;			/* XXX */
	  } else {
	      XA_SET_ATIME(&msg.attr, atime->tv_sec);
	      XA_SET_MTIME(&msg.attr, mtime->tv_sec);
	  }
	  break;
      }
      case V_MODE:
	  XA_SET_MODE(&msg.attr, arg1);
	  break;
      default:
	  panic ("nnpfs_setattr: bad cmd");
      }

      NNPFS_TOKEN_CLEAR(xn, NNPFS_ATTR_VALID, NNPFS_ATTR_MASK);
      error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
      if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }

 done:
  return error;
}

static int
check_rights (u_char rights, int mode)
{
    int error = 0;

    if (mode & S_IREAD)
	if ((rights & NNPFS_RIGHT_R) == 0)
	    error = EACCES;
    if (mode & S_IWRITE)
	if ((rights & NNPFS_RIGHT_W) == 0)
	    error = EACCES;
    if (mode & S_IEXEC)
	if ((rights & NNPFS_RIGHT_X) == 0)
	    error = EACCES;
    return error;
}

static int
nnpfs_access(struct vnode *vp,
	   int mode,
	   int who,
	   struct ucred *cred)     
{
  int error = 0;
  nnpfs_pag_t pag = nnpfs_get_pag(cred);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_access mode = 0%o\n", mode));

  error = nnpfs_attr_valid(vp, cred, NNPFS_ATTR_R);
  if (error == 0) {
      struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
      int i;

      switch (who) {
      case ACC_SELF : {
	  error = check_rights (xn->anonrights, mode);
	
	  if (error == 0)
	      goto done;

	  NNPFSDEB(XDEBVNOPS, ("nnpfs_access anonaccess failed\n"));

	  if (error != 0)
	      nnpfs_fetch_rights(vp, cred); /* ignore error */
	
	  error = EACCES;
	
	  for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	      if (xn->id[i] == pag) {
		  error = check_rights (xn->rights[i], mode);
		  break;
	      }
	  break;
      }
      case ACC_OTHERS :
	  error = 0;		/* XXX */
	  break;
      case ACC_ANY :
      case ACC_ALL :
	  error = check_rights (xn->anonrights, mode);
	  break;
      default :
	  panic ("nnpfs_access: bad who");
      }
  }

done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access(0%o) = %d\n", mode, error));
    return error;

}

static int
nnpfs_lookup(struct vnode *dvp,
	   struct vnode **vpp,
	   char *nm,
	   int flag,
	   struct vattr *vattr,
	   struct ucred *cred)
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
	msg.cred.uid = cred->cr_uid;
	msg.cred.pag = nnpfs_get_pag(cred);
	msg.parent_handle = d->handle;
	if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	    return ENAMETOOLONG;
	error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) &msg)->error;
      }
    else
      {
	*vpp = v;
	VNOP_HOLD(v);
	goto done;
      }
  } while (error == 0);

 done:
  NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup() = %d\n", error));
  return error;
}

static int
nnpfs_create(struct vnode *dvp,
	   struct vnode **vpp,
	   int flag,
	   /*char **/ caddr_t nm,
	   int mode,
	   caddr_t *vinfop,
	   struct ucred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_create\n"));
  {
    struct nnpfs_message_create msg;
    msg.header.opcode = NNPFS_MSG_CREATE;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
#if 0
    vattr2nnpfs_attr (va, &msg.attr);
#endif
#if 0
    msg.exclusive = exclusive;
#endif
    msg.mode = mode;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }

  if (error == 0)
    error = nnpfs_lookup(dvp, vpp, nm, /*flag*/0, /*vattr*/ NULL, cred);
  return error;
}

static int
nnpfs_hold (struct vnode *vp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_hold\n"));
    ++vp->v_count;
    return 0;
}

static void
nnpfs_inactive(struct vnode *vp)
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
}

static int
nnpfs_rele (struct vnode *vp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_rele\n"));
    if (--vp->v_count == 0)
	nnpfs_inactive (vp);
    return 0;
}

static int
nnpfs_remove(struct vnode *vp,
	   struct vnode *dvp,
	   char *nm,
	   struct ucred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  struct nnpfs_message_remove msg;
  int error;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_remove: %s\n", nm));

  msg.header.opcode = NNPFS_MSG_REMOVE;
  msg.parent_handle = xn->handle;
  if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
      return ENAMETOOLONG;
  msg.cred.uid = cred->cr_uid;
  msg.cred.pag = nnpfs_get_pag(cred);
  error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
  if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;

  if (error == 0)
      nnpfs_dnlc_remove (dvp, nm);
  VNOP_RELE(vp);

  return error;
}

static int
nnpfs_link(struct vnode *vp,
	 struct vnode *tdvp,
	 char *tnm,
	 struct ucred *cred)     
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(tdvp);
    struct nnpfs_node *xn2 = VNODE_TO_XNODE(vp);
    struct nnpfs_message_link msg;
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_link: (%s)\n", tnm));

    msg.header.opcode = NNPFS_MSG_LINK;
    msg.parent_handle = xn->handle;
    msg.from_handle   = xn2->handle;
    if (strlcpy(msg.name, tnm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);

    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    return error;
}

static int
nnpfs_rename(struct vnode *svp,
	   struct vnode *sdvp,
	   char *onm,
	   struct vnode *tvp,
	   struct vnode *tdvp,
	   char *nnm,
	   struct ucred *cred)     
{
  struct nnpfs_message_rename msg;
  struct vnode **vpp;
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_rename\n"));

  /* If the old name is too long, don't remove then name */
  if (strlen(onm) >= NNPFS_MAX_NAME)
      return ENAMETOOLONG;

  if (tvp) {
      /* the filename being moved to already exists */
      struct nnpfs_message_remove remmsg;
      
      remmsg.header.opcode = NNPFS_MSG_REMOVE;
      remmsg.parent_handle = VNODE_TO_XNODE(tdvp)->handle;
      if (strlcpy(remmsg.name, nnm, sizeof(remmsg.name)) >= NNPFS_MAX_NAME)
	  return ENAMETOOLONG;
      remmsg.cred.uid = cred->cr_uid;
      remmsg.cred.pag = nnpfs_get_pag(cred);
      error = nnpfs_message_rpc(NNPFS_FROM_VNODE(tdvp)->fd, &remmsg.header,
			      sizeof(remmsg));
      if (error == 0)
	  error = ((struct nnpfs_message_wakeup *) & remmsg)->error;
      if (error != 0)
	  return error;
  }

  msg.header.opcode = NNPFS_MSG_RENAME;
  msg.old_parent_handle = VNODE_TO_XNODE(sdvp)->handle;
  if (strlcpy(msg.old_name, onm, sizeof(msg.old_name)) >= NNPFS_MAX_NAME)
      return ENAMETOOLONG;
  msg.new_parent_handle = VNODE_TO_XNODE(tdvp)->handle;
  if (strlcpy(msg.new_name, nnm, sizeof(msg.new_name)) >= NNPFS_MAX_NAME)
      return ENAMETOOLONG;
  msg.cred.uid = cred->cr_uid;
  msg.cred.pag = nnpfs_get_pag(cred);
  error = nnpfs_message_rpc(NNPFS_FROM_VNODE(sdvp)->fd, &msg.header,
			  sizeof(msg));
  if (error == 0)
      error = ((struct nnpfs_message_wakeup *) & msg)->error;
  
  return error;
}

static int
nnpfs_mkdir(struct vnode *dvp,
	  char *nm,
	  int foo,		/* XXX */
	  struct ucred *cred)     
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir\n"));
  {
    struct nnpfs_message_mkdir msg;
    msg.header.opcode = NNPFS_MSG_MKDIR;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
#if 0
    vattr2nnpfs_attr (va, &msg.attr);
#endif
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }
#if 0
  if (error == 0)
      error = nnpfs_lookup(dvp, vpp, nm, /*flag*/ 0, /*vattr*/NULL, cred);
#endif
  return error;
}

static int
nnpfs_mknod(struct vnode *vp,
	  caddr_t ext,
	  int foo,
	  dev_t dev,
	  struct ucred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mknod\n"));
    return ENOSYS;
}

static int
nnpfs_rmdir(struct vnode *dvp,
	  struct vnode *vp,
	  char *nm,
	  struct ucred *cred)     
{
    struct nnpfs_message_rmdir msg;
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    int error = 0;


    NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir\n"));

    msg.header.opcode = NNPFS_MSG_RMDIR;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, nm, sizeof(msg.name)) < NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;

    return error;
}

static int
nnpfs_readdir(struct vnode *vp,
	    struct uio *uiop,
	    struct ucred *cred)
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      ASSERT(t != NULL);
      VNOP_HOLD(t);
      error = VNOP_RDWR(t, UIO_READ, 0, uiop, 0, NULL, NULL, cred);
      VNOP_RELE(t);
    }

  return error;
}

static int
nnpfs_symlink(struct vnode *dvp,
	    char *lnm,
	    char *tnm,
	    struct ucred *cred)
{
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    struct nnpfs_message_symlink msg;
    int error = 0;
 
    NNPFSDEB(XDEBVNOPS, ("nnpfs_symlink\n"));
   
    msg.header.opcode = NNPFS_MSG_SYMLINK;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, lnm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    if (strlcpy(msg.contents, tnm, sizeof(msg.contents)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
#if 0
    vattr2nnpfs_attr (tva, &msg.attr);
#endif
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);

    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    return error;
}

static int
nnpfs_readlink(struct vnode *vp,
	     struct uio *uiop,
	     struct ucred *cred)
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      ASSERT(t != NULL);
      VNOP_HOLD(t);
      error = VNOP_RDWR(t, UIO_READ, 0, uiop, 0, NULL, NULL, cred);
      VNOP_RELE(t);
    }

  return error;
}

static int
nnpfs_fsync(struct vnode *vp,
	  int syncflag,
	  int foo,
	  struct ucred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync\n"));

  if (xn->flags & NNPFS_DATA_DIRTY)
      error = do_fsync (nnpfsp, xn, cred, NNPFS_WRITE | NNPFS_FSYNC);
  return error;
}

static int
nnpfs_fid(struct vnode *vp,
	struct fileid *fileid,
	struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fid\n"));
  return ENOSYS;
}

static int
nnpfs_fclear (struct vnode *vp,
	    int flags,
	    offset_t offset,
	    offset_t len,
	    caddr_t vinfo,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fclear\n"));
  return ENOSYS;
}

static int
nnpfs_ftrunc (struct vnode *vp,
	    int flags,
	    offset_t length,
	    caddr_t vinfo,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_ftrunc\n"));
  return ENOSYS;
}

static int
nnpfs_lockctl (struct vnode *vp,
	     offset_t offset,
	     struct eflock *lckdat,
	     int cmd,
	     int (*retry_fn)(),
	     ulong *retry_id,
	     struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_lockctl\n"));
  return ENOSYS;
}

static int
nnpfs_select (struct vnode *vp,
	    int correl,
	    ushort e,
	    ushort *re,
	    void (*notify)(),
	    caddr_t vinfo,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_select\n"));
  return ENOSYS;
}

static int
nnpfs_strategy (struct vnode *vp,
	      struct buf *buf,
	      struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_strategy\n"));
  return ENOSYS;
}

static int
nnpfs_revoke (struct vnode *vp,
	    int cmd,
	    int flag,
	    struct vattr *attr,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_revoke\n"));
  return ENOSYS;
}

static int
nnpfs_getacl (struct vnode *vp,
	    struct uio *uip,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_getacl\n"));
  return ENOSYS;
}

static int
nnpfs_setacl (struct vnode *vp,
	    struct uio *uip,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_getacl\n"));
  return ENOSYS;
}

static int
nnpfs_getpcl (struct vnode *vp,
	    struct uio *uip,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_getpcl\n"));
  return ENOSYS;
}

static int
nnpfs_setpcl (struct vnode *vp,
	    struct uio *uip,
	    struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_setpcl\n"));
  return ENOSYS;
}

static int
nnpfs_seek (struct vnode *vp,
	  offset_t *offset,
	  struct ucred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_seek\n"));
  return ENOSYS;
}

struct vnodeops nnpfs_vnodeops = {
    nnpfs_link,
    nnpfs_mkdir,
    nnpfs_mknod,
    nnpfs_remove,
    nnpfs_rename,
    nnpfs_rmdir,
    nnpfs_lookup,
    nnpfs_fid,
    nnpfs_open,
    nnpfs_create,
    nnpfs_hold,
    nnpfs_rele,
    nnpfs_close,
    nnpfs_map,
    nnpfs_unmap,
    nnpfs_access,
    nnpfs_getattr,
    nnpfs_setattr,
    nnpfs_fclear,
    nnpfs_fsync,
    nnpfs_ftrunc,
    nnpfs_rdwr,
    nnpfs_lockctl,
    nnpfs_ioctl,
    nnpfs_readlink,
    nnpfs_select,
    nnpfs_symlink,
    nnpfs_readdir,
    nnpfs_strategy,
    nnpfs_revoke,
    nnpfs_getacl,
    nnpfs_setacl,
    nnpfs_getpcl,
    nnpfs_setpcl,
    nnpfs_seek
};
