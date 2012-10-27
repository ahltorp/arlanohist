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

RCSID("$Id: nnpfs_vnodeops.c,v 1.14 2004/06/13 15:04:05 lha Exp $");

static int
nnpfs_open_valid(struct vnode *vp, struct cred *cred, u_int tok)
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
nnpfs_attr_valid(struct vnode *vp, struct cred *cred, u_int tok)
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
nnpfs_fetch_rights(struct vnode *vp, struct cred *cred)
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
nnpfs_data_valid(struct vnode *vp, struct cred *cred, u_int tok)
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
	 struct cred *cred,
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
nnpfs_open_common(struct vnode **vpp,
		mode_t mode,
		struct cred *cred)
{
  int error = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_open\n"));
  
  if (mode & VWRITE)
    error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NW);
  else
    error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NR);
  
  return error;
}

static int
nnpfs_close_common(struct vnode *vp,
		 int flag,
		 lastclose_t lastclose,
		 off_t offset,
		 struct cred *cred)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_close\n"));
  
  if (flag & FWRITE && xn->flags & NNPFS_DATA_DIRTY)
    error = do_fsync (nnpfsp, xn, cred, NNPFS_WRITE);
  
  return error;
}

static int
nnpfs_read_common(struct vnode *vp,
		struct uio *uio,
		int ioflag,
		struct cred *cred)
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_read\n"));

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);

    if (error == 0) {
	struct vnode *t = DATA_FROM_VNODE(vp);
	ASSERT(t != NULL);
	VOP_RWLOCK(t, 0);
#if IRIX_64
	VOP_READ(t, uio, ioflag, cred, NULL, error);
#else
	error = VOP_READ(t, uio, ioflag, cred);
#endif
	VOP_RWUNLOCK(t, 0);
    }

    return error;
}

static int
nnpfs_write_common(struct vnode *vp,
		 struct uio *uio,
		 int ioflag,
		 struct cred *cred)
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_write\n"));

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);

    if (error == 0) {
	struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
	struct vnode *t = DATA_FROM_VNODE(vp);
	struct vattr sub_attr;
	int error2 = 0;

	ASSERT(t != NULL);
	VOP_RWLOCK(t, 1);
#if IRIX_64
	VOP_WRITE(t, uio, ioflag, cred, NULL, error);
	VOP_GETATTR(t, &sub_attr, 0, cred, error2);
#else
	error  = VOP_WRITE(t, uio, ioflag, cred);
	error2 = VOP_GETATTR(t, &sub_attr, 0, cred);
#endif
	VOP_RWUNLOCK(t, 1);
	VNODE_TO_XNODE(vp)->flags |= NNPFS_DATA_DIRTY;

	if (error2 == 0) {
	    xn->attr.va_size  = sub_attr.va_size;
	    xn->attr.va_mtime = sub_attr.va_mtime;
	}
    }

    return error;
}

static int
nnpfs_ioctl_common(struct vnode *vp,
		 int cmd,
		 void *arg,
		 int flag,
		 struct cred *cred,
		 int *result)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));
  return ENOSYS;
}

static int
nnpfs_setfl_common(struct vnode *vp,
		 int oflags,
		 int nflags,
		 struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_setfl\n"));
  return fs_setfl (vp, oflags, nflags, cred);
}

static int
nnpfs_getattr_common(struct vnode *vp,
		   struct vattr *vap,
		   int flags,
		   struct cred *cred)     
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
nnpfs_setattr_common(struct vnode *vp,
		   struct vattr *vap,
		   int flags,
		   struct cred *cred)
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
      vattr2nnpfs_attr (vap, &msg.attr);
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

    if (mode & VREAD)
	if ((rights & NNPFS_RIGHT_R) == 0)
	    error = EACCES;
    if (mode & VWRITE)
	if ((rights & NNPFS_RIGHT_W) == 0)
	    error = EACCES;
    if (mode & VEXEC)
	if ((rights & NNPFS_RIGHT_X) == 0)
	    error = EACCES;
    return error;
}

static int
nnpfs_access_common(struct vnode *vp,
		  int mode,
		  int flags,
		  struct cred *cred)     
{
  int error = 0;
  nnpfs_pag_t pag = nnpfs_get_pag(cred);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_access mode = 0%o\n", mode));

  error = nnpfs_attr_valid(vp, cred, NNPFS_ATTR_R);
  if (error == 0) {
      struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
      int i;

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
  }

done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access(0%o) = %d\n", mode, error));
    return error;

}

static int
nnpfs_lookup_common(struct vnode *dvp,
		  char *nm,
		  struct vnode **vpp,
		  struct pathname *pnp,
		  int flags,
		  struct vnode *rdir,
		  struct cred *cred)
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

static int
nnpfs_create_common(struct vnode *dvp,
		  char *nm,
		  struct vattr *va,
		  int exclusive,
		  int mode,
		  struct vnode **vpp,
		  struct cred *cred)     
{
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
  int error = 0;
  int do_trunc = 0;
  
  NNPFSDEB(XDEBVNOPS, ("nnpfs_create\n"));
  {
    struct nnpfs_message_create msg;
    msg.header.opcode = NNPFS_MSG_CREATE;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    vattr2nnpfs_attr (va, &msg.attr);
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

  if (error == EEXIST) {
      do_trunc = 1;
      error = 0;
  }

  if (error == 0)
    error = nnpfs_lookup_common(dvp, nm, vpp, /*pnp*/ NULL, /*flags*/ 0,
			      /*rdir*/ NULL, cred);

  if (error = 0 && do_trunc)
      error = nnpfs_setattr_common (*vpp, va, 0, cred);

  return error;
}

static int
nnpfs_remove_common(struct vnode *dvp,
		  char *nm,
		  struct cred *cred)
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

  return error;
}

static int
nnpfs_link_common(struct vnode *vp,
		struct vnode *tdvp,
		char *tnm,
		struct cred *cred)     
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
nnpfs_rename_common(struct vnode *sdvp,
		  char *onm,
		  struct vnode *tdvp,
		  char *nnm,
		  struct pathname *npnp,
		  struct cred *cred)     
{
  struct nnpfs_message_rename msg;
  struct vnode **vpp;
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_rename\n"));

  if (strlen(onm >= NNPFS_MAX_NAME)
      return ENAMETOOLONG;

  error = nnpfs_lookup_common(tdvp, nnm, vpp, /*pnp*/ NULL, /*flags*/ 0,
			    /*rdir*/ NULL, cred);
  if (error != ENOENT) {
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
nnpfs_mkdir_common(struct vnode *dvp,
		 char *nm,
		 struct vattr *va,
		 struct vnode **vpp,
		 struct cred *cred)     
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
    vattr2nnpfs_attr (va, &msg.attr);
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
      error = ((struct nnpfs_message_wakeup *) &msg)->error;
  }
  if (error == 0)
      error = nnpfs_lookup_common(dvp, nm, vpp, /*pnp*/ NULL, /*flags*/ 0,
				/*rdir*/ NULL, cred);
  return error;
}

static int
nnpfs_rmdir_common(struct vnode *dvp,
		 char *nm,
		 struct vnode *foo,
		 struct cred *cred)     
{
    struct nnpfs_message_rmdir msg;
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir\n"));

    msg.header.opcode = NNPFS_MSG_RMDIR;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, nm, sizeof(msg.name))) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;

    return error;
}

static int
nnpfs_readdir_common(struct vnode *vp,
		   struct uio *uiop,
		   struct cred *cred,
		   int *eofp)		/* XXX */
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0) {
      struct vnode *t      = DATA_FROM_VNODE(vp);

      ASSERT(t != NULL);

      if(ABI_IS_64BIT(GETDENTS_ABI(curprocp->p_abi, uiop))) {
	  VOP_RWLOCK(t, 0);
#if IRIX_64
	  VOP_READ(t, uiop, 0, cred, NULL, error);
#else
	  error = VOP_READ(t, uiop, 0, cred);
#endif
	  VOP_RWUNLOCK(t, 0);
      } else {
	  struct uio tmp_uio;
	  struct iovec iovec;
	  char *buf;
	  size_t count = uiop->uio_resid;

	  buf = nnpfs_alloc (count);
	  iovec.iov_base     = buf;
	  iovec.iov_len      = count;
	  tmp_uio.uio_iov    = &iovec;
	  tmp_uio.uio_iovcnt = 1;
	  tmp_uio.uio_offset = uiop->uio_offset;
	  tmp_uio.uio_segflg = UIO_SYSSPACE;
	  tmp_uio.uio_fmode  = uiop->uio_fmode;
	  tmp_uio.uio_limit  = uiop->uio_limit;
	  tmp_uio.uio_resid  = count;
	  VOP_RWLOCK(t, 0);
#if IRIX_64
	  VOP_READ(t, &tmp_uio, 0, cred, NULL, error);
#else
	  error = VOP_READ(t, &tmp_uio, 0, cred);
#endif
	  VOP_RWUNLOCK(t, 0);

	  if (error == 0) {
	      char *ptr;
	      struct dirent64 *d;
	      size_t len = count - tmp_uio.uio_resid;
	      
	      for (ptr = buf;
		   ptr < buf + len;
		   ptr += d->d_reclen) {
		  char tmp_buf[1024];
		  struct irix5_dirent *d5 = (struct irix5_dirent *)tmp_buf;

		  d = (struct dirent64 *)ptr;

		  d5->d_ino    = d->d_ino;
		  d5->d_off    = d->d_off;
		  d5->d_reclen = DIRENTSIZE(strlen(d->d_name));
		  strcpy (d5->d_name, d->d_name);

		  error = uiomove (d5, d5->d_reclen, UIO_READ, uiop);
		  if (error) {
		      NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir: uiomove failed: %d\n",
					 error));
		      break;
		  }
	      }
	  }
	  nnpfs_free (buf, count);
      }
  }

  return error;
}

static int
nnpfs_symlink_common(struct vnode *dvp,
		   char *lnm,
		   struct vattr *tva,
		   char *tnm,
		   struct cred *cred)
{
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    struct nnpfs_message_symlink msg;
    int error = 0;
 
    NNPFSDEB(XDEBVNOPS, ("nnpfs_symlink\n"));
   
    msg.header.opcode = NNPFS_MSG_SYMLINK;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, lnm, sizeof(msg.name))) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    if (strlcpy(msg.contents, tnm, sizeof(msg.contents))) >= NNPFS_MAX_SYMLINK_CONENT)
	return ENAMETOOLONG;
    vattr2nnpfs_attr (tva, &msg.attr);
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);

    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    return error;
}

static int
nnpfs_readlink_common(struct vnode *vp,
		    struct uio *uiop,
		    struct cred *cred)
{
  int error = 0;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink\n"));

  error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  if (error == 0)
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      ASSERT(t != NULL);
      VOP_RWLOCK(t, 0);
#if IRIX_64
      VOP_READ(t, uiop, 0, cred, NULL, error);
#else
      error = VOP_READ(t, uiop, 0, cred);
#endif
      VOP_RWUNLOCK(t, 0);
    }

  return error;
}

static int
nnpfs_fsync_common(struct vnode *vp,
		 int syncflag,
		 struct cred *cred)
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
nnpfs_inactive_common(struct vnode *vp,
		    struct cred *cred)
{
  struct nnpfs_message_inactivenode msg;
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive\n"));

  msg.header.opcode = NNPFS_MSG_INACTIVENODE;
  msg.handle = xn->handle;
  msg.flag   = NNPFS_NOREFS; /* | NNPFS_DELETE; */
#if 0
  free_nnpfs_node(VNODE_TO_XNODE(vp));
#endif
  nnpfs_message_send(nnpfsp->fd, &msg.header, sizeof(msg));
  return 0;
}

static int
nnpfs_fid_common(struct vnode *vp,
	       struct fid **fid)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fid\n"));
  return ENOSYS;
}

static int
nnpfs_fid_common2(struct vnode *vp,
		struct fid *fid)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fid2\n"));
  return ENOSYS;
}

static void
nnpfs_rwlock_common(struct vnode *vp,
		  vrwlock_t write_lock)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_rwlock\n"));
}

static void
nnpfs_rwunlock_common(struct vnode *vp,
		    vrwlock_t write_lock)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_rwunlock\n"));
}

static int
nnpfs_seek_common(struct vnode *vp,
		off_t offset,
		off_t *roffset)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_seek\n"));
  return 0;
}

static int
nnpfs_cmp_common(struct vnode *vp1,
	       struct vnode *vp2)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_cmp\n"));
  return vp1 == vp2;
}

static int
nnpfs_frlock_common(struct vnode *vp,
		  int foo,
		  struct flock *fl,
		  int bar,
		  off_t off,
		  struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_frlock\n"));
  return ENOSYS;
}

static int
nnpfs_realvp_common(struct vnode *vp,
		  struct vnode **vpp)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_realvp\n"));
  return ENOSYS;
}

static int
nnpfs_bmap_common (struct vnode *vp,
		 off_t off,
		 ssize_t sz,
		 int flags,
		 struct cred *cred,
		 struct bmapval *bv,
		 int *foo)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_bmap\n"));
  return ENOSYS;

}

static void
nnpfs_strategy_common (struct vnode *vp,
		     struct buf *buf)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_strategy\n"));
}

static int
nnpfs_map_common(struct vnode *vp,
	       off_t off,
	       struct pregion *pregion,
	       char **a,
	       size_t sz,
	       u_int prot,
	       u_int max_prot,
	       u_int map_flag,
	       struct cred *cred)
{
  int error = 0;
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
  struct vattr *va = &xn->attr;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_map\n"));

  error = fs_map_subr (vp, va->va_size, va->va_mode, off, pregion,
		       *a, sz, prot, max_prot, map_flag, cred);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_map: error = %d\n", error));
}

#if 0
  if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
  else
    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
  
  if (error != 0)
    /* Can't map today */;
  else if (off + len > VNODE_TO_XNODE(vp)->attr.va_size)
    error = EINVAL;
#if 0
  else if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
    error = EROFS;		/* XXX This is currently not supported */
#endif
  else
    {
      struct vnode *t = DATA_FROM_VNODE(vp);
      ASSERT(t != NULL);
      VOP_RWLOCK(t, 1);
#if IRIX_64
      VOP_MAP(t, off, as, addrp, len, prot, maxprot, flags, cred, error);
#else
      error = VOP_MAP(t, off, as, addrp, len, prot, maxprot, flags, cred);
#endif
      /* XXX Patch vnode so that we can intercept get/putpage and inactive. */
      VOP_RWUNLOCK(t, 1);
    }

  return error;
  NNPFSDEB(XDEBVNOPS, ("nnpfs_map\n"));
  return ENOSYS;

}
#endif

static int
nnpfs_addmap_common(struct vnode *vp,
	   off_t off,
	   struct pregion *as,
	   addr_t addr,
	   size_t len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_addmap\n"));
  return 0;
}

static int
nnpfs_delmap_common(struct vnode *vp,
	   off_t off,
	   struct pregion *as,
	   addr_t addr,
	   u_int len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_delmap\n"));
  return 0;
}


static int
nnpfs_poll_common(struct vnode *vp,
	 short events,
	 int anyyet,
	 short *revents,
	 struct pollhead **ph)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_poll\n"));
  return fs_poll(vp, events, anyyet, revents, ph);
}

static int
nnpfs_dump_common(struct vnode *dumpvp,
	 caddr_t addr,
	 daddr_t darr,
	 u_int foo)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_dump\n"));
  return ENOSYS;
}

static int
nnpfs_pathconf_common(struct vnode *vp,
	     int cmd,
	     u_long *valp,
	     struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_pathconf\n"));
  return fs_pathconf (vp, cmd, valp, cred);
}

static int
nnpfs_allocstore_common(struct vnode *vp,
	       off_t off,
	       size_t sz,
	       struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_allocstore\n"));
  return ENOSYS;
}

static int
nnpfs_fcntl_common(struct vnode *vp,
	  int cmd,
	  void *arg,
	  int foo,
	  off_t off,
	  struct cred *cred,
	  union rval *result)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_fcntl\n"));
  return ENOSYS;
}

static int
nnpfs_reclaim_common (struct vnode *vp,
	     int foo)
{
  struct nnpfs_message_inactivenode msg;
  struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
  struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

  NNPFSDEB(XDEBVNOPS, ("nnpfs_reclaim\n"));

  msg.header.opcode = NNPFS_MSG_INACTIVENODE;
  msg.handle = xn->handle;
  msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;
#if 1
  free_nnpfs_node(VNODE_TO_XNODE(vp));
#endif
  nnpfs_message_send(nnpfsp->fd, &msg.header, sizeof(msg));
  return 0;
}

static int
nnpfs_attr_get_common (struct vnode *vp,
		     char *a,
		     char *b,
		     int *c,
		     int d,
		     struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_attr_get\n"));
  return ENOSYS;
}

static int
nnpfs_attr_set_common (struct vnode *vp,
		     char *a,
		     char *b,
		     int c,
		     int d,
		     struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_attr_set\n"));
  return ENOSYS;
}

static int
nnpfs_attr_remove_common (struct vnode *vp,
			char *a,
			int b,
			struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_attr_remove\n"));
  return ENOSYS;
}

static int
nnpfs_attr_list_common (struct vnode *vp,
		      char *a,
		      int b,
		      int c,
		      struct attrlist_cursor_kern *k,
		      struct cred *cred)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_attr_list\n"));
  return ENOSYS;
}

#if IRIX_64

static int
nnpfs_open(bhv_desc_t *bh,
	 vnode_t **vpp,
	 mode_t mode,
	 struct cred *cred)
{
    return nnpfs_open_common (vpp, mode, cred);
}

static int
nnpfs_close (bhv_desc_t *bh,
	   int flag,
	   lastclose_t lastclose,
	   off_t offset,
	   struct cred *cred,
	   struct flid *flid)
{
    return nnpfs_close_common (BHV_TO_VNODE(bh), flag, lastclose,
			     offset, cred);
}

static int
nnpfs_read (bhv_desc_t *bh,
	  struct uio *uio,
	  int ioflag,
	  struct cred *cred,
	  struct flid *flid)
{
    return nnpfs_read_common (BHV_TO_VNODE(bh), uio, ioflag, cred);
}

static int
nnpfs_write (bhv_desc_t *bh,
	   struct uio *uio,
	   int ioflag,
	   struct cred *cred,
	   struct flid *flid)
{
    return nnpfs_write_common (BHV_TO_VNODE(bh), uio, ioflag, cred);
}

static int
nnpfs_ioctl(bhv_desc_t *bh,
	  int cmd,
	  void *arg,
	  int flag,
	  struct cred *cred,
	  int *result)
{
    return nnpfs_ioctl_common (BHV_TO_VNODE(bh), cmd, arg, flag, cred, result);
}

static int
nnpfs_setfl(bhv_desc_t *bh,
	  int oflags,
	  int nflags,
	  struct cred *cred)
{
    return nnpfs_setfl_common (BHV_TO_VNODE(bh), oflags, nflags, cred);
}

static int
nnpfs_getattr(bhv_desc_t *bh,
	    struct vattr *vap,
	    int flags,
	    struct cred *cred)
{
    return nnpfs_getattr_common (BHV_TO_VNODE(bh), vap, flags, cred);
}

static int
nnpfs_setattr(bhv_desc_t *bh,
	    struct vattr *vap,
	    int flags,
	    struct cred *cred)
{
    return nnpfs_setattr_common (BHV_TO_VNODE(bh), vap, flags, cred);
}

static int
nnpfs_access(bhv_desc_t *bh,
	   int mode,
	   int flags,
	   struct cred *cred)     
{
    return nnpfs_access_common (BHV_TO_VNODE(bh), mode, flags, cred);
}

static int
nnpfs_lookup(bhv_desc_t *bh,
	   char *nm,
	   struct vnode **vpp,
	   struct pathname *pnp,
	   int flags,
	   struct vnode *rdir,
	   struct cred *cred)
{
    return nnpfs_lookup_common (BHV_TO_VNODE(bh), nm, vpp, pnp,
			      flags, rdir, cred);
}

static int
nnpfs_create(bhv_desc_t *bh,
	   char *nm,
	   struct vattr *va,
	   int exclusive,
	   int mode,
	   struct vnode **vpp,
	   struct cred *cred)
{
    return nnpfs_create_common (BHV_TO_VNODE(bh), nm, va,
			      exclusive, mode, vpp, cred);
}

static int
nnpfs_remove(bhv_desc_t *bh,
	   char *nm,
	   struct cred *cred)
{
    return nnpfs_remove_common (BHV_TO_VNODE(bh), nm, cred);
}

static int
nnpfs_link(bhv_desc_t *bh,
	 struct vnode *tdvp,
	 char *tnm,
	 struct cred *cred)     
{
    return nnpfs_link_common (BHV_TO_VNODE(bh), tdvp, tnm, cred);
}

static int
nnpfs_rename(bhv_desc_t *bh,
	   char *onm,
	   struct vnode *tdvp,
	   char *nnm,
	   struct pathname *npnp,
	   struct cred *cred)
{
    return nnpfs_rename_common (BHV_TO_VNODE(bh), onm, tdvp, nnm, npnp, cred);
}

static int
nnpfs_mkdir(bhv_desc_t *bh,
	  char *nm,
	  struct vattr *va,
	  struct vnode **vpp,
	  struct cred *cred)
{
    return nnpfs_mkdir_common (BHV_TO_VNODE(bh), nm, va, vpp, cred);
}

static int
nnpfs_rmdir(bhv_desc_t *bh,
	  char *nm,
	  struct vnode *foo,
	  struct cred *cred)     
{
    return nnpfs_rmdir_common (BHV_TO_VNODE(bh), nm, foo, cred);
}

static int
nnpfs_readdir(bhv_desc_t *bh,
	    struct uio *uiop,
	    struct cred *cred,
	    int *eofp)		/* XXX */
{
    return nnpfs_readdir_common (BHV_TO_VNODE(bh), uiop, cred, eofp);
}

static int
nnpfs_symlink(bhv_desc_t *bh,
	    char *lnm,
	    struct vattr *tva,
	    char *tnm,
	    struct cred *cred)
{
    return nnpfs_symlink_common (BHV_TO_VNODE(bh), lnm, tva, tnm, cred);
}

static int
nnpfs_readlink(bhv_desc_t *bh,
	     struct uio *uiop,
	     struct cred *cred)
{
    return nnpfs_readlink_common (BHV_TO_VNODE(bh), uiop, cred);
}

static int
nnpfs_fsync(bhv_desc_t *bh,
	  int syncflag,
	  struct cred *cred)
{
    return nnpfs_fsync_common (BHV_TO_VNODE(bh), syncflag, cred);
}

static int
nnpfs_inactive(bhv_desc_t *bh,
	     struct cred *cred)
{
    return nnpfs_inactive_common (BHV_TO_VNODE(bh), cred);
}

static int
nnpfs_fid(bhv_desc_t *bh,
	struct fid **fid)
{
    return nnpfs_fid_common (BHV_TO_VNODE(bh), fid);
}

static int
nnpfs_fid2(bhv_desc_t *bh,
	 struct fid *fid)
{
    return nnpfs_fid2_common (BHV_TO_VNODE(bh), fid);
}

static void
nnpfs_rwlock(bhv_desc_t *bh,
	   vrwlock_t write_lock)
{
    nnpfs_rwlock_common (BHV_TO_VNODE(bh), write_lock);
}

static void
nnpfs_rwunlock(bhv_desc_t *bh,
	     vrwlock_t write_lock)
{
    nnpfs_rwunlock_common (BHV_TO_VNODE(bh), write_lock);
}

static int
nnpfs_seek(bhv_desc_t *bh,
	 off_t offset,
	 off_t *roffset)
{
    return nnpfs_seek_common (BHV_TO_VNODE(bh), offset, roffset);
}

static int
nnpfs_cmp(bhv_desc_t *bh1,
	vnode_t *vp2)
{
    return nnpfs_cmp_common (BHV_TO_VNODE(bh1), vp2);
}

static int
nnpfs_frlock(bhv_desc_t *bh,
	   int foo,
	   struct flock *fl,
	   int bar,
	   off_t off,
	   struct cred *cred)
{
    return nnpfs_frlock_common (BHV_TO_VNODE(bh), foo, fl, bar, off, cred);
}

static int
nnpfs_realvp(bhv_desc_t *bh,
	   struct vnode **vpp)
{
    return nnpfs_realvp_common (BHV_TO_VNODE(bh), vpp);
}

static int
nnpfs_bmap (bhv_desc_t *bh,
	  off_t off,
	  ssize_t sz,
	  int flags,
	  struct cred *cred,
	  struct bmapval *bv,
	  int *foo)
{
    return nnpfs_bmap_common (BHV_TO_VNODE(bh), off, sz, flags, cred, bv, foo);
}

static void
nnpfs_strategy (bhv_desc_t *bh,
	      struct buf *buf)
{
    nnpfs_strategy_common (BHV_TO_VNODE(bh), buf);
}

static int
nnpfs_map(bhv_desc_t *bh,
	off_t off,
	void *pregion,
	char **a,
	size_t sz,
	u_int prot,
	u_int max_prot,
	u_int map_flag,
	struct cred *cred)
{
    return nnpfs_map_common (BHV_TO_VNODE(bh), off, pregion, a, sz, prot,
			   max_prot, map_flag, cred);
}

static int
nnpfs_addmap(bhv_desc_t *bh,
	   off_t off,
	   void *as,
	   addr_t addr,
	   size_t len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
    return nnpfs_addmap_common (BHV_TO_VNODE(bh), off, as, addr, len, prot,
			      maxprot, flags, cred);
}

static int
nnpfs_delmap(bhv_desc_t *bh,
	   off_t off,
	   void *as,
	   addr_t addr,
	   size_t len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
    return nnpfs_delmap_common (BHV_TO_VNODE(bh), off, as, addr, len, prot,
			      maxprot, flags, cred);
}

static int
nnpfs_poll(bhv_desc_t *bh,
	 short events,
	 int anyyet,
	 short *revents,
	 struct pollhead **ph)
{
    return nnpfs_poll_common (BHV_TO_VNODE(bh), events, anyyet, revents, ph);
}

static int
nnpfs_dump(bhv_desc_t *bh,
	 caddr_t addr,
	 daddr_t darr,
	 u_int foo)
{
    return nnpfs_dump_common (BHV_TO_VNODE(bh), addr, darr, foo);
}

static int
nnpfs_pathconf(bhv_desc_t *bh,
	     int cmd,
	     u_long *valp,
	     struct cred *cred)
{
    return nnpfs_pathconf_common (BHV_TO_VNODE(bh), cmd, valp, cred);
}

static int
nnpfs_allocstore(bhv_desc_t *bh,
	       off_t off,
	       size_t sz,
	       struct cred *cred)
{
    return nnpfs_allocstore_common (BHV_TO_VNODE(bh), off, sz, cred);
}

static int
nnpfs_fcntl(bhv_desc_t *bh,
	  int cmd,
	  void *arg,
	  int foo,
	  off_t off,
	  struct cred *cred,
	  union rval *result)
{
    return nnpfs_fcntl_common (BHV_TO_VNODE(bh), cmd, arg, foo, off, cred,
			     result);
}

static int
nnpfs_reclaim (bhv_desc_t *bh, int foo)
{
    return nnpfs_reclaim_common (BHV_TO_VNODE(bh), foo);
}

static int
nnpfs_attr_get (bhv_desc_t *bh,
	      char *a,
	      char *b,
	      int *c,
	      int d,
	      struct cred *cred)
{
    return nnpfs_attr_get_common (BHV_TO_VNODE(bh), a, b, c, d, cred);
}

static int
nnpfs_attr_set (bhv_desc_t *bh,
	      char *a,
	      char *b,
	      int c,
	      int d,
	      struct cred *cred)
{
    return nnpfs_attr_set_common (BHV_TO_VNODE(bh), a, b, c, d, cred);
}

static int
nnpfs_attr_remove (bhv_desc_t *bh,
		 char *a,
		 int b,
		 struct cred *cred)
{
    return nnpfs_attr_remove_common (BHV_TO_VNODE(bh), a, b, cred);
}

static int
nnpfs_attr_list (bhv_desc_t *bh,
	       char *a,
	       int b,
	       int c,
	       struct attrlist_cursor_kern *k,
	       struct cred *cred)
{
    return nnpfs_attr_list_common (BHV_TO_VNODE(bh), a, b, c, k, cred);
}

static int
nnpfs_mount (bhv_desc_t *bh,
	   struct mounta *uap,
	   char *path,
	   struct vfsops *vfsops)
{
  NNPFSDEB(XDEBVNOPS, ("nnpfs_mount\n"));
  return ENOSYS;
}

struct vnodeops nnpfs_vnodeops = {
	VNODE_POSITION_BASE,
        nnpfs_open,
        nnpfs_close,
        nnpfs_read,
        nnpfs_write,
        nnpfs_ioctl,
	nnpfs_setfl,
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
	nnpfs_fid,
	nnpfs_fid2,
	nnpfs_rwlock,
	nnpfs_rwunlock,
	nnpfs_seek,
	nnpfs_cmp,
	nnpfs_frlock,
	nnpfs_realvp,
        nnpfs_bmap,
        nnpfs_strategy,
        nnpfs_map,
	nnpfs_addmap,
	nnpfs_delmap,
	nnpfs_poll,
        nnpfs_dump,
	nnpfs_pathconf,
	nnpfs_allocstore,
	nnpfs_fcntl,
	nnpfs_reclaim,
	nnpfs_attr_get,
	nnpfs_attr_set,
	nnpfs_attr_remove,
	nnpfs_attr_list,
	nnpfs_mount
};

#else /* !IRIX_64 */

static int
nnpfs_open(struct vnode **vpp,
	 mode_t mode,
	 struct cred *cred)
{
    return nnpfs_open_common (vpp, mode, cred);
}

static int
nnpfs_close(struct vnode *vp,
	  int flag,
	  lastclose_t lastclose,
	  off_t offset,
	  struct cred *cred)
{
    return nnpfs_close_common (vp, flag, lastclose, offset, cred);
}

static int
nnpfs_read(struct vnode *vp,
	 struct uio *uio,
	 int ioflag,
	 struct cred *cred)
{
    return nnpfs_read_common (vp, uio, ioflag, cred);
}

static int
nnpfs_write(struct vnode *vp,
	  struct uio *uio,
	  int ioflag,
	  struct cred *cred)
{
    return nnpfs_write_common (vp, uio, ioflag, cred);
}

static int
nnpfs_ioctl(struct vnode *vp,
	  int cmd,
	  void *arg,
	  int flag,
	  struct cred *cred,
	  int *result)
{
    return nnpfs_ioctl_common (vp, cmd, arg, flag, cred, result);
}

static int
nnpfs_setfl(struct vnode *vp,
	  int oflags,
	  int nflags,
	  struct cred *cred)
{
    return nnpfs_setfl_common (vp, oflags, nflags, cred);
}

static int
nnpfs_getattr(struct vnode *vp,
	    struct vattr *vap,
	    int flags,
	    struct cred *cred)
{
    return nnpfs_getattr_common (vp, vap, flags, cred);
}

static int
nnpfs_setattr(struct vnode *vp,
	    struct vattr *vap,
	    int flags,
	    struct cred *cred)
{
    return nnpfs_setattr_common (vp, vap, flags, cred);
}

static int
nnpfs_access(struct vnode *vp,
	   int mode,
	   int flags,
	   struct cred *cred)     
{
    return nnpfs_access_common (vp, mode, flags, cred);
}

static int
nnpfs_lookup(struct vnode *dvp,
	   char *nm,
	   struct vnode **vpp,
	   struct pathname *pnp,
	   int flags,
	   struct vnode *rdir,
	   struct cred *cred)
{
    return nnpfs_lookup_common (dvp, nm, vpp, pnp, flags, rdir, cred);
}

static int
nnpfs_create(struct vnode *dvp,
	   char *nm,
	   struct vattr *va,
	   enum vcexcl exclusive,
	   int mode,
	   struct vnode **vpp,
	   struct cred *cred)
{
    return nnpfs_create_common (dvp, nm, va, exclusive, mode, vpp, cred);
}

static int
nnpfs_remove(struct vnode *dvp,
	   char *nm,
	   struct cred *cred)
{
    return nnpfs_remove_common (dvp, nm, cred);
}

static int
nnpfs_link(struct vnode *vp,
	 struct vnode *tdvp,
	 char *tnm,
	 struct cred *cred)     
{
    return nnpfs_link_common (vp, tdvp, tnm, cred);
}

static int
nnpfs_rename(struct vnode *sdvp,
	   char *onm,
	   struct vnode *tdvp,
	   char *nnm,
	   struct pathname *npnp,
	   struct cred *cred)
{
    return nnpfs_rename_common (sdvp, onm, tdvp, nnm, npnp, cred);
}

static int
nnpfs_mkdir(struct vnode *dvp,
	  char *nm,
	  struct vattr *va,
	  struct vnode **vpp,
	  struct cred *cred)
{
    return nnpfs_mkdir_common (dvp, nm, va, vpp, cred);
}

static int
nnpfs_rmdir(struct vnode *dvp,
	  char *nm,
	  struct vnode *foo,
	  struct cred *cred)     
{
    return nnpfs_rmdir_common (dvp, nm, foo, cred);
}

static int
nnpfs_readdir(struct vnode *vp,
	    struct uio *uiop,
	    struct cred *cred,
	    int *eofp)		/* XXX */
{
    return nnpfs_readdir_common (vp, uiop, cred, eofp);
}

static int
nnpfs_symlink(struct vnode *dvp,
	    char *lnm,
	    struct vattr *tva,
	    char *tnm,
	    struct cred *cred)
{
    return nnpfs_symlink_common (dvp, lnm, tva, tnm, cred);
}

static int
nnpfs_readlink(struct vnode *vp,
	     struct uio *uiop,
	     struct cred *cred)
{
    return nnpfs_readlink_common (vp, uiop, cred);
}

static int
nnpfs_fsync(struct vnode *vp,
	  int syncflag,
	  struct cred *cred)
{
    return nnpfs_fsync_common (vp, syncflag, cred);
}

static void
nnpfs_inactive(struct vnode *vp,
	     struct cred *cred)
{
    nnpfs_inactive_common (vp, cred);
}

static int
nnpfs_fid(struct vnode *vp,
	struct fid **fid)
{
    return nnpfs_fid_common (vp, fid);
}

static int
nnpfs_fid2(struct vnode *vp,
	 struct fid *fid)
{
    return nnpfs_fid2_common (vp, fid);
}

static void
nnpfs_rwlock(struct vnode *vp,
	   vrwlock_t write_lock)
{
    nnpfs_rwlock_common (vp, write_lock);
}

static void
nnpfs_rwunlock(struct vnode *vp,
	     vrwlock_t write_lock)
{
    nnpfs_rwunlock_common (vp, write_lock);
}

static int
nnpfs_seek(struct vnode *vp,
	 off_t offset,
	 off_t *roffset)
{
    return nnpfs_seek_common (vp, offset, roffset);
}

static int
nnpfs_cmp(struct vnode *vp1,
	struct vnode *vp2)
{
    return nnpfs_cmp_common (vp1, vp2);
}

static int
nnpfs_frlock(struct vnode *vp,
	   int foo,
	   struct flock *fl,
	   int bar,
	   off_t off,
	   struct cred *cred)
{
    return nnpfs_frlock_common (vp, foo, fl, bar, off, cred);
}

static int
nnpfs_realvp(struct vnode *vp,
	   struct vnode **vpp)
{
    return nnpfs_realvp_common (vp, vpp);
}

static int
nnpfs_bmap (struct vnode *vp,
	  off_t off,
	  ssize_t sz,
	  int flags,
	  struct cred *cred,
	  struct bmapval *bv,
	  int *foo)
{
    return nnpfs_bmap_common (vp, off, sz, flags, cred, bv, foo);
}

static void
nnpfs_strategy (struct vnode *vp,
	      struct buf *buf)
{
    nnpfs_strategy_common (vp, buf);
}

static int
nnpfs_map(struct vnode *vp,
	off_t off,
	struct pregion *pregion,
	char **a,
	size_t sz,
	u_int prot,
	u_int max_prot,
	u_int map_flag,
	struct cred *cred)
{
    return nnpfs_map_common (vp, off, pregion, a, sz, prot, max_prot,
			   map_flag, cred);
}

static int
nnpfs_addmap(struct vnode *vp,
	   off_t off,
	   struct pregion *as,
	   addr_t addr,
	   size_t len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
    return nnpfs_addmap_common (vp, off, as, addr, len, prot, maxprot,
			      flags, cred);
}

static int
nnpfs_delmap(struct vnode *vp,
	   off_t off,
	   struct pregion *as,
	   addr_t addr,
	   size_t len,
	   u_int prot,
	   u_int maxprot,
	   u_int flags,
	   struct cred *cred)
{
    return nnpfs_delmap_common (vp, off, as, addr, len, prot, maxprot,
			      flags, cred);
}

static int
nnpfs_poll(struct vnode *vp,
	 short events,
	 int anyyet,
	 short *revents,
	 struct pollhead **ph)
{
    return nnpfs_poll_common (vp, events, anyyet, revents, ph);
}

static int
nnpfs_dump(struct vnode *dumpvp,
	 caddr_t addr,
	 daddr_t darr,
	 u_int foo)
{
    return nnpfs_dump_common (dumpvp, addr, darr, foo);
}

static int
nnpfs_pathconf(struct vnode *vp,
	     int cmd,
	     u_long *valp,
	     struct cred *cred)
{
    return nnpfs_pathconf_common (vp, cmd, valp, cred);
}

static int
nnpfs_allocstore(struct vnode *vp,
	       off_t off,
	       size_t sz,
	       struct cred *cred)
{
    return nnpfs_allocstore_common (vp, off, sz, cred);
}

static int
nnpfs_fcntl(struct vnode *vp,
	  int cmd,
	  void *arg,
	  int foo,
	  off_t off,
	  struct cred *cred,
	  union rval *result)
{
    return nnpfs_fcntl_common (vp, cmd, arg, foo, off, cred, result);
}

static int
nnpfs_reclaim (struct vnode *vp,
	     int foo)
{
    return nnpfs_reclaim_common (vp, foo);
}

static int
nnpfs_attr_get (struct vnode *vp,
	      char *a,
	      char *b,
	      int *c,
	      int d,
	      struct cred *cred)
{
    return nnpfs_attr_get_common (vp, a, b, c, d, cred);
}

static int
nnpfs_attr_set (struct vnode *vp,
	      char *a,
	      char *b,
	      int c,
	      int d,
	      struct cred *cred)
{
    return nnpfs_attr_set_common (vp, a, b, c, d, cred);
}

static int
nnpfs_attr_remove (struct vnode *vp,
		 char *a,
		 int b,
		 struct cred *cred)
{
    return nnpfs_attr_remove_common (vp, a, b, cred);
}

static int
nnpfs_attr_list (struct vnode *vp,
	       char *a,
	       int b,
	       int c,
	       struct attrlist_cursor_kern *k,
	       struct cred *cred)
{
    return nnpfs_attr_list_common (vp, a, b, c, k, cred);
}

struct vnodeops nnpfs_vnodeops = {
        nnpfs_open,
        nnpfs_close,
        nnpfs_read,
        nnpfs_write,
        nnpfs_ioctl,
	nnpfs_setfl,
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
	nnpfs_fid,
	nnpfs_fid2,
	nnpfs_rwlock,
	nnpfs_rwunlock,
	nnpfs_seek,
	nnpfs_cmp,
	nnpfs_frlock,
	nnpfs_realvp,
        nnpfs_bmap,
        nnpfs_strategy,
        nnpfs_map,
	nnpfs_addmap,
	nnpfs_delmap,
	nnpfs_poll,
        nnpfs_dump,
	nnpfs_pathconf,
	nnpfs_allocstore,
	nnpfs_fcntl,
	nnpfs_reclaim,
	nnpfs_attr_get,
	nnpfs_attr_set,
	nnpfs_attr_remove,
	nnpfs_attr_list
};

#endif
