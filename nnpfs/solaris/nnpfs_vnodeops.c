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
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/fs_subr.h>

RCSID("$Id: nnpfs_vnodeops.c,v 1.42 2004/06/13 15:06:27 lha Exp $");

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
    vattr2nnpfs_attr (&xn->attr, &msg.attr);
    msg.flag = flag;
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) & msg)->error;

    if (error == 0)
	xn->flags &= ~NNPFS_DATA_DIRTY;

    return error;
}

static int
nnpfs_open(struct vnode **vpp,
	 int flag,
	 struct cred *cred)
{
    int error = 0;
  
    NNPFSDEB(XDEBVNOPS, ("nnpfs_open\n"));
  
    if (flag & FWRITE)
	error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NW);
    else
	error = nnpfs_open_valid(*vpp, cred, NNPFS_OPEN_NR);
  
    return error;
}

static int
nnpfs_close(struct vnode *vp,
	  int flag,
	  int count,
	  offset_t offset,
	  struct cred *cred)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_close\n"));
  
    if (flag & FWRITE && xn->flags & NNPFS_DATA_DIRTY)
	error = do_fsync (nnpfsp, xn, cred, NNPFS_WRITE);
  
    NNPFSDEB(XDEBVNOPS, ("nnpfs_close: %d\n", error));

    return error;
}

static int
nnpfs_read(struct vnode *vp,
	 struct uio *uio,
	 int ioflag,
	 struct cred *cred)
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_read\n"));

    if (vp->v_type != VREG)
	return EISDIR;

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);

    if (error == 0) {
	struct vnode *t = DATA_FROM_VNODE(vp);
	ASSERT(t != NULL);
	VOP_RWLOCK(t, 0);
	error = VOP_READ(t, uio, ioflag, cred);
	VOP_RWUNLOCK(t, 0);
    }

    return error;
}

static int
nnpfs_write(struct vnode *vp,
	  struct uio *uio,
	  int ioflag,
	  struct cred *cred)
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_write\n"));

    if (vp->v_type != VREG)
	return EISDIR;

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);

    if (error == 0) {
	struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
	struct vnode *t = DATA_FROM_VNODE(vp);
	struct vattr sub_attr;
	int error2 = 0;

	ASSERT(t != NULL);
	VOP_RWLOCK(t, 1);
	error  = VOP_WRITE(t, uio, ioflag, cred);
	error2 = VOP_GETATTR(t, &sub_attr, 0, cred);
	VOP_RWUNLOCK(t, 1);
	VNODE_TO_XNODE(vp)->flags |= NNPFS_DATA_DIRTY;

	if (error2 == 0) {
	    xn->attr.va_size  = sub_attr.va_size;
	    xn->attr.va_mtime = sub_attr.va_mtime;
	}
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_write: %d\n", error));

    return error;
}

static int
nnpfs_ioctl(struct vnode *vp,
	  int cmd,
	  intptr_t arg,
	  int flag,
	  struct cred *cred,
	  int *result)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));
    return ENOSYS;
}

static int
nnpfs_setfl(struct vnode *vp,
	  int oflags,
	  int nflags,
	  struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_setfl\n"));
    return fs_setfl (vp, oflags, nflags, cred);
}

static int
nnpfs_getattr(struct vnode *vp,
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
  
    NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr: size: 0x%lx\n",
		       (unsigned long)xn->attr.va_size));

    return error;
}

static int
nnpfs_setattr(struct vnode *vp,
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
	if (NNPFS_TOKEN_GOT(xn, NNPFS_DATA_R)) {
	    if (vp->v_type == VREG) {
		if (vap->va_mask & AT_SIZE)
		    XA_SET_SIZE(&msg.attr,  vap->va_size);
		else
		    XA_SET_SIZE(&msg.attr,  xn->attr.va_size);
	    }
	    if (vap->va_mask & AT_MTIME)
		XA_SET_MTIME(&msg.attr, vap->va_mtime.tv_sec);
	    else
		XA_SET_MTIME(&msg.attr, xn->attr.va_mtime.tv_sec);
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
nnpfs_access(struct vnode *vp,
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
nnpfs_lookup(struct vnode *dvp,
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
  
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup (%s)\n", nm));
  
    if (*nm == '\0') {
	VN_HOLD(dvp);
	*vpp = dvp;
	error = 0;
	goto done;
    }

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
		error = ENAMETOOLONG;
	    else
		error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
	    if (error == 0)
		error = ((struct nnpfs_message_wakeup *) &msg)->error;
	}
	else
	{
	    *vpp = v;
	    goto done;
	}
    } while (error == 0);

 done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup() = %d\n", error));
    return error;
}

static int
nnpfs_create(struct vnode *dvp,
	   char *nm,
	   struct vattr *va,
	   vcexcl_t exclusive,
	   int mode,
	   struct vnode **vpp,
	   struct cred *cred
#ifdef _LARGEFILE64_SOURCE
	   ,int file_awareness  /* Solaris 2.6+ */
#endif
    )     
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
	error = nnpfs_lookup(dvp, nm, vpp, /*pnp*/ NULL, /*flags*/ 0,
			   /*rdir*/ NULL, cred);

    if (error == 0 && do_trunc)
	error = nnpfs_setattr (*vpp, va, 0, cred);

    return error;
}

static int
nnpfs_remove(struct vnode *dvp,
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
    if (error == 0)
	dnlc_remove(dvp, nm);

    return error;
}

static int
nnpfs_link(struct vnode *tdvp,
	 struct vnode *vp,
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
nnpfs_rename(struct vnode *sdvp,
	   char *onm,
	   struct vnode *tdvp,
	   char *nnm,
	   struct cred *cred)     
{
    struct nnpfs_message_rename msg;
    struct vnode *vp;
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename\n"));

    error = nnpfs_lookup(tdvp, nnm, &vp, /*pnp*/ NULL, /*flags*/ 0,
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
	if (error != 0 && error != ENOENT)
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
	error = nnpfs_lookup(dvp, nm, vpp, /*pnp*/ NULL, /*flags*/ 0,
			   /*rdir*/ NULL, cred);
    return error;
}

static int
nnpfs_rmdir(struct vnode *dvp,
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
    if (strlcpy(msg.name, nm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    msg.cred.uid = cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(cred);
    error = nnpfs_message_rpc(nnpfsp->fd, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;
    if (error == 0)
	dnlc_remove(dvp, nm);

    return error;
}

static int
nnpfs_readdir(struct vnode *vp,
	    struct uio *uiop,
	    struct cred *cred,
	    int *eofp)		/* XXX */
{
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir\n"));

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
    if (error == 0)
    {
	struct vnode *t = DATA_FROM_VNODE(vp);
	ASSERT(t != NULL);
	VOP_RWLOCK(t, 0);
	error = VOP_READ(t, uiop, 0, cred);
	VOP_RWUNLOCK(t, 0);
    }

    return error;
}

static int
nnpfs_symlink(struct vnode *dvp,
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
    if (strlcpy(msg.name, lnm, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
    if (strlcpy(msg.contents, tnm, sizeof(msg.contents)) >= NNPFS_MAX_SYMLINK_CONTENT)
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
nnpfs_readlink(struct vnode *vp,
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
	error = VOP_READ(t, uiop, 0, cred);
	VOP_RWUNLOCK(t, 0);
    }

    return error;
}

static int
nnpfs_fsync(struct vnode *vp,
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

static void
nnpfs_inactive(struct vnode *vp,
	     struct cred *cred)
{
    struct nnpfs_message_inactivenode msg;
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive: 0x%x\n", (int)vp));

    mutex_enter(&vp->v_lock);
    if (vp->v_count != 1) {
	mutex_exit(&vp->v_lock);
	return;
    }
    --vp->v_count;
    mutex_exit(&vp->v_lock);

    mutex_enter(&xn->node_lock);

    msg.header.opcode = NNPFS_MSG_INACTIVENODE;
    msg.handle = xn->handle;
    msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;
    free_nnpfs_node(xn);
    nnpfs_message_send(nnpfsp->fd, &msg.header, sizeof(msg));
}

static int
nnpfs_fid(struct vnode *vp,
	struct fid *fid)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_fid\n"));
    return ENOSYS;
}

static void
nnpfs_rwlock(struct vnode *vp,
	   int write_lock)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rwlock\n"));
}

static void
nnpfs_rwunlock(struct vnode *vp,
	     int write_lock)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rwunlock\n"));
}

static int
nnpfs_seek(struct vnode *vp,
	 offset_t offset,
	 offset_t *roffset)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_seek\n"));
    return 0;
}

static int
nnpfs_cmp(struct vnode *vp1, struct vnode *vp2)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_cmp\n"));
    return vp1 == vp2;
}

static int
nnpfs_frlock(struct vnode *vp,
	   int foo,
#ifdef _LARGEFILE64_SOURCE
	   struct flock64 *fl,
#else
	   struct flock *fl,
#endif
	   int bar,
	   offset_t off,
	   struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_frlock\n"));
    return ENOSYS;
}

static int
nnpfs_space(struct vnode *vp,
	  int cmd,
#ifdef _LARGEFILE64_SOURCE
	  struct flock64 *fl,
#else
	  struct flock *fl,
#endif
	  int flag,
	  offset_t offset,
	  struct cred *cred)
{
    int error = 0;
    struct vattr attr;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_space\n"));

    if (cmd != F_FREESP) {
	error = EINVAL;
	goto done;
    }
      
    error = convoff (vp, fl, 0, offset);
    if (error)
	goto done;

    if (fl->l_len != 0) {
	error = EINVAL;
	goto done;
    }

    attr.va_mask = AT_SIZE;
    attr.va_size = fl->l_start;
    error = nnpfs_setattr (vp, &attr, 0, cred);
 done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_space: %d\n", error));
    return error;
}

static int
nnpfs_realvp(struct vnode *vp,
	   struct vnode **vpp)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_realvp\n"));
    return ENOSYS;
}

static int
nnpfs_getpage(struct vnode *vp,
	    offset_t off,
	    size_t len,
	    uint_t *protp,
	    struct page *pl[],
	    size_t plsz,
	    struct seg *seg,
	    caddr_t addr,
	    enum seg_rw rw,
	    struct cred *cred)
{
    struct vnode *t;
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getpage\n"));

    if (vp->v_flag & VNOMAP)	/* File doesn't allow mapping */
	return (ENOSYS);

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
    if (error)
	return error;

    t = DATA_FROM_VNODE(vp);
    error = VOP_GETPAGE(t, off, len, protp, pl, plsz, seg, addr, rw, cred);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getpage: return %d\n", error));
    return error;
}

static int
nnpfs_putpage(struct vnode *vp,
	    offset_t off,
	    size_t len,
	    int flags,
	    struct cred *cred)
{
    struct vnode *t;
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_putpage\n"));

    if (vp->v_flag & VNOMAP)	/* File doesn't allow mapping */
	return (ENOSYS);

    error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
    if (error)
	return error;
    t = DATA_FROM_VNODE(vp);

    VNODE_TO_XNODE(vp)->flags |= NNPFS_DATA_DIRTY;

    error = VOP_PUTPAGE(t, off, len, flags, cred);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getpage: return %d\n", error));
    return error;
}

static int
nnpfs_map(struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred)
{
    struct segvn_crargs vn_a;
    int error = 0;
    
    NNPFSDEB(XDEBVNOPS,
	   ("nnpfs_map"
	    "(0x%x, 0x%lx, 0x%x, 0x%x, 0x%lx, 0x%x, 0x%x, 0x%x, 0x%x)\n",
	    (int) vp, (unsigned long)off,
	    (int) as, (int) addrp, (unsigned long)len, prot, maxprot,
	    flags, (int) cred));
    
    
    if (vp->v_flag & VNOMAP)
	return ENOSYS;

    if (off < (offset_t)0 || (off + len) < (offset_t)0)
	return EINVAL;

    if (vp->v_type != VREG)
	return ENODEV;

    if (vp->v_filocks != NULL)
	return EAGAIN;

    error = nnpfs_attr_valid (vp, cred, NNPFS_ATTR_R);
    if (error)
	goto out;
    
    if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
	error = nnpfs_data_valid(vp, cred, NNPFS_DATA_W);
    else
	error = nnpfs_data_valid(vp, cred, NNPFS_DATA_R);
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_map: size = %u\n",
		       (unsigned)VNODE_TO_XNODE(vp)->attr.va_size));
    
    if (error != 0)
	/* Can't map today */;
#if 0
    else if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
	error = EROFS;		/* XXX This is currently not supported */
#endif
    else
    {
	as_rangelock(as);
	
	
	if ((flags & MAP_FIXED) == 0) {
	    map_addr(addrp, len, off, 1, flags);
	    if (*addrp == NULL) {
		as_rangeunlock(as);
		return ENOMEM;
	    }
	} else {
	    as_unmap(as, *addrp, len);
	}
	
	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cred;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	
	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);
    }
    
 out:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_map: %d\n", error));
    return error;
}

static int
nnpfs_addmap(struct vnode *vp,
	   offset_t off,
	   struct as *as,
	   caddr_t addr,
	   size_t len,
	   uchar_t prot,
	   uchar_t maxprot,
	   uint_t flags,
	   struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_addmap\n"));
    return 0;
}

static int
nnpfs_delmap(struct vnode *vp,
	   offset_t off,
	   struct as *as,
	   caddr_t addr,
	   size_t len,
	   uint_t prot,
	   uint_t maxprot,
	   uint_t flags,
	   struct cred *cred)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_delmap\n"));

    if (xn->flags & NNPFS_DATA_DIRTY) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_delmap: data dirty\n"));
	error = do_fsync (nnpfsp, xn, cred, NNPFS_WRITE | NNPFS_FSYNC);
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_delmap: %d\n", error));
    return error;
}


static int
nnpfs_poll(struct vnode *vp,
	 short events,
	 int anyyet,
	 short *revents,
	 struct pollhead **ph)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_poll\n"));
    return fs_poll(vp, events, anyyet, revents, ph);
}

static int
nnpfs_dump(struct vnode *dumpvp,
	 caddr_t addr,
	 int bn,
	 int count)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dump\n"));
    return ENOSYS;
}

static int
nnpfs_pathconf(struct vnode *vp,
	     int cmd,
	     u_long *valp,
	     struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_pathconf\n"));
    return fs_pathconf (vp, cmd, valp, cred);
}

static int
nnpfs_pageio(struct vnode *vp,
	   struct page *page,
#ifdef _LARGEFILE64_SOURCE
	   u_offset_t io_off,  /* Solaris 2.6+ */
#else
	   u_int io_off,  /* Solaris 2.5 */
#endif
	   size_t io_len,
	   int flags,
	   struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_pageio\n"));
    return ENOSYS;
}

static int
nnpfs_dumpctl(struct vnode *vp,
	    int flag)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dumpctl\n"));
    return ENOSYS;
}

static void
nnpfs_dispose(struct vnode *vp,
	    struct page *page,
	    int a,
	    int b,
	    struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_dispose\n"));
}

static int
nnpfs_setsecattr(struct vnode *vp,
	       vsecattr_t *attr,
	       int flag,
	       struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_setsecattr\n"));
    return ENOSYS;
}

static int
nnpfs_getsecattr(struct vnode *vp,
	       vsecattr_t *attr,
	       int flag,
	       struct cred *cred)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_getsecattr\n"));
    return fs_fab_acl(vp, attr, flag, cred);
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
    nnpfs_rwlock,
    nnpfs_rwunlock,
    nnpfs_seek,
    nnpfs_cmp,
    nnpfs_frlock,
    nnpfs_space,
    nnpfs_realvp,
    nnpfs_getpage,
    nnpfs_putpage,
    nnpfs_map,
    nnpfs_addmap,
    nnpfs_delmap,
    nnpfs_poll,
    nnpfs_dump,
    nnpfs_pathconf,
    nnpfs_pageio,
    nnpfs_dumpctl,
    nnpfs_dispose,
    nnpfs_setsecattr,
    nnpfs_getsecattr
    /* nnpfs_shrlock */
};
