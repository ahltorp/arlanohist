/*
 * Copyright (c) 1995 - 2007 Kungliga Tekniska Högskolan
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
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_vnodeops.h>
#ifdef HAVE_VM_VNODE_PAGER_H
#include <vm/vnode_pager.h>
#endif

RCSID("$Id: nnpfs_vnodeops-bsd.c,v 1.165 2010/06/16 19:58:51 tol Exp $");


#ifdef HAVE_FREEBSD_THREAD
#define NNPFS_AP_PROC(ap) ((ap)->a_td)
#elif defined(__NetBSD__) && __NetBSD_Version__ >= 399001400 /* 3.99.14 */
#define NNPFS_AP_PROC(ap) ((ap)->a_l)
#else
#define NNPFS_AP_PROC(ap) ((ap)->a_p)
#endif


/*
 * vnode functions
 */

#ifdef HAVE_VOP_OPEN
int
nnpfs_open(struct vop_open_args * ap)
     /*
  struct vop_open {
          struct vnode *vp;
          int mode;
          nnpfs_kernel_cred cred;
          struct proc *p;
#ifdef __FreeBSD__
	  int fdidx;
#endif
  }; */
{
    nnpfs_vfs_context ctx;
    int ret;

    nnpfs_vfs_context_init(ctx, nnpfs_curproc(), ap->a_cred);
    
    ret = nnpfs_open_common(ap->a_vp, ap->a_mode, ctx);
#ifdef __FreeBSD__
    if (!ret)
#ifdef HAVE_THREE_ARGUMENT_VNODE_CREATE_VOBJ
	vnode_create_vobject(ap->a_vp,
#else
	vnode_create_vobject_off(ap->a_vp,
#endif
				 nnpfs_vattr_get_size(&VNODE_TO_XNODE(ap->a_vp)->attr),
				 ap->a_td);
#endif
    return ret;
}
#endif /* HAVE_VOP_OPEN */

#ifdef HAVE_VOP_FSYNC
int
nnpfs_fsync(struct vop_fsync_args * ap)
     /*
  vop_fsync {
	struct vnode *vp;
	nnpfs_kernel_cred cred;
	int waitfor;
	struct proc *p;
};  */
{
#ifdef HAVE_STRUCT_VOP_FSYNC_ARGS_A_FLAGS
    return nnpfs_fsync_common(ap->a_vp, ap->a_cred, NULL, ap->a_flags, NNPFS_AP_PROC(ap));
#else
#if defined(__DragonFly__) || defined(__FreeBSD__)
    return nnpfs_fsync_common(ap->a_vp, ap->a_td->td_proc->p_ucred, NULL,
                              ap->a_waitfor, ap->a_td);
#else
    return nnpfs_fsync_common(ap->a_vp, ap->a_cred, NULL,
			      ap->a_waitfor, NNPFS_AP_PROC(ap));
#endif
#endif
}
#endif /* HAVE_VOP_FSYNC */

#ifdef HAVE_VOP_CLOSE 
int
nnpfs_close(struct vop_close_args * ap)
     /* vop_close {
	IN struct vnode *vp;
	IN int fflag;
	IN nnpfs_kernel_cred cred;
	IN struct proc *p;
  }; */
{
#ifdef __DragonFly__
    return nnpfs_close_common(ap->a_vp, ap->a_fflag, ap->a_td,
                              ap->a_td->td_proc->p_ucred);
#else
    return nnpfs_close_common(ap->a_vp, ap->a_fflag, NNPFS_AP_PROC(ap), ap->a_cred);
#endif
}
#endif /* HAVE_VOP_CLOSE */

#if defined(HAVE_VOP_READ) && !defined(__NetBSD__)
int
nnpfs_read(struct vop_read_args * ap)
     /* vop_read {
	IN struct vnode *vp;
	INOUT struct uio *uio;
	IN int ioflag;
	IN nnpfs_kernel_cred cred;
   }; */
{
    return nnpfs_read_common(ap->a_vp, ap->a_uio, ap->a_ioflag, ap->a_cred);
}
#endif /* HAVE_VOP_READ */

#if defined(HAVE_VOP_WRITE) && !defined(__NetBSD__)
int
nnpfs_write(struct vop_write_args * ap)
     /* vop_write {
	IN struct vnode *vp;
	INOUT struct uio *uio;
	IN int ioflag;
	IN nnpfs_kernel_cred cred;
   }; */
{
    nnpfs_vfs_context ctx;
    nnpfs_vfs_context_init(ctx, nnpfs_curproc(), ap->a_cred);

    return nnpfs_write_common(ap->a_vp, ap->a_uio, ap->a_ioflag, ctx);
}
#endif /* HAVE_VOP_WRITE */

#ifdef HAVE_VOP_IOCTL
int
nnpfs_ioctl(struct vop_ioctl_args * ap)
     /* struct vnode *vp,
	  int com,
	  caddr_t data,
	  int flag,
	  nnpfs_kernel_cred cred) */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));

    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_IOCTL */

#ifdef HAVE_VOP_SELECT
int
nnpfs_select(struct vop_select_args * ap)
     /* struct vnode *vp,
	   int which,
	   nnpfs_kernel_cred cred ) */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_select\n"));

    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_SELECT */

#ifdef HAVE_VOP_SEEK
int
nnpfs_seek(struct vop_seek_args * ap)
     /*
struct vop_seek_args {
        struct vnodeop_desc *a_desc;
        struct vnode *a_vp;
        off_t a_oldoff;
        off_t a_newoff;
        nnpfs_kernel_cred a_cred;
};
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_seek\n"));
    return 0;
}
#endif /* HAVE_VOP_SEEK */

#ifdef HAVE_VOP_POLL
int
nnpfs_poll(struct vop_poll_args * ap)
     /* vop_poll {
	IN struct vnode *vp;
	IN int events;
	IN struct proc *p;
   }; */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_poll\n"));
    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_POLL */

#ifdef HAVE_VOP_GETATTR
int
nnpfs_getattr(struct vop_getattr_args * ap)
     /* struct vnode *vp,
	    struct vattr *vap,
	    nnpfs_kernel_cred cred,
	    struct proc *p) */
{
#ifdef __DragonFly__
    return nnpfs_getattr_common(ap->a_vp, ap->a_vap,
                                ap->a_td->td_proc->p_ucred, ap->a_td);
#else
    return nnpfs_getattr_common(ap->a_vp, ap->a_vap, ap->a_cred, NNPFS_AP_PROC(ap));
#endif
}
#endif /* HAVE_VOP_GETATTR */

#ifdef HAVE_VOP_SETATTR
int
nnpfs_setattr(struct vop_setattr_args * ap)
     /* struct vnode *vp,
	    struct vattr *vap,
	    nnpfs_kernel_cred cred,
	    struct proc *p)
	    */
{
    return nnpfs_setattr_common(ap->a_vp, ap->a_vap, ap->a_cred, NNPFS_AP_PROC(ap));
}
#endif /* HAVE_VOP_SETATTR */

#ifdef HAVE_VOP_ACCESS
int
nnpfs_access(struct vop_access_args * ap)
     /*
struct vnode *vp,
	   int mode,
	   nnpfs_kernel_cred cred,
	   struct proc *p)
	   */
{
    return nnpfs_access_common(ap->a_vp, ap->a_mode, ap->a_cred, NNPFS_AP_PROC(ap));
}
#endif /* HAVE_VOP_ACCESS */

#ifdef HAVE_VOP_LOOKUP
int
nnpfs_lookup(struct vop_lookup_args * ap)
     /* struct vop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
}; */
{
    struct componentname *cnp = ap->a_cnp;
    d_thread_t *p  = nnpfs_cnp_to_proc(cnp);
    nnpfs_kernel_cred cred = nnpfs_proc_to_cred(p);
    nnpfs_vfs_context ctx;
    int error;

#if !defined(__NetBSD__) || (__NetBSD_Version__ < 499000600 && __NetBSD_Version__ >= 49000000) | __NetBSD_Version__  < 400000002
    int lockparent = (cnp->cn_flags & (LOCKPARENT | ISLASTCN))
	== (LOCKPARENT | ISLASTCN);
#endif

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: (%s, %ld), nameiop = %lu, flags = %lu\n",
		       cnp->cn_nameptr,
		       cnp->cn_namelen,
		       cnp->cn_nameiop,
		       cnp->cn_flags));

#ifdef PDIRUNLOCK
    cnp->cn_flags &= ~PDIRUNLOCK;
#endif

    nnpfs_vfs_context_init(ctx, p, cred);
    error = nnpfs_lookup_common(ap->a_dvp, cnp, ap->a_vpp, ctx);

    if (error == ENOENT
	&& (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME)
	&& (cnp->cn_flags & ISLASTCN)) {
	error = EJUSTRETURN;
    }

    if (cnp->cn_nameiop != LOOKUP && cnp->cn_flags & ISLASTCN)
	cnp->cn_flags |= SAVENAME;

#if !defined(__NetBSD__) || (__NetBSD_Version__ < 499000600 && __NetBSD_Version__ >= 49000000) | __NetBSD_Version__  < 400000002
    if (error == 0 || error == EJUSTRETURN) {
	if (ap->a_dvp == *(ap->a_vpp)) {
	    /* if we looked up ourself, do nothing */
	} else if (!(cnp->cn_flags & ISLASTCN) || !lockparent) {
	    /* if we isn't last component and is isn't requested,
	     * return parent unlocked */

	    /* FreeBSD 6 cache_lookup() takes care of locking for us. */
#ifndef __FreeBSD__
	    nnpfs_vfs_unlock (ap->a_dvp, p);
#ifdef PDIRUNLOCK
	    cnp->cn_flags |= PDIRUNLOCK;
#endif
#endif
	}
    } else {
	/* in case of a error do nothing  */
    } 
#endif
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: error = %d\n", error));

    return error;
}
#endif /* HAVE_VOP_LOOKUP */

#ifdef HAVE_VOP_CACHEDLOOKUP
int
nnpfs_cachedlookup(struct vop_cachedlookup_args * ap)
     /* struct vop_cachedlookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
}; */
{
    return nnpfs_lookup((struct vop_lookup_args *)ap);
}
#endif /* HAVE_VOP_CACHEDLOOKUP */

/*
 * whatever clean-ups are needed for a componentname.
 */

static void
cleanup_cnp (struct componentname *cnp, int error)
{
    if (error != 0 || (cnp->cn_flags & SAVESTART) == 0) {
#if defined(HAVE_KERNEL_ZFREEI)
	zfreei(namei_zone, cnp->cn_pnbuf);
	cnp->cn_flags &= ~HASBUF;
#elif defined(HAVE_KERNEL_UMA_ZFREE_ARG)
	uma_zfree_arg(namei_zone, cnp->cn_pnbuf, NULL);
	cnp->cn_flags &= ~HASBUF;
#elif defined(FREE_ZONE)
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
#elif defined(HAVE_KERNEL_ZFREE)
	zfree(namei_zone, cnp->cn_pnbuf);
	cnp->cn_flags &= ~HASBUF;
#elif defined(PNBUF_PUT)
	PNBUF_PUT(cnp->cn_pnbuf);
#else
	FREE (cnp->cn_pnbuf, M_NAMEI);
#endif
    }
}

#ifdef HAVE_VOP_CREATE
int
nnpfs_create(struct vop_create_args *ap)
{
    struct vnode *dvp  = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    const char *name   = cnp->cn_nameptr;
    nnpfs_kernel_cred cred = cnp->cn_cred;
    d_thread_t *p     = nnpfs_cnp_to_proc(cnp);
    nnpfs_vfs_context ctx;
    int error;

    nnpfs_vfs_context_init(ctx, p, cred);
    error = nnpfs_create_common(dvp, name, ap->a_vap, cred, p);

    if (error == 0) {
	error = nnpfs_lookup_common(dvp, cnp, ap->a_vpp, ctx);
    }

    cleanup_cnp (cnp, error);

#if defined(__NetBSD__) || defined(__OpenBSD__)
    vput (dvp);
#endif

    NNPFSDEB(XDEBVNOPS, ("nnpfs_create: error = %d\n", error));
    
    return error;
}
#endif /* HAVE_VOP_CREATE */

#ifdef HAVE_VOP_REMOVE
int
nnpfs_remove(struct vop_remove_args * ap)
     /* struct vnode *dvp,
   struct vnode *vp,
   struct componentname *cnp */
{
    struct componentname *cnp = ap->a_cnp;
    struct vnode *dvp = ap->a_dvp;
    struct vnode *vp  = ap->a_vp;

    int error = nnpfs_remove_common(dvp, vp, cnp->cn_nameptr, 
				    cnp->cn_cred, nnpfs_cnp_to_proc(cnp));

    cleanup_cnp (cnp, error);

#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    if (dvp == vp)
	vrele(vp);
    else
	vput(vp);
    vput(dvp);
#endif
    
    return error;
}
#endif /* HAVE_VOP_REMOVE */

#ifdef HAVE_VOP_RENAME
int
nnpfs_rename(struct vop_rename_args * ap)
     /* vop_rename {
	IN WILLRELE struct vnode *fdvp;
	IN WILLRELE struct vnode *fvp;
	IN struct componentname *fcnp;
	IN WILLRELE struct vnode *tdvp;
	IN WILLRELE struct vnode *tvp;
	IN struct componentname *tcnp;
  }; */
{
    struct vnode *tdvp = ap->a_tdvp;
    struct vnode *tvp  = ap->a_tvp;
    struct vnode *fdvp = ap->a_fdvp;
    struct vnode *fvp  = ap->a_fvp;

    int error = nnpfs_rename_common(fdvp,
				  fvp,
				  ap->a_fcnp->cn_nameptr,
				  tdvp,
				  tvp,
				  ap->a_tcnp->cn_nameptr,
				  ap->a_tcnp->cn_cred,
				  nnpfs_cnp_to_proc (ap->a_fcnp));
    if(tdvp == tvp)
	vrele(tdvp);
    else
	vput(tdvp);
    if(tvp)
	vput(tvp);
    vrele(fdvp);
    vrele(fvp);
    return error;
}
#endif /* HAVE_VOP_RENAME */

#ifdef HAVE_VOP_MKDIR
int
nnpfs_mkdir(struct vop_mkdir_args * ap)
     /* struct vnode *dvp,
	  char *nm,
	  struct vattr *va,
	  struct vnode **vpp,
	  nnpfs_kernel_cred cred)      */
{
    struct vnode *dvp  = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    const char *name   = cnp->cn_nameptr;
    nnpfs_kernel_cred cred = cnp->cn_cred;
    d_thread_t *p     = nnpfs_cnp_to_proc(cnp);
    nnpfs_vfs_context ctx;
    int error;

    nnpfs_vfs_context_init(ctx, p, cred);
    error = nnpfs_mkdir_common(dvp, name, ap->a_vap, cred, p);

    if (error == 0)
	error = nnpfs_lookup_common(dvp, cnp, ap->a_vpp, ctx);

    cleanup_cnp (cnp, error);

#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    vput(dvp);
#endif

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir: error = %d\n", error));

    return error;
}
#endif /* HAVE_VOP_MKDIR */

#ifdef HAVE_VOP_RMDIR
int
nnpfs_rmdir(struct vop_rmdir_args * ap)
     /* struct vnode *dvp,
   struct vnode *vp,
   struct componentname *cnp */
{
    struct componentname *cnp = ap->a_cnp;
#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    struct vnode *dvp = ap->a_dvp;
    struct vnode *vp  = ap->a_vp;
#endif
    
    int error = nnpfs_rmdir_common(ap->a_dvp, ap->a_vp, 
				   cnp->cn_nameptr,
				   cnp->cn_cred,
				   nnpfs_cnp_to_proc(cnp));
    
    cleanup_cnp (cnp, error);
#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    if (dvp == vp)
	vrele(vp);
    else
	vput(vp);
    vput(dvp);
#endif

    return error;
}
#endif /* HAVE_VOP_RMDIR */

#ifdef HAVE_VOP_READDIR

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
typedef u_long nnpfs_cookie_t;
#elif defined(__NetBSD__)
typedef off_t nnpfs_cookie_t;
#else
#error dunno want kind of cookies you have
#endif

int
nnpfs_readdir(struct vop_readdir_args * ap)
     /* struct vnode *vp,
	    struct uio *uiop,
	    nnpfs_kernel_cred cred) */
{
    nnpfs_vfs_context ctx;
    int error;
    off_t off;

    nnpfs_vfs_context_init(ctx, nnpfs_curproc(), ap->a_cred);
    off = nnpfs_uio_offset(ap->a_uio);

    error = nnpfs_readdir_common(ap->a_vp, ap->a_uio, ap->a_eofflag, ctx);

    if (!error && ap->a_ncookies != NULL) {
	struct uio *uio = ap->a_uio;
	const struct dirent *dp, *dp_start, *dp_end;
	int ncookies;
	nnpfs_cookie_t *cookies, *cookiep;

#if 0
	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1)
	    panic("nnpfs_readdir: mail arla-drinkers and tell them to bake burned cookies");
#endif
	dp = (const struct dirent *)
	    ((const char *)uio->uio_iov->iov_base - (nnpfs_uio_offset(uio) - off));

	dp_end = (const struct dirent *) uio->uio_iov->iov_base;
	for (dp_start = dp, ncookies = 0;
	     dp < dp_end;
	     dp = (const struct dirent *)((const char *) dp + dp->d_reclen)) {
	    if (dp->d_reclen <= 0)
		break;
	    ncookies++;
	}

#if (defined(__OpenBSD__) && OpenBSD >= 200811)
	cookies = malloc(ncookies * sizeof(nnpfs_cookie_t), M_TEMP, M_WAITOK);
#else
	MALLOC(cookies, nnpfs_cookie_t *, ncookies * sizeof(nnpfs_cookie_t),
	       M_TEMP, M_WAITOK);
#endif
	for (dp = dp_start, cookiep = cookies;
	     dp < dp_end;
	     dp = (const struct dirent *)((const char *) dp + dp->d_reclen)) {
	    if (dp->d_reclen <= 0)
		break;
	    off += dp->d_reclen;
	    *cookiep++ = off;
	}
	*ap->a_cookies = cookies;
	*ap->a_ncookies = ncookies;
    }
    return error;
}
#endif

#ifdef HAVE_VOP_LINK
int
nnpfs_link(struct vop_link_args * ap)
     /*
	WILLRELE struct vnode *tdvp;
	struct vnode *vp;
	struct componentname *cnp;
	*/
{
    struct componentname *cnp = ap->a_cnp;
    struct vnode *vp = ap->a_vp;
    struct vnode *dvp;
    int error;

#if defined (__OpenBSD__) || defined(__NetBSD__)
    dvp = ap->a_dvp;
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    dvp = ap->a_tdvp;
#else
#error what kind of BSD is this?
#endif

    if (vp->v_type == VDIR) {
#ifdef HAVE_VOP_ABORTOP
	    VOP_ABORTOP(dvp, cnp);
#endif
	    error = EPERM;
	    goto out;
    }
    if (dvp->v_mount != vp->v_mount) {
#ifdef HAVE_VOP_ABORTOP
	    VOP_ABORTOP(dvp, cnp);
#endif
	    error = EXDEV;
	    goto out;
    }
    /* FreeBSD 5.0 doesn't need to lock the vnode in VOP_LINK */
#if !defined(__FreeBSD_version) || __FreeBSD_version < 500043
    
    if (dvp != vp && (error = nnpfs_vfs_writelock(vp,
						  nnpfs_cnp_to_proc(cnp)))) {
#ifdef HAVE_VOP_ABORTOP
	    VOP_ABORTOP(dvp, cnp);
#endif
	    goto out;
    }
#endif /* defined(__FreeBSD_version) || __FreeBSD_version < 500043 */
    
    error = nnpfs_link_common(dvp,
			      vp,
			      cnp->cn_nameptr,
			      cnp->cn_cred,
			      nnpfs_cnp_to_proc (cnp));

    cleanup_cnp (cnp, error);

#if !defined(__FreeBSD_version) || __FreeBSD_version < 500043
    if (dvp != vp)
	nnpfs_vfs_unlock(vp, nnpfs_cnp_to_proc(cnp));
#endif

out:
#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    vput(dvp);
#endif

    return error;
}
#endif /* HAVE_VOP_LINK */

#ifdef HAVE_VOP_SYMLINK
int
nnpfs_symlink(struct vop_symlink_args * ap)
     /*
  IN WILLRELE struct vnode *dvp;
  OUT WILLRELE struct vnode **vpp;
  IN struct componentname *cnp;
  IN struct vattr *vap;
  IN char *target;
  */
{
    struct componentname *cnp = ap->a_cnp;
    d_thread_t *proc  = nnpfs_cnp_to_proc(cnp);
    nnpfs_kernel_cred cred = nnpfs_proc_to_cred(proc);
    nnpfs_vfs_context ctx;
    struct vnode *dvp  = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    int error;

    nnpfs_vfs_context_init(ctx, proc, cred);
    error = nnpfs_symlink_common(dvp,
				 vpp,
				 cnp,
				 ap->a_vap,
				 ap->a_target,
				 ctx);
    if (error == 0) {
	error = nnpfs_lookup_common(dvp, cnp, vpp, ctx);
#if (!defined(__FreeBSD__) || __FreeBSD_version < 400012) && (!defined(__NetBSD__) || __NetBSD_Version__ < 105240000) && !defined(__DragonFly__)
	if (error == 0)
	    vput (*vpp);
#endif
    }
    cleanup_cnp (cnp, error);
#if !(defined(__FreeBSD__) || defined(__DragonFly__))
    if (error || dvp != *vpp)
        vput(dvp);
#endif

    return error;
}
#endif /* HAVE_VOP_SYMLINK */


int
nnpfs_readlink(struct vop_readlink_args * ap)
     /* struct vnode *vp,
	     struct uio *uiop,
	     nnpfs_kernel_cred cred) */
{
    nnpfs_vfs_context ctx;
    nnpfs_vfs_context_init(ctx, nnpfs_curproc(), ap->a_cred);

    return nnpfs_readlink_common(ap->a_vp, ap->a_uio, ctx);
}

#ifdef HAVE_VOP_INACTIVE
int
nnpfs_inactive(struct vop_inactive_args * ap)
{
#ifdef HAVE_FREEBSD_THREAD
    return nnpfs_inactive_common(ap->a_vp, ap->a_td);
#else
    return nnpfs_inactive_common(ap->a_vp, nnpfs_curproc());
#endif
}
#endif /* HAVE_VOP_INACTICE */

#ifdef HAVE_VOP_RECLAIM
int
nnpfs_reclaim(struct vop_reclaim_args * ap)
     /*struct vop_reclaim_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
};*/
{
    struct vnode *vp = ap->a_vp;
    int ret;

#ifdef __FreeBSD__
    vnode_destroy_vobject(vp);
    /* vfs_hash_remove(vp); */
#endif

    ret = nnpfs_reclaim_common(vp);
    vp->v_data = NULL;

    return ret;
}
#endif /* HAVE_VOP_RECLAIM */

/*
 * Do lock, unlock, and islocked with lockmgr if we have it.
 */

#if defined(HAVE_KERNEL_LOCKMGR) || defined(HAVE_KERNEL_DEBUGLOCKMGR)

static void
nnpfs_lk_info(char *msg, struct vnode *vp)
{
#ifdef NNPFS_DEBUG
#ifdef __FreeBSD__
    nnpfs_vnode_lock *l = vp->v_vnlock;
#else
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_vnode_lock *l = &xn->lock;
#endif

    NNPFSDEB(XDEBVNOPS, ("%s: lk flags: %d share: %d "
			 "wait: %d excl: %d holder: 0x%llx\n",
			 msg, l->lk_flags, l->lk_sharecount,
			 l->lk_waitcount, l->lk_exclusivecount,
			 (unsigned long long)
			 (nnpfs_uintptr_t)l->lk_lockholder));
#endif
}

#ifdef __FreeBSD__

int
#ifdef HAVE_VOP_LOCK1
nnpfs_lock1(struct vop_lock1_args * ap)
#else
nnpfs_lock(struct vop_lock_args * ap)
#endif
{               
    struct vnode *vp = ap->a_vp;
    int ret;

    nnpfs_assert(vp);
#ifdef HAVE_VOP_LOCK1
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lock1: %lx, flags 0x%x\n",
			 (unsigned long)vp, ap->a_flags));
#else
    nnpfs_assert(ap->a_td);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lock: %lx, td %p, flags 0x%x, nlocks %d\n",
			 (unsigned long)vp, NNPFS_AP_PROC(ap), ap->a_flags,
			 NNPFS_AP_PROC(ap)->td_locks));
#endif

    nnpfs_lk_info("nnpfs_lock before", vp);
    ret = vop_stdlock(ap);
    nnpfs_lk_info("nnpfs_lock after", vp);

    return ret;
}

int
nnpfs_unlock(struct vop_unlock_args * ap)
{
    struct vnode *vp = ap->a_vp;
    int ret;

#ifdef HAVE_TWO_ARGUMENT_VOP_UNLOCK
    NNPFSDEB(XDEBVNOPS,
	     ("nnpfs_unlock: %lx, flags 0x%x\n", (unsigned long)vp,
	      ap->a_flags));
#else
    NNPFSDEB(XDEBVNOPS,
	     ("nnpfs_unlock: %lx, td %p, flags 0x%x, nlocks %d\n",
	      (unsigned long)vp, ap->a_td, ap->a_flags,
	      NNPFS_AP_PROC(ap)->td_locks));
#endif
    
    nnpfs_lk_info("nnpfs_unlock before", vp);
    ret = vop_stdunlock(ap);

#ifdef HAVE_TWO_ARGUMENT_VOP_UNLOCK
    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: return %d\n", ret));
#else
    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: return %d, td %p, nlocks %d\n",
			 ret, NNPFS_AP_PROC(ap), NNPFS_AP_PROC(ap)->td_locks));
#endif
    return ret;
}

int
nnpfs_islocked (struct vop_islocked_args *ap)
{
    struct vnode *vp = ap->a_vp;
    int ret;

    nnpfs_lk_info("nnpfs_islocked", vp);
    ret = vop_stdislocked(ap);
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_islocked(%lx) -> 0x%lx\n",
			 (unsigned long)vp, (unsigned long)ret));
    return ret;
}

#else /* !__FreeBSD__ */

#ifdef HAVE_VOP_LOCK

int
nnpfs_lock(struct vop_lock_args * ap)
{               
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_vnode_lock *l = &xn->lock;
    int flags           = ap->a_flags;
    int ret;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lock: %lx, flags 0x%x\n",
			 (unsigned long)vp, flags));
	     
    if (l == NULL)
	panic("nnpfs_lock: lock NULL");

    nnpfs_lk_info("nnpfs_lock before", vp);

#ifndef	DEBUG_LOCKS
#ifdef HAVE_FOUR_ARGUMENT_LOCKMGR
#ifdef __DragonFly__
    ret = lockmgr(l, flags, ap->a_vlock, ap->a_td);
#else
    ret = lockmgr(l, flags, &vp->v_interlock, NNPFS_AP_PROC(ap));
#endif
#else
#if (defined(__OpenBSD__) && OpenBSD >= 200805)
    ret = lockmgr(l, flags, NULL);
#else
    ret = lockmgr(l, flags, &vp->v_interlock);
#endif
#endif
#else
    ret = debuglockmgr(l, flags, &vp->v_interlock, NNPFS_AP_PROC(ap),
		       "nnpfs_lock", ap->a_vp->filename, ap->a_vp->line);
#endif

    nnpfs_lk_info("nnpfs_lock after", vp);

    return ret;
}

#endif /* HAVE_VOP_LOCK */

#ifdef HAVE_VOP_UNLOCK
int
nnpfs_unlock(struct vop_unlock_args * ap)
{
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_vnode_lock *l   = &xn->lock;
    int flags           = ap->a_flags;
    int ret;

    if (l == NULL)
	panic("nnpfs_unlock: lock NULL");

    NNPFSDEB(XDEBVNOPS,
	     ("nnpfs_unlock: %lx, flags 0x%x, l %lx\n",
	      (unsigned long)vp, flags, (unsigned long)l));
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: lk flags: %d share: %d "
			 "wait: %d excl: %d holder: 0x%llx\n",
			 l->lk_flags, l->lk_sharecount, l->lk_waitcount,
			 l->lk_exclusivecount, 
			 (unsigned long long)
			 (nnpfs_uintptr_t)l->lk_lockholder));

#ifndef	DEBUG_LOCKS
#ifdef HAVE_FOUR_ARGUMENT_LOCKMGR
#ifdef __DragonFly__
    ret = lockmgr (l, flags | LK_RELEASE, ap->a_vlock, ap->a_td);
#else
    ret = lockmgr (l, flags | LK_RELEASE, &vp->v_interlock, NNPFS_AP_PROC(ap));
#endif
#else
#if (defined(__OpenBSD__) && OpenBSD >= 200805)
    ret = lockmgr (l, flags | LK_RELEASE, NULL);
#else
    ret = lockmgr (l, flags | LK_RELEASE, &vp->v_interlock);
#endif
#endif
#else
    ret = debuglockmgr (l, flags | LK_RELEASE, &vp->v_interlock, NNPFS_AP_PROC(ap),
			"nnpfs_lock", ap->a_vp->filename, ap->a_vp->line);
#endif

    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: return %d\n", ret));
    return ret;
}
#endif /* HAVE_VOP_UNLOCK */

#ifdef HAVE_VOP_ISLOCKED
int
nnpfs_islocked (struct vop_islocked_args *ap)
{
    struct vnode *vp = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int ret;

#if defined(HAVE_TWO_ARGUMENT_LOCKSTATUS)
    ret = lockstatus(&xn->lock, NNPFS_AP_PROC(ap));
#elif defined(HAVE_ONE_ARGUMENT_LOCKSTATUS)
    ret = lockstatus(&xn->lock);
#else
#error what lockstatus?
#endif
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_islocked(%lx) -> 0x%lx\n",
			 (unsigned long)vp, (unsigned long)ret));
    return ret;
}
#endif /* HAVE_VOP_ISLOCKED */
#endif /* !__FreeBSD__ */

#else /* !HAVE_KERNEL_LOCKMGR && !HAVE_KERNEL_DEBUGLOCKMGR */

#ifdef HAVE_VOP_LOCK
int
nnpfs_lock(struct vop_lock_args * ap)
{
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lock: %lx, %d\n",
		       (unsigned long)vp, xn->vnlocks));

    while (vp->v_flag & VXLOCK) {
	vp->v_flag |= VXWANT;
	(void) nnpfs_tsleep((caddr_t)vp, PINOD, "nnpfs_vnlock");
    }
    if (vp->v_tag == VT_NON)
	return (ENOENT);
    ++xn->vnlocks;
    return 0;
}
#endif /* HAVE_VOP_LOCK */

#ifdef HAVE_VOP_UNLOCK
int
nnpfs_unlock(struct vop_unlock_args * ap)
{
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: %lx, %d\n",
		       (unsigned long)vp, xn->vnlocks));

    --xn->vnlocks;
    if (xn->vnlocks < 0) {
	printf ("PANIC: nnpfs_unlock: unlocking unlocked\n");
	xn->vnlocks = 0;
    }
    NNPFSDEB(XDEBVNOPS, ("nnpfs_unlock: return\n"));

    return 0;
}
#endif /* HAVE_VOP_UNLOCK */

#ifdef HAVE_VOP_ISLOCKED
int
nnpfs_islocked (struct vop_islocked_args *ap)
{
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_islocked: %lx, %d\n",
		       (unsigned long)vp, xn->vnlocks));

    return xn->vnlocks;
}
#endif /* HAVE_VOP_ISLOCKED */
#endif /* !HAVE_KERNEL_LOCKMGR */

#ifdef HAVE_VOP_ABORTOP
int
nnpfs_abortop (struct vop_abortop_args *ap)
     /* struct vnode *dvp;
   struct componentname *cnp; */
{
    struct componentname *cnp = ap->a_cnp;

    if ((cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF)
#if defined(HAVE_KERNEL_ZFREEI)
	zfreei(namei_zone, cnp->cn_pnbuf);
	ap->a_cnp->cn_flags &= ~HASBUF;
#elif defined(HAVE_KERNEL_UMA_ZFREE_ARG)
	uma_zfree_arg(namei_zone, cnp->cn_pnbuf, NULL);
	cnp->cn_flags &= ~HASBUF;
#elif defined(FREE_ZONE)
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
#elif defined(HAVE_KERNEL_ZFREE)
	zfree(namei_zone, cnp->cn_pnbuf);
	ap->a_cnp->cn_flags &= ~HASBUF;
#elif defined(PNBUF_PUT)
	PNBUF_PUT(cnp->cn_pnbuf);
#else
	FREE(cnp->cn_pnbuf, M_NAMEI);
#endif
    return 0;
}
#endif /* HAVE_VOP_ABORTOP */

#ifdef HAVE_VOP_MMAP
int
nnpfs_mmap(struct vop_mmap_args *ap)
     /*
	IN struct vnode *vp;
	IN int fflags;
	IN nnpfs_kernel_cred cred;
	IN struct proc *p;
	*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap\n"));
#ifdef HAVE_KERNEL_GENFS_MMAP
    return genfs_mmap(ap);
#else
    return EOPNOTSUPP;
#endif
}
#endif /* HAVE_VOP_MMAP */

#if defined(HAVE_VOP_BMAP) && !defined(__NetBSD__)
int
nnpfs_bmap(struct vop_bmap_args *ap)
     /*	IN struct vnode *vp;
	IN daddr_t bn;
	OUT struct vnode **vpp;
	IN daddr_t *bnp;
	OUT int *runp;
	OUT int *runb;
	*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_bmap\n"));
    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_BMAP */

#ifdef HAVE_VOP_GETPAGES

#ifdef __FreeBSD__
int
nnpfs_getpages (struct vop_getpages_args *ap)
     /*
       struct vnodeop_desc *a_desc;
       struct vnode *a_vp;
       vm_page_t *a_m;
       int a_count;
       int a_reqpage;
       vm_ooffset_t a_offset;
     */
{
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getpages\n"));

    error = vnode_pager_generic_getpages (ap->a_vp, ap->a_m, 
					  ap->a_count, ap->a_reqpage);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getpages = %d\n", error));
    return error;
}
#endif

#endif /* HAVE_VOP_GETPAGES */

#ifdef HAVE_VOP_PUTPAGES

#ifdef __FreeBSD__
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

int
nnpfs_putpages (struct vop_putpages_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	vm_page_t *a_m;
	int a_count;
	int a_sync;
	int *a_rtvals;
	vm_ooffset_t a_offset;
     */
{
    struct vnode *vp    = ap->a_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int ret;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_putpages\n"));

    xn->flags |= NNPFS_DATA_DIRTY;

    ret = vnode_pager_generic_putpages(ap->a_vp, ap->a_m, ap->a_count,
				       ap->a_sync, ap->a_rtvals);
    if (ret)
        printf("nnpfs_putpages: -> %d\n", ret);

    return ret;
}
#endif /* __FreeBSD__ */
#endif /* HAVE_VOP_PUTPAGES */

#ifdef HAVE_VOP_CMP
int
nnpfs_cmp(struct vnode * vp1, struct vnode * vp2)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_cmp\n"));
    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_CMP */

#ifdef HAVE_VOP_REALVP
int
nnpfs_realvp(struct vnode * vp,
	   struct vnode ** vpp)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_realvp\n"));
    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_REALVP */

#ifdef HAVE_VOP_CNTL
int
nnpfs_cntl(struct vnode * vp,
	 int cmd,
	 caddr_t idata,
	 caddr_t odata,
	 int iflag,
	 int oflag)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_cntl\n"));
    return EOPNOTSUPP;
}
#endif /* HAVE_VOP_CNTL */

#ifdef HAVE_VOP_PRINT
int
nnpfs_print (struct vop_print_args *v)
{
    struct vop_print_args /* {
	struct vnode	*a_vp;
    } */ *ap = v;
    nnpfs_printnode_common (ap->a_vp);
    return 0;
}
#endif

#ifdef HAVE_VOP_ADVLOCK
int
nnpfs_advlock(struct vop_advlock_args *v)
{
    struct vop_advlock_args /* {
	struct vnode *a_vp;
	caddr_t  a_id;
	int  a_op;
	struct flock *a_fl;
	int  a_flags;
    } */ *ap = v;
#if 0
    struct nnpfs_node *xn = VNODE_TO_XNODE(ap->a_vp);
    int ret;
    nnpfs_locktype_t locktype;

/*     if (NNPFS_TOKEN_GOT(xn,  */

    if (ap->a_fl.l_start != 0 ||
	ap->a_fl.l_end != 0)
	printf ("WARN: someone is trying byte-range locking\n");
    
    switch (ap->a_op) {
    case F_SETLCK:
	locktype = NNPFS_READLOCK;
	break;

    ret = nnpfs_advlock_common (xn, );

    return ret;
#elif defined(HAVE_KERNEL_LF_ADVLOCK)
    struct nnpfs_node *xn = VNODE_TO_XNODE(ap->a_vp);
 
#ifdef __OpenBSD__
    return lf_advlock(&xn->lockf, nnpfs_vattr_get_size(&xn->attr), ap->a_id,
		      ap->a_op, ap->a_fl, ap->a_flags);
#else
    return lf_advlock(ap, &xn->lockf, nnpfs_vattr_get_size(&xn->attr));
#endif /* __OpenBSD__ */
#else
     return EOPNOTSUPP;
#endif
}
#endif /* HAVE_VOP_ADVOCK */

#if defined(HAVE_VOP_REVOKE) && !defined(__NetBSD__)
int
nnpfs_revoke(struct vop_revoke_args *v)
{
#if defined(HAVE_KERNEL_GENFS_REVOKE)
    return genfs_revoke (v);
#elif defined(HAVE_KERNEL_VOP_REVOKE)
    return vop_revoke (v);
#else
    return EOPNOTSUPP;
#endif
}
#endif /* HAVE_VOP_REVOKE */

#ifdef HAVE_VOP_CREATEVOBJECT
int
nnpfs_createvobject(struct vop_createvobject_args *ap)
/*
struct vop_createvobject_args {
	struct vnode *vp;
	nnpfs_kernel_cred cred;
	struct proc *p;
};
 */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_createvobject\n"));

    return vop_stdcreatevobject (ap);
}
#endif /* HAVE_VOP_CREATEVOBJECT */

#ifdef HAVE_VOP_DESTROYVOBJECT
int
nnpfs_destroyvobject(struct vop_destroyvobject_args *ap)
/*
struct vop_destroyvobject_args {
	struct vnode *vp;
};
 */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_destroyvobject\n"));

    return vop_stddestroyvobject (ap);
}
#endif /* HAVE_VOP_DESTROYVOBJECT */

#ifdef HAVE_VOP_GETVOBJECT
int
nnpfs_getvobject(struct vop_getvobject_args *ap)
/*
struct vop_getvobject_args {
	struct vnode *vp;
	struct vm_object **objpp;
};
 */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_getvobject\n"));

    return vop_stdgetvobject (ap);
}
#endif /* HAVE_VOP_GETVOBJECT */

#ifdef HAVE_VOP_PATHCONF
int
nnpfs_pathconf(struct vop_pathconf_args *ap)
/*
struct vop_pathconf_args {
        struct vnodeop_desc *a_desc;
        struct vnode *a_vp;
        int a_name;
};
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_pathconf\n"));

#ifdef HAVE_KERNEL_VOP_STDPATHCONF
    return vop_stdpathconf(ap);
#else
    return EOPNOTSUPP;
#endif
}
#endif

#ifdef HAVE_VOP_VPTOFH
int
nnpfs_vptofh(struct vop_vptofh_args *ap)
/*
struct vop_vptofh_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct fid *a_fhp;
};
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_vptofh\n"));

    return EOPNOTSUPP;
}
#endif



vop_t **nnpfs_vnodeop_p;

int
nnpfs_eopnotsupp (struct vop_generic_args *ap)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_eopnotsupp %s\n", ap->a_desc->vdesc_name));
    return EOPNOTSUPP;
}

int
nnpfs_returnzero (struct vop_generic_args *ap)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_returnzero %s\n", ap->a_desc->vdesc_name));
    return 0;
}

void
nnpfs_pushdirty(struct vnode *vp)
{
#ifdef __NetBSD__
    if ((vp->v_flag & VONWORKLST) == 0)
	return;
    simple_lock(&vp->v_interlock);
    VOP_PUTPAGES(vp, 0, 0, PGO_ALLPAGES|PGO_SYNCIO|PGO_CLEANIT);
#endif
}

#ifdef __FreeBSD__

static void
filt_nnpfsdetach(struct knote *kn)
{
    struct vnode *vp = (struct vnode *)kn->kn_hook;
    knlist_remove(&vp->v_pollinfo->vpi_selinfo.si_note, kn, 0);
}

static int
filt_nnpfsread(struct knote *kn, long hint)
{
    struct vnode *vp = (struct vnode *)kn->kn_hook;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

    if (hint == NOTE_REVOKE)
	kn->kn_flags |= (EV_EOF | EV_ONESHOT);

    kn->kn_data = nnpfs_vattr_get_size(&xn->attr) - kn->kn_fp->f_offset;
    return (kn->kn_data != 0);

    kn->kn_data = 0;
    return (1);
}

static int
filt_nnpfswrite(struct knote *kn, long hint)
{
    if (hint == NOTE_REVOKE)
	kn->kn_flags |= (EV_EOF | EV_ONESHOT);

    kn->kn_data = 0;
    return (1);
}

static int
filt_nnpfsvnode(struct knote *kn, long hint)
{
    if (kn->kn_sfflags & hint)
	kn->kn_fflags |= hint;
    if (hint == NOTE_REVOKE) {
	kn->kn_flags |= EV_EOF;
	return (1);
    }
    return (kn->kn_fflags != 0);
}

static struct filterops nnpfsread_filtops = 
	{ 1, NULL, filt_nnpfsdetach, filt_nnpfsread };
static struct filterops nnpfswrite_filtops = 
	{ 1, NULL, filt_nnpfsdetach, filt_nnpfswrite };
static struct filterops nnpfsvnode_filtops = 
	{ 1, NULL, filt_nnpfsdetach, filt_nnpfsvnode };

int
nnpfs_kqfilter(struct vop_kqfilter_args *ap)
{
    struct vnode *vp = ap->a_vp;
    struct knote *kn = ap->a_kn;

    switch (kn->kn_filter) {
    case EVFILT_READ:
	kn->kn_fop = &nnpfsread_filtops;
	break;
    case EVFILT_WRITE:
	kn->kn_fop = &nnpfswrite_filtops;
	break;
    case EVFILT_VNODE:
	kn->kn_fop = &nnpfsvnode_filtops;
	break;
    default:
	return (1);
    }

    kn->kn_hook = (caddr_t)vp;

    if (vp->v_pollinfo == NULL)
	v_addpollinfo(vp);
    if (vp->v_pollinfo == NULL)
	return ENOMEM;
    knlist_add(&vp->v_pollinfo->vpi_selinfo.si_note, kn, 0);

    return (0);
}

#endif /* !__FreeBSD__ */

#ifdef __FreeBSD__

struct vop_vector nnpfs_vnodeops = {
	.vop_default =		&default_vnodeops,
	.vop_access =   	nnpfs_access,
	.vop_advlock =  	nnpfs_advlock,
	.vop_close =    	nnpfs_close,
	.vop_create =   	nnpfs_create,
	.vop_fsync =    	nnpfs_fsync,
	.vop_getattr =  	nnpfs_getattr,
	.vop_getpages = 	nnpfs_getpages,
	.vop_inactive = 	nnpfs_inactive,
	.vop_ioctl =    	nnpfs_ioctl,
	.vop_link =     	nnpfs_link,
	.vop_lookup =   	vfs_cache_lookup,
	.vop_mkdir =    	nnpfs_mkdir,
	.vop_open =     	nnpfs_open,
	.vop_pathconf = 	nnpfs_pathconf,
	.vop_print =    	nnpfs_print,
	.vop_putpages = 	nnpfs_putpages,
	.vop_read =     	nnpfs_read,
	.vop_readdir =  	nnpfs_readdir,
	.vop_readlink = 	nnpfs_readlink,
	.vop_reclaim =  	nnpfs_reclaim,
	.vop_remove =   	nnpfs_remove,
	.vop_rename =   	nnpfs_rename,
	.vop_rmdir =    	nnpfs_rmdir,
	.vop_setattr =  	nnpfs_setattr,
/*      .vop_setextattr */
/*	.vop_strategy = 	nnpfs_strategy, */
	.vop_symlink =  	nnpfs_symlink,
	.vop_write =    	nnpfs_write,
	.vop_kqfilter =		nnpfs_kqfilter,
	.vop_cachedlookup =	nnpfs_cachedlookup,
	.vop_bmap =		nnpfs_bmap,

	.vop_poll =		nnpfs_poll,
#ifdef HAVE_VOP_LOCK1
	.vop_lock1 =		nnpfs_lock1,
#endif
#ifdef HAVE_VOP_LOCK
	.vop_lock =		nnpfs_lock,  
#endif
	.vop_unlock =		nnpfs_unlock,
	.vop_islocked =		nnpfs_islocked,
	.vop_revoke =		nnpfs_revoke,
};

#elif !defined(__NetBSD__)

static struct vnodeopv_entry_desc nnpfs_vnodeop_entries[] = {
    {&vop_default_desc, (vop_t *) nnpfs_eopnotsupp},
#ifdef HAVE_VOP_LOOKUP
#ifdef HAVE_KERNEL_VFS_CACHE_LOOKUP
    {&vop_lookup_desc, (vop_t *) vfs_cache_lookup },
#else
    {&vop_lookup_desc, (vop_t *) nnpfs_lookup },
#endif
#endif
#ifdef HAVE_VOP_CACHEDLOOKUP
    {&vop_cachedlookup_desc, (vop_t *) nnpfs_cachedlookup },
#endif
#ifdef HAVE_VOP_OPEN
    {&vop_open_desc, (vop_t *) nnpfs_open },
#endif
#ifdef HAVE_VOP_FSYNC
    {&vop_fsync_desc, (vop_t *) nnpfs_fsync },
#endif
#ifdef HAVE_VOP_CLOSE
    {&vop_close_desc, (vop_t *) nnpfs_close },
#endif
#ifdef HAVE_VOP_READ
    {&vop_read_desc, (vop_t *) nnpfs_read },
#endif
#ifdef HAVE_VOP_WRITE
    {&vop_write_desc, (vop_t *) nnpfs_write },
#endif
#ifdef HAVE_VOP_MMAP
    {&vop_mmap_desc, (vop_t *) nnpfs_mmap },
#endif
#ifdef HAVE_VOP_BMAP
    {&vop_bmap_desc, (vop_t *) nnpfs_bmap },
#endif
#ifdef HAVE_VOP_IOCTL
    {&vop_ioctl_desc, (vop_t *) nnpfs_ioctl },
#endif
#ifdef HAVE_VOP_SELECT
    {&vop_select_desc, (vop_t *) nnpfs_select },
#endif
#ifdef HAVE_VOP_SEEK
    {&vop_seek_desc, (vop_t *) nnpfs_seek },
#endif
#ifdef HAVE_VOP_POLL
    {&vop_poll_desc, (vop_t *) nnpfs_poll },
#endif
#ifdef HAVE_VOP_GETATTR
    {&vop_getattr_desc, (vop_t *) nnpfs_getattr },
#endif
#ifdef HAVE_VOP_SETATTR
    {&vop_setattr_desc, (vop_t *) nnpfs_setattr },
#endif
#ifdef HAVE_VOP_ACCESS
    {&vop_access_desc, (vop_t *) nnpfs_access },
#endif
#ifdef HAVE_VOP_CREATE
    {&vop_create_desc, (vop_t *) nnpfs_create },
#endif
#ifdef HAVE_VOP_REMOVE
    {&vop_remove_desc, (vop_t *) nnpfs_remove },
#endif
#ifdef HAVE_VOP_LINK
    {&vop_link_desc, (vop_t *) nnpfs_link },
#endif
#ifdef HAVE_VOP_RENAME
    {&vop_rename_desc, (vop_t *) nnpfs_rename },
#endif
#ifdef HAVE_VOP_MKDIR
    {&vop_mkdir_desc, (vop_t *) nnpfs_mkdir },
#endif
#ifdef HAVE_VOP_RMDIR
    {&vop_rmdir_desc, (vop_t *) nnpfs_rmdir },
#endif
#ifdef HAVE_VOP_READDIR
    {&vop_readdir_desc, (vop_t *) nnpfs_readdir },
#endif
#ifdef HAVE_VOP_SYMLINK
    {&vop_symlink_desc, (vop_t *) nnpfs_symlink },
#endif
#ifdef HAVE_VOP_READLINK
    {&vop_readlink_desc, (vop_t *) nnpfs_readlink },
#endif
#ifdef HAVE_VOP_INACTIVE
    {&vop_inactive_desc, (vop_t *) nnpfs_inactive },
#endif
#ifdef HAVE_VOP_RECLAIM
    {&vop_reclaim_desc, (vop_t *) nnpfs_reclaim },
#endif
#ifdef HAVE_VOP_LOCK
    {&vop_lock_desc, (vop_t *) nnpfs_lock },
#endif
#ifdef HAVE_VOP_UNLOCK
    {&vop_unlock_desc, (vop_t *) nnpfs_unlock },
#endif
#ifdef HAVE_VOP_ISLOCKED
    {&vop_islocked_desc, (vop_t *) nnpfs_islocked },
#endif
#ifdef HAVE_VOP_ABORTOP
    {&vop_abortop_desc, (vop_t *) nnpfs_abortop },
#endif
#ifdef HAVE_VOP_GETPAGES
    {&vop_getpages_desc, (vop_t *) nnpfs_getpages },
#endif
#ifdef HAVE_VOP_PUTPAGES
    {&vop_putpages_desc, (vop_t *) nnpfs_putpages },
#endif
#ifdef HAVE_VOP_REVOKE
    {&vop_revoke_desc, (vop_t *) nnpfs_revoke },
#endif
#ifdef HAVE_VOP_PRINT
    {&vop_print_desc, (vop_t *) nnpfs_print}, 
#endif
#ifdef HAVE_VOP_ADVLOCK
    {&vop_advlock_desc, (vop_t *) nnpfs_advlock },
#endif
#ifdef HAVE_VOP_PAGEIN
    {&vop_pagein_desc, (vop_t *) nnpfs_pagein },
#endif
#ifdef HAVE_VOP_PAGEOUT
    {&vop_pageout_desc, (vop_t *) nnpfs_pageout },
#endif
#ifdef HAVE_VOP_CREATEVOBJECT
    {&vop_createvobject_desc, (vop_t *) nnpfs_createvobject },
#endif
#ifdef HAVE_VOP_DESTROYVOBJECT
    {&vop_destroyvobject_desc, (vop_t *) nnpfs_destroyvobject },
#endif
#ifdef HAVE_VOP_GETVOBJECT
    {&vop_getvobject_desc, (vop_t *) nnpfs_getvobject },
#endif
#ifdef HAVE_VOP_PATHCONF
    {&vop_pathconf_desc, (vop_t *) nnpfs_pathconf },
#endif
#ifdef HAVE_VOP_VPTOFH
    {&vop_vptofh_desc, (vop_t *) nnpfs_vptofh },
#endif
    {(struct vnodeop_desc *) NULL, (int (*) (void *)) NULL}
};

struct vnodeopv_desc nnpfs_vnodeop_opv_desc =
{&nnpfs_vnodeop_p, nnpfs_vnodeop_entries};

#ifdef VNODEOP_SET
VNODEOP_SET(nnpfs_vnodeop_opv_desc);
#endif

#endif /* !__NetBSD__ / !__FreeBSD__ */
