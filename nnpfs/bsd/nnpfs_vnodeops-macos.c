/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska Högskolan
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

#ifdef __APPLE__
#define MACH_KERNEL 1
#endif

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_vnodeops.h>

RCSID("$Id: nnpfs_vnodeops-macos.c,v 1.10 2006/11/17 16:12:00 tol Exp $");

/*
 * vnode functions
 */

static int
nnpfs_open(struct vnop_open_args *ap)
     /*
struct vnop_open_args {
        struct vnodeop_desc *a_desc;
        vnode_t a_vp;
        int a_mode;
        vfs_context_t a_context;
}; */
{
    return nnpfs_open_common (ap->a_vp, ap->a_mode, ap->a_context);
}

static int
nnpfs_fsync(struct vnop_fsync_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_waitfor;
	vfs_context_t a_context;
     */
{
    vfs_context_t ctx = ap->a_context;
    return nnpfs_fsync_common(ap->a_vp, nnpfs_vfs_context_ucred(ctx), NULL,
			      ap->a_waitfor, nnpfs_vfs_context_proc(ctx));
}

static int
nnpfs_close(struct vnop_close_args *ap)
/* struct vnop_close_args {
        struct vnodeop_desc *a_desc;
        vnode_t a_vp;
        int a_fflag;
        vfs_context_t a_context;
 */
{
    nnpfs_vfs_context ctx = ap->a_context;

    return nnpfs_close_common(ap->a_vp, ap->a_fflag,
			      nnpfs_vfs_context_proc(ctx),
			      nnpfs_vfs_context_ucred(ctx));
}

static int
nnpfs_read(struct vnop_read_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
     */
{
    return nnpfs_read_common(ap->a_vp, ap->a_uio, ap->a_ioflag,
			     nnpfs_vfs_context_ucred(ap->a_context));
}

static int
nnpfs_write(struct vnop_write_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
     */
{
    return nnpfs_write_common(ap->a_vp, ap->a_uio, ap->a_ioflag, ap->a_context);
}

static int
nnpfs_ioctl(struct vnop_ioctl_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	u_long a_command;
	caddr_t a_data;
	int a_fflag;
	vfs_context_t a_context;
     */
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_ioctl\n"));

    return ENOTSUP;
}

static int
nnpfs_select(struct vnop_select_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_which;
	int a_fflags;
	void *a_wql;
	vfs_context_t a_context;
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_select\n"));

    return ENOTSUP;
}

static int
nnpfs_getattr(struct vnop_getattr_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
     */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct vnode_attr *vap = ap->a_vap;
    int error;

    /* XXX save some data from the original struct */
    uint64_t va_active = vap->va_active;
    struct kauth_acl *va_acl = vap->va_acl;
    char *va_name = vap->va_name;

    if (VATTR_IS_ACTIVE(vap, va_acl)) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr: acl requested\n"));
    }
    
    error = nnpfs_getattr_common(ap->a_vp, vap, nnpfs_vfs_context_ucred(ctx),
				 nnpfs_vfs_context_proc(ctx));
    if (error == 0)
	VATTR_RETURN(vap, va_fsid, vfs_statfs(vnode_mount(ap->a_vp))->f_fsid.val[0]); 

    /* restore relevant parts of the original request */
    vap->va_active = va_active;
    vap->va_name = va_name;
    vap->va_acl = va_acl;
    
    return error;
}

static int
nnpfs_setattr(struct vnop_setattr_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
     */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct vnode *vp = ap->a_vp;
    struct nnpfs_vfs_vattr *vap = ap->a_vap;
    struct nnpfs_node *xn;

    int error = nnpfs_setattr_common(vp, vap, nnpfs_vfs_context_ucred(ctx),
				     nnpfs_vfs_context_proc(ctx));
    
    xn = VNODE_TO_XNODE(vp);
    vap->va_supported = xn->attr.va_supported;
    return error;
}

static int
nnpfs_access(struct vnop_access_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_action;
	vfs_context_t a_context;
     */
{
    nnpfs_vfs_context ctx = ap->a_context;
    return nnpfs_access_common(ap->a_vp, ap->a_action, 
			       nnpfs_vfs_context_ucred(ctx),
			       nnpfs_vfs_context_proc(ctx));
}

static int
nnpfs_lookup(struct vnop_lookup_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_dvp;
  vnode_t *a_vpp;
  struct componentname *a_cnp;
  vfs_context_t a_context;
*/
{
    struct componentname *cnp = ap->a_cnp;
    int error;
    int lockparent = (cnp->cn_flags & (LOCKPARENT | ISLASTCN))
	== (LOCKPARENT | ISLASTCN);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: (%s, %ld), nameiop = %lu, flags = %lu\n",
		       cnp->cn_nameptr,
		       cnp->cn_namelen,
		       cnp->cn_nameiop,
		       cnp->cn_flags));

    error = nnpfs_lookup_common(ap->a_dvp, cnp, ap->a_vpp, ap->a_context);

    if (error == ENOENT
	&& (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME)
	&& (cnp->cn_flags & ISLASTCN)) {
	error = EJUSTRETURN;
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: error = %d\n", error));

    return error;
}


/*
 * whatever clean-ups are needed for a componentname.
 */

static void
cleanup_cnp (struct componentname *cnp, int error)
{
}

static int
nnpfs_create(struct vnop_create_args *ap)
/*
struct vnop_create_args {
        struct vnodeop_desc *a_desc;
        vnode_t a_dvp;
        vnode_t *a_vpp;
        struct componentname *a_cnp;
        struct vnode_attr *a_vap;
        vfs_context_t a_context;
}; */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct vnode *dvp  = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    const char *name   = cnp->cn_nameptr;
    int error;

    error = nnpfs_create_common(dvp, name, ap->a_vap, 
				nnpfs_vfs_context_ucred(ctx),
				nnpfs_vfs_context_proc(ctx));
    if (error == 0) {
	error = nnpfs_lookup_common(dvp, cnp, ap->a_vpp, ctx);
    }

    cleanup_cnp(cnp, error);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_create: error = %d\n", error));
    
    return error;
}

static int
nnpfs_remove(struct vnop_remove_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t a_vp;
	struct componentname *a_cnp;
	int a_flags;
	vfs_context_t a_context;
 */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct componentname *cnp = ap->a_cnp;
    struct vnode *dvp = ap->a_dvp;
    struct vnode *vp  = ap->a_vp;

    int error = nnpfs_remove_common(dvp, vp, cnp->cn_nameptr,
				    nnpfs_vfs_context_ucred(ctx),
				    nnpfs_vfs_context_proc(ctx));
    cleanup_cnp (cnp, error);

#if 0
    if (error == 0 && UBCINFOEXISTS(vp))
	ubc_uncache(vp);
#endif

    return error;
}

static int
nnpfs_rename(struct vnop_rename_args *ap)
     /*
	struct vnodeop_desc *a_desc;
	vnode_t a_fdvp;
	vnode_t a_fvp;
	struct componentname *a_fcnp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	vfs_context_t a_context;
     */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct vnode *tdvp = ap->a_tdvp;
    struct vnode *tvp  = ap->a_tvp;
    struct vnode *fdvp = ap->a_fdvp;
    struct vnode *fvp  = ap->a_fvp;

    int error = nnpfs_rename_common(fdvp, fvp, ap->a_fcnp->cn_nameptr,
				    tdvp, tvp, ap->a_tcnp->cn_nameptr,
				    nnpfs_vfs_context_ucred(ctx),
				    nnpfs_vfs_context_proc(ctx));
    return error;
}

static int
nnpfs_mkdir(struct vnop_mkdir_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
*/
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct vnode *dvp  = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    const char *name   = cnp->cn_nameptr;
    int error;

    error = nnpfs_mkdir_common(dvp, name, ap->a_vap,
			       nnpfs_vfs_context_ucred(ctx),
			       nnpfs_vfs_context_proc(ctx));
    if (error == 0)
	error = nnpfs_lookup_common(dvp, cnp, ap->a_vpp, ctx);

    cleanup_cnp (cnp, error);
    /* nnpfs_vput(dvp); seems to be done in xnu's mkdir1 */

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir: error = %d\n", error));

    return error;
}

static int
nnpfs_rmdir(struct vnop_rmdir_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_dvp;
  vnode_t a_vp;
  struct componentname *a_cnp;
  vfs_context_t a_context;
 */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct componentname *cnp = ap->a_cnp;
    struct vnode *dvp = ap->a_dvp;
    struct vnode *vp  = ap->a_vp;
    
    int error = nnpfs_rmdir_common(ap->a_dvp, ap->a_vp, 
				   cnp->cn_nameptr,
				   nnpfs_vfs_context_ucred(ctx),
				   nnpfs_vfs_context_proc(ctx));
    cleanup_cnp(cnp, error);

    return error;
}

typedef u_long nnpfs_cookie_t;

static int
nnpfs_readdir(struct vnop_readdir_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  struct uio *a_uio;
  int a_flags;
  int *a_eofflag;
  int *a_numdirent;
  vfs_context_t a_context;
 */
{
    int error;
    off_t off;

    off = nnpfs_uio_offset(ap->a_uio);

    /* no cookies here */
    if (ap->a_flags & VNODE_READDIR_REQSEEKOFF)
	return EINVAL;
    
    /* ...and we don't do EXTENDED yet*/
    if (ap->a_flags & VNODE_READDIR_EXTENDED)
	return EINVAL;

    error = nnpfs_readdir_common(ap->a_vp, ap->a_uio, ap->a_eofflag,
				 ap->a_context);

#if 0
    if (!error && ap->a_ncookies != NULL) {
	struct uio *uio = ap->a_uio;
	const struct dirent *dp, *dp_start, *dp_end;
	int ncookies;
	nnpfs_cookie_t *cookies, *cookiep;

	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1)
	    panic("nnpfs_readdir: mail arla-drinkers and tell them to bake burned cookies");
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

	MALLOC(cookies, nnpfs_cookie_t *, ncookies * sizeof(nnpfs_cookie_t),
	       M_TEMP, M_WAITOK);
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
#endif
    return error;
}

static int
nnpfs_link(struct vnop_link_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vnode_t a_tdvp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
 */
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct componentname *cnp = ap->a_cnp;
    struct vnode *vp = ap->a_vp;
    struct vnode *dvp = ap->a_tdvp;
    int error;

    if (nnpfs_vnode_isdir(vp)) {
	    error = EPERM;
	    goto out;
    }
    if (nnpfs_vnode_mount(dvp) != nnpfs_vnode_mount(vp)) {
	    error = EXDEV;
	    goto out;
    }

    error = nnpfs_link_common(dvp, vp, cnp->cn_nameptr,
			      nnpfs_vfs_context_ucred(ctx),
			      nnpfs_vfs_context_proc(ctx));
    cleanup_cnp (cnp, error);

    if (dvp != vp)
	nnpfs_vfs_unlock(vp, p);

out:
#if 0
/*
 * ok, so kpi_vfs.c comments indicate that we always should unlock
 * dvp, but vfs_syscalls.c does it for us
 */
    nnpfs_vput(dvp);
#endif

    return error;
}

static int
nnpfs_symlink(struct vnop_symlink_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_dvp;
  vnode_t *a_vpp;
  struct componentname *a_cnp;
  struct vnode_attr *a_vap;
  char *a_target;
  vfs_context_t a_context;
*/
{
    nnpfs_vfs_context ctx = ap->a_context;
    struct componentname *cnp = ap->a_cnp;
    struct vnode *dvp  = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;

    int error = nnpfs_symlink_common(dvp, vpp, cnp, ap->a_vap,
				     ap->a_target, ctx);
    if (error == 0)
	error = nnpfs_lookup_common(dvp, cnp, vpp, ctx);

    cleanup_cnp (cnp, error);
    return error;
}

static int
nnpfs_readlink(struct vnop_readlink_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	vfs_context_t a_context;
*/
{
    return nnpfs_readlink_common(ap->a_vp, ap->a_uio, ap->a_context);
}

static int
nnpfs_inactive(struct vnop_inactive_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
 */
{
    return nnpfs_inactive_common(ap->a_vp, nnpfs_vfs_context_proc(ap->a_context));
}

static int
nnpfs_reclaim(struct vnop_reclaim_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
 */
{
    struct vnode *vp = ap->a_vp;
    int ret;

    ret = nnpfs_reclaim_common(vp);
    vnode_clearfsnode(vp);

    return ret;
}

static int
nnpfs_mmap(struct vnop_mmap_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  int a_fflags;
  vfs_context_t a_context;
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap\n"));

    return ENOTSUP;
}

static int
nnpfs_mnomap(struct vnop_mnomap_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mnomap\n"));

    return ENOTSUP;
}

#ifdef HAVE_VOP_PRINT
static int
nnpfs_print (struct vnop_print_args *v)
{
    struct vnop_print_args /* {
	struct vnode	*a_vp;
    } */ *ap = v;
    nnpfs_printnode_common (ap->a_vp);
    return 0;
}
#endif

#ifdef FINNSINTE
static int
nnpfs_advlock(struct vnop_advlock_args *v)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  caddr_t a_id;
  int a_op;
  struct flock *a_fl;
  int a_flags;
  vfs_context_t a_context;
*/
{
     return ENOTSUP;
}

static int
nnpfs_revoke(struct vnop_revoke_args *ap)
/*
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_flags;
	vfs_context_t a_context;
*/
{
    return vn_revoke(ap->a_vp, ap->a_flags, ap->a_context);
}
#endif /* FINNSINTE */

static int
nnpfs_pagein(struct vnop_pagein_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  upl_t a_pl;
  vm_offset_t a_pl_offset;
  off_t a_f_offset;
  size_t a_size;
  int a_flags;
  vfs_context_t a_context;
*/
{
    vm_offset_t ioaddr;
    uio_t uio;
    int ioflags = (ap->a_flags & UPL_IOSYNC) ? IO_SYNC : 0;
    kern_return_t kret;
    int ret;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_pagein\n"));
	
    uio = uio_create(1, ap->a_f_offset, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL)
	return EIO;

    kret = ubc_upl_map(ap->a_pl, &ioaddr);
    if (kret != KERN_SUCCESS)
	panic("nnpfs_pagein: ubc_upl_map() failed %d", kret);

    ioaddr += ap->a_pl_offset;
    ret = uio_addiov(uio, (user_addr_t)ioaddr, ap->a_size);
    if (ret) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_pagein: bailout %d\n", ret));
	uio_free(uio);
	ubc_upl_unmap(ap->a_pl);
	return ret;
    }

    ret = VNOP_READ(ap->a_vp, uio, ioflags, ap->a_context);

    /* Zero out rest of last page if there wasn't enough data in the file */
    if (ret == 0 && uio_resid(uio) > 0) {
	vm_offset_t bytes_to_zero = ioaddr + ap->a_size - uio_resid(uio);
	bzero((caddr_t)bytes_to_zero, uio_resid(uio));
    }

    if (uio != NULL)
	uio_free(uio);
    
    ubc_upl_unmap(ap->a_pl);
    
    if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
	if (ret) {
	    ubc_upl_abort_range(ap->a_pl, ap->a_pl_offset, ap->a_size,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
	} else {
	    ubc_upl_commit_range(ap->a_pl, ap->a_pl_offset, ap->a_size,
				 UPL_COMMIT_CLEAR_DIRTY /* XXX ? */
				 | UPL_COMMIT_FREE_ON_EMPTY);
	}
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_pageout: returning %d\n", ret));

    return ret;
}

static int
nnpfs_pageout(struct vnop_pageout_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  upl_t a_pl;
  vm_offset_t a_pl_offset;
  off_t a_f_offset;
  size_t a_size;
  int a_flags;
  vfs_context_t a_context;
*/
{
    int ioflags = (ap->a_flags & UPL_IOSYNC) ? IO_SYNC : 0;
    vm_offset_t ioaddr;
    uio_t uio;
    off_t size;
    kern_return_t kret;
    int ret;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_pageout\n"));

    uio = uio_create(1, ap->a_f_offset, UIO_SYSSPACE, UIO_WRITE);
    if (uio == NULL)
	return EIO;

    kret = ubc_upl_map(ap->a_pl, &ioaddr);
    if (kret != KERN_SUCCESS)
	panic("nnpfs_pagein: ubc_upl_map() failed %d", kret);

    ioaddr += ap->a_pl_offset;
    ret = uio_addiov(uio, (user_addr_t)ioaddr, ap->a_size);
    if (ret) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_pageout: bailout %d\n", ret));
	uio_free(uio);
	ubc_upl_unmap(ap->a_pl);
	return ret;
    }

    size = nnpfs_vattr_get_size(&VNODE_TO_XNODE(ap->a_vp)->attr);

    if (uio_offset(uio) + uio_resid(uio) > size) {
	if (uio_offset(uio) < size) {
	    /* we can't pageout beyond the current EOF */
	    uio_setresid(uio, size - uio_offset(uio));
	} else {
	    NNPFSDEB(XDEBVNOPS,
		     ("nnpfs_pageout: file truncated under out feet!\n"));
	    uio_free(uio);
	    ubc_upl_unmap(ap->a_pl);
	    return EFAULT;
	}
    }

    ret = VNOP_WRITE(ap->a_vp, uio, ioflags, ap->a_context);

    if (uio != NULL)
	uio_free(uio);
    
    ubc_upl_unmap(ap->a_pl);

    if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
	if (ret) {
	    ubc_upl_abort_range(ap->a_pl, ap->a_pl_offset, ap->a_size,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
	} else {
	    ubc_upl_commit_range(ap->a_pl, ap->a_pl_offset, ap->a_size,
				 UPL_COMMIT_CLEAR_DIRTY /* XXX */ |
				 UPL_COMMIT_FREE_ON_EMPTY);
	}
    }
    NNPFSDEB(XDEBVNOPS, ("nnpfs_pageout returning %d\n", ret));

    return ret;
}

static int
nnpfs_pathconf(struct vnop_pathconf_args *ap)
/*
  struct vnodeop_desc *a_desc;
  vnode_t a_vp;
  int a_name;
  register_t *a_retval;
  vfs_context_t a_context;
*/
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_pathconf\n"));

    return ENOTSUP;
}



vop_t **nnpfs_vnodeop_p;

void
nnpfs_pushdirty(struct vnode *vp)
{
    (void)ubc_sync_range(vp, 0, ubc_getsize(vp), UBC_PUSHDIRTY);
}

static int
nnpfs_enotsup_vn(void)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_enotsup_vn\n"));
    return ENOTSUP;
}

#if 0
static int
nnpfs_kqfiltadd(struct vnop_kqfilt_add_args *ap)
/*
  struct vnodeop_desc *a_desc;
  struct vnode *a_vp;
  struct knote *a_kn;
  vfs_context_t a_context;
*/
{
    printf("kqadd\n");
    return ENOTSUP;
}

static int
nnpfs_kqfiltremove(struct vnop_kqfilt_remove_args *ap)
/*
  struct vnodeop_desc *a_desc;
  struct vnode *a_vp;
  uintptr_t a_ident;
  vfs_context_t a_context;
*/
{
    printf("kqrm\n");
    return ENOTSUP;
}
#endif

struct vnodeopv_entry_desc nnpfs_vnodeop_entries[] = {
	{&vnop_default_desc, (vop_t *) nnpfs_enotsup_vn},
	{&vnop_lookup_desc, (vop_t *) nnpfs_lookup},
	{&vnop_create_desc, (vop_t *) nnpfs_create},
	{&vnop_open_desc, (vop_t *) nnpfs_open},
	{&vnop_close_desc, (vop_t *) nnpfs_close},
	{&vnop_access_desc, (vop_t *) nnpfs_access},
	{&vnop_getattr_desc, (vop_t *) nnpfs_getattr},
	{&vnop_setattr_desc, (vop_t *) nnpfs_setattr},
	{&vnop_read_desc, (vop_t *) nnpfs_read},
	{&vnop_write_desc, (vop_t *) nnpfs_write},
	{&vnop_ioctl_desc, (vop_t *) nnpfs_ioctl},
	{&vnop_mmap_desc, (vop_t *) nnpfs_mmap},
	{&vnop_mnomap_desc, (vop_t *) nnpfs_mnomap},
	{&vnop_fsync_desc, (vop_t *) nnpfs_fsync},
	{&vnop_remove_desc, (vop_t *) nnpfs_remove},
	{&vnop_symlink_desc, (vop_t *) nnpfs_symlink},
	{&vnop_link_desc, (vop_t *) nnpfs_link},
	{&vnop_readlink_desc, (vop_t *) nnpfs_readlink},
	{&vnop_rename_desc, (vop_t *) nnpfs_rename},
	{&vnop_mkdir_desc, (vop_t *) nnpfs_mkdir},
	{&vnop_rmdir_desc, (vop_t *) nnpfs_rmdir},
	{&vnop_readdir_desc, (vop_t *) nnpfs_readdir},
	{&vnop_inactive_desc, (vop_t *) nnpfs_inactive},
	{&vnop_reclaim_desc, (vop_t *) nnpfs_reclaim},
	{&vnop_pathconf_desc, (vop_t *) nnpfs_pathconf},
	{&vnop_pagein_desc, (vop_t *) nnpfs_pagein},
	{&vnop_pageout_desc, (vop_t *) nnpfs_pageout},
#if 0
	{&vnop_kqfilt_add_desc, (vop_t *) nnpfs_kqfiltadd},
	{&vnop_kqfilt_remove_desc, (vop_t *) nnpfs_kqfiltremove},
#endif
	{(struct vnodeop_desc *)NULL, (vop_t *) NULL}
};

struct vnodeopv_desc nnpfs_vnodeop_opv_desc =
{&nnpfs_vnodeop_p, nnpfs_vnodeop_entries};
