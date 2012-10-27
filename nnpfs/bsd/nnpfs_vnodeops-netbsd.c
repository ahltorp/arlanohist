/*
 * Copyright (c) 2002-2007 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vnodeops-netbsd.c,v 1.31 2007/12/02 23:27:29 tol Exp $");

/*
 * This is the UBC version of the io function (read/write/getpages/putpages)
 */

extern vop_t **nnpfs_vnodeop_p;

static void
nnpfs_gop_size(struct vnode *vp, off_t size, off_t *eobp, int flag)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_gop_size: %p\n", vp));

    *eobp = MAX(size, vp->v_size);
}

static int
nnpfs_gop_alloc(struct vnode *vp, off_t off, off_t len, int flags,
		nnpfs_kernel_cred cred)
{
    return 0;
}

struct genfs_ops nnpfs_genfsops = {
    nnpfs_gop_size,
    nnpfs_gop_alloc,
    genfs_gop_write,
};

/*
 *
 */

static int
nnpfs_netbsd_bmap(struct vop_bmap_args *ap)
{
    /* {
	struct vnode *a_vp;
	daddr_t a_bn;
	struct vnode **a_vpp;
	daddr_t *a_bnp;
	int *a_runp;
    } */
    struct vnode *vp = ap->a_vp;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_bmap: %p\n", vp));

    *ap->a_bnp = ap->a_bn;

    if (ap->a_vpp)
	*ap->a_vpp = vp;
    if (ap->a_runp)
	*ap->a_runp = 0;
    return 0;
}

static int
nnpfs_netbsd_strategy(struct vop_strategy_args *ap)
{
    /* {
        struct buf *a_bp;
    } */
    struct buf *bp = ap->a_bp;
    struct vnode *vp = bp->b_vp;
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    struct iovec iov;
    struct uio uio;
    d_thread_t *p = nnpfs_curproc();
    nnpfs_kernel_cred cred = nnpfs_proc_to_cred(p);
    int rw = (bp->b_flags & B_READ) == 0;
    int error;
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_strategy: %p\n", vp));
    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_strategy: from %lld with %d\n", 
			 (long long)dbtob(bp->b_blkno), (int)bp->b_resid));

    iov.iov_base = (void *)bp->b_data;
    iov.iov_len = bp->b_resid;
    uio.uio_iov = &iov;
    uio.uio_iovcnt = 1;
    nnpfs_uio_setoffset(&uio, dbtob(bp->b_blkno));
    uio.uio_rw = rw ? UIO_WRITE : UIO_READ;
    uio.uio_resid = bp->b_resid;
    
#if __NetBSD_Version__ < 399002100 /* 3.99.21 */
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_procp = p;
#else /* >= 399002100 */
    UIO_SETUP_SYSSPACE(&uio);
#endif

    if (rw) {
	nnpfs_vfs_context ctx;
	nnpfs_vfs_context_init(ctx, p, cred);
	error = nnpfs_write_common(vp, &uio, FWRITE, ctx);
    } else {
	error = nnpfs_read_common(vp, &uio, FREAD, cred);
    }

    if (error) {
	bp->b_error = error;
	bp->b_flags |= B_ERROR;
    }

    bp->b_resid = uio.uio_resid;
 done:
    biodone(bp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_strategy: returns %d\n", error));
    return error;
}

static int
nnpfs_netbsd_read(struct vop_read_args *ap)
{
    /* {
       struct vnode *a_vp;
       struct uio *a_uio;
       int a_ioflag;
       nnpfs_kernel_cred a_cred;
    } */
    struct nnpfs_node *xn;
    nnpfs_cred *ncred;
    struct vnode *vp;
    struct uio *uio;
    void *win;
    vsize_t bytelen;
    struct buf *bp;
    long size;
    int error;
    
    vp = ap->a_vp;
    uio = ap->a_uio;
    error = 0;
    xn = VNODE_TO_XNODE(vp);
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: %p @%llu\n", vp,
		nnpfs_uio_offset(uio)));

    if (vp->v_type != VREG && vp->v_type != VLNK)
	return EISDIR;
    
    if (uio->uio_resid == 0)
	return (0);
    if (nnpfs_uio_offset(uio) < 0)
	return EFBIG;
    if (nnpfs_uio_offset(uio) > vp->v_size)
	return 0;
    
    ncred = &(VNODE_TO_XNODE(vp))->rd_cred;
    nnpfs_setcred(ncred, ap->a_cred);

    error = nnpfs_data_valid(vp, ncred, NNPFS_DATA_R,
			     nnpfs_uio_offset(uio),
			     nnpfs_uio_end_length(uio));

    while (uio->uio_resid > 0) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: need to copy %ld\n",
	    (long)uio->uio_resid));

	bytelen = MIN(xn->attr.va_size - nnpfs_uio_offset(uio),
		      uio->uio_resid);
	if (bytelen == 0)
	    break;
	
	NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: allocating window\n"));

	win = ubc_alloc(&vp->v_uobj, nnpfs_uio_offset(uio),
			&bytelen, 
#if __NetBSD_Version__ >= 399001300
			UVM_ADV_NORMAL,
#endif
			UBC_READ);

	NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: copy data\n"));
	error = uiomove(win, bytelen, uio);
	NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: release window\n"));
	ubc_release(win, 0);
	if (error)
	    break;
    }
    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_read: done, error = %d\n", error));
    
    return (error);
}

static int
nnpfs_netbsd_write(struct vop_write_args *ap)
{
    struct vnode *vp;
    struct uio *uio;
    nnpfs_kernel_cred cred;
    off_t osize, origoff, oldoff;
    int error, flags, ioflag, resid;
    void *win;
    vsize_t bytelen;
    struct nnpfs_node *xn;
    int extended = 0;
    nnpfs_cred *ncred;

    cred = ap->a_cred;
    ioflag = ap->a_ioflag;
    uio = ap->a_uio;
    vp = ap->a_vp;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_write: %p @%llu + %d\n", vp,
		nnpfs_uio_offset(uio), uio->uio_resid));

#ifdef DIAGNOSTIC
    if (uio->uio_rw != UIO_WRITE)
	panic("nnpfs_netbsd_write: mode");
#endif
    if (nnpfs_uio_offset(uio) < 0)
	return (EFBIG);

    if (vp->v_type != VREG && vp->v_type != VLNK)
	return EISDIR;

    ncred = &(VNODE_TO_XNODE(vp))->wr_cred;
    nnpfs_setcred(ncred, ap->a_cred);

    error = nnpfs_data_valid(vp, ncred, NNPFS_DATA_W,
			     nnpfs_uio_offset(uio),
			     nnpfs_uio_end_length(uio));
    if (error)
	return (error);
    
    xn = VNODE_TO_XNODE(vp);

    if (ioflag & IO_APPEND)
	nnpfs_uio_offset(uio) = xn->attr.va_size;

    flags = ioflag & IO_SYNC ? B_SYNC : 0;
    origoff = nnpfs_uio_offset(uio);
    resid = uio->uio_resid;
    osize = xn->attr.va_size;
    error = 0;

    if (origoff > osize) {
	/* zero out beginning of offset's block */
	off_t zero_start = nnpfs_offset(origoff);
	if (osize >= zero_start)
	    zero_start = osize;	
	uvm_vnp_zerorange(vp, zero_start, origoff - zero_start);
    }

    while (uio->uio_resid > 0) {
	oldoff = nnpfs_uio_offset(uio);

	bytelen = uio->uio_resid;

	/*
	 * copy the data.
	 */

	win = ubc_alloc(&vp->v_uobj, nnpfs_uio_offset(uio), &bytelen,
#if __NetBSD_Version__ >= 399001300
			UVM_ADV_NORMAL,
#endif
			UBC_WRITE);
	error = uiomove(win, bytelen, uio);
	ubc_release(win, 0);
	if (error)
	    break;

	/*
	 * update UVM's notion of the size now that we've
	 * copied the data into the vnode's pages.
	 */

	if (vp->v_size < nnpfs_uio_offset(uio)) {
	    uvm_vnp_setsize(vp, nnpfs_uio_offset(uio));
	    extended = 1;
	    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_write: extended to %llu\n",
		nnpfs_uio_offset(uio)));
	}

#if 0 /* don't need this? */
	if (oldoff >> 16 != nnpfs_uio_offset(uio) >> 16) {
	    simple_lock(&vp->v_interlock);
	    error = VOP_PUTPAGES(vp, (oldoff >> 16) << 16,
		(nnpfs_uio_offset(uio) >> 16) << 16, PGO_CLEANIT);
	    if (error) {
		break;
	    }
	}
#endif
    }

    if (error) {
	if (extended)
	    uvm_vnp_setsize(vp, osize);
	nnpfs_uio_setoffset(uio, origoff);
	uio->uio_resid = resid;
    } else {
	if (extended) {
	    nnpfs_vattr_set_size(&xn->attr, vp->v_size);
	    nnpfs_vattr_set_bytes(&xn->attr, vp->v_size);
	}

#if __NetBSD_Version__ >= 399001900 /* NetBSD 3.99.21 */
	vfs_timestamp(&xn->attr.va_mtime);
#else
	{
	    struct timespec ts;
	    TIMEVAL_TO_TIMESPEC(&time, &ts);
	    xn->attr.va_mtime = ts;
	}
#endif /* NetBSD 3.99.21 */

	xn->flags |= NNPFS_DATA_DIRTY;

	VN_KNOTE(vp, NOTE_WRITE | (extended ? NOTE_EXTEND : 0));
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_netbsd_write: %p -> %d\n", vp, error));
    return (error);
}


/*
 * vnode functions
 */

static struct vnodeopv_entry_desc nnpfs_vnodeop_entries[] = {
    {&vop_default_desc,		(vop_t *) nnpfs_eopnotsupp},
    {&vop_lookup_desc,		(vop_t *) nnpfs_lookup },
    {&vop_open_desc,		(vop_t *) nnpfs_open },
    {&vop_fsync_desc,		(vop_t *) nnpfs_fsync },
    {&vop_close_desc,		(vop_t *) nnpfs_close },
    {&vop_read_desc,		(vop_t *) nnpfs_netbsd_read },
    {&vop_write_desc,		(vop_t *) nnpfs_netbsd_write },
    {&vop_mmap_desc,		(vop_t *) nnpfs_mmap },
    {&vop_ioctl_desc,		(vop_t *) nnpfs_ioctl },
    {&vop_seek_desc,		(vop_t *) nnpfs_seek },
    {&vop_poll_desc,		(vop_t *) nnpfs_poll },
    {&vop_getattr_desc,		(vop_t *) nnpfs_getattr },
    {&vop_setattr_desc,		(vop_t *) nnpfs_setattr },
    {&vop_access_desc,		(vop_t *) nnpfs_access },
    {&vop_create_desc,		(vop_t *) nnpfs_create },
    {&vop_remove_desc,		(vop_t *) nnpfs_remove },
    {&vop_link_desc,		(vop_t *) nnpfs_link },
    {&vop_rename_desc,		(vop_t *) nnpfs_rename },
    {&vop_mkdir_desc,		(vop_t *) nnpfs_mkdir },
    {&vop_rmdir_desc,		(vop_t *) nnpfs_rmdir },
    {&vop_readdir_desc,		(vop_t *) nnpfs_readdir },
    {&vop_symlink_desc,		(vop_t *) nnpfs_symlink },
    {&vop_readlink_desc,	(vop_t *) nnpfs_readlink },
    {&vop_inactive_desc,	(vop_t *) nnpfs_inactive },
    {&vop_reclaim_desc,		(vop_t *) nnpfs_reclaim },
    {&vop_lock_desc,		(vop_t *) nnpfs_lock },
    {&vop_unlock_desc,		(vop_t *) nnpfs_unlock },
    {&vop_islocked_desc,	(vop_t *) nnpfs_islocked },
    {&vop_abortop_desc,		(vop_t *) nnpfs_abortop },
    {&vop_getpages_desc,	(vop_t *) genfs_getpages },
    {&vop_putpages_desc,	(vop_t *) genfs_putpages },
    {&vop_revoke_desc,		(vop_t *) genfs_revoke },
    {&vop_bmap_desc,		(vop_t *) nnpfs_netbsd_bmap },
    {&vop_strategy_desc,	(vop_t *) nnpfs_netbsd_strategy },
    {&vop_print_desc,		(vop_t *) nnpfs_print}, 
    {&vop_advlock_desc,		(vop_t *) nnpfs_advlock },
    {&vop_kqfilter_desc,	(vop_t *) genfs_kqfilter },
    {(struct vnodeop_desc *) NULL, (int (*) (void *)) NULL}
};

struct vnodeopv_desc nnpfs_netbsd_vnodeop_opv_desc =
{&nnpfs_vnodeop_p, nnpfs_vnodeop_entries};
