/*
 * Copyright (c) 1995 - 2002, 2004 - 2007 Kungliga Tekniska Högskolan
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
#include <sys/param.h>

RCSID("$Id: nnpfs_vnodeops-common.c,v 1.125 2010/06/16 19:58:52 tol Exp $");

static void
nnpfs_handle_stale(struct nnpfs_node *xn)
{
#ifdef __APPLE__
    struct vnode *vp = XNODE_TO_VNODE(xn);
#endif

    if ((xn->flags & NNPFS_STALE) == 0)
	return;

#if 0
    if (UBCISVALID(vp) && !ubc_isinuse(vp, 1)) {
	xn->flags &= ~NNPFS_STALE;
	ubc_setsize(vp, 0);
	NNPFS_TOKEN_CLEAR(xn, ~0,
			NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
			NNPFS_DATA_MASK | NNPFS_LOCK_MASK);
    }
#endif
}

int
nnpfs_open_valid(struct vnode *vp, nnpfs_vfs_context ctx, u_int tok)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
    int error = 0;

    NNPFSDEB(XDEBVFOPS, ("nnpfs_open_valid\n"));

    nnpfs_handle_stale(xn);

    do {
	if (!NNPFS_TOKEN_GOT(xn, tok)) {
	    struct nnpfs_message_open msg;

	    msg.header.opcode = NNPFS_MSG_OPEN;
	    msg.cred.uid = nnpfs_cred_get_uid(cred);
	    msg.cred.pag = nnpfs_get_pag(cred);
	    msg.handle = xn->handle;
	    msg.tokens = tok;

	    error = nnpfs_message_rpc(nnpfsp, &msg.header,
				      sizeof(msg), nnpfs_vfs_context_proc(ctx));
	    if (error == 0)
		error = NNPFS_MSG_WAKEUP_ERROR(&msg);

	} else {
	    goto done;
	}
    } while (error == 0);

done:
    NNPFSDEB(XDEBVFOPS, ("nnpfs_open_valid: error = %d\n", error));

    return error;
}

int
nnpfs_attr_valid(struct vnode *vp, nnpfs_kernel_cred cred, d_thread_t *p,
		 u_int tok)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;
    nnpfs_pag_t pag = nnpfs_get_pag(cred);

    do {
	if (!NNPFS_TOKEN_GOT(xn, tok) || !nnpfs_has_pag(xn, pag)) {
	    struct nnpfs_message_getattr msg;

	    msg.header.opcode = NNPFS_MSG_GETATTR;
	    msg.cred.uid = nnpfs_cred_get_uid(cred);
	    msg.cred.pag = pag;
	    msg.handle = xn->handle;
	    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	    if (error == 0)
		error = NNPFS_MSG_WAKEUP_ERROR(&msg);
	} else {
	    goto done;
	}
    } while (error == 0);

done:
    return error;
}

static int
nnpfs_do_getdata(struct nnpfs_node *xn, nnpfs_cred *cred, u_int tok,
		 off_t offset, off_t end)
{
    struct nnpfs_message_getdata msg;
    int error;

    msg.header.opcode = NNPFS_MSG_GETDATA;
    msg.cred = *cred;
    msg.handle = xn->handle;
    msg.tokens = tok;
    msg.offset = offset;
    msg.len = end - offset;
		
    error = nnpfs_message_rpc(NNPFS_FROM_XNODE(xn), &msg.header, sizeof(msg),
			      nnpfs_curproc());
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    return error;
}

static void
update_end(struct nnpfs_node *xn, off_t *end, int writep)
{
    if (NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_R)) {
	off_t size = nnpfs_vattr_get_size(&xn->attr);
	
	if (*end > size && !writep)
	    *end = size;
    }
}

int
nnpfs_data_valid(struct vnode *vp, nnpfs_cred *cred,
		 u_int tok, off_t want_offset, off_t want_end)
{
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;
    int writep = ((tok & NNPFS_DATA_W) == NNPFS_DATA_W);
    int did_rpc;
    off_t offset = nnpfs_offset(want_offset);
    off_t end, off;

    if (!NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_R))
	printf("NNPFS PANIC WARNING! data_valid w/o tokens!\n");

    if (nnpfs_vnode_isdir(vp)) {
	/* hack, entire dir goes in 'first block' */
	offset = 0;
	want_end = 1;
    }

    do {
	did_rpc = 0;
	end = want_end;
	
	update_end(xn, &end, writep);

	NNPFSDEB(XDEBVNOPS, ("nnpfs_data_valid: want %lld - %lld, "
			     "tokens: want %lx has %lx length: %lld\n",
			     (long long) offset, (long long) end,
			     (long) tok, (long) xn->tokens,
			     (long long) nnpfs_vattr_get_size(&xn->attr)));
	
	/* use find_first_block() ? */
	off = offset;

	while (off < end) {
	    if (!nnpfs_block_have_p(xn, off)) {
		off_t size = nnpfs_vattr_get_size(&xn->attr);
		
		/*
		 * For append beyond what daemon knows, just go ahead.
		 * Offset zero is special in that the block always exists;
		 * we need it "installed" to be safe against gc.
		 */
		
		/* XXX can length be less than end after rpc or schedule? */
		if (off >= xn->daemon_length && off > 0
		    && NNPFS_TOKEN_GOT_ALL(xn, tok|NNPFS_ATTR_R)
		    && (writep || off < nnpfs_end_offset(size))) {
		    error = nnpfs_block_create(xn, off);
		    if (error)
			break;
		    
		    update_end(xn, &end, writep);
		    continue;
		}
		
 		did_rpc = 1;
		
		error = nnpfs_do_getdata(xn, cred, tok, off, end);
		if (error)
		    break;
		
		update_end(xn, &end, writep);
	    }
	    off += nnpfs_blocksize;
	}

	if (error)
	    break;

	if (!NNPFS_TOKEN_GOT_ALL(xn, tok|NNPFS_ATTR_R)) {
	    error = nnpfs_do_getdata(xn, cred, tok, offset, end);
	    did_rpc = 1;
	}

    } while (error == 0 && did_rpc);

    return error;
}

int
nnpfs_open_common(struct vnode *vp,
		  int mode,
		  nnpfs_vfs_context ctx)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
    int ret;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_open(%p)\n", vp));

    if (mode & FWRITE) {
	ret = nnpfs_open_valid(vp, ctx, NNPFS_OPEN_NW);

	if (!ret) {
#ifdef __APPLE__
	    xn->writers++;
#endif	
	    nnpfs_setcred(&xn->wr_cred, cred);
	}
    } else {
	ret = nnpfs_open_valid(vp, ctx, NNPFS_OPEN_NR);
    }
    
    /* always update the read cred */
    if (!ret)
	nnpfs_setcred(&xn->rd_cred, cred);

    nnpfs_dev_unlock(nnpfsp);

    return ret;
}

/*
 * find first block in given range with validity according to 'validp'
 *
 * returns offset of first such block, or NNPFS_NO_OFFSET if none
 */

static uint64_t
find_first_block(struct nnpfs_node *node, uint64_t offset,
		 uint64_t end, int validp)
{
    off_t eof = nnpfs_vattr_get_size(&node->attr);
    uint64_t off;
    
    if (nnpfs_block_empty(node)
	|| offset >= eof)
	return NNPFS_NO_OFFSET;

    /* get some batch search perhaps? */

    nnpfs_assert(nnpfs_offset(offset) == offset);

    if (end > eof)
	end = eof;
	
    for (off = offset; off < end; off += nnpfs_blocksize) {
	int validity = nnpfs_block_have_p(node, off);
	if (validp) {
	    if (validity)
		return off;
	} else {
	    if (!validity)
		return off;
	}
    }

    return NNPFS_NO_OFFSET;
}

/*
 * store data for entire node
 */
static int
do_fsync(struct nnpfs *nnpfsp,
         struct nnpfs_node *xn,
         nnpfs_kernel_cred cred,
         nnpfs_cred *ncred,
         d_thread_t *p,
         u_int flag)
{
    off_t len = nnpfs_vattr_get_size(&xn->attr); /* XXX may change on rpc */
    struct nnpfs_message_putdata msg;
    uint64_t off = 0;
    uint64_t end;
    int error = 0;
    int nrpcs = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: len 0x%llx, mask0=0x%lx\n",
			 (unsigned long long)len,
			 (unsigned long)(xn->data.nmasks > 1
					 ? xn->data.masks.list[0]
					 : xn->data.masks.first)));

    do {	
	/* get first valid block */
	off = find_first_block(xn, off, len, TRUE);
	if (off >= len || off == NNPFS_NO_OFFSET)
	    break; /* no more blocks installed */
	
	/* find the end of this range of valid blocks */
	end = find_first_block(xn, off + nnpfs_blocksize, len, FALSE);
	if (end > len || off == NNPFS_NO_OFFSET)
	    end = len;
	
	vattr2nnpfs_attr(&xn->attr, &msg.attr);
	
	if (ncred != NULL)
	    msg.cred = *ncred;
	else
	    nnpfs_setcred(&msg.cred, cred);

	msg.header.opcode = NNPFS_MSG_PUTDATA;
	msg.handle = xn->handle;
	msg.flag   = flag;
	msg.offset = off;
	msg.len = end - off;

	xn->pending_writes++; /* XXX lock */

	nrpcs++;
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);

	/* XXX locking, rpc may fail */
	xn->daemon_length = nnpfs_vattr_get_size(&xn->attr);

	xn->pending_writes--; /* XXX lock */
	nnpfs_assert(xn->pending_writes >= 0);

	off = end;
    } while (!error && end < len);

    if (error == 0)
	xn->flags &= ~NNPFS_DATA_DIRTY;
	
    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: nrpcs %d -> %d\n", nrpcs, error));

    return error;
}

int
nnpfs_fsync_common(struct vnode *vp, nnpfs_kernel_cred cred, nnpfs_cred *ncred,
		   int waitfor, d_thread_t *proc)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: %lx\n", (unsigned long)vp));

    /*
     * It seems that fsync is sometimes called after reclaiming a node.
     * In that case we just look happy.
     */

    if (xn == NULL) {
	printf("NNPFS PANIC WARNING! nnpfs_fsync called after reclaiming!\n");
	return 0;
    }
    
    nnpfs_pushdirty(vp);

    nnpfs_dev_lock(nnpfsp);
    if (xn->flags & NNPFS_DATA_DIRTY) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: dirty\n"));
#ifdef FSYNC_RECLAIM
	/* writing back the data from this vnode failed */
	if (waitfor & FSYNC_RECLAIM) {
	    printf("nnpfs_fsync: data lost, failed to write back\n");
	    xn->flags &= ~NNPFS_DATA_DIRTY;
	    return 0;
	}
#endif    
	error = do_fsync(nnpfsp, xn, cred, ncred, proc, NNPFS_WRITE | NNPFS_FSYNC);
    }
    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: return %d\n", error));

    return error;
}

int
nnpfs_close_common(struct vnode *vp, int fflag,
		   d_thread_t *proc, nnpfs_kernel_cred cred)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;
    
    NNPFSDEB(XDEBVNOPS,
	     ("nnpfs_close(%p) cred = %lx, fflag = %x, xn->flags = %x\n",
	      vp, (unsigned long)cred, fflag, xn->flags));

    if (nnpfs_vnode_isreg(vp))
        nnpfs_pushdirty(vp);
    
    nnpfs_dev_lock(nnpfsp);

    if (fflag & FWRITE) {
	if (xn->async_error == 0 && xn->flags & NNPFS_DATA_DIRTY) {
	    NNPFSDEB(XDEBVNOPS, ("nnpfs_close: fsync\n"));
    
	    error = do_fsync(nnpfsp, xn, cred, NULL, proc, NNPFS_WRITE);
	}
	/* XXX DATA_DIRTY on async_error? */
	
#ifdef __APPLE__
	if (--xn->writers < 0)
	    panic("xn -ve writers");
#endif
    }
    
    if (xn->async_error) {
	xn->async_error = 0;
	error = EIO;
    }
    
    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_close -> %d\n", error));

    return error;
}

/*
 * return offset + resid
 */

off_t
nnpfs_uio_end_length (struct uio *uio)
{
#if defined(DIAGNOSTIC) && !defined(__APPLE__)
    size_t sz = 0;
    int i;

    for (i = 0; i < uio->uio_iovcnt; i++)
	sz += uio->uio_iov[i].iov_len;
    if (sz != uio->uio_resid)
	panic("nnpfs_uio_end_length");
#endif
    return nnpfs_uio_offset(uio) + nnpfs_uio_resid(uio);
}

int
nnpfs_read_common(struct vnode *vp, struct uio *uio, int ioflag, nnpfs_kernel_cred cred)
{
    int error = 0;
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *node = VNODE_TO_XNODE(vp);
    off_t offset = nnpfs_uio_offset(uio);
    off_t length = nnpfs_uio_end_length(uio);
    off_t resid_add = 0;
    off_t eof;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_read\n"));

    /*
     * Currently, directories are handled in a different way than
     * ordinary files, so we refuse to read them. Very un-BSD-ish.
     */
    if (nnpfs_vnode_isdir(vp))
	return EINVAL;

    nnpfs_dev_lock(nnpfsp);

    nnpfs_setcred(&node->rd_cred, cred); 

    error = nnpfs_data_valid(vp, &node->rd_cred, NNPFS_DATA_R,
			     offset, length);

    if (error == 0)
	eof = nnpfs_vattr_get_size(&node->attr);

    if (error == 0 && offset < eof) {
	if (length > eof) {
	    resid_add = length - eof;
	    nnpfs_uio_setresid(uio, eof - offset);
	    length = eof;
	}

	while (offset < length) {
	    struct vnode *t;
	    off_t off = offset & (nnpfs_blocksize - 1);
	    off_t nbytes;

	    error = nnpfs_block_open(node,
				     nnpfs_offset(offset),
				     FREAD, &t);
	    if (error)
		break;

	    nnpfs_uio_setoffset(uio, off);

#if defined(__APPLE__)
	    nnpfs_vop_read(t, uio, ioflag, NULL, error);
#else
	    nnpfs_vfs_readlock(t, nnpfs_uio_to_proc(uio));
	    nnpfs_vop_read(t, uio, ioflag,
			   nnpfs_vfs_context_ucred(nnpfsp->ctx), error);
	    nnpfs_vfs_unlock(t, nnpfs_uio_to_proc(uio));
#endif
	    nnpfs_block_close(node, t, 0);

	    if (error)
		break;

	    nbytes = nnpfs_uio_offset(uio) - off;
	    if (nbytes <= 0) {
		error = EIO; /* XXX maybe should be no error? */
		printf("nnpfs_read: nbytes is %lld @0x%llx, index 0x%x\n",
		       (long long)nbytes, (unsigned long long)offset,
		       node->index);
		break;
	    }

	    offset += nbytes;
	}

	nnpfs_uio_setoffset(uio, offset);
	if (resid_add)
	    nnpfs_uio_setresid(uio, nnpfs_uio_resid(uio) + resid_add);
    }

    NNPFSDEB(XDEBVNOPS, ("nnpfs_read offset: %lu resid: %lu\n",
			 (unsigned long)nnpfs_uio_offset(uio),
			 (unsigned long)nnpfs_uio_resid(uio)));
    NNPFSDEB(XDEBVNOPS, ("nnpfs_read error: %d\n", error));

    nnpfs_dev_unlock(nnpfsp);

    return error;
}

/*
 * update node attributes after write, using cache file 't' as time
 * stamp source
 */

static void
nnpfs_update_write_attr(struct vnode *vp, struct nnpfs_node *xn,
			struct vnode *t, off_t length,
			nnpfs_vfs_context ctx)
{
    off_t eof = nnpfs_vattr_get_size(&xn->attr);
    struct nnpfs_vfs_vattr sub_attr;
    int error2 = 0;

#ifdef __APPLE__
    VATTR_INIT(&sub_attr);
    VATTR_WANTED(&sub_attr, va_modify_time);
#endif

    if (length > eof) {
	nnpfs_vattr_set_size(&xn->attr, length);
	nnpfs_vattr_set_bytes(&xn->attr, length);
#ifndef __NetBSD__
	nnpfs_set_vp_size(vp, length);
#endif
    }

#ifndef __NetBSD__
    nnpfs_vop_getattr(t, &sub_attr, ctx, error2);
    if (error2 == 0) {
	nnpfs_vattr_set_mtime(&xn->attr,
			      nnpfs_vattr_get_mtime_sec(&sub_attr),
			      nnpfs_vattr_get_mtime_nsec(&sub_attr));
    } else {
	printf("nnpfs_update_write_attr: "
	       "getattr failed for len 0x%llx\n",
	       (unsigned long long)length);
    }
#endif
}

int
nnpfs_write_common(struct vnode *vp, struct uio *uiop, int ioflag,
		   nnpfs_vfs_context ctx)
{
    nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    nnpfs_vfs_context daemon_ctx = NNPFS_FROM_VNODE(vp)->ctx;
    off_t eof = nnpfs_vattr_get_size(&xn->attr);
    int error = xn->async_error;
    off_t offset;
    off_t length;
    
    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_write(%p)\n", vp));
    
    nnpfs_assert(!nnpfs_vnode_isdir(vp));
    
    nnpfs_setcred(&xn->wr_cred, cred); 
    
    if (error) {
	xn->async_error = 0;
	nnpfs_dev_unlock(nnpfsp);
	return error;
    }

    if (ioflag & IO_APPEND)
	nnpfs_uio_setoffset(uiop, eof);
    
    offset = nnpfs_uio_offset(uiop);
    length = nnpfs_uio_end_length(uiop);
    
    error = nnpfs_data_valid(vp, &xn->wr_cred, NNPFS_DATA_W, offset, length);
    if (error) {
	nnpfs_dev_unlock(nnpfsp);
	return error;
    }

    while (offset < length) {
	off_t off = offset & (nnpfs_blocksize - 1);
	int flags = FWRITE;
	off_t resid;
	struct vnode *t;
	off_t nbytes;
	
#ifdef __FreeBSD__
	struct mount *mp;
#endif

	if (offset >= eof)
	    flags = FWRITE | O_CREAT;
	
	error = nnpfs_block_open(xn, nnpfs_offset(offset), flags, &t);
	if (error) {
	    error = EIO;
	    break;
	}
	
	resid = nnpfs_blocksize - off;
	if (offset + resid > length)
	    resid = length - offset;
	
	nnpfs_uio_setoffset(uiop, off);
	nnpfs_uio_setresid(uiop, resid);
	
#ifdef __APPLE__
	nnpfs_vop_write(t, uiop, ioflag, daemon_ctx, error);
#else

#ifdef __FreeBSD__
	(void)vn_start_write(t, &mp, V_WAIT);
	nnpfs_vfs_writelock(t, nnpfs_vfs_context_proc(ctx));
	(void)VOP_LEASE(t, nnpfs_vfs_context_proc(ctx), cred, LEASE_WRITE);
#endif

	nnpfs_vop_write(t, uiop, ioflag, cred, error);
#endif
	
	if (!error) {
	    nbytes = nnpfs_uio_offset(uiop) - off;
	    if (nbytes > 0) {
		offset += nbytes;
	    } else {
		error = EIO;
		printf("nnpfs_write: nbytes is %lld!\n",
		       (long long)nbytes);
	    }

/* #ifndef __NetBSD__ */
	    /* get time stamp etc from the last cache file */
	    if (offset >= length)
		nnpfs_update_write_attr(vp, xn, t, offset, daemon_ctx);
/* #endif  !__NetBSD__ */

	}	    
#ifndef __NetBSD__
	nnpfs_vfs_unlock(t, nnpfs_vfs_context_proc(ctx));
#endif

#ifdef __FreeBSD__
	vn_finished_write(mp);
#endif

	nnpfs_block_close(xn, t, 1);

	if (error)
	    break;
    }
        
    xn->flags |= NNPFS_DATA_DIRTY;
    nnpfs_uio_setoffset(uiop, offset);
    nnpfs_uio_setresid(uiop, length - offset);

    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_write -> %d\n", error));

    return error;
}

int
nnpfs_getattr_common(struct vnode *vp, struct nnpfs_vfs_vattr *vap,
		     nnpfs_kernel_cred cred, d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr\n"));

    error = nnpfs_attr_valid(vp, cred, p, NNPFS_ATTR_R);
    if (error == 0)
	*vap = xn->attr;

    nnpfs_dev_unlock(nnpfsp);

    return error;
}

static int
setattr_is_noop(struct nnpfs_node *xn, struct nnpfs_vfs_vattr *vap)
{
#ifdef __APPLE__
    
#define CHECK_NNPFSATTR(A) (!VATTR_IS_ACTIVE(vap, A) || vap->A == xn->attr.A)
    if (CHECK_NNPFSATTR(va_mode) &&
	CHECK_NNPFSATTR(va_nlink) &&
	CHECK_NNPFSATTR(va_data_size) &&
	CHECK_NNPFSATTR(va_uid) &&
	CHECK_NNPFSATTR(va_gid) &&
	CHECK_NNPFSATTR(va_fileid) && /* we ignore va_type */
	(!VATTR_IS_ACTIVE(vap, va_modify_time)
	 || vap->va_modify_time.tv_sec == xn->attr.va_modify_time.tv_sec))
	return 1;
#undef CHECK_NNPFSATTR

#else

#define CHECK_NNPFSATTR(A, cast) (vap->A == cast VNOVAL || vap->A == xn->attr.A)
    if (CHECK_NNPFSATTR(va_mode,(mode_t)) &&
	CHECK_NNPFSATTR(va_nlink,(short)) &&
	CHECK_NNPFSATTR(va_size,(va_size_t)) &&
	CHECK_NNPFSATTR(va_uid,(uid_t)) &&
	CHECK_NNPFSATTR(va_gid,(gid_t)) &&
	CHECK_NNPFSATTR(va_mtime.tv_sec,(time_t)) &&
	CHECK_NNPFSATTR(va_fileid,(long)) &&
	CHECK_NNPFSATTR(va_type,(enum vtype)))
	return 1;
#undef CHECK_NNPFSATTR

#endif /* ! __APPLE__ */

    return 0;
}

int
nnpfs_setattr_common(struct vnode *vp, struct nnpfs_vfs_vattr *vap,
		     nnpfs_kernel_cred cred, d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_setattr\n"));

    if (setattr_is_noop(xn, vap)) {
	nnpfs_dev_unlock(nnpfsp);
	return 0; /* nothing to do */
    }

    if (NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_W)) {
	/* Update attributes and mark them dirty. */
	VNODE_TO_XNODE(vp)->flags |= NNPFS_ATTR_DIRTY;
	error = EINVAL;		       /* XXX not yet implemented */
	goto done;
    } else {
	struct nnpfs_message_putattr msg;
	uint64_t old_length, new_length;

	msg.header.opcode = NNPFS_MSG_PUTATTR;
	nnpfs_setcred(&msg.cred, cred);
	msg.handle = xn->handle;
	vattr2nnpfs_attr(vap, &msg.attr);

	if (NNPFS_TOKEN_GOT(xn, NNPFS_DATA_R)) {
	    if (nnpfs_vnode_isreg(vp)) {
		old_length = nnpfs_vattr_get_size(&xn->attr);
		
		if (nnpfs_vattr_size_isactive(vap)) {
		    new_length = nnpfs_vattr_get_size(vap);

		    XA_SET_SIZE(&msg.attr, new_length);
		} else {
		    XA_SET_SIZE(&msg.attr, old_length);
		}
	    }

	    if (nnpfs_vattr_mtime_isactive(vap))
		XA_SET_MTIME(&msg.attr, nnpfs_vattr_get_mtime_sec(vap));
	    else
		XA_SET_MTIME(&msg.attr, nnpfs_vattr_get_mtime_sec(&xn->attr));
	}
	
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);

#if 0 /* assume length is always in (loose) sync with daemon nowadays */
	if (error == 0 && do_fixup)
	    truncate_block_fixup(xn, old_length, new_length);
#endif
    }

done:
    nnpfs_dev_unlock(nnpfsp);
    NNPFS_VN_KNOTE(vp, NOTE_ATTRIB);

    return error;
}

static int
check_rights (nnpfs_rights rights, int mode, int dirp)
{
    int error = 0;

#ifdef __APPLE__
    /* VNOP_ACCESS passes a kauth action instead of ordinary unix mode */

    if (dirp) {
	if (mode & (KAUTH_VNODE_LIST_DIRECTORY | KAUTH_VNODE_SEARCH))
	    if ((rights & NNPFS_RIGHT_X) == 0)
		error = EACCES;
	if (mode & KAUTH_VNODE_DELETE_CHILD)
	    if ((rights & NNPFS_RIGHT_AD) == 0)
		error = EACCES;
	if (mode & (KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY))
	    if ((rights & NNPFS_RIGHT_AI) == 0)
		error = EACCES;

	/* XXX can't check KAUTH_VNODE_DELETE, have no info */

    } else {
	if (mode & (KAUTH_VNODE_READ_DATA | KAUTH_VNODE_READ_ATTRIBUTES))
	    if ((rights & NNPFS_RIGHT_AR) == 0)
		error = EACCES;
	if (mode & (KAUTH_VNODE_WRITE_DATA | KAUTH_VNODE_APPEND_DATA | KAUTH_VNODE_WRITE_ATTRIBUTES | KAUTH_VNODE_TAKE_OWNERSHIP))
	    if ((rights & NNPFS_RIGHT_W) == 0)
		error = EACCES;
	if (mode & KAUTH_VNODE_EXECUTE)
	    if ((rights & NNPFS_RIGHT_X) == 0)
		error = EACCES;
	if (mode & KAUTH_VNODE_DELETE)
	    if ((rights & NNPFS_RIGHT_AD) == 0)
		error = EACCES;
    }
    
#if 0
KAUTH_VNODE_READ_EXTATTRIBUTES
KAUTH_VNODE_WRITE_EXTATTRIBUTES
KAUTH_VNODE_READ_SECURITY
KAUTH_VNODE_WRITE_SECURITY
KAUTH_VNODE_SYNCHRONIZE notused
KAUTH_VNODE_LINKTARGET like insert, but for target???
KAUTH_VNODE_CHECKIMMUTABLE always ok
KAUTH_VNODE_ACCESS (advisory)
KAUTH_VNODE_NOIMMUTABLE ?
#endif

#else /* !__APPLE__ */

    if (mode & VREAD)
	if ((rights & NNPFS_RIGHT_R) == 0)
	    error = EACCES;
    if (mode & VWRITE)
	if ((rights & NNPFS_RIGHT_W) == 0)
	    error = EACCES;
    if (mode & VEXEC)
	if ((rights & NNPFS_RIGHT_X) == 0)
	    error = EACCES;

#endif /* !__APPLE__ */

    return error;
}

int
nnpfs_access_common(struct vnode *vp, int mode, nnpfs_kernel_cred cred,
		    d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    int dirp = nnpfs_vnode_isdir(vp);
    int error = 0;
    nnpfs_pag_t pag;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access mode = 0%o\n", mode));

    pag = nnpfs_get_pag(cred);

    error = nnpfs_attr_valid(vp, cred, p, NNPFS_ATTR_R);
    if (error == 0) {
	struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
	int i;

	error = check_rights(xn->anonrights, mode, dirp);

	if (error == 0)
	    goto done;

	NNPFSDEB(XDEBVNOPS, ("nnpfs_access anonaccess failed\n"));

	error = EACCES;		/* default to EACCES if pag isn't in xn->id */

	for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	    if (xn->id[i] == pag) {
		error = check_rights(xn->rights[i], mode, dirp);
		break;
	    }
    }

done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access(0%o) = %d\n", mode, error));
    nnpfs_dev_unlock(nnpfsp);

    return error;
}

int
nnpfs_lookup_common(struct vnode *dvp, 
		    nnpfs_componentname *cnp, 
		    struct vnode **vpp,
		    nnpfs_vfs_context ctx)
{
    struct nnpfs_message_getnode msg;
    nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
    d_thread_t *p  = nnpfs_vfs_context_proc(ctx);
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *d = VNODE_TO_XNODE(dvp);
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup_common: enter\n"));

    *vpp = NULL;

    if (cnp->cn_namelen >= NNPFS_MAX_NAME)
	return ENAMETOOLONG;
	
    if (!nnpfs_vnode_isdir(dvp))
	return ENOTDIR;

    if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
	*vpp = dvp;
#ifdef __APPLE__
	nnpfs_do_vget(*vpp, 0 /* XXX flag */, NULL /*proc */);
#else
	nnpfs_vref(*vpp);
#endif
	return 0;
    }
    
    nnpfs_dev_lock(nnpfsp);
    do {
	nnpfs_lookup_access(dvp, ctx, p, error);
	if (error != 0)
	    goto done;

	NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup_common: dvp = %lx\n",
			   (unsigned long) dvp));
	NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup_common: cnp = %lx, "
			   "cnp->cn_nameiop = %d\n", 
			   (unsigned long) cnp, (int)cnp->cn_nameiop));
	
	error = nnpfs_dnlc_lookup(dvp, cnp, vpp);
	if (error == 0) { /* not cached */

	    /*
	     * Doesn't quite work.
	     */

#if 0
	    if ((cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME)
		&& (cnp->cn_flags & ISLASTCN)) {
		error = EJUSTRETURN;
		goto done;
	    }
#endif

	    msg.header.opcode = NNPFS_MSG_GETNODE;
	    nnpfs_setcred(&msg.cred, cred);
	    msg.parent_handle = d->handle;
	    memcpy(msg.name, cnp->cn_nameptr, cnp->cn_namelen);
	    msg.name[cnp->cn_namelen] = '\0';
	    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	    if (error == 0)
		error = NNPFS_MSG_WAKEUP_ERROR(&msg);
	    if(error == ENOENT && cnp->cn_nameiop != CREATE) {
		NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: neg cache %lx (%s, %ld)\n",
				   (unsigned long)dvp,
				   cnp->cn_nameptr, cnp->cn_namelen));
		nnpfs_dnlc_enter (dvp, cnp, NULL);
	    }
	} else if (error == -1) { /* found */
	    error = 0;
	    goto done;
	}
    } while (error == 0);

 done:
    nnpfs_dev_unlock(nnpfsp);
    NNPFS_VN_KNOTE(dvp, NOTE_WRITE);
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup_common: return %d, vn %p\n",
			 error, *vpp));
    return error;
}

int
nnpfs_create_common(struct vnode *dvp,
		    const char *name,
		    struct nnpfs_vfs_vattr *vap, 
		    nnpfs_kernel_cred cred,
		    d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_create: (%lx, %s)\n",
			 (unsigned long)dvp, name));
    {
	struct nnpfs_message_create msg;

	msg.header.opcode = NNPFS_MSG_CREATE;
	msg.parent_handle = xn->handle;
	if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	    return ENAMETOOLONG;
	vattr2nnpfs_attr(vap, &msg.attr);

	msg.mode = 0;		       /* XXX - mode */
	nnpfs_setcred(&msg.cred, cred);

#ifdef __APPLE__
	/* needed for subsequent writes to succeed with n */
	msg.attr.valid &= ~XA_V_UID; 
#endif

	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    }

#if 0
    if (error == EEXIST)
	error = 0;
#endif

    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_create -> %d\n", error));

    return error;
}

int
nnpfs_remove_common(struct vnode *dvp,
		    struct vnode *vp,
		    const char *name,
		    nnpfs_kernel_cred cred,
		    d_thread_t *p)
{
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    struct nnpfs_message_remove msg;
    int error;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_remove(%p): %s\n", dvp, name));

    msg.header.opcode = NNPFS_MSG_REMOVE;
    msg.parent_handle = xn->handle;
    msg.cred.uid = nnpfs_cred_get_uid(cred);
    msg.cred.pag = nnpfs_get_pag(cred);
    
    if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	error = ENAMETOOLONG;
    else
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    if (error == 0)
	nnpfs_dnlc_purge (vp);
    
    nnpfs_dev_unlock(nnpfsp);
    
    if (error == 0) {
	NNPFS_VN_KNOTE(vp, NOTE_DELETE);
	NNPFS_VN_KNOTE(dvp, NOTE_WRITE);
    }
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_remove -> %d\n", error));
    
    return error;
}

int
nnpfs_rename_common(struct vnode *fdvp, 
		    struct vnode *fvp,
		    const char *fname,
		    struct vnode *tdvp,
		    struct vnode *tvp,
		    const char *tname,
		    nnpfs_kernel_cred cred,
		    d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(fdvp);
    int error;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: %s %s\n", fname, tname));

#if 0
    if ((fvp->v_mount != tdvp->v_mount)
	|| (tvp && (fvp->v_mount != tvp->v_mount))) {
	return  EXDEV;
    }
#endif

    {
	struct nnpfs_message_rename msg;

	msg.header.opcode = NNPFS_MSG_RENAME;
	msg.old_parent_handle = VNODE_TO_XNODE(fdvp)->handle;
	if (strlcpy(msg.old_name, fname, sizeof(msg.old_name)) >= NNPFS_MAX_NAME) {
	    nnpfs_dev_unlock(nnpfsp);
	    return ENAMETOOLONG;
	}

	msg.new_parent_handle = VNODE_TO_XNODE(tdvp)->handle;
	if (strlcpy(msg.new_name, tname, sizeof(msg.new_name)) >= NNPFS_MAX_NAME) {
	    nnpfs_dev_unlock(nnpfsp);
	    return ENAMETOOLONG;
	}

	msg.cred.uid = nnpfs_cred_get_uid(cred);
	msg.cred.pag = nnpfs_get_pag(cred);
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    }

    nnpfs_dev_unlock(nnpfsp);
    NNPFS_VN_KNOTE(fdvp, NOTE_WRITE);
    NNPFS_VN_KNOTE(fvp, NOTE_WRITE);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: error = %d\n", error));

    return error;
}

int
nnpfs_mkdir_common(struct vnode *dvp, 
		   const char *name,
		   struct nnpfs_vfs_vattr *vap, 
		   nnpfs_kernel_cred cred,
		   d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir(%p): %s\n", dvp, name));
    {
	struct nnpfs_message_mkdir msg;

	msg.header.opcode = NNPFS_MSG_MKDIR;
	msg.parent_handle = xn->handle;
	if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME) {
	    nnpfs_dev_unlock(nnpfsp);
	    return ENAMETOOLONG;
	}

	vattr2nnpfs_attr(vap, &msg.attr);
	nnpfs_setcred(&msg.cred, cred);
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    }

    nnpfs_dev_unlock(nnpfsp);

    if (error == 0)
	NNPFS_VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir -> %d\n", error));
    return error;
}

int
nnpfs_rmdir_common(struct vnode *dvp,
		   struct vnode *vp,
		   const char *name,
		   nnpfs_kernel_cred cred,
		   d_thread_t *p)
{
    struct nnpfs *nnpfsp  = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    struct nnpfs_message_rmdir msg;
    int error;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir: %s\n", name));

    msg.header.opcode = NNPFS_MSG_RMDIR;
    msg.parent_handle = xn->handle;
    msg.cred.uid = nnpfs_cred_get_uid(cred);
    msg.cred.pag = nnpfs_get_pag(cred);
    if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	error = ENAMETOOLONG;
    else
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    if (error == 0) {
	nnpfs_dnlc_purge (vp);

	/* XXX knote even on error? */
	NNPFS_VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
	NNPFS_VN_KNOTE(vp, NOTE_DELETE);
    }

    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir error: %d\n", error));

    return error;
}

int
nnpfs_readdir_common(struct vnode *vp, 
		     struct uio *uiop, 
		     int *eofflag,
		     nnpfs_vfs_context ctx)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct vnode *t = NULL;
    struct nnpfs_node *node;
    nnpfs_cred cred;
    int error;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir(%p)\n", vp));

    if (eofflag)
	*eofflag = 0;

    nnpfs_assert(nnpfs_vnode_isdir(vp));

    nnpfs_setcred(&cred, nnpfs_vfs_context_ucred(ctx));

    /* XXX dir can be removed at any moment, but this is ridiculous. */
    while (1) {
	error = nnpfs_data_valid(vp, &cred, NNPFS_DATA_R,
				 nnpfs_uio_offset(uiop),
				 nnpfs_uio_end_length(uiop));
	if (error) {
	    nnpfs_dev_unlock(nnpfsp);
	    return error;
	}
	node = VNODE_TO_XNODE(vp);
	error = nnpfs_block_open(node, 0, FREAD, &t);
	if (!error)
	    break;
    }
    
    nnpfs_vfs_readlock(t, nnpfs_uio_to_proc(uiop));
    nnpfs_vop_read(t, uiop, 0, NULL, error);
    if (eofflag) {
	struct nnpfs_vfs_vattr t_attr;
	int error2;
	
#ifdef __APPLE__
	VATTR_INIT(&t_attr);
	VATTR_WANTED(&t_attr, va_data_size);
#endif
	nnpfs_vop_getattr(t, &t_attr, ctx, error2);  /* XXX check bitmask */
	if (error2 == 0)
	    *eofflag = nnpfs_vattr_get_size(&t_attr) <= nnpfs_uio_offset(uiop);
    }
    nnpfs_vfs_unlock(t, nnpfs_uio_to_proc(uiop));
    nnpfs_block_close(node, t, 0);

    nnpfs_dev_unlock(nnpfsp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_readdir -> %d\n", error));

    return error;
}

int
nnpfs_link_common(struct vnode *dvp, 
		  struct vnode *vp, 
		  const char *name,
		  nnpfs_kernel_cred cred,
		  d_thread_t *p)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    struct nnpfs_node *xn2 = VNODE_TO_XNODE(vp);
    struct nnpfs_message_link msg;
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_link: %s\n", name));
    
    msg.header.opcode = NNPFS_MSG_LINK;
    msg.parent_handle = xn->handle;
    msg.from_handle   = xn2->handle;
    if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME) {
	nnpfs_dev_unlock(nnpfsp);
	return ENAMETOOLONG;
    }

    msg.cred.uid = nnpfs_cred_get_uid(cred);
    msg.cred.pag = nnpfs_get_pag(cred);

    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), p);
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    
    nnpfs_dev_unlock(nnpfsp);
    NNPFS_VN_KNOTE(vp, NOTE_LINK);

    return error;
}

int
nnpfs_symlink_common(struct vnode *dvp,
		     struct vnode **vpp,
		     nnpfs_componentname *cnp,
		     struct nnpfs_vfs_vattr *vap,
		     char *target,
		     nnpfs_vfs_context ctx)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
    struct nnpfs_message_symlink *msg = NULL;
    const char *name = cnp->cn_nameptr;
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_symlink: %s\n", name));

    msg = malloc(sizeof(*msg), M_TEMP, M_WAITOK | M_ZERO);

    msg->header.opcode = NNPFS_MSG_SYMLINK;
    msg->parent_handle = xn->handle;
    vattr2nnpfs_attr(vap, &msg->attr);
    msg->cred.uid = nnpfs_cred_get_uid(cred);
    msg->cred.pag = nnpfs_get_pag(cred);
    if (strlcpy(msg->contents, target, sizeof(msg->contents)) >= NNPFS_MAX_SYMLINK_CONTENT) {
	error = ENAMETOOLONG;
	goto done;
    }
    if (strlcpy(msg->name, name, sizeof(msg->name)) >= NNPFS_MAX_NAME) {
	error = ENAMETOOLONG;
	goto done;
    }
    error = nnpfs_message_rpc(nnpfsp, &msg->header, sizeof(*msg),
			      nnpfs_vfs_context_proc(ctx));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(msg);

 done:
    free(msg, M_TEMP);
    nnpfs_dev_unlock(nnpfsp);
    NNPFS_VN_KNOTE(dvp, NOTE_WRITE);

    return error;
}

int
nnpfs_readlink_common(struct vnode *vp, struct uio *uiop, nnpfs_vfs_context ctx)
{
    int error = 0;
    nnpfs_cred cred;
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
#if defined(HAVE_THREE_ARGUMENT_VOP_UNLOCK) || defined(__OpenBSD__)
    d_thread_t *proc = nnpfs_vfs_context_proc(ctx);
#endif

    NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink\n"));

    if (!nnpfs_vnode_islnk(vp) || (nnpfs_uio_offset(uiop) != (off_t)0))
	return EINVAL;

    nnpfs_dev_lock(nnpfsp);

    /* XXX check it fits in one block */

    nnpfs_setcred(&cred, nnpfs_vfs_context_ucred(ctx));
    error = nnpfs_data_valid(vp, &cred, NNPFS_DATA_R,
			     nnpfs_uio_offset(uiop),
			     nnpfs_uio_end_length(uiop));

    if (error == 0) {
	struct nnpfs_node *node = VNODE_TO_XNODE(vp);
	off_t eof, resid;
	struct vnode *t;

	error = nnpfs_block_open(node, 0, FREAD, &t);
	if (error)
	    goto out;

	eof = nnpfs_vattr_get_size(&node->attr);
	resid = nnpfs_uio_resid(uiop);

	if (resid > eof)
	    nnpfs_uio_setresid(uiop, eof);
	    
#if defined(__APPLE__)
	nnpfs_vop_read(t, uiop, 0, ctx, error);
#else
	nnpfs_vfs_readlock(t, proc);
	nnpfs_vop_read(t, uiop, 0, nnpfs_vfs_context_ucred(ctx), error);
	nnpfs_vfs_unlock(t, proc);
#endif
	nnpfs_block_close(node, t, 0);

	if (resid > eof)
	    nnpfs_uio_setresid(uiop, nnpfs_uio_resid(uiop) + (resid - eof));
    }

out:
    nnpfs_dev_unlock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink: return %d\n", error));

    return error;
}

int
nnpfs_inactive_common(struct vnode *vp, d_thread_t *proc)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);
    int recyclep;
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive(%lx)\n", (unsigned long)vp));

    /*
     * This seems rather bogus, but sometimes we get an already
     * cleaned node to be made inactive.  Just ignoring it seems safe.
     */

    if (xn == NULL) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive: clean node\n"));
	return 0;
    }

    /* xn->wr_cred not set -> NOCRED */

    if (nnpfs_vnode_isreg(vp))
	nnpfs_pushdirty(vp);

    nnpfs_dev_lock(nnpfsp);

    error = nnpfs_fsync_common(vp, NULL, &xn->wr_cred, 0, proc);
    if (error) {
	printf ("nnpfs_inactive: failed writing back data: %d\n", error);
	xn->flags &= ~NNPFS_DATA_DIRTY;
    }

    /* If this node is no longer valid, recycle immediately. */
    recyclep = (!NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_R | NNPFS_ATTR_W)
		|| (xn->flags & NNPFS_STALE) == NNPFS_STALE);
    
#ifndef __FreeBSD__	
    nnpfs_vfs_unlock(vp, proc);
#endif
    
    if (recyclep) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_inactive: vrecycle\n"));
	nnpfs_vrecycle(vp, 0, proc);
    }

    NNPFSDEB(XDEBVNOPS, ("return: nnpfs_inactive done\n"));

    nnpfs_dev_unlock(nnpfsp);
    return 0;
}

int
nnpfs_reclaim_common(struct vnode *vp)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(vp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_reclaim(%lx)\n", (unsigned long)vp));

    nnpfs_dev_lock(nnpfsp);

    xn->flags |= NNPFS_LIMBO;

    nnpfs_release_data(xn);

    nnpfs_dnlc_purge(vp);

    NNPQUEUE_INSERT_HEAD(&nnpfsp->freehead, xn, nn_free);

    if (nnpfsp->status & CHANNEL_OPENED) {
	struct nnpfs_message_inactivenode msg;

	msg.header.opcode = NNPFS_MSG_INACTIVENODE;
	msg.handle = xn->handle;
	msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;
	nnpfs_message_send(nnpfsp, &msg.header, sizeof(msg));
    } else {
	nnpfs_free_node(nnpfsp, xn);
    }
    
    nnpfs_dev_unlock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_reclaim done\n"));

    return 0;
}

/*
 *
 */

#if 0

int
nnpfs_advlock_common(struct vnode *dvp, 
		   int locktype,
		   unsigned long lockid, /* XXX this good ? */
		   nnpfs_kernel_cred cred)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(dvp);
    struct nnpfs_node *xn = VNODE_TO_XNODE(dvp);
    int error = 0;

    nnpfs_dev_lock(nnpfsp);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_advlock\n"));
    {
	struct nnpfs_message_advlock msg;

	msg.header.opcode = NNPFS_MSG_ADVLOCK;
	msg.handle = xn->handle;
	msg.locktype = locktype;
	msg.lockid = lockid;

	nnpfs_setcred(&msg.cred, cred);
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg), 
				  nnpfs_vfs_context_proc(ctx));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    }

    if (error == 0) {
	
	/* sleep until woken */

    } else {

	/* die */
    }

    nnpfs_dev_unlock(nnpfsp);
    return error;
}

#endif

/*
 *
 */

void
nnpfs_printnode_common (struct vnode *vp)
{
    struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

    printf ("xnode: fid: %d.%d.%d.%d\n", 
	    xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d);
    printf ("\tattr: %svalid\n", 
	    NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_VALID) ? "": "in");
    printf ("\tdata: %svalid\n", 
	    NNPFS_TOKEN_GOT(xn, NNPFS_DATA_VALID) ? "": "in");
    printf ("\tflags: 0x%x\n", xn->flags);
}
