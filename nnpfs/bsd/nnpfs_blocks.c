/*
 * Copyright (c) 2005-2007, Stockholms Universitet
 * (Stockholm University, Stockholm Sweden)
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
 * 3. Neither the name of the university nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: nnpfs_blocks.c,v 1.14 2010/06/16 19:58:50 tol Exp $ */

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vnodeops.h>

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>

/*
 * return true if block is in cache
 */

int
nnpfs_block_have_p(struct nnpfs_node *node, uint64_t offset)
{
    struct nnpfs_cache_handle *handle = &node->data;
    uint32_t index = nnpfs_block_index(offset);
    uint32_t maskno = nnpfs_block_masknumber(index);

    nnpfs_assert(nnpfs_offset(offset) == offset);

    if (handle->nmasks == 0)
	return 0;

    if (maskno >= handle->nmasks)
	return 0;

    if (handle->nmasks == 1)
	return (handle->masks.first & nnpfs_block_mask(index));

    return (handle->masks.list[maskno] & nnpfs_block_mask(index));
}

/*
 * mark block at offset as present in cache
 *
 * XXX assert on the bit being changed?
 */

static int
nnpfs_block_set_have(struct nnpfs_node *node, uint64_t offset, int val)
{
    struct nnpfs_cache_handle *handle = &node->data;
    uint32_t index = nnpfs_block_index(offset);
    uint32_t maskno = nnpfs_block_masknumber(index);
    uint32_t mask = nnpfs_block_mask(index);
    uint32_t *slot;

    nnpfs_assert(nnpfs_offset(offset) == offset);

    if (maskno == 0 && handle->nmasks <= 1) {
	handle->nmasks = 1;
	slot = &handle->masks.first;
    } else {
	if (maskno >= handle->nmasks) {
	    int n = maskno + NNPFS_NMASKS - (maskno % NNPFS_NMASKS);
	    int size = n * sizeof(uint32_t);
	    uint32_t *new;

	    nnpfs_assert(val);

	    new = nnpfs_alloc(size, M_NNPFS_BLOCKS);
	    nnpfs_debug_assert(new);
	    if (!new)
		return ENOMEM;
	    
	    if (handle->nmasks == 1) {
		new[0] = handle->masks.first;
	    } else if (handle->nmasks > 1) {
		memcpy(new, handle->masks.list,
		       handle->nmasks * sizeof(uint32_t));
		nnpfs_free(handle->masks.list, handle->nmasks * sizeof(uint32_t),
			   M_NNPFS_BLOCKS);
	    }

	    memset(&new[handle->nmasks], 0,
		   (n - handle->nmasks) * sizeof(uint32_t));
	    handle->nmasks = n;
	    handle->masks.list = new;
	}
	slot = &handle->masks.list[maskno];
    }
    
    if (val)
	*slot |= mask;
    else
	*slot &= ~mask;

    return 0;
}

/*
 * mark block at offset as present in cache
 */

int
nnpfs_block_setvalid(struct nnpfs_node *node, uint64_t offset)
{
    return nnpfs_block_set_have(node, offset, TRUE);
}

/*
 * mark block at offset as not present in cache
 */

void
nnpfs_block_setinvalid(struct nnpfs_node *node, uint64_t offset)
{
    (void)nnpfs_block_set_have(node, offset, FALSE);
}

static void
nnpfs_block_foreach_int(struct nnpfs_node *node,
			nnpfs_block_callback_t fun,
			void *data, 
			uint64_t base_offset,
			int32_t mask)
{
    uint32_t tmp_mask = 1;
    int i;

    if (!mask)
	return;

    for (i = 0; i < 32; i++) {
	if (mask & tmp_mask) {
	    fun(node, base_offset + i * nnpfs_blocksize, data);
	    mask -= tmp_mask;
	    if (!mask)
		return;
	}

	tmp_mask = tmp_mask << 1;
    }
}

/*
 * call callback for every block present in cache
 */

void
nnpfs_block_foreach(struct nnpfs_node *node,
		    nnpfs_block_callback_t fun,
		    void *data)
{
    struct nnpfs_cache_handle *handle = &node->data;
    int i;
    
    if (handle->nmasks == 0)
	return;

    if (handle->nmasks == 1) {
	nnpfs_block_foreach_int(node, fun, data, 0, handle->masks.first);
	return;
    }

    for (i = 0; i < handle->nmasks; i++)
	nnpfs_block_foreach_int(node, fun, data, i * 32 * nnpfs_blocksize,
				handle->masks.list[i]);
}

/*
 * Foreach callback for nnpfs_block_truncate()
 */

static void
truncate_callback(struct nnpfs_node *node, uint64_t offset, void *data)
{
    uint64_t *size = (uint64_t *)data;
    if (*size <= offset && offset > 0)
	(void)nnpfs_block_set_have(node, offset, FALSE);
}

/*
 * Forget all blocks beyond `size´ for `node' 
 */

void
nnpfs_block_truncate(struct nnpfs_node *node, uint64_t size)
{
    nnpfs_block_foreach(node, truncate_callback, &size);
}

/*
 * free all handle internal resources 
 */

void
nnpfs_block_free_all(struct nnpfs_node *node)
{
    struct nnpfs_cache_handle *handle = &node->data;
    if (handle->nmasks > 1) {
	nnpfs_free(handle->masks.list, handle->nmasks * sizeof(uint32_t),
		   M_NNPFS_BLOCKS);
	handle->masks.list = NULL;
    } else {
	handle->masks.first = 0;
    }

    handle->nmasks = 0;
}

/*
 * return true if we have no data
 */

int
nnpfs_block_empty(struct nnpfs_node *node)
{
    struct nnpfs_cache_handle *handle = &node->data;
    int i;

    if (handle->nmasks == 0)
	return 1;

    if (handle->nmasks == 1) {
	if (handle->masks.first == 0)
	    return 1;
	return 0;
    }
    
    for (i = 0; i < handle->nmasks; i++)
	if (handle->masks.list[i] != 0)
	    return 0;

    return 1;
}

static int
nnpfs_block_extend_int(struct nnpfs_node *node, struct vnode *vp, d_thread_t *p)
{
    struct nnpfs_vfs_vattr va;
    int ret;

    VATTR_INIT(&va);
    nnpfs_set_va_size(&va, nnpfs_blocksize);
    nnpfs_vfs_writelock(vp, p);

    /* printf("nnpfs extend_int(%p)\n", vp); */
    ret = nnpfs_vnode_setattr(vp, &va, NNPFS_FROM_XNODE(node)->ctx);
    nnpfs_vfs_unlock(vp, p);
    nnpfs_debug_assert(!ret);
    return ret;
}

/*
 * Extend an existing block to full block size.
 */

static int
nnpfs_block_extend(struct nnpfs_node *node, uint64_t offset)
{
    d_thread_t *p = nnpfs_curproc();
    struct vnode *vp;
    int ret;

    nnpfs_assert(nnpfs_block_have_p(node, offset));
    
    ret = nnpfs_block_open(node, offset, FREAD|FWRITE, &vp);
    if (!ret) {
	nnpfs_assert(vp);

#ifdef __FreeBSD__
	{
	    struct mount *mp;

	    (void)vn_start_write(vp, &mp, V_WAIT);
	    VOP_LEASE(vp, p,
		      nnpfs_vfs_context_ucred(NNPFS_FROM_XNODE(node)->ctx),
		      LEASE_WRITE);
	    
	    ret = nnpfs_block_extend_int(node, vp, p);
	    
	    nnpfs_vfs_unlock(vp, p);
	    vn_finished_write(mp);
	}
#else
	ret = nnpfs_block_extend_int(node, vp, p);
#endif
	
	nnpfs_block_close(node, vp, 1);
    }

    if (ret)
	printf("nnpfs_block_extend: failed at offset 0x%llx: %d\n",
	       (unsigned long long)offset, ret);

    return ret;
}

#ifndef __APPLE__
/*
 * namei() compatible alloc/free
 */

static long nnpfs_namei_allocs, nnpfs_namei_frees;
static void
nnpfs_namei_alloc(struct componentname *cnp)
{
    void *p = NULL;

    if (cnp->cn_flags & HASBUF) {
	printf("nnpfs_namei_alloc: cnp flags 0x%lx\n", cnp->cn_flags);
	return;
    }

#ifdef __FreeBSD__
    p = uma_zalloc(namei_zone, M_WAITOK);
#endif
#ifdef __OpenBSD__
    p = pool_get(&namei_pool, PR_WAITOK);
#endif
#ifdef __NetBSD__
    p = PNBUF_GET();
#endif
    if (p) {
        cnp->cn_pnbuf = p;
        cnp->cn_flags |= HASBUF;
	nnpfs_namei_allocs++;
    }
}

static void
nnpfs_namei_free(struct componentname *cnp)
{
    if ((cnp->cn_flags & HASBUF) == 0)
        return;

#ifdef __FreeBSD__
    uma_zfree(namei_zone, cnp->cn_pnbuf);
#endif
#ifdef __NetBSD__
    PNBUF_PUT(cnp->cn_pnbuf);
#endif
#ifdef __OpenBSD__
    pool_put(&namei_pool, cnp->cn_pnbuf);
#endif

    cnp->cn_flags &= ~HASBUF;
    nnpfs_namei_frees++;
}

#endif /* !__APPLE__ */


/*
 * a handy implementation of open()
 *
 * nnpfs_block_close() on success.
 */

static int
open_file(struct vnode *cachedir, char *name, int fmode,
	  nnpfs_vfs_context ctx, struct vnode **vpp)
{
    int error;

#ifdef __APPLE__ /* XXX */
    error = vnode_open(name, fmode, S_IRUSR|S_IWUSR, 0, vpp, ctx);
#else
    {
	d_thread_t *p = nnpfs_curproc();
	nnpfs_kernel_cred cred = nnpfs_vfs_context_ucred(ctx);
 	/* nnpfs_kernel_cred cred = nnpfs_proc_to_cred(p); */
	struct nameidata nd;

	memset(&nd, 0, sizeof(nd));

	if (fmode & O_CREAT) {
	    NDINIT(&nd, CREATE,
		   FOLLOW | LOCKLEAF | LOCKPARENT | SAVENAME | NNPFS_MPSAFE,
		   UIO_SYSSPACE, name, p);
	} else {
	    NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | NNPFS_MPSAFE, UIO_SYSSPACE, name, p);
	}

	nd.ni_cnd.cn_cred = cred;
	nd.ni_startdir = cachedir;

        nnpfs_namei_alloc(&nd.ni_cnd);
	nd.ni_cnd.cn_nameptr = nd.ni_cnd.cn_pnbuf;

	error = copystr(name, nd.ni_cnd.cn_pnbuf, MAXPATHLEN, &nd.ni_pathlen);
	if (error == 0 && nd.ni_pathlen == 1)
	    error = ENOENT;
	
	if (error) {
            nnpfs_namei_free(&nd.ni_cnd);
	    printf("nnpfs open_file(%p, %s) copystr -> %d\n",
		   cachedir, name, error);
	    return error;
	}

#ifdef __FreeBSD__
	if ((fmode & O_ACCMODE) != FREAD)
	    bwillwrite(); /* do this before getting devlock? */
#endif
	/* XXX vn_start_write() etc? */

	nnpfs_vref(cachedir);

	error = lookup(&nd);
	if (error) {
	    nnpfs_namei_free(&nd.ni_cnd);
	    printf("lookup(%s) -> %d\n", name, error);
	    return error;
	}

	if (fmode & O_CREAT && nd.ni_vp) {
	    fmode &= ~O_CREAT;
#ifndef __NetBSD__
	    nnpfs_vfs_unlock(cachedir, p);
#endif
	}

	if (fmode & O_CREAT) {
	    struct vattr vat;
	    struct mount *mp;

	    if ((nd.ni_cnd.cn_flags & SAVENAME) == 0) {
		nnpfs_namei_free(&nd.ni_cnd);
		printf("lookup: not SAVENAME, flags 0x%lx\n", nd.ni_cnd.cn_flags);
		return EINVAL;
	    }

	    VATTR_NULL(&vat);
	    vat.va_type = VREG;
	    vat.va_mode = S_IRUSR|S_IWUSR;
	    if ((nd.ni_cnd.cn_flags & HASBUF) == 0)
		panic("HASBUF was cleared\n");

	    /* nd.ni_cnd.cn_flags |= HASBUF; */

#ifdef __FreeBSD__
	    (void)vn_start_write(cachedir, &mp, V_WAIT); /* V_NOWAIT? */
#endif
#ifndef __OpenBSD__
	    VOP_LEASE(cachedir, p, cred, LEASE_WRITE);
#endif
	    error = VOP_CREATE(cachedir, vpp, &nd.ni_cnd, &vat);

#ifdef __FreeBSD__
	    nnpfs_namei_free(&nd.ni_cnd);
	    nnpfs_vfs_unlock(cachedir, p);
	    vn_finished_write(mp);
#else
	    /* NetBSD and OpenBSD releases buf w/o clearing HASBUF */
	    nd.ni_cnd.cn_flags &= ~HASBUF;
	    nnpfs_namei_frees++;
#endif

	    if (error) {
		printf("nnpfs open_file(%p, %s) create -> %d\n",
		       cachedir, name, error);
		return error;
	    }
	} else {
	    *vpp = nd.ni_vp;
	    nnpfs_namei_free(&nd.ni_cnd);
	}
	
#if defined(__FreeBSD__) && 0
	if (nd.ni_vp
	    && vn_canvmio(nd.ni_vp) == TRUE
	    && ((nd.ni_cnd.cn_flags & (NOOBJ|LOCKLEAF)) == LOCKLEAF))
	    vfs_object_create(nd.ni_vp, p, cred);
#endif

#ifdef __FreeBSD__
#ifdef HAVE_FINAL_ARG_FILE_VOP_OPEN
	error = VOP_OPEN(*vpp, fmode, cred, p, NULL);
#else
	error = VOP_OPEN(*vpp, fmode, cred, p, -1);
#endif
#else
	error = VOP_OPEN(*vpp, fmode, cred, p);
#endif

	if (error) {
	    nnpfs_vput(*vpp);
	} else {
	    if (fmode & FWRITE)
		(*vpp)->v_writecount++;

	    nnpfs_vfs_unlock(*vpp, p);
	}
    }

#endif /* !__APPLE__! */
    
    NNPFSDEB(XDEBNODE, ("nnpfs open_file(%p, %s) -> %d (%p)\n",
			cachedir, name, error, *vpp));
    return error;
}

/*
 * open indicated cache block file. needs to be closed by caller.
 */

int
nnpfs_block_open(struct nnpfs_node *node, uint64_t offset, int flags,
		 struct vnode **vpp)
{
    char cachename[NNPFS_CACHE_PATH_SIZE];
    uint64_t blockindex = nnpfs_block_index(offset);
    struct nnpfs *nnpfsp = NNPFS_FROM_XNODE(node);
    off_t eof = nnpfs_vattr_get_size(&node->attr);
    int ret;
    
    NNPFSDEB(XDEBNODE, ("nnpfs_block_open(0x%llx)\n", (unsigned long long)offset));

    nnpfs_assert(nnpfsp);

    nnpfs_assert(nnpfs_block_have_p(node, offset)
	   || (flags & O_CREAT));

    if (nnpfs_vnode_isdir(XNODE_TO_VNODE(node))) {
	nnpfs_assert((flags & O_CREAT) == 0);
	*vpp = node->cache_vn;
	ret = 0;
    } else {
#ifdef __APPLE__
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_FILE_PATH,
		       node->index / 0x100, node->index % 0x100,
		       (unsigned long long)blockindex);
#else
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_FILE_BLOCK_PATH,
		       (unsigned long long)blockindex);
#endif
    
	nnpfs_assert(ret > 0 && ret < sizeof(cachename)); /* XXX */
	
	ret = open_file(node->cache_vn, cachename, flags, nnpfsp->ctx, vpp);
	nnpfs_debug_assert(!ret);
	if (ret)
	    return ret;
    }

    /* blocks in the middle of the file should be of full length */
    if ((flags & O_CREAT) && offset < nnpfs_offset(eof)) {
	ret = nnpfs_block_extend_int(node, *vpp, nnpfs_curproc());
	nnpfs_debug_assert(!ret);
	if (ret)
	    nnpfs_block_close(node, *vpp,
			      ((flags & FWRITE) == FWRITE) ? 1 : 0);
    }

    NNPFSDEB(XDEBNODE, ("nnpfs_block_open -> %d\n", ret));

#if 0
    nnpfs_assert(node->cache_vn);
    if (VOP_ISLOCKED(node->cache_vn, nnpfs_curproc())) {
	printf("%p is locked at %d\n", node->cache_vn, __LINE__);
	panic("locked at block_open:exit");
    }
#endif

    return ret;
}

void
nnpfs_block_close(struct nnpfs_node *node, struct vnode *vp, int rw)
{
    NNPFSDEB(XDEBNODE, ("nnpfs_block_close(%p)\n", vp));
    
    if (nnpfs_vnode_isdir(XNODE_TO_VNODE(node)))
	return;

#ifdef __APPLE__
    vnode_close(vp, 0, NULL);
#else
    {
	d_thread_t *p = nnpfs_curproc();
	
	nnpfs_vfs_writelock(vp, p);

	if (rw)
	    vp->v_writecount--;

	VOP_CLOSE(vp, rw ? FWRITE : FREAD, NULL, p);
	nnpfs_vput(vp);
    }
#endif /* !__APPLE__ */

    NNPFSDEB(XDEBNODE, ("nnpfs_block_close done\n"));
}

/*
 * Create the indicated block and mark it as present in cache.
 *
 * Intended for writes beyond EOF.
 */

int
nnpfs_block_create(struct nnpfs_node *node, uint64_t offset)
{
    struct nnpfs_message_appenddata msg;
    struct nnpfs *nnpfsp = NNPFS_FROM_XNODE(node);
    off_t eof = nnpfs_vattr_get_size(&node->attr);
    struct vnode *vp;
    int ret;

    nnpfs_assert(!nnpfs_block_have_p(node, offset));
    nnpfs_assert(!nnpfs_vnode_isdir(XNODE_TO_VNODE(node)));

    /* printf("nnpfs_block_create @0x%llx\n", (unsigned long long)offset);*/

    NNPFSDEB(XDEBNODE, ("nnpfs_block_create: %lx @0x%llx\n",
			(unsigned long)node, (unsigned long long )offset));

    ret = nnpfs_block_setvalid(node, offset);
    if (ret) {
	nnpfs_debug_assert(0);
	return ret;
    }

    ret = nnpfs_block_open(node, offset, O_CREAT|FWRITE, &vp);
    if (!ret) {
	nnpfs_assert(vp);
	nnpfs_block_close(node, vp, 1);
    }

    /* extend previously last block to full length */
    if (!ret && eof < offset) {
	uint64_t prevoff = nnpfs_offset(eof);
	if (nnpfs_block_have_p(node, prevoff))
	    ret = nnpfs_block_extend(node, prevoff);
    }
    
    nnpfs_debug_assert(!ret);
    
    if (ret) {
	/* XXX roll back file changes? */
	nnpfs_block_setinvalid(node, offset);
	return ret;
    }
    
    while (nnpfsp->appendquota < nnpfs_blocksize
	   && nnpfsp->status & CHANNEL_OPENED) {
	int waiting = (nnpfsp->status & NNPFS_QUOTAWAIT);
	nnpfsp->status |= NNPFS_QUOTAWAIT;
	/* XXX */
	(void)nnpfs_dev_msleep(nnpfsp, (caddr_t)&nnpfsp->appendquota,
			       (PZERO + 1), "nnpfsquota");
	if (!waiting)
	    nnpfsp->status &= ~NNPFS_QUOTAWAIT;
    }
    
    if ((nnpfsp->status & CHANNEL_OPENED) == 0)
	return ENODEV;
    
    nnpfsp->appendquota -= nnpfs_blocksize;
    nnpfs_assert(nnpfsp->appendquota >= 0);

    msg.header.opcode = NNPFS_MSG_APPENDDATA;
    msg.handle = node->handle;
    msg.offset = offset;

    /* XXX currently no cleanup on failed send, hope it's just a devclose */
    return nnpfs_message_send(nnpfsp, &msg.header, sizeof(msg));
}
