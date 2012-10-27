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

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_vnodeops.h>
#include <nnpfs/nnpfs_dev.h>

RCSID("$Id: nnpfs_message.c,v 1.110 2008/02/26 21:59:08 tol Exp $");

int
nnpfs_message_installroot(struct nnpfs *nnpfsp,
			struct nnpfs_message_installroot * message,
			u_int size,
			d_thread_t *p)
{
    int error = 0;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installroot (%d,%d,%d,%d)\n",
		     message->node.handle.a,
		     message->node.handle.b,
		     message->node.handle.c,
		     message->node.handle.d));

    if (nnpfsp->root != NULL) {
	printf("NNPFS PANIC nnpfs_message_installroot: called again!\n");
	error = EBUSY;
    } else {
	error = nnpfs_new_node(nnpfsp,
			       &message->node,
			       NULL,
			       &nnpfsp->root,
			       p,
			       1 /* mark as root */);
    }

    NNPFSDEB(XDEBMSG, ("installroot returning %d\n", error));

    return error;
}

int
nnpfs_message_installnode(struct nnpfs *nnpfsp,
			struct nnpfs_message_installnode * message,
			u_int size,
			d_thread_t *p)
{
    int error = 0;
    struct nnpfs_node *n, *dp;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode (%d,%d,%d,%d)\n",
		     message->node.handle.a,
		     message->node.handle.b,
		     message->node.handle.c,
		     message->node.handle.d));

retry:
    error = nnpfs_node_find(nnpfsp, &message->parent_handle, &dp);
    if (error) {
	if (error == EISDIR)
	    NNPFSDEB(XDEBMSG, ("installnode: parent node deleted\n"));
	else if (error == ENOENT)
	    printf("NNPFS PANIC WARNING! nnpfs_message_installnode: no parent\n");
	
	return error;
    }

    if (dp) {
	struct vnode *t_vnode = XNODE_TO_VNODE(dp);

	NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: t_vnode = %lx\n",
			   (unsigned long)t_vnode));

	if (nnpfs_do_vget(t_vnode, 0 /* LK_SHARED */, p))
		goto retry;

	error = nnpfs_new_node(nnpfsp, &message->node, NULL, &n, p, 0);
	if (error) {
	    nnpfs_vletgo(t_vnode);
	    return error;
	}

	nnpfs_dnlc_enter_name(t_vnode,
			      message->name,
			      XNODE_TO_VNODE(n));
	nnpfs_vletgo(XNODE_TO_VNODE(n));
	nnpfs_vletgo(t_vnode);
    } else {
	printf("NNPFS PANIC WARNING! nnpfs_message_installnode: no node\n");
	error = ENOENT;
    }

    NNPFSDEB(XDEBMSG, ("return: nnpfs_message_installnode: %d\n", error));

    return error;
}

int
nnpfs_message_installattr(struct nnpfs *nnpfsp,
			struct nnpfs_message_installattr * message,
			u_int size,
			d_thread_t *p)
{
    struct nnpfs_attr *xa = &message->node.attr;
    int error = 0;
    struct nnpfs_node *t;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr (%d,%d,%d,%d) \n",
		       message->node.handle.a,
		       message->node.handle.b,
		       message->node.handle.c,
		       message->node.handle.d));

    error = nnpfs_node_find(nnpfsp, &message->node.handle, &t);
    if (error) {
	if (error == EISDIR) {
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: node deleted\n"));
	} else if (error == ENOENT) {
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: no such node\n"));
	    error = 0;
	}
	return error;
    }

    t->tokens |= (message->node.tokens & NNPFS_ATTR_MASK);
    if ((t->tokens & NNPFS_DATA_MASK) && t->index == NNPFS_NO_INDEX) {
	printf ("nnpfs_message_installattr: tokens and no data\n");
	t->tokens &= ~NNPFS_DATA_MASK;
    }

    if ((t->tokens & NNPFS_DATA_MASK) == 0 && t->index != NNPFS_NO_INDEX) {
	printf("nnpfs_message_installattr: data but no tokens "
	       "(%d,%d,%d,%d) \n",
	       message->node.handle.a,
	       message->node.handle.b,
	       message->node.handle.c,
	       message->node.handle.d);
    }
    
    /* if we're writing and we didn't initiate this, ignore daemon's size */
    if (t->flags & NNPFS_DATA_DIRTY && !(message->flag & NNPFS_PUTATTR_REPLY))
	XA_CLEAR_SIZE(xa);
    nnpfs_store_attr(xa, t, 0);
    if ((t->flags & NNPFS_VMOPEN) == 0)
	nnpfs_setsize(t, nnpfs_vattr_get_size(&t->attr));
    bcopy(message->node.id, t->id, sizeof(t->id));
    bcopy(message->node.rights, t->rights, sizeof(t->rights));
    t->anonrights = message->node.anonrights;
    
    /* make sure we get rid of deleted entries on inactive */
    if (XA_VALID_NLINK(xa) && xa->xa_nlink == 0)
	t->flags |= NNPFS_STALE;

    return 0;
}

int
nnpfs_message_installdata(struct nnpfs *nnpfsp,
			struct nnpfs_message_installdata * message,
			u_int size,
			d_thread_t *p)
{
    char cachename[NNPFS_CACHE_PATH_SIZE];
    uint32_t id = message->cache_id;
    struct nnpfs_node *t;
    struct vnode *t_vnode;
    int error = 0;
    int lookupp = 1;
    int ret;
 
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata (%d,%d,%d,%d) @%llx\n",
		       message->node.handle.a, message->node.handle.b,
		       message->node.handle.c, message->node.handle.d,
		       (unsigned long long)message->offset));
    
 retry:
    error = nnpfs_node_find(nnpfsp, &message->node.handle, &t);
    if (error) {
	if (error == ENOENT) {
	    printf("NNPFS PANIC WARNING! nnpfs_message_installdata failed\n");
	    printf("No node for (%d,%d,%d,%d) @%llx\n",
		   message->node.handle.a, message->node.handle.b,
		   message->node.handle.c, message->node.handle.d,
		   (unsigned long long)message->offset);
	} else if (error == EISDIR) {
	    NNPFSDEB(XDEBMSG, ("installdata: node deleted\n"));
	}
	return error;
    }

    t_vnode = XNODE_TO_VNODE(t);

    if (nnpfs_do_vget(t_vnode, 0 /* LK_SHARED */, p))
	goto retry;

    if (t->index != NNPFS_NO_INDEX) {
	if (t->index == message->cache_id)
	    goto install_attrs; /* XXX could dir vn change under our feet? */
	else
	    printf("nnpfs_message_installdata: "
		   "changing index for (%d.%d.%d.%d), %x -> %x!\n",
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   t->index, message->cache_id);
    } else {
	nnpfs_assert(!t->cache_vn); /* XXX */
    }

    if (nnpfs_vnode_isdir(t_vnode)) {
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_DIR_PATH,
		       id / 0x100, id % 0x100);
    } else {
#ifdef __APPLE__
	lookupp = 0; /* don't open cache vnode */
#else
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_FILE_DIR_PATH,
		       id / 0x100, id % 0x100);
#endif
    }
    
    if (lookupp)
	nnpfs_assert(ret > 0 && ret < sizeof(cachename)); /* XXX */

    if (lookupp) {
	struct vnode *vp;
#ifdef __APPLE__
	error = vnode_open(cachename, O_RDONLY, S_IRUSR|S_IWUSR, 0, &vp, NULL);
#else
	struct nameidata nd;
	struct nameidata *ndp = &nd;

	NDINIT(ndp, LOOKUP, FOLLOW | NNPFS_MPSAFE, UIO_SYSSPACE, cachename, p);
	error = namei(ndp);
	vp = ndp->ni_vp;

#endif /* __APPLE__ */
    
	if (error) {
	    printf("nnpfs_message_installdata: (%d.%d.%d.%d), lookup(%s) -> %x!\n",
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   cachename, error);
	    nnpfs_vletgo(t_vnode);
	    return error;
	}

	if (t->cache_vn) { /* XXX id change, this shouldn't happen? */
	    printf("nnpfs_message_installdata: (%d.%d.%d.%d), "
		   "vn %p -> %p, id %lx -> %lx!\n",
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   t->cache_vn, vp,
		   (unsigned long)t->index,
		   (unsigned long)message->cache_id);
	    nnpfs_release_cachevn(t);
	}
	t->cache_vn = vp;
    }
    
    t->index = message->cache_id;

 install_attrs:

    if (message->offset != NNPFS_NO_OFFSET) {
	error = nnpfs_block_setvalid(t, message->offset);
	if (error) {
	    printf("nnpfs_message_installdata: "
		   "(%d.%d.%d.%d) setvalid -> %d!\n",
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   error);
	    nnpfs_vletgo(t_vnode);
	    return error;
	}
    }

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata: t = %lx;"
		       " tokens = %x\n",
		       (unsigned long)t, message->node.tokens));
    
    /* if we're writing, ignore daemon's size */
    if (t->flags & NNPFS_DATA_DIRTY)
	XA_CLEAR_SIZE(&message->node.attr);
    
    t->tokens |= (message->node.tokens & (NNPFS_DATA_MASK|NNPFS_OPEN_MASK));
    nnpfs_store_attr(&message->node.attr, t, 0);
    if ((t->flags & NNPFS_VMOPEN) == 0)
	nnpfs_setsize(t, nnpfs_vattr_get_size(&t->attr));
    if (nnpfs_vnode_isdir(XNODE_TO_VNODE(t))
	&& (message->flag & NNPFS_ID_INVALID_DNLC))
	nnpfs_dnlc_purge (XNODE_TO_VNODE(t));

    t->anonrights = message->node.anonrights;
    bcopy(message->node.id, t->id, sizeof(t->id));
    bcopy(message->node.rights, t->rights, sizeof(t->rights));

    nnpfs_vletgo(t_vnode);

    return error;
}

int
nnpfs_message_invalidnode(struct nnpfs *nnpfsp,
			  struct nnpfs_message_invalidnode * message,
			  u_int size,
			  d_thread_t *p)
{
    struct nnpfs_node *t;
    struct vnode *vp;
    int error;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode (%d,%d,%d,%d)\n",
		       message->handle.a,
		       message->handle.b,
		       message->handle.c,
		       message->handle.d));

    error = nnpfs_node_find(nnpfsp, &message->handle, &t);
    if (error) {
	if (error == ENOENT)
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: no such node\n"));
	else if (error == EISDIR)
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: node deleted\n"));
	
	return error;
    }

    vp = XNODE_TO_VNODE(t);

    /* If open for writing, return immediately. Last close:er wins! */
#ifdef __APPLE__
    if (t->writers > 0)
	return 0;
#else
    if (vp->v_writecount >= 1)
	return 0;
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
    {
	vm_object_t obj = vp->v_object;

	if (obj != NULL
	    && (obj->ref_count != 0 || (obj->flags & OBJ_MIGHTBEDIRTY) != 0))
	    return 0;

    }
#endif /* __FreeBSD__ || __DragonFly__ */

    /* If node is in use, mark as stale */
    if (nnpfs_vnode_isinuse(vp, 0) && !nnpfs_vnode_isdir(vp)) {
	t->flags |= NNPFS_STALE;
	return 0;
    }
    
    nnpfs_release_data(t);

    /* Dir changed, must invalidate DNLC. */
    if (nnpfs_vnode_isdir(vp))
	nnpfs_dnlc_purge(vp);
    if (!nnpfs_vnode_isinuse(vp, 0)) {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: vrecycle\n"));
#ifdef __FreeBSD__
	nnpfs_do_vget(vp, LK_EXCLUSIVE, p); /* XXX retval, readlock */
	nnpfs_vrecycle(vp, 0, p);
	nnpfs_vput(vp);
#else
	nnpfs_vrecycle(vp, 0, p);
#endif
    }

    return 0;
}

int
nnpfs_message_updatefid(struct nnpfs *nnpfsp,
		      struct nnpfs_message_updatefid * message,
		      u_int size,
		      d_thread_t *p)
{
    int error = 0;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_updatefid (%d,%d,%d,%d) (%d,%d,%d,%d)\n",
		       message->old_handle.a,
		       message->old_handle.b,
		       message->old_handle.c,
		       message->old_handle.d,
		       message->new_handle.a,
		       message->new_handle.b,
		       message->new_handle.c,
		       message->new_handle.d));

    error = nnpfs_update_handle(nnpfsp, 
				&message->old_handle,
				&message->new_handle);
    if (error)
	printf ("NNPFS PANIC WARNING! nnpfs_message_updatefid: %d\n", error);
    return error;
}

/*
 * Try to clean out nodes for the userland daemon
 */

#ifdef __APPLE__
static void
gc_vnode(struct vnode *vp, d_thread_t *p)
{
    /* This node is on the freelist */
    if (!nnpfs_vnode_isinuse(vp, 0)) {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: success\n"));
	
	nnpfs_block_free_all(VNODE_TO_XNODE(vp));
	vnode_recycle(vp);
    } else {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: used\n"));
    }
}
#else /* !__APPLE__ */

static void
gc_vnode(struct vnode *vp, d_thread_t *p)
{
    nnpfs_interlock_lock(&vp->v_interlock);
    
    /* This node is on the freelist */
    if (vp->v_usecount <= 0) {
#ifdef __FreeBSD__
	vm_object_t obj;

	obj = vp->v_object;

	if (obj != NULL
	    && (obj->ref_count != 0
#ifdef OBJ_MIGHTBEDIRTY
		|| (obj->flags & OBJ_MIGHTBEDIRTY) != 0
#endif
		)) {
	    nnpfs_interlock_unlock(&vp->v_interlock);
	    return;
	}
#endif
	
	if (vp->v_usecount < 0 || vp->v_writecount != 0) {
	    nnpfs_vprint("vrele: bad ref count", vp);
	    panic("vrele: ref cnt");
	}
	
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: success\n"));
	
	nnpfs_block_free_all(VNODE_TO_XNODE(vp));
	
#ifdef HAVE_KERNEL_VGONEL
	vgonel (vp, p);
#else /* !have vgonel */
	nnpfs_interlock_unlock(&vp->v_interlock);

#ifdef __FreeBSD__
	vhold(vp);
	vgone(vp);
	vdrop(vp);
#else
	vgone (vp);
#endif
#endif
	
    } else {
	nnpfs_interlock_unlock(&vp->v_interlock);
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: used\n"));
    }
}
#endif /* !__APPLE__ */

static int
gc_block(struct nnpfs *nnpfsp,
	 struct nnpfs_node *xn,
	 uint64_t offset,
	 d_thread_t *p)
{
    off_t end = nnpfs_vattr_get_size(&xn->attr);
    int error = 0;

    if (xn->pending_writes) {
	printf("NNPFS/gc_block: EBUSY (%d,%d,%d,%d) 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset);
	return EBUSY;
    }
    
    /* this may happen with pending writes, so order matters. */
    if (offset > end) {
	printf("NNPFS/gc_block: bad block (%d,%d,%d,%d) 0x%llx, len 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset, (unsigned long long)end);
	return EINVAL;
    }
	
    if (!nnpfs_block_have_p(xn, offset)) {
	printf("NNPFS/gc_block: ENOENT (%d,%d,%d,%d) 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset);
	return ENOENT;
    }

    if (xn->flags & NNPFS_DATA_DIRTY) {
	struct nnpfs_message_putdata msg;
	uint64_t len = nnpfs_blocksize;
		
	if (offset + len > end)
	    len = end - offset;
	
	vattr2nnpfs_attr(&xn->attr, &msg.attr);
	
	msg.header.opcode = NNPFS_MSG_PUTDATA;
	msg.cred   = xn->wr_cred;
	msg.handle = xn->handle;
	msg.offset = offset;
	msg.len    = len;
	msg.flag   = NNPFS_WRITE | NNPFS_GC;
	
	/* XXX locking, rpc may fail */
	xn->daemon_length = nnpfs_vattr_get_size(&xn->attr);
	nnpfs_block_setinvalid(xn, offset);
	error = nnpfs_message_rpc_async(nnpfsp, &msg.header, sizeof(msg), p);
    } else {
	struct nnpfs_message_deletedata msg;
	
	msg.header.opcode = NNPFS_MSG_DELETEDATA;
	msg.handle = xn->handle;
	msg.offset = offset;
	
	nnpfs_block_setinvalid(xn, offset);
	error = nnpfs_message_send(nnpfsp, &msg.header, sizeof(msg));
    }

    if (error)
	printf("NNPFS/gc_block: couldn't send gc putdata (%d)\n", error);

    return error;
}

/*
 * NNPFS_MESSAGE_GC
 *
 * Instruct nnpfs to release the indicated blocks if possible.
 * If offset is NNPFS_NO_OFFSET, it's the node we're after.
 *
 *
 * XXX we may want to return number of successes or failures, so
 * daemon can tune its gc parameters
 */

/*
  struct nnpfs_message_gc {
  struct nnpfs_message_header header;
  uint32_t len;
  uint32_t pad1;
  nnpfs_block_handle handle[NNPFS_GC_MAX_HANDLE];
  };
*/

int
nnpfs_message_gc(struct nnpfs *nnpfsp,
		 struct nnpfs_message_gc *message,
		 u_int size,
		 d_thread_t *p)
{
    struct nnpfs_node *node;
    int i;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_gc\n"));
    
    for (i = 0; i < message->len; i++) {
	int error = nnpfs_node_find(nnpfsp,
				    &message->handle[i].node, &node);
	if (error) {
	    if (error == ENOENT)
		NNPFSDEB(XDEBMSG, ("PANIC gc_nodes node not found\n"));
	    else if (error == EISDIR)
		NNPFSDEB(XDEBMSG, ("gcnode: node deleted\n"));
	    continue;
	}
	if (message->handle[i].offset == NNPFS_NO_OFFSET)
	    gc_vnode(XNODE_TO_VNODE(node), p);
	else {
	    gc_block(nnpfsp, node, message->handle[i].offset, p);
	}
    }

    return 0;
}

/*
 * Probe what version of nnpfs this is, and exchange some initial
 * handshake info
 */

int
nnpfs_message_version(struct nnpfs *nnpfsp,
		      struct nnpfs_message_version *message,
		      u_int size,
		      d_thread_t *p)
{
    struct nnpfs_message_wakeup msg;
    int ret = NNPFS_VERSION;
    int error = 0;

#ifdef __APPLE__
    if (nnpfsp->ctx != NULL) {
	/*
	 * Bad call, ignore it.
	 * It would be nice to be able to communicate failure, now
	 * we risk looping on getroot. XXX
	 */
	printf("NNPFS Panic: "
	       "nnpfs_message_version with existing context!\n");
	
	error = EBUSY;
    }
#endif

    /* sanity check before we look at it */
    if (size == sizeof(*message)
	&& message->version == NNPFS_VERSION
	&& !error) {
	uint64_t blocksize = message->blocksize;
	
	nnpfs_vfs_context_create(nnpfsp);

	/* XXX we should validate these values */
	nnpfs_blocksize = blocksize;
	nnpfs_blocksizebits = 0;
	while ((blocksize >> nnpfs_blocksizebits) > 1) 
	    nnpfs_blocksizebits++;

	nnpfsp->appendquota = message->appendquota;
    }

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;
    msg.len = 0;

    return nnpfs_message_send(nnpfsp, 
			      (struct nnpfs_message_header *) &msg,
			      sizeof(msg));
}

/*
 *
 */

int
nnpfs_message_delete_node(struct nnpfs *nnpfsp,
			  struct nnpfs_message_delete_node *message,
			  u_int size,
			  d_thread_t *p)
{
    struct nnpfs_node *node;
    int ret;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_delete_node\n"));

    ret = nnpfs_node_find(nnpfsp, &message->handle, &node);
    if (ret == ENOENT) {
	printf("nnpfs_message_delete_node: no such node\n");
	return ENOENT;
    }
    NNPFSDEB(XDEBMSG, ("nnpfs_delete_node: %p\n", node));
    NNPFSDEB(XDEBMSG, ("nnpfs_delete_node: flags 0x%x\n", node->flags));
    if (node->flags & NNPFS_LIMBO) {
	NNPFSDEB(XDEBMSG, ("nnpfs_delete_node: free node\n"));
	nnpfs_free_node(nnpfsp, node);
    } else {
	NNPFSDEB(XDEBMSG, ("nnpfs_delete_node: not deleted"));
    }

    return 0;
}

/*
 *
 */

int
nnpfs_message_installquota(struct nnpfs *nnpfsp,
			   struct nnpfs_message_installquota *message,
			   u_int size,
			   d_thread_t *p)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installquota\n"));

    nnpfsp->appendquota += message->appendbytes;
    nnpfs_assert(nnpfsp->appendquota >= 0);

    if (nnpfsp->status & NNPFS_QUOTAWAIT)
	wakeup((caddr_t)&nnpfsp->appendquota);

    return 0;
}
