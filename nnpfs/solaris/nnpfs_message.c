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

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_dev.h>

RCSID("$Id: nnpfs_message.c,v 1.29 2002/09/07 10:47:38 lha Exp $");

int
nnpfs_message_installroot(int fd,
			struct nnpfs_message_installroot *message,
			u_int size)
{
    int error = 0;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installroot\n"));

    if (nnpfs[fd].root != 0)
    {
	printf("NNPFS PANIC Warning: nnpfs_message_installroot again\n");
	error = EBUSY;
    }
    else
    {
	nnpfs[fd].root = new_nnpfs_node(&nnpfs[fd], NULL, &message->node); /*VN_HOLD's*/
	nnpfs[fd].root->vn.v_flag |= VROOT;
	mutex_exit(&nnpfs[fd].root->node_lock);
    }
    return error;
}

int
nnpfs_message_installnode(int fd,
			struct nnpfs_message_installnode *message,
			u_int size)
{
    int error = 0;
    struct nnpfs_node *n, *dp;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode\n"));

    dp = nnpfs_node_find(&nnpfs[fd], &message->parent_handle);
    if (dp) 
    {
	/* XXXSMP here it could be so that we lock child->parent
	 * and that might not be a good idea */
	n = new_nnpfs_node(&nnpfs[fd], dp, &message->node); /* VN_HOLD's */
	dnlc_remove (XNODE_TO_VNODE(dp), message->name);
	nnpfs_dnlc_enter(XNODE_TO_VNODE(dp), message->name, XNODE_TO_VNODE(n));
	if (dp != n) /* in case of "." */
	    mutex_exit(&dp->node_lock);
	mutex_exit(&n->node_lock);
	VN_RELE(XNODE_TO_VNODE(n));
    }
    else
    {
	printf("NNPFS PANIC Warning: nnpfs_message_install could not find parent\n");
	error = ENOENT;
    }
    return error;
}

int
nnpfs_message_installattr(int fd,
			struct nnpfs_message_installattr *message,
			u_int size)
{
    int error = 0;
    struct nnpfs_node *t;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr\n"));

    t = nnpfs_node_find(&nnpfs[fd], &message->node.handle);
    if (t != 0)
    {
	t->tokens = message->node.tokens;
	nnpfs_attr2vattr(&message->node.attr, &t->attr, 0);
	bcopy((caddr_t)message->node.id,
	      (caddr_t)t->id, sizeof(t->id));
	bcopy((caddr_t)message->node.rights,
	      (caddr_t)t->rights, sizeof(t->rights));
	t->anonrights = message->node.anonrights;
	mutex_exit(&t->node_lock);
    }
    else
    {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: no such node\n"));
    }
    return error;
}

int
nnpfs_message_installdata(int fd,
			struct nnpfs_message_installdata *message,
			u_int size)
{
    struct nnpfs_node *t;
    struct vnode *vp;
    int error = 0;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata\n"));
    
    t = nnpfs_node_find(&nnpfs[fd], &message->node.handle);
    if (t != 0) 
    {
	struct nnpfs_fh_args *fh_args = 
	    (struct nnpfs_fh_args *)&message->cache_handle;
	
	VN_HOLD(XNODE_TO_VNODE(t));
	message->cache_name[sizeof(message->cache_name)-1] = '\0';
	NNPFSDEB(XDEBMSG, ("cache_name = '%s'\n",
			 message->cache_name));
	
	if (message->flag & NNPFS_ID_HANDLE_VALID) {
	    error = nnpfs_fhlookup (fh_args->fsid, fh_args->fid, &vp);
	} else {
	    error = lookupname(message->cache_name, UIO_SYSSPACE,
			       NO_FOLLOW, NULL, &vp);
	}
	if (error == 0) {
	    if (DATA_FROM_XNODE(t)) {
		VN_RELE(DATA_FROM_XNODE(t));
	    }
	    if (XNODE_TO_VNODE(t)->v_type == VDIR
		&& (message->flag & NNPFS_ID_INVALID_DNLC)) {
		dnlc_purge_vp(XNODE_TO_VNODE(t));
	    }
	    ASSERT(vp != NULL);
	    DATA_FROM_XNODE(t) = vp;
	    t->tokens = message->node.tokens;
	    nnpfs_attr2vattr(&message->node.attr, &t->attr, 1);
	    bcopy((caddr_t)message->node.id,
		  (caddr_t)t->id, sizeof(t->id));
	    bcopy((caddr_t)message->node.rights,
		  (caddr_t)t->rights, sizeof(t->rights));
	    t->anonrights = message->node.anonrights;
	} else {
	    printf("NNPFS PANIC Warning: nnpfs_message_installdata failed to "
		   "lookup cache file = %s, error = %d\n",
		   message->cache_name, error);
	}
	mutex_exit(&t->node_lock);
	VN_RELE(XNODE_TO_VNODE(t));
    } else {
	printf("NNPFS PANIC Warning: "
	       "nnpfs_message_installdata didn't find node!\n");
	error = ENOENT;
    }
    
    return error;
}

int
nnpfs_message_invalidnode(int fd,
			struct nnpfs_message_invalidnode *message,
			u_int size)
{
    int error = 0;
    struct nnpfs_node *t;
  
    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode\n"));

    t = nnpfs_node_find(&nnpfs[fd], &message->handle);
    if (t != 0)
    {
	struct vnode *vp;
	/* XXX Really need to put back dirty data first. */
	if (DATA_FROM_XNODE(t))
	{
	    VN_RELE(DATA_FROM_XNODE(t));
	    DATA_FROM_XNODE(t) = (struct vnode *) 0;
	}
	NNPFS_TOKEN_CLEAR(t, ~0,
			NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
			NNPFS_DATA_MASK | NNPFS_LOCK_MASK);
	vp = XNODE_TO_VNODE(t);
	mutex_exit(&t->node_lock);
	dnlc_purge_vp (vp);
    } 
    else
    {
#if 0
	printf("NNPFS PANIC Warning: nnpfs_message_invalidnode didn't find node!\n");
#endif
	error = ENOENT;
    }
    return error;
}

int
nnpfs_message_updatefid(int fd,
		      struct nnpfs_message_updatefid *message,
		      u_int size)
{
    int error = 0;
    struct nnpfs_node *t;
  
    NNPFSDEB(XDEBMSG, ("nnpfs_message_updatefid\n"));

    t = nnpfs_node_find(&nnpfs[fd], &message->old_handle);
    if (t != 0)
    {
	t->handle = message->new_handle;
	mutex_exit(&t->node_lock);
    }
    else
    {
	printf("NNPFS PANIC Warning: nnpfs_message_updatefid didn't find node!\n");
	error = ENOENT;
    }
    return error;
}

static void
gc_vnode (struct vnode *vp)
{
    mutex_enter (&vp->v_lock);
    if (vp->v_count <= 1)
    {
	mutex_exit (&vp->v_lock);
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: try\n"));
	dnlc_purge_vp(vp);
    } 
    else 
    {
	int count = vp->v_count;
	mutex_exit (&vp->v_lock);
	NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: used (%d)\n", count));
    }
}

int
nnpfs_message_gc_nodes(int fd,
		     struct nnpfs_message_gc_nodes *message,
		     u_int size)
{
    struct nnpfs *nnpfsp = &nnpfs[fd];
    NNPFSDEB(XDEBMSG, ("nnpfs_message_gc\n"));

    if (message->len == 0) {
	struct nnpfs_node *t;
	
	for (t = nnpfs_node_iter_start(nnpfsp);
	     t != NULL; 
	     t = nnpfs_node_iter_next(nnpfsp))
	{
	    struct vnode *vp = XNODE_TO_VNODE(t);
	    gc_vnode (vp);
	}

    } else {
	int i;
	
	for (i = 0; i < message->len; i++) {
	    struct nnpfs_node *t;
	    struct vnode *vp;

	    t = nnpfs_node_find (nnpfsp, &message->handle[i]);
	    if (t == NULL)
		continue;
	    vp = XNODE_TO_VNODE(t);
	    mutex_exit(&t->node_lock);

	    gc_vnode(vp);
	}
    }

    return 0;
}


/*
 * Probe what this nnpfs support
 */

int
nnpfs_message_version(int fd,
		    struct nnpfs_message_version *message,
		    u_int size)
{
    struct nnpfs_message_wakeup msg;
    int ret;

    ret = NNPFS_VERSION;

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;

    return nnpfs_message_send(fd, (struct nnpfs_message_header *) &msg, sizeof(msg));
}
