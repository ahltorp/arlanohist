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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

#define __NO_VERSION__

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <linux/mount.h>

#ifdef RCSID
RCSID("$Id: nnpfs_message.c,v 1.145 2010/08/08 20:43:05 tol Exp $");
#endif

static void
clear_all_children (struct inode *inode, int parent);

static void
nnpfs_d_remove(struct dentry *dentry)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_d_remove %p\n", dentry));
    spin_lock(&dcache_lock);
    dget_locked(dentry);
    spin_unlock(&dcache_lock);
    d_drop(dentry);
    dput(dentry);
}

int
nnpfs_message_installroot(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installroot *message,
			  u_int size)
{
    struct inode *inode = nnpfsp->root;
    struct nnpfs_handle real_handle = message->node.handle;
    struct nnpfs_node *t;
    int error = 0;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installroot\n"));
    
    down(&nnpfsp->channel_sem);

    if (nnpfsp->status & NNPFS_ROOTINSTALLED) {
	printk("NNPFS Panic: nnpfs_message_installroot again\n");
	error = -EBUSY;
	goto out;
    }

    if (!inode) {
	printk("NNPFS Panic: nnpfs_message_installroot w/o mount\n");
	error = -ENOENT;
	goto out;
    }

    t = VNODE_TO_XNODE(inode);
    message->node.handle = t->handle; /* to grab the right node */
    inode = nnpfs_node_add(nnpfsp, &message->node);
    if (IS_ERR(inode)) {
	error = PTR_ERR(inode);
	printk("nnpfs_message_installroot: no new node (%d)\n", error);
	goto out;
    }

    down(&nnpfsp->inactive_sem);
    t->handle = real_handle;
    nnpfs_node_rehash(t);
    up(&nnpfsp->inactive_sem);
    iput(inode);

    nnpfsp->status |= NNPFS_ROOTINSTALLED;

out:
    up(&nnpfsp->channel_sem);
    return error;
}

int
nnpfs_message_installnode(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installnode *message,
			  u_int size)
{
    int error = 0;
    struct nnpfs_node *n, *dp;
    struct dentry *dentry = NULL;
    struct inode *di, *inode;
    struct dentry *parent = NULL;
    struct qstr sqstr;
    struct list_head *alias;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode\n"));
    
    error = nnpfs_node_find(nnpfsp, &message->parent_handle, &dp);
    if (error) {
    	printk(KERN_EMERG "NNPFS Panic: nnpfs_message_install "
	       "could not find parent (%d)\n", error);
	return error;
    }

    di = XNODE_TO_VNODE(dp);
	
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: dp: %p aliases:", di));
    nnpfs_print_aliases(di);
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: fetching new node\n"));

    inode = nnpfs_node_add(nnpfsp, &message->node); /* iget:s */
    if (IS_ERR(inode)) {
	error = PTR_ERR(inode);
	NNPFSDEB(XDEBMSG,
		 ("nnpfs_message_installnode: no new node (%d)\n", error));
	
	iput(di);

	if (error == -EISDIR)
	    return 0;
	
	return error;
    }

    n = VNODE_TO_XNODE(inode);

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: inode: %p tokens: 0x%x aliases: ",
		       inode, n->tokens));
    nnpfs_print_aliases(inode);
    sqstr.name = message->name;
    sqstr.len  = strlen(message->name);
    sqstr.hash = full_name_hash(sqstr.name, sqstr.len);
    
    /*
     * for all parent dentries
     *   if node with name
     *     if empty
     *       d_instantiate
     *     else if `check inode'
     *       complain
     *     else
     *       already inserted
     *   else
     *     allocate node
     *
     */
    
    alias = di->i_dentry.next;
    while (alias != &di->i_dentry) {
	parent = list_entry(alias, struct dentry, d_alias);
	spin_lock(&dcache_lock);
	dget_locked(parent);
	spin_unlock(&dcache_lock);
	dentry = d_lookup(parent, &sqstr);
	NNPFSDEB(XDEBMSG,
		 ("nnpfs_message_installnode: alias %p, lookup %p\n",
		  parent, dentry));
	
	if (dentry) {
	    if (dentry->d_inode == NULL) {
		BUG_ON(!igrab(inode));
		d_instantiate(dentry, inode);
		DENTRY_TO_XDENTRY(dentry)->xd_flags =
		    (NNPFS_XD_ENTRY_VALID|NNPFS_XD_NAME_VALID);
	    } else if (dentry->d_inode != inode) {
		/* if the name was invalid */
		if ((DENTRY_TO_XDENTRY(dentry)->xd_flags & NNPFS_XD_NAME_VALID) != 0)
		    printk(KERN_EMERG "NNPFS SoftAssert: existing inode "
			   "(%p, fid %d.%d.%d.%d) != "
			   "installing %s(%p, fid %d.%d.%d.%d)\n",
			   dentry->d_inode,
			   VNODE_TO_XNODE(dentry->d_inode)->handle.a,
			   VNODE_TO_XNODE(dentry->d_inode)->handle.b,
			   VNODE_TO_XNODE(dentry->d_inode)->handle.c,
			   VNODE_TO_XNODE(dentry->d_inode)->handle.d,
			   message->name, inode,
			   n->handle.a, n->handle.b, n->handle.c, n->handle.d);
		if (nnpfs_dcount(dentry) == 0)
		    nnpfs_d_remove(dentry);
		else
		    d_drop(dentry);
		goto insert_name;
	    } else {
		DENTRY_TO_XDENTRY(dentry)->xd_flags =
			(NNPFS_XD_ENTRY_VALID|NNPFS_XD_NAME_VALID);
	    }
	} else {
	    /* unprovoked installnode, ie bulkstatus) */
	insert_name:
	    dentry = d_alloc(parent, &sqstr);
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: "
			       "allocated new entry: %p\n",
			       dentry));
	    error = nnpfs_d_init(dentry);
	    if (error == 0) {
		DENTRY_TO_XDENTRY(dentry)->xd_flags =
		    (NNPFS_XD_ENTRY_VALID|NNPFS_XD_NAME_VALID);
		BUG_ON(!igrab(inode));
		d_add(dentry, inode);
	    }
	}
	
	dput(dentry);
	dentry = NULL;
	alias = alias->next;
	dput(parent);
    }
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installnode: done installing\n"));
    
    iput(inode);
    iput(di);
    
    return error;
}

int
nnpfs_message_installattr(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installattr *message,
			  u_int size)
{
    struct nnpfs_node *t;
    struct inode *inode;
    struct dentry *dentry;
    int i, error;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr (%d.%d.%d.%d)\n",
		       message->node.handle.a,
		       message->node.handle.b,
		       message->node.handle.c,
		       message->node.handle.d));
    
    error = nnpfs_node_find(nnpfsp, &message->node.handle, &t);
    if (error) {
	NNPFSDEB(XDEBMSG,
		 ("nnpfs_message_installattr: no such node (%d)\n", error));
	return error;
    }

    inode = XNODE_TO_VNODE(t);
    dentry = list_entry(inode->i_dentry.next, struct dentry, d_alias);
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr name:%s\n",
		       dentry->d_name.name));
    
    /*
     * Paranoid checks
     */
    
    t->tokens |= (message->node.tokens & NNPFS_ATTR_MASK);
    if (NNPFS_TOKEN_GOT(t, NNPFS_DATA_R)) {
	if (t->index == NNPFS_NO_INDEX) {
	    printk(KERN_EMERG "nnpfs_message_installattr: "
		   "token w/o data (%x %x)(%d.%d.%d.%d)!\n",
		   t->tokens, t->index, 
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d);
	    NNPFS_TOKEN_CLEAR (t, NNPFS_DATA_R|NNPFS_DATA_W , NNPFS_DATA_MASK);
	}
    } else {
	if (t->index != NNPFS_NO_INDEX) {
	    printk(KERN_EMERG "nnpfs_message_installattr: "
		   "data w/o token (%x %x) (%d.%d.%d.%d), msg %d!\n",
		   t->tokens, t->index,
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   message->header.sequence_num);
	}
    }
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: tokens: 0x%x\n", t->tokens));

    /* if we're writing and we didn't initiate this, ignore daemon's size */
    if (t->flags & NNPFS_DATA_DIRTY && !(message->flag & NNPFS_PUTATTR_REPLY))
	XA_CLEAR_SIZE(&message->node.attr);
    nnpfs_attr2inode(&message->node.attr, inode, 0);
    
    memmove(t->id, message->node.id, sizeof(t->id));
    memmove(t->rights, message->node.rights, sizeof(t->rights));
    for (i = 0; i < NNPFS_MAXRIGHTS; i++) {
	NNPFSDEB(XDEBMSG, ("rights %d:", t->id[i]));
	NNPFSDEB(XDEBMSG, (t->rights[i]&NNPFS_RIGHT_R?"r":"-"));
	NNPFSDEB(XDEBMSG, (t->rights[i]&NNPFS_RIGHT_W?"w":"-"));
	NNPFSDEB(XDEBMSG, (t->rights[i]&NNPFS_RIGHT_X?"x":"-"));
	NNPFSDEB(XDEBMSG, ("\n"));
    }
    t->anonrights = message->node.anonrights;
    iput(inode);
    
    return 0;
}

int
nnpfs_message_installdata(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installdata *message,
			  u_int size)
{
    struct nnpfs_node *t;
    struct inode *inode;
    int error = 0;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata\n"));
    
    if ((message->node.tokens & NNPFS_DATA_MASK) == 0) {
	printk(KERN_EMERG "nnpfs_message_installdata: "
	       "no token (%d.%d.%d.%d)!\n",
	       message->node.handle.a, message->node.handle.b,
	       message->node.handle.c, message->node.handle.d);
	return 0;
    }

    error = nnpfs_node_find(nnpfsp, &message->node.handle, &t);
    if (error) {
	printk(KERN_EMERG "NNPFS Panic: "
	       "nnpfs_message_installdata didn't find node (%d)!\n",
	       error);
	return error;
    }

    inode = XNODE_TO_VNODE(t);

    if (t->index != NNPFS_NO_INDEX && t->index != message->cache_id) {
	printk(KERN_EMERG "nnpfs_message_installdata: "
	       "changing index for (%d.%d.%d.%d), %x -> %x!\n",
	       t->handle.a, t->handle.b, t->handle.c, t->handle.d,
	       t->index, message->cache_id);
    }
        
    if (message->offset != NNPFS_NO_OFFSET) {
	error = nnpfs_block_setvalid(t, message->offset);
	if (error) {
	    printk(KERN_EMERG "nnpfs_message_installdata: "
		   "(%d.%d.%d.%d) setvalid -> %d!\n",
		   t->handle.a, t->handle.b, t->handle.c, t->handle.d,
		   error);
	    iput(inode);
	    return error;
	}
    }

    t->index = message->cache_id;

    if (message->flag & NNPFS_ID_INVALID_DNLC)
	clear_all_children (inode, 0);

    t->tokens |= (message->node.tokens & (NNPFS_DATA_MASK|NNPFS_OPEN_MASK));

    NNPFSDEB(XDEBMSG,
	     ("nnpfs_message_installdata: tokens: 0x%x, size before: %lld\n",
	      t->tokens, (long long)inode->i_size));

    /* if we're writing, ignore daemon's size */
    if (t->flags & NNPFS_DATA_DIRTY)
	XA_CLEAR_SIZE(&message->node.attr);
    nnpfs_attr2inode (&message->node.attr, inode, 0);

    NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata size after: %lld\n",
		       (long long) inode->i_size));
    memmove(t->id, message->node.id, sizeof(t->id));
    memmove(t->rights, message->node.rights, sizeof(t->rights));
    t->anonrights = message->node.anonrights;

    iput(inode);

    return 0;
}

static void
clear_all_children (struct inode *inode, int parent)
{
    struct list_head *alias;

 again:
    spin_lock(&dcache_lock);
    alias = inode->i_dentry.next;
    while (alias != &inode->i_dentry) {
	struct dentry *dentry;
	struct list_head *subdirs;
	struct nnpfs_dentry_data *xd;
	
	dentry = list_entry(alias, struct dentry, d_alias);
	if (dentry == NULL) {
	    printk(KERN_EMERG "NNPFS Panic: dentry in alias list is null\n");
	    break;
	}

	xd = DENTRY_TO_XDENTRY(dentry);
	if (parent)
	    xd->xd_flags &= ~NNPFS_XD_NAME_VALID;

	NNPFSDEB(XDEBMSG, ("clear_all_children parent: %.*s\n",
			   (int)dentry->d_name.len, dentry->d_name.name));

	subdirs = dentry->d_subdirs.next;
	while (subdirs != &dentry->d_subdirs) {
	    struct list_head *tmp = subdirs;
	    struct dentry *child = list_entry(tmp, struct dentry, d_u.d_child);
	    subdirs = tmp->next;
	    NNPFSDEB(XDEBMSG, ("clear_all_children child: %.*s inode: %p/%p "
			       "dcount: %d aliases:\n",
			       (int)child->d_name.len, child->d_name.name,
			       inode, child->d_inode, nnpfs_dcount(child)));
	    if (d_unhashed(child))
		continue;
	    
	    if (child->d_inode) {
		nnpfs_print_aliases(child->d_inode);
		if (DENTRY_TO_XDENTRY(child) == NULL)
		    printk(KERN_EMERG "NNPFS Panic: xdentry is null!\n");
		else
		    DENTRY_TO_XDENTRY(child)->xd_flags &= ~NNPFS_XD_NAME_VALID;
	    }
	    /* can't throw ref:ed negative dentries */

	    /* Throw immediately */
	    if (nnpfs_dcount(child) == 0) {
	        spin_unlock(&dcache_lock);
		nnpfs_d_remove(child);
		goto again;
	    }
	}
	alias = alias->next;
    }
    spin_unlock(&dcache_lock);
}

static void
nnpfs_invalid_node(struct nnpfs_node *node)
{
    struct inode *inode = XNODE_TO_VNODE(node);
    int num_users;

    /* last close wins */
    if (nnpfs_iwritecount(inode) > 0)
	return;
    
    num_users = nnpfs_node_users(inode);
    
    NNPFSDEB(XDEBNODE, ("nnpfs_invalid_node: used dentries: %d\n",
			num_users));
    
    if (num_users == 0 || S_ISDIR(inode->i_mode)) {
  	nnpfs_force_invalid_node(node);
    } else {
	/* can't drop data now, just mark it stale. */
	node->flags |= NNPFS_STALE;
    }
}

/*
 * Clean out and invalidate node as best we can, may be called with
 * inactive_sem held.
 *
 * XXX nnpfs_node_clear()?
 */
void
nnpfs_force_invalid_node(struct nnpfs_node *node)
{
    struct inode *inode = XNODE_TO_VNODE(node);

    NNPFSDEB(XDEBNODE, ("nnpfs_force_invalid_node: %p\n", inode));
    
    /* 
     * XXX Really need to put back dirty data first.
     * XXXRACE set DATA_FROM_XNODE(node) before dput() ?
     */
    NNPFS_TOKEN_CLEAR(node, ~0,
		      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK | NNPFS_LOCK_MASK);
    if (node->index != NNPFS_NO_INDEX) {
	invalidate_inode_pages2(inode->i_mapping);
	nnpfs_block_free_all(node);
	/* node->index = NNPFS_NO_INDEX; XXX don't drop before inactivenode */
	/* NNPFS_TOKEN_CLEAR(node, ~0, NNPFS_DATA_MASK); */
    }
    clear_all_children(inode, 1);
    if (!S_ISDIR(inode->i_mode))
	/* we must drop node before daemon can refresh its data */
	d_prune_aliases(inode);
}

int
nnpfs_message_invalidnode(struct nnpfs *nnpfsp,
			  struct nnpfs_message_invalidnode *message,
			  u_int size)
{
    int error;
    struct nnpfs_node *t;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode\n"));
    error = nnpfs_node_find(nnpfsp, &message->handle, &t);
    if (error) {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: didn't find node!"
		 " (%d.%d.%d.%d) (%d)\n",
		 message->handle.a,
		 message->handle.b,
		 message->handle.c,
		 message->handle.d, error));
	return error;
    }

    nnpfs_invalid_node(t);
    iput(XNODE_TO_VNODE(t));

    return 0;
}

int
nnpfs_message_updatefid(struct nnpfs *nnpfsp,
			struct nnpfs_message_updatefid * message,
			u_int size)
{
    struct nnpfs_node *t;
    int error;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_updatefid\n"));
    error = nnpfs_node_find (nnpfsp, &message->old_handle, &t);
    if (error) {
 	printk(KERN_EMERG
	       "NNPFS Panic: nnpfs_message_updatefid: no node! (%d)\n", error);
	return error;
    }

    down(&nnpfsp->inactive_sem);
    t->handle = message->new_handle;
    nnpfs_node_rehash(t);
    up(&nnpfsp->inactive_sem);

    iput(XNODE_TO_VNODE(t));

    return 0;
}

void
gc_vnode(struct inode *inode)
{
    NNPFSDEB(XDEBMSG,("nnpfs_message_gc: inode: %p count: %d",
		      inode, nnpfs_icount(inode)));
    d_prune_aliases(inode);
    NNPFSDEB(XDEBMSG, ("\nnnpfs_message_gc: i_count after gc: %d\n",
		       nnpfs_icount(inode)));
}

static int
gc_block(struct nnpfs *nnpfsp,
	 struct nnpfs_node *xn,
	 uint64_t offset)
{
    struct inode *inode = XNODE_TO_VNODE(xn);
    loff_t end = i_size_read(inode);
    int error = 0;

#if 0
    /* XXX
     * ok, so we ought to write out all changes to the block before we
     * drop it, preferably while blocking any further accesses.
     */

    filemap_fdatawrite(mapping);
    invalidate_inode_pages2_range(mapping, start, end);
#endif
    
    if (xn->pending_writes) {
	printk(KERN_EMERG "NNPFS/gc_block: "
	       "EBUSY (%d,%d,%d,%d) 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset);
	return -EBUSY;
    }

    /* this may happen with pending writes, so order matters. */
    if (offset > end) {
	printk(KERN_EMERG "NNPFS/gc_block: "
	       "bad block (%d,%d,%d,%d) 0x%llx, len 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset, (unsigned long long)end);
	return -EINVAL;
    }

    if (!nnpfs_block_have_p(xn, offset)) {
	printk(KERN_EMERG "NNPFS/gc_block: "
	       "ENOENT (%d,%d,%d,%d) 0x%llx\n", 
	       xn->handle.a, xn->handle.b, xn->handle.c, xn->handle.d, 
	       (unsigned long long)offset);
	return -ENOENT;
    }

    if (xn->flags & NNPFS_DATA_DIRTY) {
	struct nnpfs_message_putdata msg;
	uint64_t len = nnpfs_blocksize;

	if (offset + len > end)
	    len = end - offset;
	
	nnpfs_inode2attr(inode, &msg.attr);
	
	msg.header.opcode = NNPFS_MSG_PUTDATA;
	msg.cred   = xn->wr_cred;
	msg.handle = xn->handle;
	msg.offset = offset;
	msg.len    = len;
	msg.flag   = NNPFS_WRITE | NNPFS_GC;
	
	/* XXX locking, rpc may fail */
	xn->daemon_length = end;
	nnpfs_block_setinvalid(xn, offset);
	error = nnpfs_message_rpc_async(nnpfsp, &msg.header, sizeof(msg));
    } else {
	struct nnpfs_message_deletedata msg;
	
	msg.header.opcode = NNPFS_MSG_DELETEDATA;
	msg.handle = xn->handle;
	msg.offset = offset;
	
	nnpfs_block_setinvalid(xn, offset);
	error = nnpfs_message_send(nnpfsp, &msg.header, sizeof(msg));
    }

    if (error)
	printk(KERN_EMERG "NNPFS/gc_block: couldn't send gc putdata (%d)\n", error);

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
		 u_int size)
{
    struct nnpfs_node *node;
    int i, error;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_gc\n"));
    
    for (i = 0; i < message->len; i++) {
	struct inode *inode;
	error = nnpfs_node_find(nnpfsp, &message->handle[i].node, &node);
	if (error) {
	    if (error == -ENOENT)
		NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: node not found\n"));
	    else if (error == -EISDIR)
		NNPFSDEB(XDEBMSG, ("nnpfs_message_gc: node deleted\n"));
	    continue;
	}
	inode = XNODE_TO_VNODE(node);

	if (message->handle[i].offset == NNPFS_NO_OFFSET)
	    gc_vnode(inode);
	else
	    gc_block(nnpfsp, node, message->handle[i].offset);

	iput(inode);
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
		      u_int size)
{
    struct nnpfs_message_wakeup msg;
    int ret = NNPFS_VERSION;

    down(&nnpfsp->channel_sem);

    /* sanity check before we look at it */
    if (size == sizeof(*message) && message->version == NNPFS_VERSION) {
	struct nameidata nd;
	int error;

	uint64_t blocksize = message->blocksize;

	error = path_lookup(".", 0, &nd);
	if (error) {
	    /*
	     * Bad cache root, just return.
	     * It would be nice to be able to communiacte failure, now
	     * we risk looping on getroot.
	     */
	    printk(KERN_EMERG "NNPFS Panic: "
		   "nnpfs_message_version failed path_lookup, "
		   "errno: %d\n", error);
	} else {
	    nnpfsp->cacheroot = mntget(nd.path.mnt);
	    nnpfsp->cachedir = dget(nd.path.dentry);
	    path_put(&nd.path);
	    
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	    nnpfsp->uid = current->fsuid;
	    nnpfsp->gid = current->fsgid;
#else
            nnpfsp->uid = current_fsuid();
            nnpfsp->gid = current_fsgid();
#endif

	    /* XXX we should validate these values */
	    nnpfs_blocksize = blocksize;
	    nnpfs_blocksizebits = 0;
	    while ((blocksize >> nnpfs_blocksizebits) > 1) 
		nnpfs_blocksizebits++;

	    nnpfsp->appendquota = message->appendquota;
	}
    }

    up(&nnpfsp->channel_sem);

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;
    msg.len = 0;

    return nnpfs_message_send(nnpfs, 
			      (struct nnpfs_message_header *) &msg,
			      sizeof(msg));
}

/*
 * daemon ACKs deletion of node, free it for real
 */

int
nnpfs_message_delete_node(struct nnpfs *nnpfsp,
			  struct nnpfs_message_delete_node *message,
			  u_int size)
{
    struct nnpfs_node *t;
    int error;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_delete_node\n"));

    error = nnpfs_node_find_gc(nnpfsp, &message->handle, &t);
    if (error == -ENOENT) {
	printk(KERN_EMERG "nnpfs_message_delete_node: node not found\n");
    } else {
	struct inode *inode = XNODE_TO_VNODE(t);
	NNPFSDEB(XDEBMSG,
		 ("nnpfs_message_delete_node: %p, flags 0x%x\n", t, t->flags));

	if (error == -EISDIR) {
	    /*
	     * Release the extra ref from nnpfs_node_add(), so it is
	     * free'd ASAP.
	     */
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_delete_node: free node\n"));
	    
	    iput(inode);
	    error = 0;
	} else {
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_delete_node: not deleted"));
	}

	iput(inode);
    }
	
    return error;
}

/*
 *
 */

int
nnpfs_message_installquota(struct nnpfs *nnpfsp,
			   struct nnpfs_message_installquota *message,
			   u_int size)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installquota\n"));

    down(&nnpfsp->channel_sem);

    nnpfsp->appendquota += message->appendbytes;
    BUG_ON(nnpfsp->appendquota < 0);

    if (nnpfsp->status & NNPFS_QUOTAWAIT)
	wake_up_all(&nnpfsp->wait_queue);

    up(&nnpfsp->channel_sem);

    return 0;
}
