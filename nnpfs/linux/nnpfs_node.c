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
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_dev.h>
#include <linux/mm.h>

#ifdef RCSID
RCSID("$Id: nnpfs_node.c,v 1.82 2007/01/03 13:52:02 tol Exp $");
#endif

uint64_t nnpfs_blocksize;
uint32_t nnpfs_blocksizebits;

static int
nnpfs_node_test(struct inode *inode, void *data)
{
    nnpfs_handle *handle = (nnpfs_handle *)data;
    struct nnpfs_node *node = VNODE_TO_XNODE(inode);
    return nnpfs_handle_eq(&node->handle, handle);
}

static int
nnpfs_node_set(struct inode *inode, void *data)
{
    nnpfs_handle *handle = (nnpfs_handle *)data;
    struct nnpfs_node *node = VNODE_TO_XNODE(inode);

    memset(node, 0, (char *)inode - (char *)node);
    node->handle = *handle;

    return 0;
}

/*
 * Returns a ref'd node or NULL.
 */

static struct nnpfs_node *
nnpfs_node_lookup(struct nnpfs *nnpfsp, struct nnpfs_handle *handlep)
{
    struct super_block *sb = nnpfsp->sb;
    struct nnpfs_node *xn;
    unsigned long hashvalue;
    struct inode *inode;
    
    NNPFSDEB(XDEBNODE, ("nnpfs_node_lookup: enter %d.%d.%d.%d\n",
			handlep->a,
			handlep->b,
			handlep->c,
			handlep->d));
    
    if (!sb) {
	printk(KERN_EMERG "nnpfs_node_lookup: no sb!\n");
	return NULL;
    }
    
    hashvalue = nnpfs_hash(handlep);

    down(&nnpfsp->inactive_sem);
    inode = ilookup5(sb, hashvalue, nnpfs_node_test, handlep);
    up(&nnpfsp->inactive_sem);

    if (!inode) {
	NNPFSDEB(XDEBNODE, ("nnpfs_node_lookup: not found\n"));
	return NULL;
    }
    
    BUG_ON(inode->i_state & I_NEW);
    
    xn = VNODE_TO_XNODE(inode);
    NNPFSDEB(XDEBNODE, ("nnpfs_node_lookup: found node %p\n", inode));
    return xn;
}

/*
 * Take care of updating the node's size
 */

static void
nnpfs_setsize(struct inode *inode, uint64_t size)
{
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    loff_t old_len = i_size_read(inode);
    xn->daemon_length = size;

    if (size >= old_len)
	return;

    if (mapping_mapped(inode->i_mapping)) {
	printk("nnpfs_setsize: mapped!\n");
    } else {
#if 0
	printk("nnpfs_setsize: truncating @0x%llu\n",
	       (unsigned long long)size);
#endif
	vmtruncate(inode, size); /* XXX retval */
	nnpfs_block_truncate(xn, size);
    }
}

/*
 * Copy the attributes from `attr' into `inode', setting the fields
 * that weren't set in `attr' to reasonable defaults.
 */

void
nnpfs_attr2inode(const struct nnpfs_attr *attr, struct inode *inode,
		 int clear_node)
{
    if (clear_node) {
	struct timespec notime = {0};

	inode->i_mode   = 0;
	inode->i_uid    = 0;
	inode->i_gid    = 0;
	inode->i_nlink  = 1;
	inode->i_atime  = notime;
	inode->i_mtime  = notime;
	inode->i_ctime  = notime;
	i_size_write(inode, 0);

	spin_lock(&inode->i_lock);
	inode->i_blocks = 0;	
	spin_unlock(&inode->i_lock);
    }
    if (XA_VALID_MODE(attr))
	inode->i_mode   = attr->xa_mode;
    if (XA_VALID_UID(attr))
	inode->i_uid    = attr->xa_uid;
    if (XA_VALID_GID(attr))
	inode->i_gid    = attr->xa_gid;
    if (XA_VALID_NLINK(attr))
	inode->i_nlink  = attr->xa_nlink;
    
    if (XA_VALID_SIZE(attr)) {
	nnpfs_setsize(inode, attr->xa_size);
	i_size_write(inode, attr->xa_size);
	spin_lock(&inode->i_lock);
	inode->i_blocks = (attr->xa_size + I_BLOCKS_UNIT - 1)>> I_BLOCKS_BITS;
	spin_unlock(&inode->i_lock);
    }

    if (XA_VALID_ATIME(attr))
	NNPFS_SET_TIME(inode->i_atime,attr->xa_atime);
    if (XA_VALID_MTIME(attr))
	NNPFS_SET_TIME(inode->i_mtime,attr->xa_mtime);
    if (XA_VALID_CTIME(attr))
	NNPFS_SET_TIME(inode->i_ctime,attr->xa_ctime);
    if (XA_VALID_FILEID(attr))
	inode->i_ino = attr->xa_fileid;
}

/*
 * Copy the attributes from `inode' into `attr'.
 */

void
nnpfs_inode2attr(struct inode *inode, struct nnpfs_attr *attr)
{
    XA_CLEAR(attr);

    XA_SET_MODE(attr, inode->i_mode);
    XA_SET_UID(attr, inode->i_uid);
    XA_SET_GID(attr, inode->i_gid);
    XA_SET_ATIME(attr, NNPFS_GET_TIME_SEC(inode->i_atime));
    XA_SET_MTIME(attr, NNPFS_GET_TIME_SEC(inode->i_mtime));
    XA_SET_CTIME(attr, NNPFS_GET_TIME_SEC(inode->i_ctime));
    XA_SET_SIZE(attr, i_size_read(inode));
}

void
nnpfs_iattr2attr(struct nnpfs_node *xn, const struct iattr *iattr,
		 struct nnpfs_attr *attr)
{
    int datap = NNPFS_TOKEN_GOT(xn, NNPFS_DATA_R);
    struct inode *inode = XNODE_TO_VNODE(xn);

    XA_CLEAR(attr);

    if (iattr->ia_valid & ATTR_MODE)
	XA_SET_MODE(attr, iattr->ia_mode);
    if (iattr->ia_valid & ATTR_UID)
	XA_SET_UID(attr, iattr->ia_uid);
    if (iattr->ia_valid & ATTR_GID)
	XA_SET_GID(attr, iattr->ia_gid);
    if (iattr->ia_valid & ATTR_ATIME)
	XA_SET_ATIME(attr, NNPFS_GET_TIME_SEC(iattr->ia_atime));
    if (iattr->ia_valid & ATTR_CTIME)
	XA_SET_CTIME(attr, NNPFS_GET_TIME_SEC(iattr->ia_ctime));

    if (S_ISREG(inode->i_mode)) {
	if (iattr->ia_valid & ATTR_SIZE)
	    XA_SET_SIZE(attr, iattr->ia_size);
	else if (datap)
	    XA_SET_SIZE(attr, i_size_read(inode));
    }
    
    if (iattr->ia_valid & ATTR_MTIME) /* XXX ATTR_MTIME_SET ? */
	XA_SET_MTIME(attr, NNPFS_GET_TIME_SEC(iattr->ia_mtime));
    else if (datap)
	XA_SET_MTIME(attr, NNPFS_GET_TIME_SEC(inode->i_mtime));
}

/*
 * Allocate a new inode (of the file system identified by `sb') and
 * return it, associated with `newnode'.  Return the `inode' or NULL.
 * The reference count on `inode' is incremented.
 */

static void
nnpfs_fill_inode(struct inode *inode, struct nnpfs_msg_node *node)
{
    struct nnpfs_attr *attr = &node->attr;

    if (!XA_VALID_TYPE(attr)) {
	inode->i_op  = &nnpfs_dead_inode_operations;
	inode->i_fop = &nnpfs_dead_operations;
    } else if (attr->xa_type == NNPFS_FILE_REG) {
	inode->i_op  = &nnpfs_file_inode_operations;
	inode->i_fop = &nnpfs_file_operations;
        inode->i_mapping->a_ops = &nnpfs_aops;
    } else if (attr->xa_type == NNPFS_FILE_DIR) {
	inode->i_op  = &nnpfs_dir_inode_operations;
	inode->i_fop = &nnpfs_dir_operations;
        inode->i_mapping->a_ops = &nnpfs_aops;
    } else if (attr->xa_type == NNPFS_FILE_LNK) {
	inode->i_op  = &nnpfs_link_inode_operations;
	inode->i_fop = &nnpfs_link_operations;
	inode->i_mapping->a_ops = &nnpfs_aops;
    } else {
	inode->i_op  = &nnpfs_dead_inode_operations;
	inode->i_fop = &nnpfs_dead_operations;
    }
}

/*
 * Find the node identified by `node->handle' belong to the filesystem
 * `nnpfsp' or create a new one.  The node is returned with incremented
 * reference count.
 *
 * Returns the inode or ERR_PTR.
 */

struct inode *
nnpfs_node_add(struct nnpfs *nnpfsp, struct nnpfs_msg_node *node)
{
    unsigned long hash = nnpfs_hash(&node->handle);
    struct nnpfs_node *result;
    struct inode *inode;

    NNPFSDEB(XDEBNODE, ("nnpfs_node_add %d.%d.%d.%d\n",
			node->handle.a,
			node->handle.b,
			node->handle.c,
			node->handle.d));
        
    down(&nnpfsp->inactive_sem);
    inode = iget5_locked(nnpfsp->sb, hash,
			 nnpfs_node_test, nnpfs_node_set,
			 &node->handle);
    up(&nnpfsp->inactive_sem);

    if (!inode)
	return ERR_PTR(-ENOMEM);

    result = VNODE_TO_XNODE(inode);

    if (inode->i_state & I_NEW) {
	/* assume we don't need inactive_sem here */
	nnpfsp->nnodes++;

	result->anonrights = node->anonrights;
	result->flags = 0;
	result->tokens = 0;
	INIT_LIST_HEAD(&result->inactive_list);
	result->index = NNPFS_NO_INDEX;
	result->nnpfsp = nnpfsp;

	inode->i_ino = hash;
	nnpfs_fill_inode(inode, node);
	nnpfs_attr2inode(&node->attr, inode, 1);

	/* Get extra ref. See nnpfs_put_inode, nnpfs_message_delete_node */
	nnpfs_iref(inode);

	unlock_new_inode(inode);
    } else if (result->flags & NNPFS_LIMBO) {
	iput(inode);
	return ERR_PTR(-EISDIR);
    } else {
	/* Node is already cached */
	if (result->flags & NNPFS_DATA_DIRTY)
	    XA_CLEAR_SIZE(&node->attr);

	nnpfs_attr2inode(&node->attr, inode, 0);
    }
    
    result->tokens |= node->tokens; /* XXX correct? */
    if ((result->tokens & NNPFS_DATA_MASK) && result->index == NNPFS_NO_INDEX) {
	printk("nnpfs_new_node: tokens and no data (%d,%d,%d,%d) \n",
	       node->handle.a, node->handle.b, node->handle.c, node->handle.d);
	result->tokens &= ~NNPFS_DATA_MASK;
    }

    /* XXX scary -- could this remove creator's privileges for existing node? */
    memmove(result->id, node->id, sizeof(result->id));
    memmove(result->rights, node->rights, sizeof(result->rights));
    
    return inode;
}

/*
 * handle for `node' has been updated, update hash for inode
 */
void
nnpfs_node_rehash(struct nnpfs_node *node)
{
    struct inode *inode = XNODE_TO_VNODE(node);
    unsigned long hash = nnpfs_hash(&node->handle);

    remove_inode_hash(inode);
    inode->i_ino = hash;
    __insert_inode_hash(inode, hash);
}

struct inode *
nnpfs_node_alloc(struct super_block *sb)
{
    struct nnpfs_node *n = nnpfs_alloc(sizeof(*n), NNPFS_MEM_XNODE);
    if (!n)
	return NULL;

    inode_init_once(&n->vfs_inode);
    return &n->vfs_inode;
}

/*
 * free node
 */

void
nnpfs_node_free(struct inode *inode)
{
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(inode);

    down(&nnpfsp->inactive_sem);

    if ((xn->flags & NNPFS_LIMBO) == 0)
	BUG();

    nnpfsp->nnodes--;
  
    if (!list_empty(&xn->inactive_list))
	list_del(&xn->inactive_list);

    up(&nnpfsp->inactive_sem);

    nnpfs_free(xn, NNPFS_MEM_XNODE);
}


/*
 * remove everything about `node'
 * call with inactive_sem held
 */

void
nnpfs_node_clear(struct nnpfs_node *node)
{
    struct inode *inode = XNODE_TO_VNODE(node);
    NNPFSDEB(XDEBNODE, ("nnpfs_node_clear starting\n"));
    
#if 0
    if (node->flags & NNPFS_LIMBO)
	BUG(); /* XXX race in iput() for bad nodes */
#endif

    node->flags |= NNPFS_LIMBO;

    /* XXX Really need to put back dirty data first. */
    NNPFS_TOKEN_CLEAR(node, ~0,
		      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
		      NNPFS_DATA_MASK | NNPFS_LOCK_MASK);

    node->index = NNPFS_NO_INDEX;

    truncate_inode_pages(&inode->i_data, 0);
    nnpfs_block_free_all(node);

    NNPFSDEB(XDEBNODE, ("nnpfs_node_clear: inode %p\n",
			XNODE_TO_VNODE(node)));
}

/*
 * find the node, identifed by `handlep' in `nnpfsp', and put it in
 * *node if it is not in limbo
 *
 * return 0, -ENOENT, or -EISDIR (for limbo nodes)
 */

int
nnpfs_node_find(struct nnpfs *nnpfsp, nnpfs_handle *handlep, 
		struct nnpfs_node **node)
{
    struct nnpfs_node *x;
    int ret = 0;
    
    x = nnpfs_node_lookup(nnpfsp, handlep);
    if (x == NULL) {
	ret = -ENOENT;
    } else if (x->flags & NNPFS_LIMBO) {
	iput(XNODE_TO_VNODE(x));
	x = NULL;
	ret = -EISDIR;
    }
    
    *node = x;

    return ret;
}

/*
 * find the limbo node identifed by `handlep' in `nnpfsp', and put it
 * in *node (even if in limbo)
 *
 * return 0, -ENOENT, or -EISDIR (for limbo nodes)
 */

int
nnpfs_node_find_gc(struct nnpfs *nnpfsp, nnpfs_handle *handlep, 
		   struct nnpfs_node **node)
{
    struct nnpfs_node *x;
    int ret = 0;
    
    x = nnpfs_node_lookup(nnpfsp, handlep);
    if (x == NULL)
	ret = -ENOENT;
    else if (x->flags & NNPFS_LIMBO)
	ret = -EISDIR;

    *node = x;

    return ret;
}

/*
 * Returns 1 if pag has any rights set in the node
 */

int
nnpfs_has_pag(const struct nnpfs_node *xn, nnpfs_pag_t pag)
{
    int i;

    if (xn == NULL)
	return 0;
    
    for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	if (xn->id[i] == pag)
	    return 1;
    
    return 0;
}

/*
 * Return the number of users of the node `inode'.
 */

int
nnpfs_node_users(struct inode *inode)
{
    struct list_head *pos;
    int users = 0;
    
    /* XXX this should probably be protected somehow */
    list_for_each(pos, &inode->i_dentry) {
	struct dentry *dentry = list_entry(pos, struct dentry, d_alias);
	if (nnpfs_dcount(dentry) > 1)
	    users++;
    }
    NNPFSDEB(XDEBNODE, ("nnpfs_node_users(%p): %d\n", inode, users));
    return users;
}

void
nnpfs_print_nodestats(struct nnpfs *nnpfsp)
{
#if 0
    struct list_head *next;
    struct list_head *xh;
    struct nnpfs_nodelist *xf;
    struct nnpfs_node *xn;
    int i;
    int total = 0;
    int used = 0;
    int nempty = 0;
    int maxlength = 0;

    for (i = 0; i < XN_HASHSIZE; i++) {
	int counter = 0;	
	xh = &nnpfsp->node_head.node_lists[i];

	if (list_empty(xh)) {
	    nempty++;
	    continue;
	}

	list_for_each(next, xh) {
	    struct inode *inode;
	    xf = list_entry(next, struct nnpfs_nodelist, node_list);
	    xn = xn_list_entry(xf, struct nnpfs_node, nodes);
	    
	    inode = XNODE_TO_VNODE(xn);
	    if (inode && nnpfs_icount(inode))
		used++;
	    total++;
	    counter++;
	}

	if (counter > maxlength)
	    maxlength = counter;
    }
    
    printk("nnodes: %d\n", nnpfsp->nnodes);
    printk("counted nodes: %d used, %d total\n", used, total);
    printk("buckets: %d, empty: %d, maxlength: %d\n",
	   XN_HASHSIZE, nempty, maxlength);
#endif
}
