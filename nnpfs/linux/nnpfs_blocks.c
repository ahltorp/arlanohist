/*
 * Copyright (c) 2005-2006, Stockholms Universitet
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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

/* $Id: nnpfs_blocks.c,v 1.6 2010/08/08 20:43:04 tol Exp $ */

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <linux/mount.h>
#include <linux/mm.h>

/*
 * return true if block is in cache
 */

int
nnpfs_block_have_p(struct nnpfs_node *node, uint64_t offset)
{
    struct nnpfs_cache_handle *handle = &node->data;
    uint32_t index = nnpfs_block_index(offset);
    uint32_t maskno = nnpfs_block_masknumber(index);

    BUG_ON(nnpfs_offset(offset) != offset);

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

    BUG_ON(nnpfs_offset(offset) != offset);

    if (maskno == 0 && handle->nmasks <= 1) {
	handle->nmasks = 1;
	slot = &handle->masks.first;
    } else {
	if (maskno >= handle->nmasks) {
	    int n = maskno + NNPFS_NMASKS - (maskno % NNPFS_NMASKS);
	    int size = n * sizeof(uint32_t);
	    uint32_t *new;

	    BUG_ON(!val);

	    new = nnpfs_alloc(size, NNPFS_MEM_BLOCK);
	    if (!new) {
		nnpfs_debug_oops();
		return -ENOMEM;
	    }
	    
	    if (handle->nmasks == 1) {
		new[0] = handle->masks.first;
	    } else if (handle->nmasks > 1) {
		memcpy(new, handle->masks.list,
		       handle->nmasks * sizeof(uint32_t));
		nnpfs_free(handle->masks.list, NNPFS_MEM_BLOCK);
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

    if (val)
	BUG_ON(!nnpfs_block_have_p(node, offset));
    else
	BUG_ON(nnpfs_block_have_p(node, offset));

    return 0;
}

/*
 * mark block at offset as present in cache
 */

int
nnpfs_block_setvalid(struct nnpfs_node *node, uint64_t offset)
{
    return nnpfs_block_set_have(node, offset, 1);
}

/*
 * mark block at offset as not present in cache
 */

void
nnpfs_block_setinvalid(struct nnpfs_node *node, uint64_t offset)
{
    (void)nnpfs_block_set_have(node, offset, 0);
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
	(void)nnpfs_block_set_have(node, offset, 0);
}

/*
 * Forget all blocks beyond `size' for `node' 
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
	nnpfs_free(handle->masks.list, NNPFS_MEM_BLOCK);
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

/*
 * extend a block to full length
 */
static int
nnpfs_block_extend(struct nnpfs_node *node, uint64_t offset)
{
    struct inode *inode = XNODE_TO_VNODE(node);
    struct inode *backnode;
    struct file *backfile;
    int ret;

    NNPFSDEB(XDEBNODE, ("nnpfs_block_extend: %p @0x%llx\n",
			inode, (unsigned long long)offset));

    ret = nnpfs_block_open(node, offset, O_RDWR, &backfile);
    if (ret) {
	nnpfs_debug_oops();
	return ret;
    }

    backnode = backfile->f_mapping->host;

    mutex_lock(&backnode->i_mutex);
    ret = vmtruncate(backnode, nnpfs_blocksize);
    mutex_unlock(&backnode->i_mutex);
    
    filp_close(backfile, NULL);

    if (ret) {
	printk("nnpfs_block_extend(%p) failed: %d\n", inode, -ret);
	nnpfs_debug_oops();
    }
    return ret;
}

/*
 * open indicated cache block file. needs to be closed by caller.
 *
 * With O_CREAT, file should be NULL.
 */

int
nnpfs_block_open(struct nnpfs_node *node, uint64_t offset, int flag,
		 struct file **file)
{
    char cachename[NNPFS_CACHE_PATH_SIZE];
    uint64_t blockindex = nnpfs_block_index(offset);
    uint32_t id = node->index;
    struct nnpfs *nnpfsp = NNPFS_FROM_XNODE(node);
    struct inode *inode = XNODE_TO_VNODE(node);
    int flags = O_LARGEFILE | flag;
    struct nameidata nd;
    uid_t saveuid;
    gid_t savegid;
    int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
    const struct cred *old_cred;
    struct cred *override_cred;
#endif

    BUG_ON(!nnpfsp);
    BUG_ON(flags & O_CREAT && file != NULL);

    if (S_ISDIR(XNODE_TO_VNODE(node)->i_mode)) {
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_DIR_PATH,
		       id / 0x100, id % 0x100);
    } else {
	ret = snprintf(cachename, sizeof(cachename),
		       NNPFS_CACHE_FILE_PATH,
		       id / 0x100, id % 0x100,
		       (unsigned long long)blockindex);

	if (!nnpfs_block_have_p(node, offset) && (flags & O_CREAT) == 0) {
	    printk(KERN_EMERG "reading block %s: not there\n", cachename);
	    BUG();
	}
    }

    BUG_ON(ret <= 0 || ret >= sizeof(cachename));
    BUG_ON(!nnpfsp->cachedir || !nnpfsp->cacheroot);
    
    /* use the nfsd trick to give us access */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    saveuid = current->fsuid;
    savegid = current->fsgid;
    current->fsuid = nnpfsp->uid;
    current->fsgid = nnpfsp->gid;
#else
    saveuid = current_fsuid();
    savegid = current_fsgid();
    override_cred = prepare_creds();
    if (override_cred == NULL)
        return -ENOMEM;
    override_cred->fsuid = nnpfsp->uid;
    override_cred->fsgid = nnpfsp->gid;
    old_cred = override_creds(override_cred);
#endif

    ret = vfs_path_lookup(nnpfsp->cachedir, nnpfsp->cacheroot,
			  cachename,
			  flags & O_CREAT ? LOOKUP_PARENT : 0,
			  &nd);
    if (ret) {
	uint32_t nmasks = node->data.nmasks;
	uint32_t mask;

	if (nmasks > 1)
	    mask = node->data.masks.list[0];
	else if (nmasks)
	    mask = node->data.masks.first;
	else
	    mask = 0;

	printk("nnpfs_block_open(%s) walk failed: %d\n", cachename, ret);
	printk("(%u.%u.%u.%u), fid %lu, id %lu\n",
	       node->handle.a, node->handle.b, node->handle.c, node->handle.d,
	       inode->i_ino, (unsigned long)node->index);
	printk("nnpfs_block_open: n %lu, mask %x, inode %p, aliases: ",
	       (unsigned long)nmasks, mask, inode);
	nnpfs_print_aliases_real(inode);

	nnpfs_debug_oops();
	/* don't do path_release(), it's already handled */
	goto out;
    }
    
    if (flags & O_CREAT) {
	/* XXX mode bits on create -- S_IRUSR|S_IWUSR */
	struct dentry *dentry = lookup_create(&nd, 0);	
	if (IS_ERR(dentry)) {
	    ret = PTR_ERR(dentry);
	} else {
	    ret = vfs_create(nd.path.dentry->d_inode, dentry, S_IRUSR|S_IWUSR, &nd);
	    dput(dentry);
	}

	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);

	if (ret) {
	    printk("nnpfs_block_open(%s) create failed: %d\n", cachename, -ret);
	    nnpfs_debug_oops();
	}

	/* blocks in the middle of the file should be of full length */
	if (!ret && offset < nnpfs_offset(i_size_read(inode))) {
	    NNPFSDEB(XDEBNODE, ("nnpfs_block_open(%p) truncating @0x%llx\n",
				inode, (unsigned long long)offset));
	    ret = nnpfs_block_extend(node, offset);
	}
    } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	struct file *f = dentry_open(nd.path.dentry, nd.path.mnt, flags);
#else
        struct file *f = dentry_open(nd.path.dentry, nd.path.mnt, flags, current_cred());
#endif
	if (IS_ERR(f)) {
	    ret = PTR_ERR(f);
	    printk("nnpfs_block_open(%s) open failed: %d\n", cachename, -ret);
	    nnpfs_debug_oops();
	    path_put(&nd.path);
	} else {
	    *file = f;
	}
    }
    
    /* path_release() is usually handled on close */

 out:
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    current->fsuid = saveuid;
    current->fsgid = savegid;
#else
    revert_creds(old_cred);
    put_cred(override_cred);
#endif

    return ret;
}

/*
 * predicate for msleep
 */

static int
got_appendquota(void *data)
{
    struct nnpfs *nnpfsp = (struct nnpfs *)data;
    
    if (nnpfsp->appendquota >= nnpfs_blocksize)
	return 1;

    return 0;
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
    struct inode *inode = XNODE_TO_VNODE(node);
    loff_t prevsize = i_size_read(XNODE_TO_VNODE(node));
    int ret;

    BUG_ON(nnpfs_block_have_p(node, offset));
    BUG_ON(S_ISDIR(inode->i_mode));

    NNPFSDEB(XDEBNODE, ("nnpfs_block_create: %p @0x%llx\n",
			inode, (unsigned long long)offset));

    ret = nnpfs_block_setvalid(node, offset);
    if (ret) {
	nnpfs_debug_oops();
	return ret;
    }

    ret = nnpfs_block_open(node, offset, O_CREAT, NULL);
    if (ret) {
	nnpfs_debug_oops();
	nnpfs_block_setinvalid(node, offset);
	return ret;
    }

    /* extend previously last block to full length */
    if (prevsize < offset) {
	uint64_t prevoff = nnpfs_end_offset(prevsize);
	if (nnpfs_block_have_p(node, prevoff)) {
	    ret = nnpfs_block_extend(node, prevoff);
	    if (ret) {
		nnpfs_block_setinvalid(node, offset);
		return ret;
	    }
	}
    }
    
    down(&nnpfsp->channel_sem);
    while (nnpfsp->appendquota < nnpfs_blocksize
	   && nnpfsp->status & NNPFS_DEVOPEN) {
	int waiting = (nnpfsp->status & NNPFS_QUOTAWAIT);
	nnpfsp->status |= NNPFS_QUOTAWAIT;
	/* XXX */
	(void)nnpfs_dev_msleep(nnpfsp, &nnpfsp->wait_queue,
			       got_appendquota, nnpfsp);
	if (!waiting)
	    nnpfsp->status &= ~NNPFS_QUOTAWAIT;
    }
    
    if (nnpfsp->status & NNPFS_DEVOPEN) {
	nnpfsp->appendquota -= nnpfs_blocksize;
	BUG_ON(nnpfsp->appendquota < 0);
    } else {
	ret = ENODEV;
    }

    up(&nnpfsp->channel_sem);
    
    if (ret) {
	nnpfs_block_setinvalid(node, offset);
	return ret;
    }

    msg.header.opcode = NNPFS_MSG_APPENDDATA;
    msg.handle = node->handle;
    msg.offset = offset;

    /* XXX currently no cleanup on failed send, hope it's just a devclose */
    return nnpfs_message_send(nnpfsp, &msg.header, sizeof(msg));
}
