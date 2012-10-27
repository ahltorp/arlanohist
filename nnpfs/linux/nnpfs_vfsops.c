/*
 * Copyright (c) 1995-2004, 2006 Kungliga Tekniska Högskolan
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
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnnpfs.h>
#include <linux/statfs.h>
#include <linux/mm.h>

#ifdef RCSID
RCSID("$Id: nnpfs_vfsops.c,v 1.111 2010/08/08 20:43:06 tol Exp $");
#endif

struct nnpfs nnpfs[NNNPFS];

static void nnpfs_put_super(struct super_block *sb);
static void nnpfs_write_super(struct super_block * sb);

static int nnpfs_statfs(struct dentry *dentry, struct kstatfs *buf);

static struct super_operations nnpfs_sops = { 
    alloc_inode		: nnpfs_node_alloc,
    destroy_inode	: nnpfs_node_free,
    drop_inode		: generic_delete_inode,
    put_super		: nnpfs_put_super,
    write_super		: nnpfs_write_super,
    statfs		: nnpfs_statfs,
};

int
nnpfs_fetch_root(struct inode *i)
{
    struct super_block *sb;
    struct nnpfs *nnpfsp;
    int error = 0;
    struct nnpfs_message_getroot msg;

    NNPFSDEB(XDEBVFOPS, ("nnpfs_fetch_root: inode %p\n", i));

    sb = i->i_sb;
    nnpfsp = VFS_TO_NNPFS(sb);

    BUG_ON(sb->s_root->d_inode != i);

    while ((nnpfsp->status & NNPFS_ROOTINSTALLED) == 0 && !error) {

	msg.header.opcode = NNPFS_MSG_GETROOT;
	/*
	 * Mounting should done by root, so get the root node with
	 * root's priviliges (usually none, and none is needed).
	 */
	
	msg.cred.uid = 0;
	msg.cred.pag = 0;
	
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	NNPFSDEB(XDEBVFOPS,
		 ("nnpfs_fetch_root nnpfs_message_rpc error = %d\n", error));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
	NNPFSDEB(XDEBVFOPS,
		 ("nnpfs_fetch_root nnpfs_message_wakeup error = %d\n", error));
    }
    if (error) {
	NNPFSDEB(XDEBVFOPS, ("nnpfs_fetch_root failed: %d\n", error));
	return error;
    }
    
    return 0;
}

/*
 * create a `fake' root inode for `sb'
 */

static struct inode *
make_root_inode(struct nnpfs *nnpfsp)
{
    struct nnpfs_msg_node node;

    memset (&node, 0, sizeof(node));

    node.handle.a = node.handle.b = node.handle.c = node.handle.d = 0;
    node.anonrights = NNPFS_RIGHT_R;
    XA_SET_MODE(&node.attr, S_IFDIR | 0777);
    XA_SET_NLINK(&node.attr, 100);
    XA_SET_SIZE(&node.attr, 0);
    XA_SET_UID(&node.attr, 0);
    XA_SET_GID(&node.attr, 0);
    XA_SET_ATIME(&node.attr, 0);
    XA_SET_MTIME(&node.attr, 0);
    XA_SET_CTIME(&node.attr, 0);
    XA_SET_FILEID(&node.attr, 0);
    XA_SET_TYPE(&node.attr, NNPFS_FILE_DIR);
    
    return nnpfs_node_add(nnpfsp, &node); /* iget:s */
}

/*
 * create a root dcache entry for `sb'
 */

static int
make_root (struct super_block *sb)
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(sb);
    struct inode *inode = make_root_inode(nnpfsp);
    struct dentry *dp;
    
    if (IS_ERR(inode)) {
	printk("make_root: bad inode %p\n", inode);
	return PTR_ERR(inode);
    }

    nnpfs->root = inode;

    /* XXX error handling */
    dp = d_alloc_root(inode);
    nnpfs_d_init(dp);
    sb->s_root = dp;
    return 0;
}

static struct super_block *
nnpfs_read_super (struct super_block * sb, void * data,
		  int silent)
{
    int minordevice=0;
    struct dentry *ddev;
    int error;
    
    NNPFSDEB(XDEBVFOPS, ("nnpfs_read_super starting\n"));
    NNPFSDEB(XDEBVFOPS, ("nnpfs_read_super: sb: %p data: %p silent: %d\n",
			 sb, data, silent));
    NNPFSDEB(XDEBVFOPS, ("nnpfs_read_super: %d:%d\n",
			 (int) MAJOR(sb->s_dev),
			 (int) MINOR(sb->s_dev)));
    
    NNPFSDEB(XDEBVFOPS, ("nnpfs_read_super: begin setting variables\n"));

    if (data != NULL) {
	struct nameidata nd;
	
	error = path_lookup(data, 0, &nd);
	if (error)
	    ddev = ERR_PTR(error);
	else
	    ddev = nd.path.dentry;

	if (!IS_ERR(ddev)) {
	    minordevice = MINOR(ddev->d_inode->i_rdev);
	    dput (ddev);

	    if (minordevice >= NNNPFS) {
		return NULL;
	    }
	}
    }

    nnpfs[minordevice].status |= NNPFS_MOUNTED;
    nnpfs[minordevice].sb = sb;
    nnpfs[minordevice].root = 0;
    sb->s_fs_info = &nnpfs[minordevice];
    sb->s_op = &nnpfs_sops;

    error = make_root(sb);
    if (error) {
	nnpfs[minordevice].status &= NNPFS_MOUNTED;
	nnpfs[minordevice].sb = NULL;
	nnpfs[minordevice].root = 0;
	return NULL;
    }

    sb->s_blocksize = 1024;
    sb->s_blocksize_bits = 10;
    sb->s_maxbytes = (1ULL<<63) - 1;

    NNPFSDEB(XDEBVFOPS, ("nnpfs_read_super: returning\n"));

    return sb;
}

static int
nnpfs_fill_super (struct super_block *sb, void *data, int silent)
{
    struct super_block *ret = nnpfs_read_super(sb, data, silent);
    if (ret == NULL)
        return -1; /* XXX */
    return 0;
}

int
nnpfs_get_sb(struct file_system_type *fs_type,
	     int flags, const char *dev_name,
	     void *data, struct vfsmount *mnt) 
{
    return get_sb_nodev(fs_type, flags, data, nnpfs_fill_super, mnt);
}

static void
nnpfs_write_super(struct super_block * sb)
{
    sb->s_dirt = 0;
}

/*
 * XXX is this good? 
 */

static void
nnpfs_put_super(struct super_block *sb)
{
    struct nnpfs *nnpfsp = VFS_TO_NNPFS(sb);
    NNPFSDEB(XDEBVFOPS, ("nnpfs_put_super starting\n"));
    nnpfsp->status &= ~NNPFS_MOUNTED;
    nnpfsp->status &= ~NNPFS_ROOTINSTALLED;
    sb->s_dev = 0;
    iput(nnpfsp->root);
    nnpfsp->root = NULL;
    NNPFSDEB(XDEBVFOPS, ("nnpfs_put_super exiting\n"));
}

static int
nnpfs_statfs_int(struct super_block *sb, struct kstatfs *buf)
{
    struct kstatfs tmp;
 
    tmp.f_type    = 0x47114711;
    tmp.f_bsize   = sb->s_blocksize;
    tmp.f_blocks  = 1024*1024*2;
    tmp.f_bfree   = 1024*1024*2-100;
    tmp.f_bavail  = 1024*1024*2-50;
    tmp.f_files   = 1024*1024;
    tmp.f_ffree   = 1024*1024-100;
    tmp.f_fsid.val[0] = 0;
    tmp.f_fsid.val[1] = 0;
    tmp.f_namelen = NAME_MAX;
    tmp.f_frsize  = 0;
    tmp.f_spare[0] = 0;
    tmp.f_spare[1] = 0;
    tmp.f_spare[2] = 0;
    tmp.f_spare[3] = 0;
    tmp.f_spare[4] = 0;
    *buf = tmp;
    return 0;
}

static int
nnpfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    return nnpfs_statfs_int(dentry->d_sb, buf);
}
