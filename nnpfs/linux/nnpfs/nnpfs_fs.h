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

#ifndef _nnpfs_h
#define _nnpfs_h

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>
#include <linux/types.h>

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */
struct nnpfs_link {
    struct nnpfs_link *prev, *next;
    struct nnpfs_message_header *message;
    u_int error_or_size;	/* error on sleepq and size on messageq */
    u_int woken;
    wait_queue_head_t wait_queue;
};  

/*
 * Filesystem struct.
 */
struct nnpfs {
    u_int status;		/* Inited, opened or mounted */
#define NNPFS_MOUNTED	0x1
#define NNPFS_DEVOPEN	0x2
#define NNPFS_ROOTINSTALLED 0x4
#define NNPFS_QUOTAWAIT 0x8
#define NNPFS_DEVWRITE 0x10
    struct super_block *sb;
    struct inode *root;
    u_int nnodes;
    
    /* protects lookups, inactive_list, also taken on NNPFS_DEVOPEN change */
    struct semaphore inactive_sem;
    struct list_head inactive_list;

    /* protects messageq, sleepq, nsequence, appendquota, message_buffer, status */
    struct semaphore channel_sem;
    struct nnpfs_link messageq;	/* Messages not yet read */
    struct nnpfs_link sleepq;	/* Waiting for reply message */
    u_int nsequence;
    uint64_t blocksize;
    int64_t appendquota;

    struct vfsmount *cacheroot; /* simplify open of cache blocks */
    struct dentry *cachedir;

    uid_t uid; /* keep track of daemon's identity */
    gid_t gid;

    struct {
	int recurse;
	struct task_struct *locker;
    } lock;

    wait_queue_head_t wait_queue;
    char *message_buffer;
};

#define VFS_TO_NNPFS(v)      ((struct nnpfs *) ((v)->s_fs_info))

#define NNPFS_FROM_VNODE(vp) VFS_TO_NNPFS((vp)->i_sb)
#define NNPFS_FROM_XNODE(xp) ((xp)->nnpfsp)

extern struct nnpfs nnpfs[];

extern struct vnodeops nnpfs_vnodeops;

int
nnpfs_node_find(struct nnpfs *nnpfsp, nnpfs_handle *handlep, 
		struct nnpfs_node **node);
int
nnpfs_node_find_gc(struct nnpfs *nnpfsp, nnpfs_handle *handlep, 
		   struct nnpfs_node **node);
struct inode *
nnpfs_node_add(struct nnpfs *nnpfsp, struct nnpfs_msg_node *node);
void nnpfs_node_rehash(struct nnpfs_node *node);
struct inode *
nnpfs_node_alloc(struct super_block *sb);
void nnpfs_node_free(struct inode *inode);
void nnpfs_node_clear (struct nnpfs_node *);

int nnpfs_has_pag(const struct nnpfs_node *xn, nnpfs_pag_t);

void nnpfs_force_invalid_node(struct nnpfs_node *xnode);
int  nnpfs_node_users(struct inode *inode);
void nnpfs_attr2inode(const struct nnpfs_attr *, struct inode *, int);
void nnpfs_inode2attr(struct inode *inode, struct nnpfs_attr *attr);
void nnpfs_iattr2attr(struct nnpfs_node *xn, const struct iattr *iattr,
		      struct nnpfs_attr *attr);
int nnpfs_setattr (struct dentry *inode, struct iattr *sb);

#endif /* _nnpfs_h */
