/*
 * Copyright (c) 1995 - 2003 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_common.h,v 1.33 2006/10/24 16:33:45 tol Exp $ */

#ifndef _nnpfs_common_h
#define _nnpfs_common_h

#define NNPFS_MEM_NONE		0
#define NNPFS_MEM_MSGBUF		1
#define NNPFS_MEM_SENDRPC		2
#define NNPFS_MEM_DENTRY		3
#define NNPFS_MEM_READDIR		4
#define NNPFS_MEM_FOLLOWLINK	5
#define NNPFS_MEM_XNODE		6
#define NNPFS_MEM_BLOCK		7

void *nnpfs_alloc (u_int size, unsigned int service);
void nnpfs_free (void *, unsigned int service);
void nnpfs_tell_alloc(void);
void nnpfs_print_sleep_queue(void);

extern struct inode_operations nnpfs_file_inode_operations,
                               nnpfs_dir_inode_operations,
                               nnpfs_link_inode_operations,
                               nnpfs_dead_inode_operations;

extern struct file_operations nnpfs_file_operations,
			      nnpfs_dead_operations,
			      nnpfs_dir_operations,
			      nnpfs_link_operations;

struct nnpfs_dentry_data {
    int xd_flags;
#define NNPFS_XD_ENTRY_VALID	1
#define NNPFS_XD_NAME_VALID	2
};

#define DENTRY_TO_XDENTRY(d) ((struct nnpfs_dentry_data *)((d)->d_fsdata))

int
nnpfs_d_init (struct dentry *dentry);

#define DENTRY_TO_INODE(x) ((x)->d_inode)

void nnpfs_print_aliases(const struct inode *inode);
void nnpfs_print_aliases_real(const struct inode *inode);
void nnpfs_print_children(const struct dentry *dentry);
void nnpfs_print_dentry(const struct dentry *dentry);

#endif /* _nnpfs_common_h */
