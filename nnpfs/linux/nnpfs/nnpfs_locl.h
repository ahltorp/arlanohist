/*
 * Copyright (c) 1995 - 2004 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_locl.h,v 1.78 2010/08/08 20:43:06 tol Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <asm/current.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <linux/wait.h>

/*
 * Linux 2.3.39 and above has a new setgroups() system call for
 * 32-bit UIDs, on arm, i386, m68k, sh, and sparc32. The old system call
 * also has to be handled properly, with a different type for gid_t.
 * See nnpfs_syscalls.c for more information.
 */

#include <asm/unistd.h>

#ifdef __NR_setgroups32
#define ARLA_NR_setgroups	__NR_setgroups32

/*
 * For the time being Linux 2.3/2.4 will call the old 16-bit uid
 * setgroups() __NR_setgroups; at some point in the future it may go away,
 * so we put this ifdef here
 */
#ifdef __NR_setgroups
#define ARLA_NR_setgroups16	__NR_setgroups
#endif

#else
#define ARLA_NR_setgroups	__NR_setgroups
#endif

#include <asm/uaccess.h>

/* 
 * The people at FSF seems to think that user program
 * should include /usr/include/{,sys} and the kernel
 * should have their own include files.
 *
 * That seems ok to me, but then we don't get the int23_t & friends
 * from userland. And in kernelspace it seems that we should use 
 * __{s,u}32, and that seems silly, so we typedef them ourself.
 * It's the same thing with MAXPATHLEN that is named PATH_MAX in 
 * the kernel.
 *
 * Thank you to N.N for pointing this out.
 */

#ifdef HAVE_GLIBC

#ifndef HAVE_LINUX_KERNEL_INT8_T
typedef __s8     int8_t;
#endif
#ifndef HAVE_LINUX_KERNEL_UINT8_T
typedef __u8   uint8_t;
#endif
#ifndef HAVE_LINUX_KERNEL_INT16_T
typedef __s16    int16_t;
#endif
#ifndef HAVE_LINUX_KERNEL_UINT16_T
typedef __u16  uint16_t;
#endif
#ifndef HAVE_LINUX_KERNEL_INT32_T
typedef __s32    int32_t;
#endif
#ifndef HAVE_LINUX_KERNEL_UINT32_T
typedef __u32  uint32_t;
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN PATH_MAX 
#endif

#endif

#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_deb.h>


/* A panic() suitable for testing scenarios */
#if 0
#define nnpfs_debug_oops() BUG()
#else
#define nnpfs_debug_oops() do { ; } while (0)
#endif

int
nnpfs_fetch_root(struct inode *i);

int
nnpfs_get_sb(struct file_system_type *fs_type,
	     int flags, const char *dev_name,
	     void *data, struct vfsmount *mnt);

extern struct dentry_operations nnpfs_dentry_operations;

/*
 * i_blocks should apparently always be returned in 512-bytes units
 */

#define I_BLOCKS_UNIT 512

#define I_BLOCKS_BITS 9

/*
 * Help function to read the inode->i_count a portable way
 */

static inline int
nnpfs_icount (struct inode *inode)
{
    return atomic_read(&inode->i_count);
}

/*
 * Help functions to manipulate inode->i_count
 */

static inline void
nnpfs_iref (struct inode *inode)
{
    atomic_inc(&inode->i_count);
}

static inline void
nnpfs_irele (struct inode *inode)
{
    atomic_dec(&inode->i_count);
}


/*
 * Help function to read the inode->i_writecount a portable way
 */

static inline int
nnpfs_iwritecount (struct inode *inode)
{
    return atomic_read(&inode->i_writecount);
}

/*
 * Help function to read the dentry->d_count a portable way
 */

static inline int
nnpfs_dcount (const struct dentry *dentry)
{
    return atomic_read(&dentry->d_count);
}

extern 
const
struct address_space_operations nnpfs_aops;

#ifndef list_for_each
#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)
#endif /* list_for_each */


#ifndef list_for_each_safe
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#endif

#if !defined(HAVE_INIT_MUTEX) && !defined(init_MUTEX)
#define init_MUTEX(m)	*(m) = MUTEX
#endif

typedef asmlinkage long (*nnpfs_sys_call_function)(void);

int
nnpfs_fixup_syscall_lossage(void);

#ifndef I_DIRTY_DATASYNC
#define I_DIRTY_DATASYNC 0
#endif

#define nnpfs_dev_t dev_t
#define nnpfs_d_entry_unhashed(d) hlist_unhashed(d)

#define NNPFS_NOOP      while(0){}

#define NNPFS_SET_TIME(timeunit, sec) \
    ((timeunit).tv_sec = (sec), (timeunit).tv_nsec = 0)
#define NNPFS_GET_TIME_SEC(timeunit) ((timeunit).tv_sec)

#define NNPFS_MSG_WAKEUP_ERROR(m) \
	(((struct nnpfs_message_wakeup *)(void *)m)->error)

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
