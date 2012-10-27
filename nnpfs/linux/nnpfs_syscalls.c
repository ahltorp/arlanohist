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
#include <nnpfs/nnpfs_dev.h>
#include <arla-pioctl.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_common.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>

#ifdef CONFIG_SECURITY
#include <linux/security.h>
#endif

#if 0
#ifdef CONFIG_COMPAT
#include <linux/ioctl32.h>
#define SYSCALLCOMPAT
#endif
#endif

#ifdef CONFIG_DEBUG_RODATA
#undef SYSCALLHACK
#endif

#undef NEED_VICEIOCTL32

#ifdef RCSID
RCSID("$Id: nnpfs_syscalls.c,v 1.125 2010/08/08 20:43:06 tol Exp $");
#endif

static struct proc_dir_entry *nnpfs_procfs_dir;

#define ARLA_VIOC_SYSCALL _IOW('C',1,void *)
#define ARLA_VIOC_SYSCALL32 _IOW('C',1,u32)
#define NNPFS_PROC_DIR "nnpfs"
#define NNPFS_PROC_NODE "afs_ioctl"
 
typedef struct afsprocdata {
    unsigned long param4;
    unsigned long param3;
    unsigned long param2;
    unsigned long param1;
    unsigned long syscall;
} afsprocdata;

static int
nnpfs_procfs_ioctl(struct inode *inode, struct file *file,
		   unsigned int cmd, unsigned long arg);

static struct file_operations nnpfs_procfs_fops = {
    .ioctl = nnpfs_procfs_ioctl,
};


#ifdef SYSCALLHACK
typedef asmlinkage long (*sys_afs_function)(int operation,
					    char *a_pathP,
					    int a_opcode,
					    struct arlaViceIoctl *a_paramsP,
					    int a_followSymlinks);

typedef asmlinkage long (*sys_setgroups_function)(int, gid_t *);

#ifdef ARLA_NR_setgroups16
typedef int (*sys_setgroups16_function)(int, old_gid_t *);
#endif

extern nnpfs_sys_call_function *nnpfs_sys_call_table;
#ifdef NEED_VICEIOCTL32
extern uint32_t *sys_call_table32;
#endif

static nnpfs_sys_call_function old_afs_syscall = NULL;
#ifdef NEED_VICEIOCTL32
static uint32_t old_afs_syscall32=0;
#endif

static nnpfs_sys_call_function old_setgroups = NULL;

#ifdef ARLA_NR_setgroups16
static nnpfs_sys_call_function old_setgroups16 = NULL;
#endif
#endif /* SYSCALLHACK */

#if defined(SYSCALLHACK) || defined(CONFIG_SECURITY)
static int nnpfs_sec_registered = 0;
#endif

/*
 * Valid PAGs are [NNPFS_PAG_LLIM, NNPFS_PAG_ULIM).
 * Use the same PAG range as when using 16-bit gids
 * and stay out of the PTS ID range [0, 0x80000000).
 */
#define NNPFS_PAG_LLIM 0x83007F00
#define NNPFS_PAG_ULIM 0x8700BF00
#define NNPFS_PAG_NOTFOUND NNPFS_PAG_ULIM

#ifdef CONFIG_SECURITY

/*
 * simple implementation, store pag in current->security
 * XXX should be malloced, refcounted etc.
 *
 * this depends on us being able to register as primary LSM
 * fallback on group list version
 */

#define SEC2PAG(s) (nnpfs_pag_t)(unsigned long)(s)
#define PAG2SEC(p) (void *)(unsigned long)(p)

static nnpfs_pag_t
nnpfs_get_pag_sec(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    nnpfs_pag_t pag = SEC2PAG(current->security);
#else
    nnpfs_pag_t pag = SEC2PAG(current_security());
#endif
    if (pag)
	return pag;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    return current->uid;
#else
    return current_uid();
#endif
}

static int
nnpfs_set_pag_sec(void)
{
    static nnpfs_pag_t pagnum = NNPFS_PAG_LLIM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
    struct cred *cred;
#endif

    if (pagnum == NNPFS_PAG_ULIM)
	return -ENOMEM;
    /* pagnum = NNPFS_PAG_LLIM; */
    
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    current->security = PAG2SEC(pagnum);
#else
    cred = (struct cred *) current->cred;
    cred->security = PAG2SEC(pagnum);
#endif
    pagnum++;
    return 0;
}

#endif /* CONFIG_SECURITY */

#ifdef GROUPPAGS
/* find pag index in group list, or return NNPFS_PAG_NOTFOUND */
static int
find_pag(struct group_info *gi)
{
    int i;

    NNPFSDEB(XDEBSYS, ("find_pag: ngroups = %d\n", gi->ngroups));

    for (i = gi->ngroups - 1; i >= 0; i--) {
	gid_t group = GROUP_AT(gi, i);
	if ((nnpfs_pag_t)group >= NNPFS_PAG_LLIM && (nnpfs_pag_t)group < NNPFS_PAG_ULIM) {
	    NNPFSDEB(XDEBSYS,
		     ("find_pag: Existing pag %u at pos %u\n", group, i));
	    return i;
	}
    }

    NNPFSDEB(XDEBSYS, ("find_pag: Did not find pag\n"));

    return NNPFS_PAG_NOTFOUND;
}

static nnpfs_pag_t
nnpfs_get_pag_group(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    struct group_info *gi = current->group_info;
    nnpfs_pag_t ret = current->uid;
#else
    struct group_info *gi = get_current_groups();
    nnpfs_pag_t ret = current_uid();
#endif
    int i;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    get_group_info(gi);
#endif

    i = find_pag(gi);
    if (i != NNPFS_PAG_NOTFOUND)
	ret = GROUP_AT(gi, i);

    put_group_info(gi);

    NNPFSDEB(XDEBSYS, ("nnpfs_get_pag_group: returning %u\n", ret));
    return ret;
}

/* store pag. returning !0 means state is unchanged */
static int
store_pag(nnpfs_pag_t pagnum)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    struct group_info *old_gi = current->group_info;
#else
   struct group_info *old_gi = get_current_groups();
#endif
    struct group_info *new_gi;
    unsigned int nblocks, count;
    int found = 0;
    int i, k;
    
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)    
    get_group_info(old_gi);
#endif

    i = find_pag(old_gi);
    if (i != NNPFS_PAG_NOTFOUND)
	found = 1;

    nblocks = old_gi->nblocks;
    count = old_gi->ngroups;

    if (count >= NGROUPS_MAX) {
	put_group_info(old_gi);
	return -EINVAL;
    }

    new_gi = groups_alloc(count + (found ? 0 : 1));
    if (!new_gi) {
	put_group_info(old_gi);
	return -ENOMEM;
    }

    for (k = 0; k < nblocks; k++) {
	memcpy(new_gi->blocks[k], old_gi->blocks[k], 
	       min(NGROUPS_PER_BLOCK,count) * sizeof(gid_t));
	count -= NGROUPS_PER_BLOCK;
    }

    if (found)
	GROUP_AT(new_gi, i) = pagnum;
    else
	GROUP_AT(new_gi, new_gi->ngroups - 1) = pagnum;
    
    set_current_groups(new_gi);
    put_group_info(new_gi);
    put_group_info(old_gi);
    return 0;
}

static int
nnpfs_set_pag_group(void)
{
    static gid_t pagnum = NNPFS_PAG_LLIM;
    int ret;

    if (pagnum == NNPFS_PAG_ULIM)
	return -ENOMEM;
    /* pagnum = NNPFS_PAG_LLIM; */
    
    ret = store_pag(pagnum);
    if (ret == 0)
	pagnum++;
    else
	NNPFSDEB(XDEBSYS, ("nnpfs_set_pag_group: returning %u\n", ret));

    return ret;
}
#endif /* GROUPPAGS */

nnpfs_pag_t
nnpfs_get_pag()
{
#ifdef CONFIG_SECURITY
    if (nnpfs_sec_registered)
	return nnpfs_get_pag_sec();
#endif /* !CONFIG_SECURITY */

#ifdef GROUPPAGS
    return nnpfs_get_pag_group();
#endif /* GROUPPAGS */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    return current->uid;
#else
    return current_uid();
#endif
}

static inline int
nnpfs_setpag_call(void)
{
#ifdef CONFIG_SECURITY
    if (nnpfs_sec_registered)
	return nnpfs_set_pag_sec();
#endif /* !CONFIG_SECURITY */

#ifdef GROUPPAGS
    return nnpfs_set_pag_group();
#endif /* GROUPPAGS */

    return -EINVAL;
}

#ifdef GROUPPAGS
#ifdef SYSCALLHACK
/*
 * A wrapper around sys_setgroups that tries to preserve the pag.
 */
static asmlinkage long
nnpfs_setgroups (int gidsetsize, gid_t __user *usergrouplist)
{
    sys_setgroups_function setgroups = (sys_setgroups_function)old_setgroups;
    nnpfs_pag_t current_pag = nnpfs_get_pag();
    gid_t grouplist[NGROUPS_SMALL];
    int i, n, offset;
    int pag_in_orig = 0;
    int pag_in_new = 0;
    long ret;

    if (current_pag >= NNPFS_PAG_LLIM && current_pag < NNPFS_PAG_ULIM)
	pag_in_orig = 1;

    for (offset = 0; offset < gidsetsize; offset += NGROUPS_SMALL) {
	n = min(gidsetsize - offset, NGROUPS_SMALL);
	if (copy_from_user(grouplist, usergrouplist + offset,
			   n * sizeof(gid_t)))
	    return -EFAULT;

	/* scan grouplist, return -EINVAL if fake PAG is included */
	for  (i = 0; i < n; i++) {
	    if (grouplist[i] == current_pag)
		pag_in_new = 1;
	    else 
		if ((nnpfs_pag_t)(grouplist[i]) >= NNPFS_PAG_LLIM
		    && (nnpfs_pag_t)(grouplist[i]) <= NNPFS_PAG_ULIM)
		    return -EINVAL; /* User fakes pag attempt */
	}
    }

    ret = (*setgroups) (gidsetsize, usergrouplist);

    if (ret == 0 && pag_in_orig && !pag_in_new)
	store_pag(current_pag);

    return ret;
}

#ifdef ARLA_NR_setgroups16

/*
 * Linux 2.3.39 and above has 2 setgroups() system calls on arm, i386,
 * m68k, sh, and sparc32. We call the old one setgroups16() because it
 * uses a 16-bit gid_t (old_gid_t).
 * We need to fix it up too.
 */

static asmlinkage long
nnpfs_setgroups16 (int gidsetsize, old_gid_t *grouplist)
{
    /* We don't like 16-bit gids anyway */
    return -EINVAL;
}

#if 0
/* This is not in sync with setgroups() above */
static asmlinkage long
nnpfs_setgroups16 (int gidsetsize, old_gid_t *grouplist)
{

    sys_setgroups16_function setgroups16 = (sys_setgroups16_function)old_setgroups16;
    nnpfs_pag_t current_pag = nnpfs_get_pag();
    long ret;
    int pag_in_orig = 0;
    
    if (current_pag >= NNPFS_PAG_LLIM && current_pag < NNPFS_PAG_ULIM)
	pag_in_orig = 1;

    /* all 16-bit values, won't look like a PAG */
    ret = (*setgroups16) (gidsetsize, grouplist);

    if (pag_in_orig && nnpfs_get_pag() != current_pag)
	store_pag(current_pag);

    return ret;
}
#endif /* 0 */
#endif /* ARLA_NR_setgroups16 */
#endif /* SYSCALLHACK */
#endif /* GROUPPAGS */

struct file_handle {
    nnpfs_dev_t dev;
    ino_t inode;
    __u32 gen;
};

static int
nnpfs_debug (struct arlaViceIoctl *vice_ioctl)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    if (vice_ioctl->in_size != 0) {
	int32_t tmp;

	if (vice_ioctl->in_size < sizeof(int32_t))
	    return -EINVAL;
	
	if (copy_from_user (&tmp,
			    vice_ioctl->in,
			    sizeof(tmp)) != 0)
	    return -EFAULT;

	nnpfsdeb = tmp;
    }

    if (vice_ioctl->out_size != 0) {
	int32_t tmp = nnpfsdeb;

	if (vice_ioctl->out_size < sizeof(int32_t))
	    return -EINVAL;
	
	if (copy_to_user (vice_ioctl->out,
			  &tmp,
			  sizeof(tmp)) != 0)
	    return -EFAULT;
    }

    return 0;
}

static int
nnpfs_debug_print (struct arlaViceIoctl *vice_ioctl, struct dentry *node)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    if (vice_ioctl->in_size != 0) {
	int32_t tmp;

	if (vice_ioctl->in_size < sizeof(int32_t))
	    return -EINVAL;
	
	if (copy_from_user (&tmp,
			    vice_ioctl->in,
			    sizeof(tmp)) != 0)
	    return -EFAULT;

	switch (tmp) {
	case XDEBMEM:
	    nnpfs_tell_alloc();
	    return 0;
	case XDEBMSG:
	    nnpfs_print_sleep_queue();
	    return 0;
	case XDEBNODE:
	    if (node) {
		nnpfs_print_dentry(node);
		nnpfs_print_aliases(node->d_inode);
		nnpfs_print_children(node);
	    } else {
		nnpfs_print_nodestats(&nnpfs[0]);
	    }
	    return 0;
	default:
	    return -EINVAL;
	}
    }

    return 0;
}

/*
 * convert the path `user_path' (in user memory) into an dentry.
 * follow symlinks iff `follow'
 */

static struct dentry *
user_path2dentry (struct nameidata *nd, char *user_path, int follow)
{
    char *kname;
    int flags = 0;
    int error = 0;

    kname = getname (user_path);
    if (IS_ERR(kname))
	return ERR_PTR(PTR_ERR(kname));
    if (follow)
	flags |= LOOKUP_FOLLOW;

    NNPFSDEB(XDEBMSG, ("nnpfs_syscall: looking up: %s\n", kname));

    error = path_lookup(kname, flags, nd);
    putname(kname);
    if (error)
	return ERR_PTR(error);
    return nd->path.dentry;
}

asmlinkage long
sys_afs_int (int operation,
	     char *a_pathP,
	     int a_opcode,
	     struct arlaViceIoctl *a_paramsP,
	     int a_followSymlinks)
{
    long error = 0;
    struct arlaViceIoctl vice_ioctl; 
    struct nnpfs_message_pioctl *msg = NULL;
    struct nnpfs_message_wakeup *msg2;
    struct dentry *dentry = NULL;
    struct nameidata nd;
    
    msg = kmalloc(sizeof(*msg), GFP_KERNEL);
    if (msg == NULL)
      return -ENOMEM;

    lock_kernel();

    NNPFSDEB(XDEBSYS, ("sys_afs kernel locked\n"));

    NNPFSDEB(XDEBSYS, ("sys_afs operation: %d "
		       "a_opcode: %d a_paramsP: %p "
		       "a_followSymlinks: %d\n",
		       operation, a_opcode,
		       a_paramsP, a_followSymlinks));
    
    switch (operation) {
    case arla_AFSCALL_PIOCTL:
	NNPFSDEB(XDEBSYS, ("nnpfs_pioctl\n"));
	memcpy(&vice_ioctl,a_paramsP,sizeof(*a_paramsP));

	if (((int)vice_ioctl.in_size) < 0) {
	    printk(KERN_EMERG 
		   "nnpfs: remote pioctl: got a negative data size: opcode: %d",
		   a_opcode);
	    error = -EINVAL;
	    goto unlock;
	}
	if (vice_ioctl.in_size > NNPFS_MSG_MAX_DATASIZE) {
	    printk(KERN_EMERG
		   "nnpfs_pioctl_call: got a humongous in packet: opcode: %d",
		   a_opcode);
	    error = -EINVAL;
	    goto unlock;
	}
	if (vice_ioctl.in_size != 0) {
	    if(copy_from_user(&msg->msg,
			      vice_ioctl.in,
			      vice_ioctl.in_size) != 0) {
		error = -EFAULT;
		goto unlock;
	    }
	}
	if (a_pathP != NULL) {
	    dentry = user_path2dentry (&nd, a_pathP, a_followSymlinks);
	    if (!dentry) {
		error = -EINVAL;
		goto unlock;
	    }
	    if (IS_ERR(dentry)) {
		NNPFSDEB(XDEBMSG, ("nnpfs_syscall: error during namei: %ld\n",
				 PTR_ERR(dentry)));
		error = PTR_ERR(dentry);
		dentry = NULL;
		goto unlock;
	    }
	    NNPFSDEB(XDEBMSG,("nnpfs_syscall: inode: %p inodenum: %lx\n",
			    dentry->d_inode, dentry->d_inode->i_ino));
	}

	switch (a_opcode) {
	case ARLA_VIOC_NNPFSDEBUG:
#ifdef ARLA_VIOC_NNPFSDEBUG_32
	case ARLA_VIOC_NNPFSDEBUG_32:
#endif
	    error = nnpfs_debug (&vice_ioctl);
	    goto unlock;
	case ARLA_VIOC_NNPFSDEBUG_PRINT:
#ifdef ARLA_VIOC_NNPFSDEBUG_PRINT_32
	case ARLA_VIOC_NNPFSDEBUG_PRINT_32:
#endif
	    error = nnpfs_debug_print (&vice_ioctl, dentry);
	    goto unlock;
	}

	if (dentry != NULL) {
	    struct nnpfs_node *xn;
	    if (strcmp(DENTRY_TO_INODE(dentry)->i_sb->s_type->name,
		       "nnpfs") != 0) {
		NNPFSDEB(XDEBMSG, ("nnpfs_syscall: not in afs\n"));
		error = -EINVAL;
		goto unlock;
	    }
	    xn = VNODE_TO_XNODE(DENTRY_TO_INODE(dentry));
	    if (xn == NULL) {
		NNPFSDEB(XDEBMSG, ("nnpfs_syscall: is an nnpfs dentry, but has no xnode\n"));
		error = -EINVAL;
		goto unlock;
	    }
	    msg->handle = xn->handle;
	}

	msg->header.opcode = NNPFS_MSG_PIOCTL;
	msg->opcode = a_opcode;
	
	msg->insize   = vice_ioctl.in_size;
	msg->outsize  = vice_ioctl.out_size;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg->cred.uid = current->uid;
#else
        msg->cred.uid = current_uid();
#endif
	msg->cred.pag = nnpfs_get_pag();
	
	error = nnpfs_message_rpc(&nnpfs[0], &msg->header, sizeof(*msg)); /* XXX */
	msg2 = (struct nnpfs_message_wakeup *) msg;
	if (error == 0)
	    error = msg2->error;

	if (error == -ENODEV)
	    error = -EINVAL;

	if (error == 0 && msg2->header.opcode == NNPFS_MSG_WAKEUP) {
	    if (((int)vice_ioctl.out_size) < 0)
		msg2->len = 0;
	    else if (msg2->len > vice_ioctl.out_size)
		msg2->len = vice_ioctl.out_size;

	    if(copy_to_user(vice_ioctl.out, msg2->msg, msg2->len) != 0) {
		NNPFSDEB(XDEBSYS, ("nnpfs_syscall copy_to_user "
				 "vice_ioctl.out: %p msg2->msg: %p "
				 "msg2->len: %d vice_ioctl.out_size: %d\n",
				 vice_ioctl.out, msg2->msg,
				 msg2->len, vice_ioctl.out_size));
		error = -EFAULT;
	    }
	}

	break;
    case arla_AFSCALL_SETPAG:
	error = nnpfs_setpag_call();
	break;
    default:
	NNPFSDEB(XDEBSYS, ("nnpfs_syscalls: unimplemented call\n"));
	error = -EINVAL;
	break;
    }
    
 unlock:
    if (dentry)
	path_put(&nd.path);

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall returns error: %ld\n", error));

    NNPFSDEB(XDEBSYS, ("sys_afs kernel unlock\n"));
    kfree(msg);
    unlock_kernel();

    return error;
}

#if defined SYSCALLCOMPAT || (defined SYSCALLHACK && defined NEED_VICEIOCTL32)
asmlinkage long
sys32_afs (int operation,
	   char *a_pathP,
	   int a_opcode,
	   struct ViceIoctl32 *a_paramsP,
	   int a_followSymlinks)
{
    struct arlaViceIoctl vice_ioctl;
    struct ViceIoctl32 vice_ioctl32;

    if (operation == arla_AFSCALL_PIOCTL) {
	if(copy_from_user(&vice_ioctl32, a_paramsP, sizeof(*a_paramsP)) != 0)
	    return -EFAULT;

	vice_ioctl.in = (caddr_t) (uint64_t) vice_ioctl32.in;
	vice_ioctl.out = (caddr_t) (uint64_t) vice_ioctl32.out;
	vice_ioctl.in_size = vice_ioctl32.in_size;
	vice_ioctl.out_size = vice_ioctl32.out_size;
    }

    return sys_afs_int(operation, a_pathP, a_opcode, &vice_ioctl,
		       a_followSymlinks);
}
#endif

asmlinkage long
sys_afs (int operation,
	 char *a_pathP,
	 int a_opcode,
	 struct arlaViceIoctl *a_paramsP,
	 int a_followSymlinks)
{
    struct arlaViceIoctl vice_ioctl;

    if (operation == arla_AFSCALL_PIOCTL) {
	if(copy_from_user(&vice_ioctl, a_paramsP, sizeof(*a_paramsP)) != 0)
	    return -EFAULT;
    }

    return sys_afs_int(operation, a_pathP, a_opcode, &vice_ioctl,
		       a_followSymlinks);
}

static int
nnpfs_procfs_ioctl(struct inode *inode, struct file *file,
		   unsigned int cmd, unsigned long arg)
{
    afsprocdata args;
    long ret;

    if (cmd != ARLA_VIOC_SYSCALL)
	return -EINVAL;

    if (copy_from_user(&args, (void *)arg, sizeof(args)))
	return -EFAULT;
    
    ret = sys_afs((int)args.syscall,
		  (char *)args.param1, (int)args.param2,
		  (struct arlaViceIoctl *)args.param3, (int)args.param4);
    return ret;
}

#ifdef SYSCALLCOMPAT
typedef struct afsprocdata32 {
    u32 param4;
    u32 param3;
    u32 param2;
    u32 param1;
    u32 syscall;
} afsprocdata32;

static int
nnpfs_procfs_ioctl32(unsigned int fd, unsigned int cmd, unsigned long arg,
		     struct file *file) {
    afsprocdata32 args;
    long ret;

    if (cmd != ARLA_VIOC_SYSCALL32)
	return -EINVAL;

    if (copy_from_user(&args, (void *)arg, sizeof(args)))
	return -EFAULT;
    
    ret = sys32_afs((int)args.syscall,
		    (char *)(long)args.param1, (int)args.param2,
		    (struct ViceIoctl32 *)(long)args.param3, (int)args.param4);
    return ret;
}
#endif /* SYSCALLCOMPAT */

static int nnpfs_init_procfs(void)
{
    struct proc_dir_entry *entry;
    
    nnpfs_procfs_dir = proc_mkdir("fs/" NNPFS_PROC_DIR, NULL);
    if (nnpfs_procfs_dir == NULL)
	return -ENOMEM;
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    nnpfs_procfs_dir->owner = THIS_MODULE;
#endif
    
    entry = create_proc_entry(NNPFS_PROC_NODE, 0666, nnpfs_procfs_dir);
    if (entry == NULL) {
	NNPFSDEB(XDEBSYS, ("nnpfs_init_procfs: no node\n"));
	remove_proc_entry("fs/" NNPFS_PROC_DIR, NULL);
	return -ENOMEM;
    }
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    entry->owner = THIS_MODULE;
#endif
    entry->proc_fops = &nnpfs_procfs_fops;

#ifdef SYSCALLCOMPAT
    if (register_ioctl32_conversion(ARLA_VIOC_SYSCALL32, nnpfs_procfs_ioctl32)) {
	printk(KERN_EMERG "nnpfs_init_procfs: unable to register ioctl32\n");
    }
#endif /* SYSCALLCOMPAT */
    
    NNPFSDEB(XDEBSYS, ("nnpfs_init_procfs: success\n"));

    return 0;
}

static void nnpfs_exit_procfs(void)
{
#ifdef SYSCALLCOMPAT
    if (unregister_ioctl32_conversion(ARLA_VIOC_SYSCALL32)) {
	printk(KERN_EMERG "nnpfs_exit_procfs: error unregistering ioctl32\n");
    }
#endif /* SYSCALLCOMPAT */
    remove_proc_entry(NNPFS_PROC_NODE, nnpfs_procfs_dir);
    remove_proc_entry("fs/" NNPFS_PROC_DIR, NULL);
}

#ifdef GROUPPAGS
#ifdef SYSCALLHACK
static void
install_setgroups(void)
{
    old_setgroups = nnpfs_sys_call_table[ARLA_NR_setgroups];
    nnpfs_sys_call_table[ARLA_NR_setgroups] = 
	(nnpfs_sys_call_function)&nnpfs_setgroups;
#ifdef ARLA_NR_setgroups16
    old_setgroups16 = nnpfs_sys_call_table[ARLA_NR_setgroups16];
    nnpfs_sys_call_table[ARLA_NR_setgroups16] = 
	(nnpfs_sys_call_function)&nnpfs_setgroups16;
#endif
}
#endif /* SYSCALLHACK */
#endif /* GROUPPAGS */


void
install_afs_syscall(void)
{
    nnpfs_init_procfs();

#ifdef SYSCALLHACK
    if (nnpfs_fixup_syscall_lossage()) {
	NNPFSDEB(XDEBSYS,
		 ("install_afs_syscall: no syscalltable found\n"));
	return;
    }

    if (!nnpfs_sec_registered)
	install_setgroups();	

    old_afs_syscall = nnpfs_sys_call_table[__NR_afs_syscall];
    nnpfs_sys_call_table[__NR_afs_syscall] = 
	(nnpfs_sys_call_function)&sys_afs;
#ifdef NEED_VICEIOCTL32
    old_afs_syscall32 = sys_call_table32[__NR_afs_syscall];
    sys_call_table32[__NR_afs_syscall] = (uint32_t)&sys32_afs;
#endif
#endif /* SYSCALLHACK */
}

void
restore_afs_syscall (void)
{
    nnpfs_exit_procfs();

#ifdef SYSCALLHACK
    if (old_afs_syscall) {
	nnpfs_sys_call_table[__NR_afs_syscall] = old_afs_syscall;
	old_afs_syscall = NULL;
    }
#ifdef NEED_VICEIOCTL32
    if (old_afs_syscall32) {
	sys_call_table32[__NR_afs_syscall] = old_afs_syscall32;
	old_afs_syscall32 = 0;
    }
#endif
#endif /* SYSCALLHACK */

#ifdef GROUPPAGS
#ifdef SYSCALLHACK
    if (old_setgroups) {
	nnpfs_sys_call_table[ARLA_NR_setgroups] = old_setgroups;
	old_setgroups = NULL;
    }
#ifdef ARLA_NR_setgroups16
    if (old_setgroups16) {
	nnpfs_sys_call_table[ARLA_NR_setgroups16] = old_setgroups16;
	old_setgroups16 = NULL;
    }
#endif
#endif /* SYSCALLHACK */
#endif /* GROUPPAGS */
}
