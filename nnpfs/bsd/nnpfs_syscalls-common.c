/*
 * Copyright (c) 1995 - 2010 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_syscalls-common.c,v 1.91 2010/08/08 19:58:27 tol Exp $");

/*
 * NNPFS system calls.
 */

#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_deb.h>

/* Misc syscalls */
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#elif defined(HAVE_SYS_IOCTL_H)
#include <sys/ioctl.h>
#endif
/*
 * XXX - horrible kludge.  If we are openbsd and not building an lkm,
 *     then use their headerfile.
 */
#if (defined(__OpenBSD__) || defined(__NetBSD__)) && !defined(_LKM)
#define NNPFS_NOT_LKM 1
#elif (defined(__FreeBSD__) || defined(__DragonFly__)) && !defined(KLD_MODULE)
#define NNPFS_NOT_LKM 1
#endif

#ifdef NNPFS_NOT_LKM
#include <nnpfs/nnpfs_pioctl.h>
#else
#include <arla-pioctl.h>
#endif

#if defined(__APPLE__)
/* XXX #define HAVE_SETPAG */
#elif defined(__NetBSD__) && __NetBSD_Version__ >= 399002000 /* NetBSD 3.99.20*/
#ifdef HAVE_SYS_KAUTH_H
# define HAVE_SETPAG
# define HAVE_KERNEL_KAUTH_CRED_NGROUPS
#endif
#else
#define HAVE_SETPAG
#endif

/*
 * NetBSD kauth(9) ignores the gmuid argument to
 * kauth_cred_setgroups(). The original Darwin implementation
 * doesn't. So, provide a filler on NetBSD.
 */
#ifdef HAVE_SYS_KAUTH_H
# ifdef __NetBSD__
#  ifndef KAUTH_UID_NONE
#   define KAUTH_UID_NONE 0
#  endif
# endif
#endif

#ifdef HAVE_SETPAG

int (*old_setgroups_func)(syscall_d_thread_t *p, void *v, register_t *retval);

#ifdef __DragonFly__
#define nnpfs_crcopy(cred) cratom(&(cred))
#elif defined(__FreeBSD__) && __FreeBSD_version >= 500026
/*
 * XXX This is wrong
 */
static struct ucred *
nnpfs_crcopy(struct ucred *cr)
{
    struct ucred *ncr;

    if (crshared(cr)) {
	ncr = crdup(cr);
	crfree(cr);
	return ncr;
    }
    return cr;
}
#else
#define nnpfs_crcopy crcopy
#endif

#endif /* HAVE_SETPAG */

#ifdef CAST_USER_ADDR_T
#define USER_ADDR_IN(addr)  CAST_USER_ADDR_T(addr)
#define USER_ADDR_OUT(addr) CAST_USER_ADDR_T(addr)
#else
#define USER_ADDR_IN(addr)  ((const char *)addr)
#define USER_ADDR_OUT(addr) ((char *)addr)
#endif

static int
nnpfs_pioctl_call(d_thread_t *proc, struct sys_pioctl_args *arg,
		  register_t *return_value);


/*
 * the syscall entry point
 */

#ifdef NNPFS_NOT_LKM
int
sys_nnpfspioctl(syscall_d_thread_t *proc, void *varg, register_t *return_value)
#else
int
nnpfspioctl(syscall_d_thread_t *proc, void *varg, register_t *return_value)
#endif
{
#ifdef NNPFS_NOT_LKM
    struct sys_nnpfspioctl_args *arg = (struct sys_nnpfspioctl_args *) varg;
#else
    struct sys_pioctl_args *arg = (struct sys_pioctl_args *) varg;
#endif
    int error = EINVAL;

    d_thread_t *p = syscall_thread_to_thread(proc);
    
    switch (SCARG(arg, operation)) {
    case arla_AFSCALL_PIOCTL:
	error = nnpfs_pioctl_call(p, varg, return_value);
	break;
    case arla_AFSCALL_SETPAG:
#if defined(HAVE_SETPAG)
 	error = nnpfs_setpag_call(&nnpfs_proc_to_cred(p));
#else
	error = EINVAL;
#endif
	break;
    default:
	NNPFSDEB(XDEBSYS, ("Unimplemeted nnpfspioctl: %d\n",
			   SCARG(arg, operation)));
	error = EINVAL;
	break;
    }

    return error;
}

#ifdef HAVE_SETPAG

/*
 * Def pag:
 *  33536 <= g0 <= 34560
 *  32512 <= g1 <= 48896
 */

#define NNPFS_PAG1_LLIM 33536
#define NNPFS_PAG1_ULIM 34560
#define NNPFS_PAG2_LLIM 32512
#define NNPFS_PAG2_ULIM 48896

static gid_t pag_part_one = NNPFS_PAG1_LLIM;
static gid_t pag_part_two = NNPFS_PAG2_LLIM;

/*
 * Is `cred' member of a PAG?
 */

static int
nnpfs_is_pag(nnpfs_kernel_cred cred)
{
    /* The first group is the gid of the user ? */

#ifndef HAVE_KERNEL_KAUTH_CRED_NGROUPS
    if (cred->cr_ngroups >= 3 &&
	cred->cr_groups[1] >= NNPFS_PAG1_LLIM &&
	cred->cr_groups[1] <= NNPFS_PAG1_ULIM &&
	cred->cr_groups[2] >= NNPFS_PAG2_LLIM &&
	cred->cr_groups[2] <= NNPFS_PAG2_ULIM)
	return 1;
#else
    if (kauth_cred_ngroups(cred) >= 3)
    {
         gid_t pag1, pag2;
	 pag1 = kauth_cred_group(cred, 1);
	 pag2 = kauth_cred_group(cred, 2);
         if (pag1 >= NNPFS_PAG1_LLIM &&
             pag1 <= NNPFS_PAG1_ULIM &&
             pag2 >= NNPFS_PAG2_LLIM &&
             pag2 <= NNPFS_PAG2_ULIM)
	     return 1;
    }
#endif

    return 0;
}
#endif /* HAVE_SETPAG */

/*
 * Return the pag used by `cred'
 */

nnpfs_pag_t
nnpfs_get_pag(nnpfs_kernel_cred cred)
{
#ifdef HAVE_SETPAG
    if (nnpfs_is_pag(cred))
#ifndef HAVE_SYS_KAUTH_H
	return (((cred->cr_groups[1] << 16) & 0xFFFF0000) |
		((cred->cr_groups[2] & 0x0000FFFF)));
#else
	return (((kauth_cred_group(cred, 1) << 16) & 0xFFFF0000) |
		((kauth_cred_group(cred, 2) & 0x0000FFFF)));
#endif
#endif

    return nnpfs_cred_get_uid(cred);
}

#ifdef HAVE_SETPAG
/*
 * Set the pag in `ret_cred' and return a new cred.
 */
static int
store_pag (nnpfs_kernel_cred *ret_cred, gid_t part1, gid_t part2)
{
#ifndef HAVE_SYS_KAUTH_H
    nnpfs_kernel_cred cred = *ret_cred;

    if (!nnpfs_is_pag (cred)) {
	int i;

	if (cred->cr_ngroups + 2 >= NGROUPS)
	    return E2BIG;

	cred = nnpfs_crcopy (cred);

	for (i = cred->cr_ngroups - 1; i > 0; i--) {
	    cred->cr_groups[i + 2] = cred->cr_groups[i];
	}
	cred->cr_ngroups += 2;
    } else {
	cred = nnpfs_crcopy (cred);
    }
    cred->cr_groups[1] = part1;
    cred->cr_groups[2] = part2;
    *ret_cred = cred;
#else
    nnpfs_kernel_cred *cred = ret_cred;
    gid_t groups[NGROUPS];
    u_int ngroups;
    int i;

    NNPFSDEB(XDEBSYS, ("store_pag: %d %d\n", part1, part2));

    ngroups = kauth_cred_ngroups(*cred);

    if (!nnpfs_is_pag (*cred)) { 
	if ( ngroups + 2 >= NGROUPS )
            return E2BIG;

        *cred = kauth_cred_copy(*cred);
	groups[0] = kauth_cred_group(*cred, 0);
        for (i = ngroups - 1; i > 0; i--) {
	    groups[i + 2] = kauth_cred_group(*cred, i);
	}
	// set pag gids later
	ngroups += 2;
    } else {
        *cred = kauth_cred_copy(*cred);
	for (i = 0; i < ngroups; i++)
	    groups[i] = kauth_cred_group(*cred, i);
    }

    groups[1] = part1;
    groups[2] = part2;

    kauth_cred_setgroups(*cred, groups, ngroups, KAUTH_UID_NONE);

    ret_cred = cred;
#endif
    return 0;
}

/*
 * Acquire a new pag in `ret_cred'
 */
int
nnpfs_setpag_call(nnpfs_kernel_cred *ret_cred)
{
    int ret;
    ret = store_pag (ret_cred, pag_part_one, pag_part_two++);

    if (ret)
	return ret;

    if (pag_part_two > NNPFS_PAG2_ULIM) {
	pag_part_one++;
	pag_part_two = NNPFS_PAG2_LLIM;
    }
    return 0;
}
#endif /* HAVE_SETPAG */

#if !defined(NNPFS_NOT_LKM) && defined(HAVE_SETPAG)
/*
 * remove a pag
 */

static int
nnpfs_unpag (nnpfs_kernel_cred cred)
{
#ifndef HAVE_SYS_KAUTH_H
    while (nnpfs_is_pag (cred)) {
	int i;

	for (i = 1; i < cred->cr_ngroups - 2; ++i)
	    cred->cr_groups[i] = cred->cr_groups[i+2];
	cred->cr_ngroups -= 2;
    }
#else
    while (nnpfs_is_pag (cred)) {
    	int i;
        u_int ngroups;
        gid_t groups[NGROUPS];

        ngroups = kauth_cred_ngroups(cred);
	for (i = 1; i < ngroups - 2; ++i)
	    groups[i] = kauth_cred_group(cred, i+2);
	ngroups -= 2;
        kauth_cred_setgroups(cred, groups, ngroups, KAUTH_UID_NONE);
    }
#endif

    return 0;
}

/*
 * A wrapper around setgroups that preserves the pag.
 */

int
nnpfs_setgroups (syscall_d_thread_t *p,
		 void *varg,
		 register_t *retval)
{
    struct nnpfs_setgroups_args *uap = (struct nnpfs_setgroups_args *)varg;
#ifdef HAVE_FREEBSD_THREAD
    nnpfs_kernel_cred *cred = &nnpfs_proc_to_cred(p);
#else
    nnpfs_kernel_cred *cred = &nnpfs_proc_to_cred(syscall_thread_to_thread(p));
#endif

    if (nnpfs_is_pag (*cred)) {
	gid_t part1, part2;
	int ret;

	if (SCARG(uap,gidsetsize) + 2 > NGROUPS)
	    return EINVAL;

#ifndef HAVE_SYS_KAUTH_H
	part1 = (*cred)->cr_groups[1];
	part2 = (*cred)->cr_groups[2];
#else
	part1 =  kauth_cred_group(*cred, 1);
	part2 =  kauth_cred_group(*cred, 2);
#endif
	ret = (*old_setgroups_func) (p, uap, retval);
	if (ret)
	    return ret;
	return store_pag (cred, part1, part2);
    } else {
	int ret;

	ret = (*old_setgroups_func) (p, uap, retval);
	/* don't support setting a PAG */
	if (nnpfs_is_pag (*cred)) {
	    nnpfs_unpag (*cred);
	    return EINVAL;
	}
	return ret;
    }
}
#endif /* !NNPFS_NOT_LKM && HAVE_SETPAG */

/*
 * Return the vnode corresponding to `pathptr'
 */

static int
lookup_node (const char *pathptr,
	     int follow_links_p,
	     struct vnode **res,
	     d_thread_t *proc)
{
    int error;
    char path[MAXPATHLEN];
    size_t count;

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall: looking up: %lx\n",
		       (unsigned long)pathptr));

    error = copyinstr(USER_ADDR_IN(pathptr), path, MAXPATHLEN, &count);

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall: looking up: %s, error: %d\n", path, error));

    if (error)
	return error;

#ifdef __APPLE__
    error = vnode_lookup(path, 0 /* flags */, res,
			 NULL /* XXX works but is "error" */);
    if (error) {
	NNPFSDEB(XDEBVFOPS, ("vnode_lookup failed, errno = %d\n", error));
	return error;
    }
#else
    {
	struct nameidata nd, *ndp = &nd;
	NDINIT(ndp, LOOKUP,
	       (follow_links_p ? FOLLOW : 0) | NNPFS_MPSAFE,
	       UIO_SYSSPACE, path, proc);
	
	error = namei(ndp);
	if (error != 0) {
	    NNPFSDEB(XDEBSYS, ("nnpfs_syscall: error during namei: %d\n", error));
	    return EINVAL;
	}
	*res = ndp->ni_vp;
    }
#endif

    return 0;
}

/*
 * Send the pioctl to arlad
 */

static int
remote_pioctl (d_thread_t* p,
	       struct sys_pioctl_args *arg,
	       struct arlaViceIoctl *vice_ioctl,
	       struct vnode *vp)
{
    int error;
    struct nnpfs_message_pioctl *msg = NULL;
    struct nnpfs_message_wakeup *msg2;
    nnpfs_kernel_cred cred = nnpfs_proc_to_cred(p);
    struct nnpfs *nnpfsp = &nnpfs_dev[0]; /* XXX */

    msg = malloc(sizeof(*msg), M_TEMP, M_WAITOK | M_ZERO);

    if (vp != NULL) {
	struct nnpfs_node *xn = VNODE_TO_XNODE(vp);

#ifdef __APPLE__
	if (xn == NULL || vfs_typenum(vnode_mount(vp)) != nnpfs_typenum) {
	    NNPFSDEB(XDEBSYS, ("nnpfs_syscall: file is not in afs\n"));
	    nnpfs_vletgo(vp);
	    error = EINVAL;
	    goto done;
	}
#else
	if (vp->v_tag != VT_AFS) {
	    NNPFSDEB(XDEBSYS, ("nnpfs_syscall: file is not in afs\n"));
	    nnpfs_vletgo(vp);
	    error = EINVAL;
	    goto done;
	}
#endif

	msg->handle = xn->handle;
	nnpfsp = NNPFS_FROM_VNODE(vp);
	nnpfs_vletgo(vp);
    }

    if (vice_ioctl->in_size < 0) {
	printf("nnpfs: remote pioctl: got a negative data size: opcode: %d",
	       SCARG(arg, a_opcode));
	error = EINVAL;
	goto done;
    }

    if (vice_ioctl->in_size > NNPFS_MSG_MAX_DATASIZE) {
	printf("nnpfs_pioctl_call: got a humongous in packet: opcode: %d",
	       SCARG(arg, a_opcode));
	error = EINVAL;
	goto done;
    }
    if (vice_ioctl->in_size != 0) {
	error = copyin(USER_ADDR_IN(vice_ioctl->in), msg->msg,
		       vice_ioctl->in_size);
	if (error)
	    goto done;
    }

    msg->header.opcode = NNPFS_MSG_PIOCTL;
    msg->header.size = sizeof(*msg);
    msg->opcode = SCARG(arg, a_opcode);

    msg->insize = vice_ioctl->in_size;
    msg->outsize = vice_ioctl->out_size;
    msg->cred.pag = nnpfs_get_pag(cred);

#if defined(HAVE_KERNEL_KAUTH_CRED_GETUID) || defined(__APPLE__)
    msg->cred.uid = nnpfs_cred_get_uid(cred);
#else
    msg->cred.uid = nnpfs_proc_to_euid(p);
#endif

    nnpfs_dev_lock(nnpfsp);
    error = nnpfs_message_rpc(nnpfsp, &msg->header, sizeof(*msg), p); 
    nnpfs_dev_unlock(nnpfsp);
    msg2 = (struct nnpfs_message_wakeup *) msg;

    if (error == 0)
	error = msg2->error;
    if (error == ENODEV)
	error = EINVAL;

    if (error == 0 && msg2->header.opcode == NNPFS_MSG_WAKEUP) {
	int len;

	len = msg2->len;
	if (len > vice_ioctl->out_size)
	    len = vice_ioctl->out_size;
	if (len > NNPFS_MSG_MAX_DATASIZE)
	    len = NNPFS_MSG_MAX_DATASIZE;
	if (len < 0)
	    len = 0;

	error = copyout(msg2->msg, USER_ADDR_OUT(vice_ioctl->out), len);
    }
 done:
    free(msg, M_TEMP);
    return error;
}

static int
nnpfs_debug (d_thread_t *p, struct arlaViceIoctl *vice_ioctl)
{
    int32_t flags;
    int error;

    if (vice_ioctl->in_size != 0) {
	if (vice_ioctl->in_size < sizeof(int32_t))
	    return EINVAL;
	
	error = nnpfs_priv_check_debug(p);
	if (error)
	    return error;

	error = copyin(USER_ADDR_IN(vice_ioctl->in),
		       &flags,
		       sizeof(flags));
	if (error)
	    return error;
	
	nnpfsdeb = flags;
    }
    
    if (vice_ioctl->out_size != 0) {
	if (vice_ioctl->out_size < sizeof(int32_t))
	    return EINVAL;
	
	error = copyout(&nnpfsdeb,
			USER_ADDR_OUT(vice_ioctl->out),
			sizeof(int32_t));
	if (error)
	    return error;
    }

    return 0;
}

/*
 * Handle `pioctl'
 */

static int
nnpfs_pioctl_call(d_thread_t *proc,
		  struct sys_pioctl_args *arg,
		  register_t *return_value)
{
    int error;
    struct arlaViceIoctl vice_ioctl;
    char *pathptr;
    struct vnode *vp = NULL;

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall(%d, %lx, %d, %lx, %d)\n", 
		       SCARG(arg, operation),
		       (unsigned long)SCARG(arg, a_pathP),
		       SCARG(arg, a_opcode),
		       (unsigned long)SCARG(arg, a_paramsP),
		       SCARG(arg, a_followSymlinks)));
    
    /* Copy in the data structure for us */
    error = copyin(USER_ADDR_IN(SCARG(arg, a_paramsP)),
		   &vice_ioctl, sizeof(vice_ioctl));
    if (error)
	return error;

    pathptr = SCARG(arg, a_pathP);

    if (pathptr != NULL) {
	error = lookup_node (pathptr, SCARG(arg, a_followSymlinks), &vp,
			     proc);
	if(error)
	    return error;
    }
	
    switch (SCARG(arg, a_opcode)) {
    case ARLA_VIOC_NNPFSDEBUG :
	if (vp != NULL)
	    nnpfs_vletgo(vp);
	return nnpfs_debug (proc, &vice_ioctl);
    default :
	NNPFSDEB(XDEBSYS, ("a_opcode = %x\n", SCARG(arg, a_opcode)));
	return remote_pioctl(proc, arg, &vice_ioctl, vp);
    }
}
