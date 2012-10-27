/*
 * Copyright (c) 1995 - 2001 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_syscalls.c,v 1.33 2002/09/07 10:47:41 lha Exp $");

/*
 * NNPFS system calls.
 */

#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>

/* Misc syscalls */
#include <kafs.h>

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

int
nnpfs_is_pag(struct cred *cred)
{
    /* The first group is the gid of the user ? */

    if (cred->cr_ngroups >= 3 &&
	cred->cr_groups[1] >= NNPFS_PAG1_LLIM &&
	cred->cr_groups[1] <= NNPFS_PAG1_ULIM &&
	cred->cr_groups[2] >= NNPFS_PAG2_LLIM &&
	cred->cr_groups[2] <= NNPFS_PAG2_ULIM)
	return 1;
    else
	return 0;
}

nnpfs_pag_t
nnpfs_get_pag(struct cred * cred)
{
    if (nnpfs_is_pag(cred)) {

	return (((cred->cr_groups[1] << 16) & 0xFFFF0000) |
		((cred->cr_groups[2] & 0x0000FFFF)));

    } else
	return cred->cr_uid;	       /* XXX */
}

/*
 * Set the pag in `ret_cred'.
 */

static int
store_pag (struct cred **ret_cred, gid_t part1, gid_t part2)
{
    struct cred *cred = *ret_cred;

    if (!nnpfs_is_pag(cred)) {
	int i;

	/* Check if it fits */
	if (cred->cr_ngroups + 2 >= ngroups_max)
	    return set_errno(E2BIG); /* XXX Hmmm, better error ? */

	cred = crcopy(cred);

	/* Copy the groups */
	for (i = cred->cr_ngroups; i >= 0; i--) {
	    cred->cr_groups[i + 2] = cred->cr_groups[i];
	}
	cred->cr_ngroups += 2;
    } else {
	cred = crcopy(cred);
    }

    cred->cr_groups[1] = part1;
    cred->cr_groups[2] = part2;
    *ret_cred = cred;
    return 0;
}

/*
 * Acquire a new pag for `proc'.
 */

static int
nnpfs_setpag_call(struct proc *proc)
{
    int ret;

    ret = store_pag (&proc->p_cred, pag_part_one, pag_part_two++);
    if (ret)
	return ret;

    if (pag_part_two > NNPFS_PAG2_ULIM) {
	pag_part_one++;
	pag_part_two = NNPFS_PAG2_LLIM;
    }
    return 0;
}

static struct sysent old_setgroups;

static int (*old_setgroups_func)(u_int, gid_t *) = NULL;

static int nnpfs_setgroups (u_int, gid_t *);

void
nnpfs_install_setgroups(void)
{
    old_setgroups = sysent[SYS_setgroups];
    old_setgroups_func = old_setgroups.sy_call;
    sysent[SYS_setgroups].sy_call = nnpfs_setgroups;
}

void
nnpfs_uninstall_setgroups(void)
{
    if (old_setgroups_func) {
	sysent[SYS_setgroups] = old_setgroups;
	old_setgroups_func = NULL;
    }
}

/*
 * Remove the pags from the groups
 */

static int
nnpfs_unpag (struct cred *cred)
{
    while (nnpfs_is_pag (cred)) {
	int i;

	for (i = 0; i < cred->cr_ngroups - 2; ++i)
	    cred->cr_groups[i] = cred->cr_groups[i+2];
	cred->cr_ngroups -= 2;
    }
    return 0;
}

/*
 * A wrapper around setgroups that preserves the pag.
 */

static int
nnpfs_setgroups (u_int gidsetsize, gid_t *gidset)
{
    proc_t *p = ttoproc(curthread);

    mutex_enter(&p->p_crlock);

    if (nnpfs_is_pag (p->p_cred)) {
	gid_t part1, part2;
	int ret;

	if (gidsetsize + 2 >= ngroups_max) {
	    mutex_exit(&p->p_crlock);
	    return set_errno(E2BIG);
	}

	part1 = p->p_cred->cr_groups[1];
	part2 = p->p_cred->cr_groups[2];
	ret   = (*old_setgroups_func) (gidsetsize, gidset);
	if (ret) {
	    mutex_exit(&p->p_crlock);
	    return set_errno(ret);
	}
	ret = store_pag (&p->p_cred, part1, part2);
	if (ret) {
	    mutex_exit(&p->p_crlock);
	    return set_errno(ret);
	}
    } else {
	int ret;

	ret = (*old_setgroups_func) (gidsetsize, gidset);
	if (nnpfs_is_pag (p->p_cred))
	    nnpfs_unpag (p->p_cred);
	if (ret) {
	    mutex_exit(&p->p_crlock);
	    return set_errno(ret);
	}
    }
    mutex_exit(&p->p_crlock);
    return 0;
}

/*
 *
 */

static int
fhget_call (struct vnode *vp,
	    struct ViceIoctl *vice_ioctl)
{
    int error;
    struct nnpfs_fh_args fh_args;

    NNPFSDEB(XDEBSYS, ("nnpfs_fhget: vp = %x, vice_ioctl = %x\n",
		     (int)vp, (int)vice_ioctl));

    if (vp == NULL)
	return set_errno(EBADF);

    fh_args.fsid = vp->v_vfsp->vfs_fsid;

    fh_args.fid.fid_len = MAXFIDSZ;

    error = VOP_FID(vp, &fh_args.fid);
    VN_RELE(vp);
    if (error) {
	NNPFSDEB(XDEBSYS, ("fhget: vop_fid failed: %d\n", error));
	return set_errno(error);
    }

    if (vice_ioctl->out_size < sizeof(fh_args)) {
	NNPFSDEB(XDEBSYS, ("fhget: too small argument\n"));
	return set_errno(EINVAL);
    }

    if(copyout ((caddr_t)&fh_args, (caddr_t)vice_ioctl->out, sizeof(fh_args)))
	return set_errno(EFAULT);
    return 0;
}

/*
 *
 */

static int
fhopen_call (struct vnode *vp,
	     struct ViceIoctl *vice_ioctl,
	     int flags)
{
    int error;
    struct nnpfs_fh_args fh_args;

    NNPFSDEB(XDEBSYS, ("nnpfs_fhopen: vp = %x\n", (int)vp));

    if (vp != NULL) {
	VN_RELE(vp);
	return set_errno(EINVAL);
    }

    if (vice_ioctl->in_size < sizeof(fh_args))
	return set_errno(EINVAL);

    if (copyin ((caddr_t)vice_ioctl->in, (caddr_t)&fh_args, sizeof(fh_args)))
	return set_errno(EFAULT);
    return nnpfs_fhopen (fh_args.fsid, fh_args.fid, flags);
}

/*
 * Send the pioctl to arlad
 */

static int
remote_pioctl (int a_opcode,
	       struct vnode *vp,
	       struct ViceIoctl *vice_ioctl)
{
    struct nnpfs_message_pioctl msg;
    struct nnpfs_message_wakeup_data *msg2;
    int error;

    if (vice_ioctl->in_size < 0) {
	printf("remote pioctl: got a negative data size: opcode: %d",
	       a_opcode);
	return set_errno(EINVAL);
    }
    if (vice_ioctl->in_size > NNPFS_MSG_MAX_DATASIZE) {
	printf("remote_pioctl: got a humongous in packet: opcode: %d",
	       a_opcode);
	return set_errno(EINVAL);
    }
    if (vice_ioctl->in_size != 0) {
	if(copyin((caddr_t)vice_ioctl->in, (caddr_t)&msg.msg,
		  vice_ioctl->in_size))
	    return set_errno(EFAULT);
    }

    if (vp != NULL) {
	struct nnpfs_node *xn;

	xn = VNODE_TO_XNODE(vp);
	msg.handle = xn->handle;
	VN_RELE(vp);
    }

    msg.header.opcode = NNPFS_MSG_PIOCTL;
    msg.opcode = a_opcode;

    msg.insize = vice_ioctl->in_size;
    msg.cred.uid = curproc->p_cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(curproc->p_cred);

    error = nnpfs_message_rpc(0, &msg.header, sizeof(msg)); /* XXX */
    msg2 = (struct nnpfs_message_wakeup_data *) & msg;

    if (error == 0)
	error = msg2->error;
    if (error == ENODEV || error == ENXIO)
	error = EINVAL;
    
    if (error == 0 && vice_ioctl->out_size)
	if(copyout((caddr_t)msg2->msg, (caddr_t)vice_ioctl->out, 
		   min(msg2->len, vice_ioctl->out_size)))
	   return set_errno(EFAULT);
    if (error)
	return set_errno(error);
    else
	return 0;
}

/*
 * Read/set the nnpfs debug level according to `vice_ioctl'
 */

static int
nnpfs_debug(struct ViceIoctl *vice_ioctl)
{
    int32_t flags;
    int error;

    if (!suser(CRED()))
	return EPERM;

    if (vice_ioctl->in_size != 0) {
	if (vice_ioctl->in_size < sizeof(int32_t))
	    return EINVAL;
	
	if(copyin (vice_ioctl->in, &flags, sizeof(flags)))
	    return EFAULT;
	
	nnpfsdeb = flags;
    }
    
    if (vice_ioctl->out_size != 0) {
	if (vice_ioctl->out_size < sizeof(int32_t))
	    return EINVAL;
	
	if(copyout (&nnpfsdeb, vice_ioctl->out, sizeof(int32_t)))
	    return EFAULT;
    }
    return 0;
}

/*
 * print interesting debug information
 */

static int
nnpfs_debug_print (struct ViceIoctl *vice_ioctl, struct vnode *vp)
{
    int32_t flags;
    int error;

    if (!suser(CRED()))
	return EPERM;

    if (vice_ioctl->in_size != 0) {
	int32_t tmp;

	if (vice_ioctl->in_size < sizeof(int32_t))
	    return EINVAL;
	
	if(copyin (vice_ioctl->in, &tmp, sizeof(tmp)))
	    return EFAULT;
	switch (tmp) {
	case XDEBNODE :
	    nnpfs_uprintf_filsys ();
	    break;
	default :
	    return EINVAL;
	}
    }
    return 0;
}

/*
 * Handle `pioctl'
 */

static int
nnpfs_pioctl_int(char *a_pathP,
	       int a_opcode,
	       struct ViceIoctl *a_paramsP,
	       int a_followSymlinks)
{
    int error;
    struct vnode *vp = NULL;
	
    NNPFSDEB(XDEBSYS, ("nnpfs_pioctl (opcode = %d)\n", a_opcode));
    NNPFSDEB(XDEBSYS, ("nnpfs_pioctl: params.size = (%d, %d)\n",
		     a_paramsP->in_size, a_paramsP->out_size));

    if (a_pathP != NULL) {
	char path[MAXPATHLEN];

	if(copyinstr (a_pathP, path, sizeof(path), NULL))
	    return set_errno(EFAULT);

	NNPFSDEB(XDEBSYS, ("nnpfs_syscall: looking up: %s\n", path));

	error = lookupname(path,
			   UIO_SYSSPACE,
			   a_followSymlinks ? FOLLOW : NO_FOLLOW,
			   NULL,
			   &vp);
	if (error)
	    return set_errno(EINVAL);
	NNPFSDEB(XDEBSYS, ("nnpfs_syscall: lookup -> %d, vp = %x\n",
			 error, (int)vp));
    }

    switch (a_opcode) {
    case VIOC_FHGET :
#ifdef VIOC_FHGET_32
    case VIOC_FHGET_32 :
#endif
	NNPFSDEB(XDEBSYS, ("calling fhget(%x, %x)\n",
			 (int)vp, (int)a_paramsP));
	return fhget_call (vp, a_paramsP);
    case VIOC_FHOPEN :
#ifdef VIOC_FHOPEN_32
    case VIOC_FHOPEN_32 :
#endif
	return fhopen_call (vp, a_paramsP, a_followSymlinks);
    case VIOC_NNPFSDEBUG :
#ifdef VIOC_NNPFSDEBUG_32
    case VIOC_NNPFSDEBUG_32 :
#endif
	return nnpfs_debug (a_paramsP);
    case VIOC_NNPFSDEBUG_PRINT :
#ifdef VIOC_NNPFSDEBUG_PRINT_32
    case VIOC_NNPFSDEBUG_PRINT_32 :
#endif
	return nnpfs_debug_print (a_paramsP, vp);
    default :
	return remote_pioctl (a_opcode, vp, a_paramsP);
    }
}

static int
nnpfs_pioctl_call(char *a_pathP,
		int a_opcode,
		struct ViceIoctl *a_paramsP,
		int a_followSymlinks)
{
    int error;
    struct ViceIoctl vice_ioctl;

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall\n"));

    if (copyin ((caddr_t)a_paramsP, (caddr_t)&vice_ioctl, sizeof(vice_ioctl)))
	return set_errno(EFAULT);

    return nnpfs_pioctl_int (a_pathP, a_opcode, &vice_ioctl, a_followSymlinks);
}

static int
nnpfs_syscall(int operation,
	    char *a_pathP,
	    int a_opcode,
	    struct ViceIoctl *a_paramsP,
	    int a_followSymlinks)
{
    int ret;

    switch (operation) {
    case AFSCALL_PIOCTL:
	ret = nnpfs_pioctl_call(a_pathP, a_opcode, a_paramsP,
			      a_followSymlinks);
	break;
    case AFSCALL_SETPAG:
	ret = nnpfs_setpag_call(curproc);
	break;
    default:
	uprintf("Unimplemeted call: %d\n", operation);
	ret = set_errno(EINVAL);
    }
    return ret;
}

static struct sysent nnpfs_sysent = {
    5,
    SE_ARGC | SE_LOADABLE,
    nnpfs_syscall
};

struct modlsys nnpfs_modlsys = {
    &mod_syscallops,
    "nnpfs syscall",
    &nnpfs_sysent
};

#ifdef _SYSCALL32_IMPL

static int
nnpfs_pioctl_call32(char *a_pathP,
		  int a_opcode,
		  struct ViceIoctl32 *a_paramsP32,
		  int a_followSymlinks)

{
    struct ViceIoctl vice_ioctl;
    struct ViceIoctl32 vice_ioctl32;
    int error;

    if (copyin ((caddr_t)a_paramsP32, &vice_ioctl32, sizeof(vice_ioctl32)))
	return set_errno (EFAULT);

    NNPFSDEB(XDEBSYS, ("nnpfs_pioctl_call32: params = (%x, %x, %d, %d)\n",
		     vice_ioctl32.in, vice_ioctl32.out,
		     vice_ioctl32.in_size, vice_ioctl32.out_size));

    vice_ioctl.in       = (caddr_t)vice_ioctl32.in;
    vice_ioctl.out      = (caddr_t)vice_ioctl32.out;
    vice_ioctl.in_size  = vice_ioctl32.in_size;
    vice_ioctl.out_size = vice_ioctl32.out_size;

    return nnpfs_pioctl_int (a_pathP, a_opcode, &vice_ioctl,
			   a_followSymlinks);
}

static int
nnpfs_syscall32(int operation,
	      char *a_pathP,
	      int a_opcode,
	      struct ViceIoctl32 *a_paramsP32,
	      int a_followSymlinks)
{
    int ret;

    NNPFSDEB(XDEBSYS, ("nnpfs_syscall32\n"));

    switch (operation) {
    case AFSCALL_PIOCTL:
	ret = nnpfs_pioctl_call32(a_pathP, a_opcode, a_paramsP32,
				a_followSymlinks);
	break;
    case AFSCALL_SETPAG:
	ret = nnpfs_setpag_call(curproc);
	break;
    default:
	uprintf("Unimplemeted call: %d\n", operation);
	ret = set_errno(EINVAL);
    }
    return ret;
}

static struct sysent nnpfs_sysent32 = {
    5,
    SE_ARGC | SE_LOADABLE,
    nnpfs_syscall32
};

struct modlsys nnpfs_modlsys32 = {
    &mod_syscallops32,
    "32-bit nnpfs syscall",
    &nnpfs_sysent32
};

#endif /* _SYSCALL32_IMPL */
