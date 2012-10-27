/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_syscalls.c,v 1.8 2002/09/07 10:44:36 lha Exp $");

/*
 * NNPFS system calls.
 */

#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_deb.h>

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
nnpfs_is_pag(struct ucred *cred)
{
    return 1;
}

nnpfs_pag_t
nnpfs_get_pag(struct ucred *cred)
{
    if (cred->cr_pag)
	return cred->cr_pag;
    else
	return cred->cr_uid;
}

static int
nnpfs_setpag_call(void)
{
    struct ucred *cred = U.U_cred;

    cred->cr_pag = (pag_part_one << 16) | (pag_part_two);

    ++pag_part_two;

    if (pag_part_two > NNPFS_PAG2_ULIM) {
	pag_part_one++;
	pag_part_two = NNPFS_PAG2_LLIM;
    }
    return 0;
}

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

static int
nnpfs_pioctl_call(char *a_pathP,
		int a_opcode,
		struct ViceIoctl *a_paramsP,
		int a_followSymlinks)
{
    int error;
    struct ViceIoctl vice_ioctl;
    struct nnpfs_message_pioctl msg;
    struct nnpfs_message_wakeup_data *msg2;
    char *pathptr;
	
    /* Copy in the data structure for us */

    error = copyin((caddr_t)a_paramsP,
		   (caddr_t)&vice_ioctl,
		   sizeof(vice_ioctl));

    if (error) 
	return error;

    if (vice_ioctl.in_size < 0) {
	printf("remote pioctl: got a negative data size: opcode: %d",
	       a_opcode);
	return EINVAL;
    }
    if (vice_ioctl.in_size > NNPFS_MSG_MAX_DATASIZE) {
	printf("nnpfs_pioctl_call: got a humongous in packet: opcode: %d",
	       a_opcode);
	return EINVAL;
    }
    if (vice_ioctl.in_size != 0) {
	error = copyin((caddr_t)vice_ioctl.in,
		       (caddr_t)&msg.msg,
		       vice_ioctl.in_size);

	if (error)
	    return error;
    }

    pathptr = a_pathP;

    if (pathptr != NULL) {
	char path[MAXPATHLEN];
	struct nnpfs_node *xn;
	struct vnode *vp;
	uint foo;

	error = copyinstr (pathptr, path, sizeof(path), &foo);

	if (error)
	    return error;

	NNPFSDEB(XDEBMSG, ("nnpfs_syscall: looking up: %p\n", path));

	error = lookupvp (path,
			  a_followSymlinks ? 0 : L_NOFOLLOW,
			  &vp,
			  U.U_cred);

	if (error)
	    return EINVAL;

#if 0
	if (vp->v_tag != VT_AFS) {
	    NNPFSDEB(XDEBMSG, ("nnpfs_syscall: %s not in afs\n", path));
	    vrele(vp);
	    return EINVAL;
	}
#endif

	xn = VNODE_TO_XNODE(vp);

	msg.handle = xn->handle;
    }

    msg.header.opcode = NNPFS_MSG_PIOCTL;
    msg.opcode = a_opcode;

    msg.insize = vice_ioctl.in_size;
    msg.cred.uid = U.U_cred->cr_uid;
    msg.cred.pag = nnpfs_get_pag(U.U_cred);

    error = nnpfs_message_rpc(0, &msg.header, sizeof(msg)); /* XXX */
    msg2 = (struct nnpfs_message_wakeup_data *) & msg;

    if (error == 0)
	error = msg2->error;
    if (error == ENODEV)
	error = EINVAL;
    
    if (error == 0 && vice_ioctl.out_size)
	error = copyout((caddr_t)msg2->msg,
			(caddr_t)vice_ioctl.out, 
			min(msg2->len, vice_ioctl.out_size));
    return error;
}


int
nnpfs_pioctl(int operation,
	   char *a_pathP,
	   int a_opcode,
	   struct ViceIoctl *a_paramsP,
	   int a_followSymlinks)
{
    int error = EINVAL;

    switch (operation) {
    case AFSCALL_PIOCTL:
	error = nnpfs_pioctl_call(a_pathP, a_opcode, a_paramsP,
				a_followSymlinks);
	break;
    case AFSCALL_SETPAG:
	error = nnpfs_setpag_call();
	break;
    default:
	uprintf("Unimplemeted call: %d\n", operation);
	error = EINVAL;
	break;
    }

    errno = error;
    return error?-1:0;
}
