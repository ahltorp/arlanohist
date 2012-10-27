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

RCSID("$Id: nnpfs_syscalls-wrap-freebsd.c,v 1.18 2008/02/21 20:44:08 tol Exp $");

/*
 * NNPFS system calls.
 */

#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_deb.h>

int nnpfs_syscall_num = AFS_SYSCALL;

static int
nnpfs_syscall(d_thread_t *proc, void *varg)
{
    register_t retval = 0;
    int ret;

    ret = nnpfspioctl(proc, varg, &retval);
#ifdef HAVE_FREEBSD_THREAD
    proc->td_retval[0] = retval;
#else
    proc->p_retval[0] = retval;
#endif
    return ret;
}

static int
nnpfs_setgroups_freebsd (d_thread_t *proc, void *varg)
{
    register_t retval = 0;
    int ret;

    ret = nnpfs_setgroups(proc, varg, &retval);
#ifdef HAVE_FREEBSD_THREAD
    proc->td_retval[0] = retval;
#else
    proc->p_retval[0] = retval;
#endif
    return ret;
}

static int (*freebsd_old_setgroups_func)(d_thread_t *, void *);

static int
wrap_old_setgroups_func (d_thread_t *proc,
			 void *varg,
			 register_t *return_value)
{
    int ret;
    ret = (*freebsd_old_setgroups_func) (proc, varg);
#ifdef HAVE_FREEBSD_THREAD
    *return_value = proc->td_retval[0];
#else
    *return_value = proc->p_retval[0];
#endif
    return ret;
}


struct sysent nnpfs_syscallent = {
    5,
    nnpfs_syscall
};

static struct sysent old_setgroups;
static struct sysent old_afssyscall;

int
nnpfs_install_syscalls(void)
{
    old_setgroups = sysent[SYS_setgroups];
    freebsd_old_setgroups_func = old_setgroups.sy_call;
    old_setgroups_func = wrap_old_setgroups_func;
    sysent[SYS_setgroups].sy_call = nnpfs_setgroups_freebsd;

    old_afssyscall = sysent[nnpfs_syscall_num];
    sysent[nnpfs_syscall_num] = nnpfs_syscallent;

    return 0;
}

int
nnpfs_uninstall_syscalls(void)
{
    sysent[SYS_setgroups] = old_setgroups;
    sysent[nnpfs_syscall_num] = old_afssyscall;

    return 0;
}

int
nnpfs_stat_syscalls(void)
{
    return 0;
}

#if 0
SYSCALL_MODULE(nnpfs_syscall, &nnpfs_syscall_num, &nnpfs_syscallent, NULL, NULL);
#endif
