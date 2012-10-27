/*
 * Copyright (c) 1995 - 2001, 2005 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_syscalls-wrap-macos.c,v 1.5 2005/10/28 14:33:39 tol Exp $");

/*
 * NNPFS system calls.
 */

#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_deb.h>

#include <arla-pioctl.h>

/* ARGH -- for apple's broken header files */
struct vnop_devblocksize_args;

#include <vfs/vfs_support.h>
#include <miscfs/devfs/devfs.h>
 
typedef struct afsdevfsdata {
     unsigned long syscall;
     unsigned long param1;
     unsigned long param2;
     unsigned long param3;
     unsigned long param4;
     unsigned long param5;
     unsigned long param6;
     unsigned long retval;
} afsdevfsdata;

#define ARLA_VIOC_SYSCALL32		_IOW('C',1,u32)
#define ARLA_VIOC_SYSCALL_MACOS		_IOWR('C', 2, afsdevfsdata)

#define NNPFS_DEVFS_NODE "nnpfs_ioctl"

/*
 * no syscalls in Tiger, go for devfs instead
 */

#define seltrue eno_select
struct cdevsw nnpfs_devfs_cdev = NO_CDEVICE;
#undef seltrue

static int nnpfs_devfs_major;
static void *nnpfs_devfs_handle;

static int
nnpfs_devfs_opcl(dev_t dev, int flags, int devtype, struct proc *p) {
    return 0;
}

static int
nnpfs_devfs_ioctl(nnpfs_dev_t dev, u_long cmd, caddr_t data,
		  int flags, d_thread_t *p)
{
    struct afsdevfsdata *user_args = (afsdevfsdata *)data;
    register_t retval = 0;
    int error;

    if (proc_is64bit(p))
	return EINVAL;

    if (cmd != ARLA_VIOC_SYSCALL_MACOS)
	return EINVAL;

    error = nnpfspioctl(p, user_args, &retval);
    if (error)
	return error;

    user_args->retval = retval;

    return error;
}

int
nnpfs_install_syscalls(void)
{
    nnpfs_devfs_cdev.d_open  = &nnpfs_devfs_opcl;
    nnpfs_devfs_cdev.d_close = &nnpfs_devfs_opcl;
    nnpfs_devfs_cdev.d_ioctl = &nnpfs_devfs_ioctl;

    nnpfs_devfs_major = cdevsw_add(-1, &nnpfs_devfs_cdev);
    if (nnpfs_devfs_major == -1) {
	printf("nnpfs: cdevsw_add failed\n");
	return -1;
    }

    nnpfs_devfs_handle = devfs_make_node(makedev(nnpfs_devfs_major, 0),
					 DEVFS_CHAR, UID_ROOT, GID_WHEEL,
					 0666, "nnpfs_ioctl", 0);
    if (nnpfs_devfs_handle == NULL) {
	printf("nnpfs: devfs create failed\n");
	return -1;
    }

    return 0;
}

int
nnpfs_uninstall_syscalls(void)
{
    int ret;
    devfs_remove(nnpfs_devfs_handle);
    ret = cdevsw_remove(nnpfs_devfs_major, &nnpfs_devfs_cdev);
    if (ret == -1) {
	NNPFSDEB(XDEBLKM, ("nnpfs_uninstall_device error %d\n", ret));
    } else if (ret == nnpfs_devfs_major) {
	ret = 0;
    } else {
	NNPFSDEB(XDEBLKM, ("nnpfs_uninstall_device unexpected error error %d\n",
			   ret));
    }
    return ret;
}

int
nnpfs_stat_syscalls(void)
{
    return 0;
}
