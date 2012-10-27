/*
 * Copyright (c) 1995 - 2002, 2004 Kungliga Tekniska Högskolan
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
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_wrap.h>
#include <sys/param.h>

RCSID("$Id: nnpfs_wrap-bsd.c,v 1.56 2007/03/06 16:00:57 tol Exp $");

#include "version.h"

int nnpfs_dev_major;

/*
 * Iff `dev' represents a valid nnpfs device.
 */

int
nnpfs_is_nnpfs_dev (nnpfs_dev_t dev)
{
#ifdef __FreeBSD__
    return nnpfs_minor(dev) >= 0 && nnpfs_minor(dev) < NNNPFS;
#else
    return nnpfs_major (dev) == nnpfs_dev_major
	&& nnpfs_minor(dev) >= 0 && nnpfs_minor(dev) < NNNPFS;
#endif
}

static int
nnpfs_uninstall(void)
{
    int err, i, ret = 0;
    
    /* simple, racy check */
    for (i = 0; i < NNNPFS; i++) {
	struct nnpfs *chan = &nnpfs_dev[i];
	if (chan->status & CHANNEL_OPENED)
	    return EBUSY;
    }
    
    if ((ret = nnpfs_uninstall_filesys()) != 0)
	return ret; /* we're still mounted or smth, bail out */
    
    /* we've passed the point of no return, clean up as much as we can */
    if ((err = nnpfs_uninstall_device()) != 0)
	ret = err;
    if ((err = nnpfs_uninstall_syscalls()) != 0)
	ret = err;

#ifdef __NetBSD__
    malloc_type_detach(M_NNPFS);
    malloc_type_detach(M_NNPFS_LINK);
    malloc_type_detach(M_NNPFS_MSG);
    malloc_type_detach(M_NNPFS_NODE);
#endif

    return ret;
}

static int
nnpfs_install(void)
{
    int err = 0;

#ifdef __NetBSD__
    malloc_type_attach(M_NNPFS);
    malloc_type_attach(M_NNPFS_LINK);
    malloc_type_attach(M_NNPFS_MSG);
    malloc_type_attach(M_NNPFS_NODE);
#endif

    if ((err = nnpfs_install_device()) ||
	(err = nnpfs_install_syscalls()) ||
	(err = nnpfs_install_filesys())) {
	panic("install failed");
	nnpfs_uninstall();  
    }
    return err;
}

extern struct cdevsw nnpfs_cdev;

/*
 * This is to build a kld module (FreeBSD3.0 and later, but we only
 * support FreeBSD 4.1 and later)
 */

#if KLD_MODULE

static void
make_devices (struct cdevsw *devsw)
{
    int i;

    for (i = 0; i < NNNPFS; ++i) {
#ifdef __DragonFly__
	cdevsw_add(devsw, -1, i);
#endif
	nnpfs_dev[i].dev = 
	    make_dev (devsw, i, UID_ROOT, GID_WHEEL, 0600, "nnpfs%d", i);
    }
}

static void
destroy_devices (struct cdevsw *devsw)
{
    int i;

    for (i = 0; i < NNNPFS; ++i) {
#ifdef __DragonFly__
	cdevsw_remove(devsw, -1, i);
#else
	destroy_dev (nnpfs_dev[i].dev);
#endif
    }
}

/*
 *
 */

static int
nnpfs_load(struct module *mod, int cmd, void *arg)
{
    int ret;

    NNPFSDEB(XDEBLKM, ("nnpfs_load\n"));

    switch (cmd) {
    case MOD_LOAD :
	ret = nnpfs_install ();
	if (ret == 0) {
	    make_devices (&nnpfs_cdev);
	    printf ("nnpfs: cdev: %d, syscall: %d\n",
		    nnpfs_dev_major, nnpfs_syscall_num);
	}
	break;
    case MOD_UNLOAD :
	ret = nnpfs_uninstall ();
	if (ret == 0) {
	    destroy_devices (&nnpfs_cdev);
	}
	break;
    default :
	ret = EINVAL;
	break;
    }
    NNPFSDEB(XDEBLKM, ("nnpfs_load = %d\n", ret));
    return ret;
}

extern struct vfsops nnpfs_vfsops;

extern struct sysent nnpfs_syscallent;

VFS_SET(nnpfs_vfsops, nnpfs, 0);

DEV_MODULE(arlannpfsdev, nnpfs_load, NULL);

#ifdef MODULE_VERSION
MODULE_VERSION(arlannpfsdev,1);
#endif /* MODULE_VERSION */

#else /* KLD_MODULE */

/*
 * An ordinary lkm-module
 */

#ifdef __NetBSD__
MOD_DEV("nnpfs_mod","nnpfs_mod", NULL, -1, &nnpfs_cdev, -1)
#elif !defined(__APPLE__)
MOD_DEV("nnpfs_mod",LM_DT_CHAR,-1,&nnpfs_cdev)
#endif

static int
nnpfs_stat(void)
{
    int err = 0;

    if ((err = nnpfs_stat_device()) != 0)
	return err;
    else if ((err = nnpfs_stat_syscalls()) != 0)
	return err;
    else if ((err = nnpfs_stat_filesys()) != 0)
	return err;

    return err;
}

/*
 *
 */

#if defined(__APPLE__)
__private_extern__ kern_return_t
nnpfs_modload(kmod_info_t *ki, void *data)
#else
static int
nnpfs_modload(struct lkm_table *lkmtp, int cmd)
#endif
{
    int error = 0;

    NNPFSDEB(XDEBLKM, ("nnpfs_modload\n"));

    error = nnpfs_install();
    if (error == 0)
	nnpfs_stat();

    return error;
}


/*
 *
 */

#if defined(__APPLE__)
__private_extern__ kern_return_t
nnpfs_modunload(kmod_info_t *ki, void *data)
#else
static int
nnpfs_modunload(struct lkm_table * lkmtp, int cmd)
#endif
{
    int error = 0;

    NNPFSDEB(XDEBLKM, ("nnpfs_modunload\n"));

    error = nnpfs_uninstall();
    if (!error)
	NNPFSDEB(XDEBLKM, ("nnpfs_modunload: successful\n"));
    else
	NNPFSDEB(XDEBLKM, ("nnpfs_modunload: unsuccessful, system unstable\n"));
    return error;
}

/*
 *
 */

#if !defined(__APPLE__)
static int
nnpfs_modstat(struct lkm_table * lkmtp, int cmd)
{
    int error = 0;

    NNPFSDEB(XDEBLKM, ("nnpfs_modstat\n"));

    error = nnpfs_stat();
    return error;
}

int
nnpfs_mod(struct lkm_table * lkmtp, int cmd, int ver);

int
nnpfs_mod(struct lkm_table * lkmtp, int cmd, int ver)
{
    int ret;

    if (ver != LKM_VERSION)						
	return EINVAL;	/* version mismatch */			
    switch (cmd) {							
    case LKM_E_LOAD:
	lkmtp->private.lkm_any = (struct lkm_any *)&_module;
	if ((ret = nnpfs_modload(lkmtp, cmd)) != 0)
	    return ret;
	break;
    case LKM_E_UNLOAD:
	if ((ret = nnpfs_modunload(lkmtp, cmd)) != 0)
	    return ret;
	break;
    case LKM_E_STAT:
	if ((ret = nnpfs_modstat(lkmtp, cmd)) != 0)
	    return ret;
	break;
    }
    ret = lkmdispatch(lkmtp, cmd);
    if(cmd == LKM_E_LOAD) {
	if (ret) {
	    int ret2;
	    ret2 = nnpfs_uninstall();
	    if (ret2)
		printf("nnpfs failed to unload after "
		       "unsucessful load: %d\n", ret2);
	} else {
#ifdef __NetBSD__
	    nnpfs_dev_major = _module.lkm_cdevmaj;
#else
	    nnpfs_dev_major = _module.lkm_offset;
#endif
	    printf ("nnpfs (%s): "
		    "protocol version %d, using cdev: %d, syscall: %d\n",
		    arla_version, NNPFS_VERSION,
		    nnpfs_dev_major, nnpfs_syscall_num);
	}
    }
    return ret;
}
#endif
    
#endif /* KLD_MODULE */

