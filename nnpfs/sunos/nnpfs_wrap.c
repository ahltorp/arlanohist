/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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

/*
 *
 * Load eXternal FS using modload under SunOS4.1.3
 *
 * This is a filsystem, a pseudo device driver and some
 * systemcalls, also some existing syscalls get patched.
 *
 */
static char MODULE[] = "NNPFS fs";

#include <sys/conf.h>
#include <sun/vddrv.h>
#include <sys/errno.h>

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_syscalls.h>

#include <machine/cpu.h>
#if defined(sun4m)
#  define MY_CPU_ARCH SUN4M_ARCH
#elif defined(sun4c)
#  define MY_CPU_ARCH SUN4C_ARCH
#elif defined(sun4)
#  define MY_CPU_ARCH SUN4_ARCH
#else  /* unknown */

#endif /* sun4 */

/*
 * Pseudo device.
 */

extern int nulldev();

typedef int (*int_fun)();

struct cdevsw nnpfs_cdev = {
  (int_fun) nnpfs_devopen, (int_fun) nnpfs_devclose, (int_fun) nnpfs_devread, (int_fun) nnpfs_devwrite,
  (int_fun) nnpfs_devioctl, nulldev, (int_fun) nnpfs_devselect, 0,
  0, 0,
};

struct vdldrv vd = {
  VDMAGIC_PSEUDO,		/* magic */
  MODULE,			/* name */
#if defined(sun4c) || defined(sun4m)
  (struct dev_ops*) 0,		/* dev_ops */
#else  /* sun4 */
  (struct mb_ctlr*) 0,		/* mb_ctlr */
  (struct mb_driver*) 0,	/* mb_driver */
  (struct mb_device*) 0,	/* mb_device */
  (int) 0,			/* numctlrs */
  (int) 0,			/* numdevs */
#endif /* sun4 */
  (struct bdevsw*) 0,		/* bdevsw */
  &nnpfs_cdev,			/* cdevsw */
  (int) 0,			/* blockmajor */
  (int) 0,			/* charmajor (0 means pick any slot) */
#if defined(sun4m)
  (struct mb_ctlr*) 0,		/* mb_ctlr */
  (struct mb_driver*) 0,	/* mb_driver */
  (struct mb_device*) 0,	/* mb_device */
  (int) 0,			/* numctlrs */
  (int) 0,			/* numdevs */
#endif /* sun4m */
};

static
int
nnpfs_uninstall()
{
  int err, ret = 0;
  if ((err = nnpfs_uninstall_device()) != 0)
    ret = err;
  if ((err = nnpfs_uninstall_filesys()) != 0)
    ret = err;
  if ((err = nnpfs_uninstall_syscalls()) != 0)
    ret = err;
  return ret;
}

/*
 * Install all or nothing.
 */
static int
nnpfs_install()
{
  int err;
  
  if ((err = nnpfs_install_device()) != 0)
    nnpfs_uninstall();
  else if ((err = nnpfs_install_filesys()) != 0)
    nnpfs_uninstall();
  else if ((err = nnpfs_install_syscalls()) != 0)
    nnpfs_uninstall();

  return err;
}

static int
nnpfs_vdstat()
{
  int err;
  
  if ((err = nnpfs_vdstat_filesys()) != 0)
    return err;
  else if ((err = nnpfs_vdstat_syscalls()) != 0)
    return err;
  else if ((err = nnpfs_vdstat_device()) != 0)
    return err;
  else
    return err;  
}

#if defined(__GNUC__)
extern
int xxxinit(unsigned int code,
	    struct vddrv *vdp,
	    addr_t vdi,
	    struct vdstat *vds);
#endif

#if defined(__STDC__)
int xxxinit(unsigned int code,
	    struct vddrv *vdp,
	    addr_t vdi,
	    struct vdstat *vds)
#else
int
xxxinit(code, vdp, vdi, vds)
     unsigned int code;
     struct vddrv *vdp;
     addr_t vdi;
     struct vdstat *vds;
#endif
{
  int err;

  switch (code) {

  case VDLOAD:
    if ((cpu & CPU_ARCH) != MY_CPU_ARCH)
      printf("Warning: %s compiled for 0x%x but cpu = 0x%x!\n",
	     MODULE, MY_CPU_ARCH, cpu);

    if ((err = nnpfs_install()) != 0)
      return err;
    vdp->vdd_vdtab = (struct vdlinkage*) &vd;
    return 0;			/* success */

  case VDUNLOAD:
    uprintf("Unloading %s, beware!\n", MODULE);

    if ((err = nnpfs_uninstall()) != 0)
      return err;
    return 0;

  case VDSTAT:
    if ((err = nnpfs_vdstat()) != 0)
      return err;
    return 0;

  default:
    return EIO;
  }
}
