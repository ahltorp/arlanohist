/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
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
 * Load eXternal FS using modload under Solaris
 *
 * This is a filsystem, a pseudo device driver and a
 * systemcall.
 *
 */

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_syscalls.h>

RCSID("$Id: nnpfs_wrap.c,v 1.9 2002/09/07 10:47:46 lha Exp $");

extern struct modlsys nnpfs_modlsys;

#ifdef _SYSCALL32_IMPL
extern struct modlsys nnpfs_modlsys32;
#endif

extern struct modldrv nnpfs_modldrv;

extern struct modlfs nnpfs_modlfs;

static struct modlinkage nnpfs_modlinkage = {
    MODREV_1,
    {(void *)&nnpfs_modlsys,
#ifdef _SYSCALL32_IMPL
     (void *)&nnpfs_modlsys32,
#endif
     (void *)&nnpfs_modldrv,
     (void *)&nnpfs_modlfs,
     NULL}
};

int
_init(void)
{
    int ret;

    ret = nnpfs_dev_init();
    if (ret)
	return ret;

    ret = mod_install(&nnpfs_modlinkage);
    if (ret) {
	nnpfs_dev_fini();
    }
    nnpfs_install_setgroups ();
    return ret;
}

int
_fini(void)
{
    int ret;

    if (nnpfs_unloadable())
	return EBUSY;

    ret = mod_remove(&nnpfs_modlinkage);
    if (ret)
	return ret;
    nnpfs_dev_fini();
    nnpfs_uninstall_setgroups ();
    return ret;
}

int
_info(struct modinfo *modinfop)
{
    return mod_info(&nnpfs_modlinkage, modinfop);
}
