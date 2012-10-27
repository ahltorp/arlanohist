/*
 * Copyright (c) 1995 - 2005 Kungliga Tekniska Högskolan
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

#include <nnpfs/nnpfs_locl.h>

#ifdef RCSID
RCSID("$Id: nnpfs_load.c,v 1.38 2006/10/31 10:02:41 tol Exp $");
#endif

#define NNPFS_MAJOR 103
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <linux/init.h>

/* allow specifying debuglevel mask ("nnpfsdeb") param on load */
#include <linux/moduleparam.h>
module_param(nnpfsdeb, int, 0);

extern struct file_operations nnpfs_fops;

struct file_system_type nnpfs_fs_type = {
       name:           "nnpfs",
       get_sb:         nnpfs_get_sb,
       kill_sb:        kill_litter_super,
       owner:          THIS_MODULE,
};

static int __init init_nnpfs_fs(void)
{
    int ret;
    NNPFSDEB(XDEBVFOPS, ("init_nnpfs_fs\n"));
    NNPFSDEB(XDEBVFOPS, ("nnpfs_fs_type: %p\n",&nnpfs_fs_type));
    ret = register_filesystem(&nnpfs_fs_type);
    NNPFSDEB(XDEBVFOPS, ("init_nnpfs_fs exit\n"));
    return ret;
}

static int __init init_nnpfs(void)
{
    int status;
    
    NNPFSDEB(XDEBVFOPS, ("init_nnpfs\n"));
    install_afs_syscall();
    if ((status = init_nnpfs_fs()) != 0) {
	NNPFSDEB(XDEBVFOPS, ("init_nnpfs: init_nnpfs_fs failed\n"));
	return status;
    }
    if (register_chrdev(NNPFS_MAJOR,"nnpfs",&nnpfs_fops))
	status = -EIO;

    if (status) {
	NNPFSDEB(XDEBVFOPS, ("init_nnpfs: unable to get major %d\n", NNPFS_MAJOR));
	unregister_filesystem(&nnpfs_fs_type);
	return status;
    }
    nnpfs_init_device();
    NNPFSDEB(XDEBVFOPS, ("init_nnpfs exit\n"));
    return status;
}

static void __exit exit_nnpfs(void)
{
    unregister_filesystem(&nnpfs_fs_type);
    unregister_chrdev(NNPFS_MAJOR,"nnpfs");
    restore_afs_syscall();
}

#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

module_init(init_nnpfs);
module_exit(exit_nnpfs);
