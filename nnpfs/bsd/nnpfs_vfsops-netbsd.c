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

RCSID("$Id: nnpfs_vfsops-netbsd.c,v 1.38 2006/03/21 09:33:34 tol Exp $");

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_vfsops-bsd.h>
#include <nnpfs/nnpfs_vnodeops.h>

static vop_t **nnpfs_dead_vnodeop_p;

int
nnpfs_make_dead_vnode(struct mount *mp, int isrootp, struct vnode **vpp)
{
    int error;
    NNPFSDEB(XDEBNODE, ("make_dead_vnode mp = %lx\n",
		      (unsigned long)mp));

    error = getnewvnode(VT_NON, mp, nnpfs_dead_vnodeop_p, vpp);
    if (error == 0)
      NNPFS_MAKE_VROOT(*vpp);
    return error;
}

static struct vnodeopv_entry_desc nnpfs_dead_vnodeop_entries[] = {
    {&vop_default_desc, 	(vop_t *) nnpfs_eopnotsupp},
    {&vop_lookup_desc,		(vop_t *) nnpfs_dead_lookup},
    {&vop_reclaim_desc, 	(vop_t *) nnpfs_returnzero},
    {&vop_lock_desc,		(vop_t *) genfs_nolock},
    {&vop_unlock_desc,		(vop_t *) genfs_nounlock},
    {&vop_islocked_desc,	(vop_t *) genfs_noislocked},
    {&vop_putpages_desc,	(vop_t *) nnpfs_dead_putpages},
    {NULL, NULL}};

static struct vnodeopv_desc nnpfs_dead_vnodeop_opv_desc =
{&nnpfs_dead_vnodeop_p, nnpfs_dead_vnodeop_entries};

#if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 105280000
#define nnpfs_opv_desc nnpfs_netbsd_vnodeop_opv_desc
#else
#define nnpfs_opv_desc nnpfs_vnodeop_opv_desc
#endif


extern struct vnodeopv_desc nnpfs_opv_desc;

#if __NetBSD_Version__ >= 105150000
const
#endif
struct vnodeopv_desc *nnpfs_vnodeopv_descs[] = {
    &nnpfs_opv_desc,
    NULL,
};

#if __NetBSD_Version__ >= 105150000
const
#endif
struct vnodeopv_desc *nnpfs_dead_vnodeopv_descs[] = {
    &nnpfs_dead_vnodeop_opv_desc,
    NULL
};


/*
 * Provide prototypes for vfs_opv_init_{explicit,default}
 * so we dont need to shot our head of more times then nessary
 */

#ifndef HAVE_STRUCT_VFSOPS_VFS_OPV_DESCS
void vfs_opv_init_explicit (struct vnodeopv_desc *);
void vfs_opv_init_default (struct vnodeopv_desc *);
#endif

/*
 * If the vfs_opv_descs wasn't included in `struct vfsops' it couldn't
 * get initialized by vfs_attach and we need to do it here.
 */


static void
nnpfs_init(void)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_init\n"));
#ifndef HAVE_STRUCT_VFSOPS_VFS_OPV_DESCS
    vfs_opv_init_explicit(&nnpfs_vnodeop_opv_desc);
    vfs_opv_init_default(&nnpfs_vnodeop_opv_desc);
    vfs_opv_init_explicit(&nnpfs_dead_vnodeop_opv_desc);
    vfs_opv_init_default(&nnpfs_dead_vnodeop_opv_desc);
#else
    vfs_opv_init (nnpfs_dead_vnodeopv_descs);
#endif
}

#ifdef HAVE_STRUCT_VFSOPS_VFS_REINIT
static void
nnpfs_reinit(void)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_reinit\n"));
}
#endif

#ifdef HAVE_STRUCT_VFSOPS_VFS_DONE

static void
nnpfs_done(void)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_done\n"));
}

#endif

static int
nnpfs_mount_netbsd(struct mount *mp,
		 const char *user_path,
		 void *user_data,
		 struct nameidata *ndp,
		 d_thread_t *p)
{
    int error;

    error = nnpfs_mount_common(mp, user_path, user_data, ndp, p);
#if __NetBSD_Version__ >= 105280000
    if (error == 0) {
	mp->mnt_fs_bshift = DEV_BSHIFT;
	mp->mnt_dev_bshift = DEV_BSHIFT;
    }
#endif
    return error;
}


static struct vfsops
nnpfs_vfsops = {
    "nnpfs",
    nnpfs_mount_netbsd,
    nnpfs_start,
    nnpfs_unmount,
    nnpfs_root,
    (void *)nnpfs_quotactl,
    nnpfs_statfs,
    nnpfs_sync,
    nnpfs_vget,
    nnpfs_fhtovp,
    nnpfs_vptofh,
    nnpfs_init,
#ifdef HAVE_STRUCT_VFSOPS_VFS_REINIT /* NetBSD 1.5Y */
    nnpfs_reinit,
#endif
#ifdef HAVE_STRUCT_VFSOPS_VFS_DONE
    nnpfs_done,
#endif
#ifdef HAVE_STRUCT_VFSOPS_VFS_WASSYSCTL
    NULL,			/* sysctl */
#endif
    NULL,			/* mountroot */
#ifdef HAVE_STRUCT_VFSOPS_VFS_CHECKEXP
    nnpfs_checkexp,		/* checkexp */
#endif
#ifdef HAVE_STRUCT_VFSOPS_VFS_SNAPSHOT
    nnpfs_snapshot,
#endif
#ifdef HAVE_STRUCT_VFSOPS_VFS_EXTATTRCTL
    vfs_stdextattrctl,
#endif
#ifdef HAVE_STRUCT_VFSOPS_VFS_OPV_DESCS
    nnpfs_vnodeopv_descs
#endif
};

#ifndef HAVE_KERNEL_VFS_ATTACH

int
vfs_attach (struct vfsops *ops)
{
    int i;

    for (i = 0; i < nvfssw; ++i) 
	if (vfssw[i] != NULL
	    && strcmp (vfssw[i]->vfs_name, ops->vfs_name) == 0)
	    return EEXIST;

    for (i = nvfssw - 1; i >= 0; i--)
	if (vfssw[i] == NULL)
	    break;
    if (i < 0)
	return EINVAL;

    vfssw[i] = ops;
    vfssw[i]->vfs_refcount = 0;

    if (vfssw[i]->vfs_init != NULL)
	(*(vfssw[i]->vfs_init)) ();

    return 0;
}

int
vfs_detach (struct vfsops *ops)
{
    int i;

    if (ops->vfs_refcount != 0)
	return EBUSY;

    for (i = 0; i < nvfssw; ++i)
	if (vfssw[i] == ops)
	    break;

    if (i == nvfssw)
	return ENOENT;

    vfssw[i] = NULL;
    return 0;
}

#endif /* HAVE_VFS_ATTACH */

int
nnpfs_install_filesys(void)
{
    return vfs_attach(&nnpfs_vfsops);
}

int
nnpfs_uninstall_filesys(void)
{
    return vfs_detach(&nnpfs_vfsops);
}

int
nnpfs_stat_filesys (void)
{
    return 0;
}
