/*
 * Copyright (c) 1995 - 2002, 2005 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_vfsops-macos.c,v 1.16 2005/11/08 11:33:34 tol Exp $");

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vfsops.h>
#include <nnpfs/nnpfs_vfsops-bsd.h>
#include <nnpfs/nnpfs_vnodeops.h>

struct vnop_devblocksize_args; /* XXX avoid warnings, broken headers in tiger */

#include <vfs/vfs_support.h>

static vop_t **nnpfs_dead_vnodeop_p;

int nnpfs_typenum = -1;

int
nnpfs_make_dead_vnode(struct mount *mp, int isrootp, struct vnode **vpp)
{
    struct vnode_fsparam p;
    int error;
    NNPFSDEB(XDEBNODE, ("make_dead_vnode mp = %lx\n", (unsigned long)mp));

    memset(&p, 0, sizeof(p));
    p.vnfs_mp = mp;
    p.vnfs_vtype = VDIR;
    p.vnfs_str = "arla-dead";
    p.vnfs_dvp = NULL;
    p.vnfs_fsnode = NULL;
    p.vnfs_vops = nnpfs_dead_vnodeop_p;
    p.vnfs_markroot = 1;
    p.vnfs_marksystem = 0;
    p.vnfs_rdev = 0;
    p.vnfs_filesize = 0;
    p.vnfs_cnp = NULL;
    p.vnfs_flags = VNFS_CANTCACHE;
    
    return vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &p, vpp);
}

static int
nnpfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp,
	     struct vnode **vpp, nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_fhtovp\n"));
    return ENOTSUP;
}

static int
nnpfs_vptofh(struct vnode *vp, int *fhlen, unsigned char *fhp,
	     nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vptofh\n"));
    return ENOTSUP;
}

static int
nnpfs_init(struct vfsconf *vfsp)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_init\n"));

    return 0;
}

int
nnpfs_mount_context(struct mount *mp, vnode_t devvp, user_addr_t user_data,
		    nnpfs_vfs_context ctx)
{
    char data[MAXPATHLEN];
    size_t count;
    int error;

    error = copyinstr(user_data, data, MAXPATHLEN, &count);
    if (error)
	return error;

    if (devvp == NULLVP) {
	error = vnode_lookup(data, 0 /* flags */, &devvp, ctx);
	if (error) {
	    NNPFSDEB(XDEBVFOPS, ("vnode_lookup failed, errno = %d\n", error));
	    return error;
	}
    } else {
	panic("nnpfs_mount_context: got devvp"); /* XXX */
    }

    return nnpfs_mount_common_sys(mp, devvp, NULL, data, NULL, ctx);
}

int
nnpfs_start(struct mount * mp, int flags, nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_start mp = %lx, flags = %d, ctx = %lx\n", 
			 (unsigned long)mp, flags, (unsigned long)ctx));
    return 0;
}

int
nnpfs_unmount(struct mount * mp, int mntflags, nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_umount: mp = %lx, mntflags = %d, ctx = %lx\n", 
		       (unsigned long)mp, mntflags, (unsigned long)ctx));
    return nnpfs_unmount_common(mp, mntflags);
}

int
nnpfs_root(struct mount *mp, struct vnode **vpp, nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_root mp = %lx\n", (unsigned long)mp));
    return nnpfs_root_common(mp, vpp, nnpfs_vfs_context_proc(ctx));
}

int
nnpfs_quotactl(struct mount *mp, int cmd, uid_t uid, caddr_t arg,
	       nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_quotactl: mp = %lx, cmd = %d, uid = %u, "
			 "arg = %lx, proc = %lx\n", 
			 (unsigned long)mp, cmd, uid,
			 (unsigned long)arg, (unsigned long)ctx));
    return ENOTSUP;
}

int
nnpfs_statfs(struct mount *mp, nnpfs_statvfs *sbp, nnpfs_vfs_context ctx)
{
    struct nnpfs *nnpfs = VFS_TO_NNPFS(mp);
    NNPFSDEB(XDEBVFOPS, ("nnpfs_statfs: mp = %lx, sbp = %lx\n", 
			 (unsigned long)mp,
			 (unsigned long)sbp));

    if (VFSATTR_IS_ACTIVE(sbp, f_bsize))
	VFSATTR_RETURN(sbp, f_bsize, DEV_BSIZE);

    if (VFSATTR_IS_ACTIVE(sbp, f_iosize))
	VFSATTR_RETURN(sbp, f_iosize, DEV_BSIZE);

    if (VFSATTR_IS_ACTIVE(sbp, f_owner))
	VFSATTR_RETURN(sbp, f_owner, 0);

    if (VFSATTR_IS_ACTIVE(sbp, f_blocks))
	VFSATTR_RETURN(sbp, f_blocks, 4711 * 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_bfree))
	VFSATTR_RETURN(sbp, f_bfree, 4711 * 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_bavail))
	VFSATTR_RETURN(sbp, f_bavail, 4711 * 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_bused))
	VFSATTR_RETURN(sbp, f_bused, 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_files))
	VFSATTR_RETURN(sbp, f_files, 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_ffree))
	VFSATTR_RETURN(sbp, f_ffree, 4711);

    if (VFSATTR_IS_ACTIVE(sbp, f_fssubtype))
	VFSATTR_RETURN(sbp, f_fssubtype, 0);

    if (VFSATTR_IS_ACTIVE(sbp, f_capabilities)) {
	vol_capabilities_attr_t *volcaps = &sbp->f_capabilities;
	
	volcaps->capabilities[VOL_CAPABILITIES_FORMAT] =
	    VOL_CAP_FMT_SYMBOLICLINKS |
	    VOL_CAP_FMT_HARDLINKS |
	    VOL_CAP_FMT_CASE_SENSITIVE |
	    VOL_CAP_FMT_CASE_PRESERVING |
	    VOL_CAP_FMT_FAST_STATFS;

	volcaps->valid[VOL_CAPABILITIES_FORMAT] =
	    VOL_CAP_FMT_PERSISTENTOBJECTIDS |
	    VOL_CAP_FMT_SYMBOLICLINKS |
	    VOL_CAP_FMT_HARDLINKS |
	    VOL_CAP_FMT_JOURNAL |
	    VOL_CAP_FMT_JOURNAL_ACTIVE |
	    VOL_CAP_FMT_NO_ROOT_TIMES |
	    VOL_CAP_FMT_SPARSE_FILES |
	    VOL_CAP_FMT_ZERO_RUNS |
	    VOL_CAP_FMT_CASE_SENSITIVE |
	    VOL_CAP_FMT_CASE_PRESERVING |
	    VOL_CAP_FMT_FAST_STATFS;

	volcaps->capabilities[VOL_CAPABILITIES_INTERFACES] = 0;

	volcaps->valid[VOL_CAPABILITIES_INTERFACES] =
	    VOL_CAP_INT_SEARCHFS |
	    VOL_CAP_INT_ATTRLIST |
	    VOL_CAP_INT_NFSEXPORT |
	    VOL_CAP_INT_READDIRATTR |
	    VOL_CAP_INT_EXCHANGEDATA |
	    VOL_CAP_INT_COPYFILE |
	    VOL_CAP_INT_ALLOCATE |
	    VOL_CAP_INT_VOL_RENAME |
	    VOL_CAP_INT_ADVLOCK |
	    VOL_CAP_INT_FLOCK;

	volcaps->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
	volcaps->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
	volcaps->valid[VOL_CAPABILITIES_RESERVED1] = 0;
	volcaps->valid[VOL_CAPABILITIES_RESERVED2] = 0;
	
	VFSATTR_SET_SUPPORTED(sbp, f_capabilities);
    }
    
    if (VFSATTR_IS_ACTIVE(sbp, f_attributes)) {
	vol_attributes_attr_t *volattr = &sbp->f_attributes;
	
	volattr->validattr.commonattr = 0;
	volattr->validattr.volattr =
	    ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
	volattr->validattr.dirattr = 0;
	volattr->validattr.fileattr = 0;
	volattr->validattr.forkattr = 0;
	
	volattr->nativeattr.commonattr = 0;
	volattr->nativeattr.volattr =
	    ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
	volattr->nativeattr.dirattr = 0;
	volattr->nativeattr.fileattr = 0;
	volattr->nativeattr.forkattr = 0;
	
	VFSATTR_SET_SUPPORTED(sbp, f_attributes);
    }

    if (VFSATTR_IS_ACTIVE(sbp, f_vol_name)) {
	(void) strncpy(sbp->f_vol_name, "afs", MAXPATHLEN);
	VFSATTR_SET_SUPPORTED(sbp, f_vol_name);
    }

    return 0;
}

int
nnpfs_sync(struct mount *mp, int waitfor, nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_sync: mp = %lx, waitfor = %d, "
			 "cred = %lx, proc = %lx\n",
			 (unsigned long)mp,
			 waitfor));
    return 0;
}

static int
nnpfs_vget(struct mount *mp, ino64_t ino, struct vnode ** vpp,
	   nnpfs_vfs_context ctx)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_vget\n"));
    return ENOTSUP;
}

static int
nnpfs_enotsup_vfs(void)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_enotsup_vfs\n"));
    return ENOTSUP;
}

/* used for reclaim */
static int
nnpfs_reclaim (struct vnop_reclaim_args *ap)
{
    NNPFSDEB(XDEBVFOPS, ("nnpfs_reclaim\n"));
    return 0;
}

static struct vnodeopv_entry_desc nnpfs_dead_vnodeop_entries[] = {
    {&vnop_default_desc, (vop_t *) nnpfs_enotsup_vfs},
    {&vnop_lookup_desc,	(vop_t *) nnpfs_dead_lookup},
    {&vnop_reclaim_desc, (vop_t *) nnpfs_reclaim},
    {NULL, NULL}};

static struct vnodeopv_desc nnpfs_dead_vnodeop_opv_desc =
{&nnpfs_dead_vnodeop_p, nnpfs_dead_vnodeop_entries};

extern struct vnodeopv_desc nnpfs_vnodeop_opv_desc;

struct vnodeopv_desc *nnpfs_vnodeopv_descs[] = {
    &nnpfs_vnodeop_opv_desc,
    &nnpfs_dead_vnodeop_opv_desc
};

static struct vfsops nnpfs_vfsops = {
    nnpfs_mount_context,
    nnpfs_start,
    nnpfs_unmount,
    nnpfs_root,
    nnpfs_quotactl,
    nnpfs_statfs, /* vfs_getattr really */
    nnpfs_sync,
    nnpfs_vget,
    nnpfs_fhtovp,
    nnpfs_vptofh,
    nnpfs_init,
    NULL			/* sysctl */
};

static vfstable_t nnpfs_vfc;

static struct vfs_fsentry nnpfs_vfe = {
    &nnpfs_vfsops,
    2, /* vopcnt */
    nnpfs_vnodeopv_descs,
    0, /* fstype */
    "nnpfs",
    VFS_TBLNOTYPENUM | VFS_TBLTHREADSAFE , /* XXX seems we're not threadsafe at this point */
    {0, 0} /* reserved */
};

int
nnpfs_install_filesys(void)
{
    return vfs_fsadd(&nnpfs_vfe, &nnpfs_vfc);
}

int
nnpfs_uninstall_filesys(void)
{
    return vfs_fsremove(nnpfs_vfc);
}

int
nnpfs_stat_filesys (void)
{
    return 0;
}
