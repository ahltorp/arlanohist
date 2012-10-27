/*
 * Copyright (c) 1995 - 2008 Kungliga Tekniska Högskolan
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
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_vnodeops.h>
#include <nnpfs/nnpfs_node.h>

RCSID("$Id: nnpfs_node-bsd.c,v 1.101 2008/02/26 21:59:09 tol Exp $");

extern vop_t **nnpfs_vnodeop_p;

#ifndef LK_NOPAUSE
#define LK_NOPAUSE 0
#endif

/*
 * Allocate a new vnode with handle `handle' in `mp' and return it in
 * `vpp'.  Return 0 or error.
 */

int
nnpfs_getnewvnode(struct nnpfs *nnpfsp,
		  struct vnode **vpp, 
		  struct nnpfs_handle *handle, 
		  struct nnpfs_msg_node *node,
		  d_thread_t *p,
		  int isrootp)
{
    struct nnpfs_node *result, *check;
    int error;

    result = nnpfs_alloc(sizeof(*result), M_NNPFS_NODE);
    bzero(result, sizeof(*result));

#ifdef __APPLE__
    {
      struct vnode_fsparam p;

      if (!XA_VALID_TYPE(&node->attr)) {
	nnpfs_free(result, sizeof(*result), M_NNPFS_NODE);
	return EINVAL;
      }

      memset(&p, 0, sizeof(p));
      p.vnfs_mp = NNPFS_TO_VFS(nnpfsp);
      switch (node->attr.xa_type) {
      case NNPFS_FILE_NON:
	p.vnfs_vtype = VNON;
	break;
      case NNPFS_FILE_REG:
	p.vnfs_vtype = VREG;
	break;
      case NNPFS_FILE_DIR:
	p.vnfs_vtype = VDIR;
	break;
      case NNPFS_FILE_BLK:
	p.vnfs_vtype = VBLK;
	break;
      case NNPFS_FILE_CHR:
	p.vnfs_vtype = VCHR;
	break;
      case NNPFS_FILE_LNK:
	p.vnfs_vtype = VLNK;
	break;
      case NNPFS_FILE_SOCK:
	p.vnfs_vtype = VSOCK;
	break;
      case NNPFS_FILE_FIFO:
	p.vnfs_vtype = VFIFO;
	break;
      case NNPFS_FILE_BAD:
	p.vnfs_vtype = VBAD;
	break;
      default:
	printf("nnpfs_getnewnvode: bad value");
	nnpfs_free(result, sizeof(*result), M_NNPFS_NODE);
	return EINVAL;
      }
      p.vnfs_str = "arla";
      p.vnfs_dvp = NULL; /* parent vnode */
      p.vnfs_fsnode = result;
      p.vnfs_vops = nnpfs_vnodeop_p;
      p.vnfs_markroot = isrootp;
      p.vnfs_marksystem = 0;
      p.vnfs_rdev = 0;
      if (XA_VALID_SIZE(&node->attr))
	p.vnfs_filesize = node->attr.xa_size;
      else
	p.vnfs_filesize = 0;
      p.vnfs_cnp = NULL;
      p.vnfs_flags = 0; /* XXX VNFS_CANTCACHE? */

      error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &p, vpp);
    }
#else /* !__APPLE__ */

#if defined __FreeBSD__
    error = getnewvnode(VT_AFS, NNPFS_TO_VFS(nnpfsp), &nnpfs_vnodeops, vpp);
#else
    error = getnewvnode(VT_AFS, NNPFS_TO_VFS(nnpfsp), nnpfs_vnodeop_p, vpp);
#endif

    if (error == 0)
      (*vpp)->v_data = result;

#endif  /* !__APPLE__ */

    if (error)
	return error;
    
    result->vn = *vpp;
    
    result->handle = *handle;
    result->flags = 0;
    result->tokens = 0;
    result->index = NNPFS_NO_INDEX;

#ifndef __FreeBSD__
#if (defined(HAVE_KERNEL_LOCKMGR) || defined(HAVE_KERNEL_DEBUGLOCKMGR)) && !defined(__APPLE__)
    lockinit (&result->lock, PVFS, "nnpfs_lock", 0, LK_NOPAUSE);
#else
    result->vnlocks = 0;
#endif
#endif /* !__FreeBSD__ */

#ifdef __APPLE__
    result->writers = 0;
#endif

    result->anonrights = 0;
    nnpfs_setcred(&result->rd_cred, NOCRED);
    nnpfs_setcred(&result->wr_cred, NOCRED);

#if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 105280000
    genfs_node_init(*vpp, &nnpfs_genfsops);
#endif

#ifdef HAVE_KERNEL_INSMNTQUE
    error = insmntque(*vpp, NNPFS_TO_VFS(nnpfsp));
    if (error) {
      nnpfs_free(result, sizeof(*result), M_NNPFS_NODE);
      *vpp = NULL;
      return error;
    }
#endif

 retry:
    error = nnpfs_node_find(nnpfsp, handle, &check);
    if (error == ENOENT) {
	nnpfs_insert(&nnpfsp->nodehead, result);
	return 0;
    }

    if (nnpfs_do_vget(XNODE_TO_VNODE(check), 0, p))
	goto retry;
    
    nnpfs_vput(*vpp);
    *vpp = NULL;
    
    if (error == EISDIR) {
	nnpfs_vletgo(XNODE_TO_VNODE(check));
	return EEXIST;
    }
    
    *vpp = check->vn;

    return 0;
}

/*
 * Create a new nnpfs_node and make a vget
 *
 * Also prevents creation of duplicates. This happens
 * whenever there are more than one name to a file,
 * "." and ".." are common cases.  */

int
nnpfs_new_node(struct nnpfs *nnpfsp,
	       struct nnpfs_msg_node *node,
	       char *name,
	       struct nnpfs_node **xpp,
	       d_thread_t *p,
	       int isrootp)
{
    struct nnpfs_node *result;
    int error;

    NNPFSDEB(XDEBNODE, ("nnpfs_new_node (%d,%d,%d,%d)\n",
		      node->handle.a,
		      node->handle.b,
		      node->handle.c,
		      node->handle.d));

retry:
    /* Does not allow duplicates */
    error = nnpfs_node_find(nnpfsp, &node->handle, &result);
    if (error == ENOENT) {
	struct vnode *v;

	error = nnpfs_getnewvnode(nnpfsp, &v, &node->handle, node, p, isrootp);
	if (error)
	    return error;

	result = VNODE_TO_XNODE(v);
	result->anonrights = node->anonrights;
	nnpfs_store_attr(&node->attr, result, 1);
    
#ifndef __APPLE__
	result->vn->v_type = result->attr.va_type;
	if (isrootp)
	    NNPFS_MAKE_VROOT(result->vn);
#endif
    } else if (error == EISDIR) {
	/* node is about to be deleted */
	NNPFSDEB(XDEBNODE, ("nnpfs_new_node: node deleted\n"));
	return error;
    } else {
	/* Node is already cached */
	if (nnpfs_do_vget(XNODE_TO_VNODE(result), 0, p))
	    goto retry;

	if (result->flags & NNPFS_DATA_DIRTY)
	    XA_CLEAR_SIZE(&node->attr);
	nnpfs_store_attr(&node->attr, result, 0);
    }

    result->tokens |= node->tokens; /* XXX correct? */
    if ((result->tokens & NNPFS_DATA_MASK) && result->index == NNPFS_NO_INDEX) {
	printf("nnpfs_new_node: tokens and no data (%d,%d,%d,%d) \n",
	       node->handle.a, node->handle.b, node->handle.c, node->handle.d);
	result->tokens &= ~NNPFS_DATA_MASK;
    }

    /* XXX scary -- could this remove creator's privileges for existing node? */
    bcopy(node->id, result->id, sizeof(result->id));
    bcopy(node->rights, result->rights, sizeof(result->rights));

    *xpp = result;
    NNPFSDEB(XDEBNODE, ("return: nnpfs_new_node\n"));
    return 0;
}

/*
 * clear data handle
 *
 * this should always be called with dev lock held
 */
void
nnpfs_release_cachevn(struct nnpfs_node *node)
{
    nnpfs_assert(node->cache_vn);
#ifdef __APPLE__
    vnode_close(node->cache_vn, 0, NULL);
#else
    nnpfs_vletgo(node->cache_vn);
#endif

    node->cache_vn = NULL;
}

/*
 * clear data handle
 *
 * this should always be called with dev lock held
 */
void
nnpfs_release_data(struct nnpfs_node *node)
{
    NNPFS_TOKEN_CLEAR(node, ~0,
		      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
		      NNPFS_DATA_MASK | NNPFS_LOCK_MASK);

    if (node->index != NNPFS_NO_INDEX) {
	node->index = NNPFS_NO_INDEX;

#ifdef __APPLE__
	if (nnpfs_vnode_isdir(XNODE_TO_VNODE(node)))
	    nnpfs_release_cachevn(node);
#else
	nnpfs_release_cachevn(node);
#endif

	nnpfs_block_free_all(node);
    }
}

/*
 * free node.
 *
 * this should always be called with dev lock held
 */
void
nnpfs_free_node(struct nnpfs *nnpfsp, struct nnpfs_node *node)
{
    NNPFSDEB(XDEBNODE, ("nnpfs_free_node(%lx) (%d,%d,%d,%d)\n",
			(unsigned long)node,
			node->handle.a,
			node->handle.b,
			node->handle.c,
			node->handle.d));
    
    NNPQUEUE_REMOVE(node, &nnpfsp->freehead, nn_free);
    nnpfs_remove_node(&nnpfsp->nodehead, node);

    nnpfs_release_data(node);
    nnpfs_free(node, sizeof(*node), M_NNPFS_NODE);

    NNPFSDEB(XDEBNODE, ("nnpfs_free_node done\n"));
}

/*
 * FreeBSD 5.2-CURRENT and newer changed to API to vflush
 */

static int
nnpfs_vflush(struct mount *mp, int flags, d_thread_t *td)
{
#if defined(__FreeBSD__) && __FreeBSD_version > 502123
    return vflush(mp, 0, flags, td);
#elif __DragonFly__
    return vflush(mp, 0, flags);
#else
    return vflush(mp, NULL, flags);
#endif
}

int
nnpfs_free_all_nodes(struct nnpfs *nnpfsp, int flags, int unmountp)
{
    int error = 0;
    struct mount *mp = NNPFS_TO_VFS(nnpfsp);

    if (mp == NULL) {
	NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes already freed\n"));
	return 0;
    }

    NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes starting\n"));

    nnpfs_dnlc_purge_mp(mp);

    if (nnpfsp->root) {
	struct nnpfs_node *root = nnpfsp->root;
	NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes now removing root\n"));

	nnpfsp->root = NULL;
#if 0
	vgone(XNODE_TO_VNODE(root));
#else
	nnpfs_vletgo(XNODE_TO_VNODE(root)); /* XXX ? */
#endif
    }

    NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes root removed\n"));
    NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes now killing all remaining nodes\n"));

    /*
     * If we have a syncer vnode, release it (to emulate dounmount)
     * and the create it again when if we are going to need it.
     */

#ifdef HAVE_STRUCT_MOUNT_MNT_SYNCER
    if (!unmountp) {
	if (mp->mnt_syncer != NULL) {
#ifdef HAVE_KERNEL_VFS_DEALLOCATE_SYNCVNODE
	    vfs_deallocate_syncvnode(mp);
#else
	    /* 
	     * FreeBSD and OpenBSD uses different semantics,
	     * FreeBSD does vrele, and OpenBSD does vgone.
	     */
#if defined(__OpenBSD__)
	    vgone(mp->mnt_syncer);
#elif defined(__FreeBSD__) || defined(__DragonFly__)
	    vrele(mp->mnt_syncer);
#else
#error what os do you use ?
#endif
	    mp->mnt_syncer = NULL;
#endif
	}
    }
#endif

    error = nnpfs_vflush(mp, flags, nnpfsp->proc);
#ifdef HAVE_STRUCT_MOUNT_MNT_SYNCER
    if (!unmountp) {
	NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes not flushing syncer vnode\n"));
	if (mp->mnt_syncer == NULL)
	    if (vfs_allocate_syncvnode(mp))
		panic("failed to allocate syncer node when nnpfs daemon died");
    }
#endif

    if (error) {
	NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes: vflush() error == %d\n",
			  error));
	return error;
    }

    NNPFSDEB(XDEBNODE, ("nnpfs_free_all_nodes done\n"));
    return error;
}

#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)					\
	for ((var) = ((head)->lh_first);				\
		(var);							\
		(var) = ((var)->field.le_next))
#endif

#ifdef __APPLE__
void
vattr2nnpfs_attr(const struct nnpfs_vfs_vattr *va, struct nnpfs_attr *xa)
{
    /* XXX macos bitmask handling */
    bzero(xa, sizeof(*xa));
    if (VATTR_IS_ACTIVE(va, va_mode))
	XA_SET_MODE(xa, va->va_mode);
    if (VATTR_IS_ACTIVE(va, va_nlink))
	XA_SET_NLINK(xa, va->va_nlink);
    if (VATTR_IS_ACTIVE(va, va_data_size))
	XA_SET_SIZE(xa, nnpfs_vattr_get_size(va));
    if (VATTR_IS_ACTIVE(va, va_uid))
	XA_SET_UID(xa, va->va_uid);
    if (VATTR_IS_ACTIVE(va, va_gid))
	XA_SET_GID(xa, va->va_gid);
    if (VATTR_IS_ACTIVE(va, va_access_time))
	XA_SET_ATIME(xa, nnpfs_vattr_get_atime_sec(va));
    if (VATTR_IS_ACTIVE(va, va_modify_time))
	XA_SET_MTIME(xa, nnpfs_vattr_get_mtime_sec(va));
    if (VATTR_IS_ACTIVE(va, va_create_time))
	XA_SET_CTIME(xa, nnpfs_vattr_get_ctime_sec(va));
    if (VATTR_IS_ACTIVE(va, va_fileid))
	XA_SET_FILEID(xa, va->va_fileid);

    if (VATTR_IS_ACTIVE(va, va_type)) {
	switch (va->va_type) {
	case VNON:
	    xa->xa_type = NNPFS_FILE_NON;
	    break;
	case VREG:
	    xa->xa_type = NNPFS_FILE_REG;
	    break;
	case VDIR:
	    xa->xa_type = NNPFS_FILE_DIR;
	    break;
	case VBLK:
	    xa->xa_type = NNPFS_FILE_BLK;
	    break;
	case VCHR:
	    xa->xa_type = NNPFS_FILE_CHR;
	    break;
	case VLNK:
	    xa->xa_type = NNPFS_FILE_LNK;
	    break;
	case VSOCK:
	    xa->xa_type = NNPFS_FILE_SOCK;
	    break;
	case VFIFO:
	    xa->xa_type = NNPFS_FILE_FIFO;
	    break;
	case VBAD:
	    xa->xa_type = NNPFS_FILE_BAD;
	    break;
	default:
	    panic("vattr2nnpfs_attr: bad value");
	}
    }
}

#else

void
vattr2nnpfs_attr(const struct nnpfs_vfs_vattr *va, struct nnpfs_attr *xa)
{
    bzero(xa, sizeof(*xa));
    if (va->va_mode != (mode_t)VNOVAL)
	XA_SET_MODE(xa, va->va_mode);
    if (va->va_nlink != VNOVAL)
	XA_SET_NLINK(xa, va->va_nlink);
    if (nnpfs_vattr_get_size(va) != VNOVAL)
	XA_SET_SIZE(xa, nnpfs_vattr_get_size(va));
    if (va->va_uid != VNOVAL)
	XA_SET_UID(xa, va->va_uid);
    if (va->va_gid != VNOVAL)
	XA_SET_GID(xa, va->va_gid);
    if (nnpfs_vattr_get_atime_sec(va) != VNOVAL)
	XA_SET_ATIME(xa, nnpfs_vattr_get_atime_sec(va));
    if (nnpfs_vattr_get_mtime_sec(va) != VNOVAL)
	XA_SET_MTIME(xa, nnpfs_vattr_get_mtime_sec(va));
    if (nnpfs_vattr_get_ctime_sec(va) != VNOVAL)
	XA_SET_CTIME(xa, nnpfs_vattr_get_ctime_sec(va));
    if (va->va_fileid != VNOVAL)
	XA_SET_FILEID(xa, va->va_fileid);

    switch (va->va_type) {
    case VNON:
	xa->xa_type = NNPFS_FILE_NON;
	break;
    case VREG:
	xa->xa_type = NNPFS_FILE_REG;
	break;
    case VDIR:
	xa->xa_type = NNPFS_FILE_DIR;
	break;
    case VBLK:
	xa->xa_type = NNPFS_FILE_BLK;
	break;
    case VCHR:
	xa->xa_type = NNPFS_FILE_CHR;
	break;
    case VLNK:
	xa->xa_type = NNPFS_FILE_LNK;
	break;
    case VSOCK:
	xa->xa_type = NNPFS_FILE_SOCK;
	break;
    case VFIFO:
	xa->xa_type = NNPFS_FILE_FIFO;
	break;
    case VBAD:
	xa->xa_type = NNPFS_FILE_BAD;
	break;
    default:
	panic("vattr2nnpfs_attr: bad value");
    }
}
#endif

/*
 * Take care of updating the node's size
 */

void
nnpfs_setsize(struct nnpfs_node *xn, uint64_t size)
{
    struct vnode *vp = XNODE_TO_VNODE(xn);
    nnpfs_block_truncate(xn, size);
    nnpfs_set_vp_size(vp, size);
}

void
nnpfs_store_attr(const struct nnpfs_attr *xa, struct nnpfs_node *node, int clear_node)
{
    struct nnpfs_vfs_vattr *va = &node->attr;

    /* XXX proper macos bitmask handling */
    if (clear_node) {
#ifdef __APPLE__
	VATTR_INIT(va);
#else
	VATTR_NULL(va);
#endif
    }
    if (XA_VALID_MODE(xa))
	nnpfs_vattr_set(va, va_mode, xa->xa_mode);
    if (XA_VALID_NLINK(xa))
	nnpfs_vattr_set(va, va_nlink, xa->xa_nlink);
    if (XA_VALID_SIZE(xa)) {
	nnpfs_vattr_set_size(va, xa->xa_size);
	nnpfs_vattr_set_bytes(va, xa->xa_size);
	node->daemon_length = xa->xa_size;
    }
    if (XA_VALID_UID(xa))
	nnpfs_vattr_set(va, va_uid, xa->xa_uid);
    if (XA_VALID_GID(xa))
	nnpfs_vattr_set(va, va_gid, xa->xa_gid);
    if (XA_VALID_ATIME(xa)) {
	nnpfs_vattr_set_atime(va, xa->xa_atime, 0);
    }
    if (XA_VALID_MTIME(xa)) {
	nnpfs_vattr_set_mtime(va, xa->xa_mtime, 0);
    }
    if (XA_VALID_CTIME(xa)) {
	nnpfs_vattr_set_ctime(va, xa->xa_ctime, 0);
    }
    if (XA_VALID_FILEID(xa)) {
	nnpfs_vattr_set(va, va_fileid, xa->xa_fileid);
    }
    if (XA_VALID_TYPE(xa)) {
	switch (xa->xa_type) {
	case NNPFS_FILE_NON:
	    nnpfs_vattr_set(va, va_type, VNON);
	    break;
	case NNPFS_FILE_REG:
	    nnpfs_vattr_set(va, va_type, VREG);
	    break;
	case NNPFS_FILE_DIR:
	    nnpfs_vattr_set(va, va_type, VDIR);
	    break;
	case NNPFS_FILE_BLK:
	    nnpfs_vattr_set(va, va_type, VBLK);
	    break;
	case NNPFS_FILE_CHR:
	    nnpfs_vattr_set(va, va_type, VCHR);
	    break;
	case NNPFS_FILE_LNK:
	    nnpfs_vattr_set(va, va_type, VLNK);
	    break;
	case NNPFS_FILE_SOCK:
	    nnpfs_vattr_set(va, va_type, VSOCK);
	    break;
	case NNPFS_FILE_FIFO:
	    nnpfs_vattr_set(va, va_type, VFIFO);
	    break;
	case NNPFS_FILE_BAD:
	    nnpfs_vattr_set(va, va_type, VBAD);
	    break;
	default:
	    panic("nnpfs_attr2vattr: bad value");
	}
    }
    nnpfs_vattr_set(va, va_flags, 0);

#ifdef __APPLE__
    VATTR_RETURN(va, va_iosize, 8192);
    va->va_active = va->va_supported;
#else
    nnpfs_vattr_set(va, va_blocksize, 8192);
#endif
}

/*
 * A single entry DNLC for systems for handling long names that don't
 * get put into the system DNLC.
 */

struct long_entry {
    struct vnode *dvp, *vp;
    char name[MAXNAMLEN + 1];
    size_t len;
};

static struct long_entry tbl;

/*
 * Nuke the `tbl'
 */

static void
tbl_clear (void)
{
    tbl.dvp = tbl.vp = NULL;
    tbl.name[0] = '\0';
    tbl.len = 0;
}

/*
 * Set the entry in the `tbl'
 */

static void
tbl_enter (size_t len, const char *name, struct vnode *dvp, struct vnode *vp)
{
    tbl.len = len;
    bcopy(name, tbl.name, len);
    tbl.dvp = dvp;
    tbl.vp = vp;
}

/*
 * Lookup in tbl (`dvp', `name', `len') and return result in `res'.
 * Return -1 if succesful, otherwise 0.
 */

static int
tbl_lookup (struct componentname *cnp,
	    struct vnode *dvp,
	    struct vnode **res)
{
    if (tbl.dvp == dvp
	&& tbl.len == cnp->cn_namelen
	&& strncmp(tbl.name, cnp->cn_nameptr, tbl.len) == 0) {

	*res = tbl.vp;

#if defined(__APPLE__) || defined(__FreeBSD__) 
	/* darwin's cache_lookup gives us ref:ed nodes, imitate */
	nnpfs_do_vget(*res, cnp->cn_lkflags, nnpfs_cnp_to_proc(cnp)); /* NULL works on apple */
#elif defined(__NetBSD__)
	nnpfs_do_vget(*res, LK_EXCLUSIVE, nnpfs_cnp_to_proc(cnp));
#endif
	
	NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup: tbl_lookup found %p\n", *res));

	return -1;
    } else
	return 0;
}

/*
 * Store a componentname in the DNLC
 */

int
nnpfs_dnlc_enter(struct vnode *dvp,
	       nnpfs_componentname *cnp,
	       struct vnode *vp)
{
    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_enter_cnp(%lx, %lx, %lx)\n",
		      (unsigned long)dvp,
		      (unsigned long)cnp,
		      (unsigned long)vp));

    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_enter: calling cache_enter:"
		      "dvp = %lx, vp = %lx, cnp = (%s, %ld), "
		      "nameiop = %lu, flags = %lx\n",
		      (unsigned long)dvp,
		      (unsigned long)vp,
		      cnp->cn_nameptr, cnp->cn_namelen,
		      cnp->cn_nameiop, cnp->cn_flags));

#ifdef NCHNAMLEN
    if (cnp->cn_namelen <= NCHNAMLEN)
#endif
    {
	/*
	 * This is to make sure there's no negative entry already in the dnlc
	 */
	u_long save_nameiop;
	u_long save_flags;
	struct vnode *dummy;

	save_nameiop    = cnp->cn_nameiop;
	save_flags      = cnp->cn_flags;
	cnp->cn_nameiop = CREATE;
	cnp->cn_flags  &= ~MAKEENTRY;

/*
 * The version number here is not entirely correct, but it's conservative.
 * The real change is sys/kern/vfs_cache:1.20
 */

#if (defined(__NetBSD_Version__) && __NetBSD_Version__ >= 104120000) || (defined(OpenBSD) && OpenBSD > 200211)
	if (cache_lookup(dvp, &dummy, cnp) != -1) {
	    nnpfs_vfs_unlock(dummy, nnpfs_cnp_to_proc(cnp));
	    printf ("NNPFS PANIC WARNING! nnpfs_dnlc_enter: %s already in cache\n",
		    cnp->cn_nameptr);
	}
#elif defined(__DragonFly__)
	if (cache_lookup(dvp, NCPNULL, &dummy, NCPPNULL, cnp) != 0) {
	    printf ("NNPFS PANIC WARNING! nnpfs_dnlc_enter: %s already in cache\n",
		    cnp->cn_nameptr);
	}
#elif !defined(__APPLE__)
	if (cache_lookup(dvp, &dummy, cnp) != 0) {
	    printf ("NNPFS PANIC WARNING! nnpfs_dnlc_enter: %s already in cache\n",
		    cnp->cn_nameptr);
	}
#endif


	cnp->cn_nameiop = save_nameiop;
	cnp->cn_flags   = save_flags;
#ifdef __DragonFly__
	cache_enter(dvp, NCPNULL, vp, cnp);
#else
 	cache_enter(dvp, vp, cnp);
#endif
    }

    if (vp != NULL)
	tbl_enter (cnp->cn_namelen, cnp->cn_nameptr, dvp, vp);

    return 0;
}
		   

static void
nnpfs_cnp_init (struct componentname *cn,
		char *name,
		d_thread_t *proc, nnpfs_kernel_cred cred,
		int nameiop)
{
    bzero(cn, sizeof(*cn));
    cn->cn_nameptr = (char *)name;
    cn->cn_namelen = strlen(name);
    cn->cn_flags   = 0;
#ifdef __APPLE__
    cn->cn_hash = 0; /* Let the vfs compute the hash */
#elif defined(HAVE_KERNEL_NAMEI_HASH)
    {
	const char *cp = name + cn->cn_namelen;
	cn->cn_hash = namei_hash(name, &cp);
    }
#elif defined(HAVE_STRUCT_COMPONENTNAME_CN_HASH)
    {
	const unsigned char *p;

	cn->cn_hash = 0;
	for (p = cn->cn_nameptr; *p; ++p)
	    cn->cn_hash += *p;
    }
#endif
    cn->cn_nameiop = nameiop;
#if defined(__APPLE__)
    /* apple have not proc */
#elif defined(__DragonFly__)
    cn->cn_td = proc;
#elif defined(HAVE_FREEBSD_THREAD)
    cn->cn_thread = proc;
#else
#if defined(__NetBSD__) && __NetBSD_Version__ >= 399001400 /* 3.99.14 */
    cn->cn_lwp = proc;
#else
    cn->cn_proc = proc;
#endif
#endif

#if !defined(__APPLE__)
    cn->cn_cred = cred;
#endif
}


/*
 * Store (dvp, name, vp) in the DNLC
 */

int
nnpfs_dnlc_enter_name(struct vnode *dvp,
		      char *name,
		      struct vnode *vp)
{
    struct componentname cn;

    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_enter_name(%lx, \"%s\", %lx)\n",
		      (unsigned long)dvp,
		      name,
		      (unsigned long)vp));

    nnpfs_cnp_init (&cn, name, NULL, NULL, LOOKUP);
    return nnpfs_dnlc_enter (dvp, &cn, vp);
}

/*
 * Lookup (dvp, cnp) in the DNLC and return the result in `res'.
 * Return the result from cache_lookup.
 */

static int
nnpfs_dnlc_lookup_int(struct vnode *dvp,
		    nnpfs_componentname *cnp,
		    struct vnode **res)
{
    int error;
    u_long saved_flags;

    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup(%lx, \"%s\")\n",
		      (unsigned long)dvp, cnp->cn_nameptr));
    
    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup: calling cache_lookup:"
		      "dvp = %lx, cnp = (%s, %ld), flags = %lx\n",
		      (unsigned long)dvp,
		      cnp->cn_nameptr, cnp->cn_namelen,
		      cnp->cn_flags));

    saved_flags = cnp->cn_flags;
    cnp->cn_flags |= MAKEENTRY | LOCKPARENT | ISLASTCN;

#ifdef __DragonFly__
    error = cache_lookup(dvp, NCPNULL, res, NCPPNULL, cnp);
#else
    error = cache_lookup(dvp, res, cnp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
    /*
     * On modern Net/OpenBSD, cache_lookup returns 0 for successful
     * and -1 for not.
     */
    if (error == 0)
	error = -1;
    else if (error == -1)
	error = 0;
#endif

    cnp->cn_flags = saved_flags;

    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup: cache_lookup returned. "
		      "error = %d, *res = %lx\n", error,
		      (unsigned long)*res));
    return error;
}

/*
 * do the last (and locking protocol) portion of nnpfs_dnlc_lookup
 *
 * return:
 * -1 for succesful
 * 0  for failed
 */

static int
nnpfs_dnlc_lock(struct vnode *dvp,
	      nnpfs_componentname *cnp,
	      struct vnode **res)
{
    int error = 0;

    /*
     * Try to handle the (complex) BSD locking protocol.
     *
     * FreeBSD 6 and NetBSD take care of locking for us.
     */

#if !defined(__FreeBSD__) && !defined(__NetBSD__)
    if (*res == dvp) {		/* "." */
	nnpfs_vref(dvp);
    } else if (cnp->cn_flags & ISDOTDOT) { /* ".." */

	nnpfs_vfs_unlock(dvp, nnpfs_cnp_to_proc(cnp));
#ifndef __APPLE__
	error = nnpfs_do_vget(*res, LK_EXCLUSIVE, nnpfs_cnp_to_proc(cnp));
	nnpfs_vfs_writelock(dvp, nnpfs_cnp_to_proc(cnp));
#endif

    } else {
#ifndef __APPLE__
	error = nnpfs_do_vget(*res, LK_EXCLUSIVE, nnpfs_cnp_to_proc(cnp));
#endif
    }

#endif /* !__FreeBSD__ && !__NetBSD__*/

    if (error == 0)
	return -1;
    else
	return 0;
}

/*
 * Lookup (`dvp', `cnp') in the DNLC (and the local cache).
 *
 * Return -1 if succesful, 0 if not and ENOENT if the entry is known
 * not to exist.
 */

int
nnpfs_dnlc_lookup(struct vnode *dvp,
		nnpfs_componentname *cnp,
		struct vnode **res)
{
    int error = nnpfs_dnlc_lookup_int (dvp, cnp, res);
    if (error == 0)
	error = tbl_lookup (cnp, dvp, res);

    if (error != -1)
	return error;

    return nnpfs_dnlc_lock (dvp, cnp, res);
}

/*
 * Remove one entry from the DNLC
 */

void
nnpfs_dnlc_purge (struct vnode *vp)
{
    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_purge\n"));

    if (tbl.dvp == vp || tbl.vp == vp)
	tbl_clear ();

    cache_purge(vp);
}

/*
 * Remove all entries belong to `mp' from the DNLC
 */

void
nnpfs_dnlc_purge_mp(struct mount *mp)
{
    NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_purge_mp()\n"));

    tbl_clear ();
#ifndef __APPLE__
    cache_purgevfs(mp);
#endif
}

/*
 * Returns 1 if pag has any rights set in the node
 */

int
nnpfs_has_pag(const struct nnpfs_node *xn, nnpfs_pag_t pag)
{
    int i;

    for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	if (xn->id[i] == pag)
	    return 1;

    return 0;
}

void
nnpfs_setcred(nnpfs_cred *ncred, nnpfs_kernel_cred cred)
{
    if (cred == NOCRED) {
	ncred->uid = 0;
	ncred->pag = NNPFS_ANONYMOUSID;
    } else {
	ncred->uid = nnpfs_cred_get_uid(cred);
	ncred->pag = nnpfs_get_pag(cred);
    }
}
