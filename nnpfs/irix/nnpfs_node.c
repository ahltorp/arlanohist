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

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>

RCSID("$Id: nnpfs_node.c,v 1.14 2004/06/13 15:04:00 lha Exp $");

/*
 * Create a new nnpfs_node and make a VN_HOLD()!
 *
 * Also prevents creation of duplicates. This happens
 * whenever there are more than one name to a file,
 * "." and ".." are common cases.
 */
struct nnpfs_node *
new_nnpfs_node(struct nnpfs *nnpfsp, struct nnpfs_msg_node *node)
{
  struct nnpfs_node *result;
  struct vattr vattr;

  NNPFSDEB(XDEBNODE, ("new_nnpfs_node: node = %x\n",
		    (int)node));

  NNPFSDEB(XDEBNODE, ("new_nnpfs_node %d.%d.%d.%d\n",
		   node->handle.a,
		   node->handle.b,
		   node->handle.c,
		   node->handle.d));

  nnpfs_attr2vattr (&node->attr, &vattr, 1);

  /* Does not allow duplicates */
  result = nnpfs_node_find(nnpfsp, &node->handle);
  if (result == 0) {
      int error;

      result = nnpfs_alloc (sizeof(*result));
      if (result == NULL) {
	  printf ("nnpfs_alloc(%d) failed\n", sizeof(*result));
	  panic ("new_nnpfs_node: you lose\n");
      }

#if IRIX_64

      result->vn = vn_alloc (NNPFS_TO_VFS(nnpfsp), vattr.va_type, vattr.va_rdev);
      if (result->vn == NULL) {
	  panic ("new_nnpfs_node: vn_alloc failed\n");
      }

      bhv_desc_init(&result->bh, result, result->vn, &nnpfs_vnodeops);
      bhv_insert_initial (&result->vn->v_bh, &result->bh);

#else

      result->vn = vn_alloc (&nnpfs_vnodeops, NNPFS_TO_VFS(nnpfsp), vattr.va_type,
			     vattr.va_rdev, result);
      if (result->vn == NULL) {
	  panic ("new_nnpfs_node: vn_alloc failed\n");
      }
#endif

      /* init xnode */
      DATA_FROM_XNODE(result) = (struct vnode *) 0;
      /* result->attr = vattr; */
      result->handle = node->handle;
      result->flags = 0;
      result->tokens = 0;
      result->anonrights = node->anonrights;
      
      /* Save reference on list */
      result->next = nnpfsp->nodes;
      nnpfsp->nodes = result;
      nnpfsp->nnodes++;
    }
  else
    {
      /* Node is already cached */
      VN_HOLD(XNODE_TO_VNODE(result));
    }

  /* Init other fields */

  result->attr = vattr;
  result->tokens = node->tokens;
  bcopy((caddr_t)node->id,
	(caddr_t)result->id, sizeof(result->id));
  bcopy((caddr_t)node->rights,
	(caddr_t)result->rights, sizeof(result->rights));

  return result;
}

void
free_nnpfs_node(struct nnpfs_node *node)
{
  struct nnpfs *nnpfsp = NNPFS_FROM_XNODE(node);
  struct nnpfs_node *t;

  NNPFSDEB(XDEBNODE, ("free_nnpfs_node starting\n"));

  /* First remove from chain. */
  if (node == nnpfsp->nodes)
    {
      nnpfsp->nodes = node->next;
    }
  else
    {
      for (t = nnpfsp->nodes; t->next; t = t->next)
	if (t->next == node)
	  {
	    t->next = t->next->next;
	    goto done;
	  }
      printf("NNPFS PANIC Error: free_nnpfs_node(0x%x) failed?\n", (int) node);
      return;
    }

 done:
  /* XXX Really need to put back dirty data first. */
  if (DATA_FROM_XNODE(node))
    {
      VN_RELE(DATA_FROM_XNODE(node));
    }
  nnpfsp->nnodes--;

#if IRIX_64
  bhv_remove(&XNODE_TO_VNODE(node)->v_bh, &node->bh);
#else
  XNODE_TO_VNODE(node)->v_data = NULL;
#endif
  nnpfs_free(node, sizeof(*node));

  NNPFSDEB(XDEBNODE, ("free_nnpfs_node done\n"));
}

void
free_all_nnpfs_nodes(struct nnpfs *nnpfsp)
{
  struct nnpfs_node *t;

  NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes starting\n"));

  nnpfs_dnlc_purge();		/* This is really a bit brutal! */
  NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes now removing root\n"));
  if (nnpfsp->root)
    {
	NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes: root = %x\n", nnpfsp->root));

      VN_RELE(XNODE_TO_VNODE(nnpfsp->root));
      nnpfsp->root = 0;
    }

  /* There might still be a few nodes out there, invalidate them */
  for (t = nnpfsp->nodes; t; t = t->next)
    {
      t->tokens = 0;
      if (DATA_FROM_XNODE(t))
	{
	  VN_RELE(DATA_FROM_XNODE(t));
	  DATA_FROM_XNODE(t) = (struct vnode *) 0;
	}
    }

  NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes done\n"));
}

struct nnpfs_node *
nnpfs_node_find(struct nnpfs *nnpfsp, nnpfs_handle *handlep)
{
  struct nnpfs_node *t;

  NNPFSDEB(XDEBNODE, ("nnpfs_node_find\n"));

  for (t = nnpfsp->nodes; t != 0; t = t->next)
    if (nnpfs_handle_eq(&t->handle, handlep))
      break;
  return t;
}

struct long_entry {
  struct vnode *dvp, *vp;
  char nm[MAXNAMELEN + 1];
  int len;
};

static struct long_entry tbl;

int
nnpfs_dnlc_enter(struct vnode *dvp, char *nm, struct vnode *vp)
{
  int len;
  
  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_enter(0x%x, \"%s\", 0x%x)\n",
		    (int) dvp, nm, (int) vp));

  len = strlen(nm);
  if (len <= NC_NAMLEN) {
#if IRIX_64
    dnlc_enter(dvp, nm, vp->v_fbhv, NOCRED);
#else
    dnlc_enter(dvp, nm, vp, NOCRED);
#endif
    return 0;
  }

  /* Be careful to HOLD first because dvp and vp
   * might be aliased to tbl.dvp or tbl.vp. */
  VN_HOLD(dvp);
  VN_HOLD(vp);
  if (tbl.dvp != 0)
    {
      VN_RELE(tbl.dvp);
      VN_RELE(tbl.vp);
    }
  bcopy(nm, tbl.nm, len);
  tbl.nm[len] = '\0';
  tbl.len = len;
  tbl.dvp = dvp;
  tbl.vp = vp; 
  return 0;
}

struct vnode *
nnpfs_dnlc_lookup(struct vnode *dvp, char *nm)
{
  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup(0x%x, \"%s\")\n", (int) dvp, nm));

#if IRIX_64
  {
    bhv_desc_t *res;

    res = dnlc_lookup(dvp, nm, NOCRED, 0 /* XXX ? */);
    if (res != NULL)
      return BHV_TO_VNODE(res);
  }
#else
  {
    struct vnode *res;

    res = dnlc_lookup(dvp, nm, NOCRED, 0 /* XXX ? */);
    if (res != NULL)
      return res;
  }
#endif
  if (   (tbl.dvp == dvp)
      && (*tbl.nm == *nm)
      && (strncmp(tbl.nm, nm, tbl.len + 1) == 0))
    return tbl.vp;
  else
    return 0;
}

void
nnpfs_dnlc_purge(void)
{
  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_purge()\n"));

  dnlc_purge();

  if (tbl.dvp)
    {
      VN_RELE(tbl.dvp);
      tbl.dvp = 0;
      VN_RELE(tbl.vp);
      tbl.vp = 0;
    }
}

void
nnpfs_dnlc_remove(vnode_t *dvp, char *name)
{
  dnlc_remove(dvp, name);

  if (tbl.dvp && tbl.dvp == dvp && strcmp(tbl.nm, name) == 0)
    {
      VN_RELE(tbl.dvp);
      tbl.dvp = 0;
      VN_RELE(tbl.vp);
      tbl.vp = 0;
    }
}

void
vattr2nnpfs_attr(const struct vattr *va, struct nnpfs_attr *xa)
{
    bzero ((caddr_t)xa, sizeof(*xa));
    if (va->va_mask & AT_MODE)
	XA_SET_MODE(xa, va->va_mode);
    if (va->va_mask & AT_NLINK)
	XA_SET_NLINK(xa, va->va_nlink);
    if (va->va_mask & AT_SIZE)
	XA_SET_SIZE(xa, va->va_size);
    if (va->va_mask & AT_UID)
	XA_SET_UID(xa, va->va_uid);
    if (va->va_mask & AT_GID)
	XA_SET_GID(xa, va->va_gid);
    if (va->va_mask & AT_ATIME)
	XA_SET_ATIME(xa, va->va_atime.tv_sec);
    if (va->va_mask & AT_MTIME)
	XA_SET_MTIME(xa, va->va_mtime.tv_sec);
    if (va->va_mask & AT_CTIME)
	XA_SET_CTIME(xa, va->va_ctime.tv_sec);
    if (va->va_mask & AT_NODEID)
	XA_SET_FILEID(xa, va->va_nodeid);
    if (va->va_mask & AT_TYPE) {
	switch(va->va_type) {
	case VNON :
	    xa->xa_type = NNPFS_FILE_NON;
	    break;
	case VREG :
	    xa->xa_type = NNPFS_FILE_REG;
	    break;
	case VDIR :
	    xa->xa_type = NNPFS_FILE_DIR;
	    break;
	case VBLK :
	    xa->xa_type = NNPFS_FILE_BLK;
	    break;
	case VCHR :
	    xa->xa_type = NNPFS_FILE_CHR;
	    break;
	case VLNK :
	    xa->xa_type = NNPFS_FILE_LNK;
	    break;
	case VFIFO :
	    xa->xa_type = NNPFS_FILE_FIFO;
	    break;
	case VBAD :
	    xa->xa_type = NNPFS_FILE_BAD;
	    break;
	default :
	    panic("vattr2nnpfs_attr: bad value");
	}
    }
}

void
nnpfs_attr2vattr(const struct nnpfs_attr *xa, struct vattr *va, int clear_attr)
{
    if (clear_attr)
	bzero((caddr_t)va, sizeof(*va));
    if (XA_VALID_MODE(xa)) {
	va->va_mode  = xa->xa_mode;
	va->va_mask |= AT_MODE;
    }
    if (XA_VALID_NLINK(xa)) {
	va->va_nlink = xa->xa_nlink;
	va->va_mask |= AT_NLINK;
    }
    if (XA_VALID_SIZE(xa)) {
	va->va_size  = xa->xa_size;
	va->va_blksize = 8192;
	va->va_nblocks = (xa->xa_size+8191)/8192;
	va->va_mask |= AT_SIZE|AT_BLKSIZE|AT_NBLOCKS;
    }
    if (XA_VALID_UID(xa)) {
	va->va_uid   = xa->xa_uid;
	va->va_mask |= AT_UID;
    }
    if (XA_VALID_GID(xa)) {
	va->va_gid   = xa->xa_gid;
	va->va_mask |= AT_GID;
    }
    if (XA_VALID_ATIME(xa)) {
	va->va_atime.tv_sec  = xa->xa_atime;
	va->va_atime.tv_nsec = 0;
	va->va_mask |= AT_ATIME;
    }
    if (XA_VALID_MTIME(xa)) {
	va->va_mtime.tv_sec  = xa->xa_mtime;
	va->va_mtime.tv_nsec = 0;
	va->va_mask |= AT_MTIME;
    }
    if (XA_VALID_CTIME(xa)) {
	va->va_ctime.tv_sec  = xa->xa_ctime;
	va->va_ctime.tv_nsec = 0;
	va->va_mask |= AT_CTIME;
    }
    if (XA_VALID_FILEID(xa)) {
	va->va_nodeid = xa->xa_fileid;
	va->va_mask |= AT_NODEID;
    }
    if (XA_VALID_TYPE(xa)) {
	va->va_mask |= AT_MODE;
	switch(xa->xa_type) {
	case NNPFS_FILE_NON :
	    va->va_type = VNON;
	    break;
	case NNPFS_FILE_REG :
	    va->va_type = VREG;
	    break;
	case NNPFS_FILE_DIR :
	    va->va_type = VDIR;
	    break;
	case NNPFS_FILE_BLK :
	    va->va_type = VBLK;
	    break;
	case NNPFS_FILE_CHR :
	    va->va_type = VCHR;
	    break;
	case NNPFS_FILE_LNK :
	    va->va_type = VLNK;
	    break;
	case NNPFS_FILE_FIFO :
	    va->va_type = VFIFO;
	    break;
	case NNPFS_FILE_BAD :
	    va->va_type = VBAD;
	    break;
	default :
	    panic("nnpfs_attr2vattr: bad value");
	}
    }
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
