/*
 * Copyright (c) 1995, 1996, 1997, 1998 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_node.c,v 1.8 2004/06/13 15:03:01 lha Exp $");

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

  NNPFSDEB(XDEBNODE, ("new_nnpfs_node: node = %x\n",
		    (int)node));

  NNPFSDEB(XDEBNODE, ("new_nnpfs_node %d.%d.%d.%d\n",
		   node->handle.a,
		   node->handle.b,
		   node->handle.c,
		   node->handle.d));

  /* Does not allow duplicates */
  result = nnpfs_node_find(nnpfsp, &node->handle);
  if (result == 0)
    {
      result = nnpfs_alloc(sizeof(*result));
      if (result == 0)
	{
	  printf("nnpfs_alloc(%d) failed\n", (int)sizeof(*result));
	  panic("new_nnpfs_node: You Lose!");
	}

      result->vn.v_flag    = 0;
      result->vn.v_count   = 1;
      result->vn.v_vfsgen  = 0;
      result->vn.v_vfsp    = nnpfsp->vfsp;
      result->vn.v_mvfsp   = NULL;
      result->vn.v_gnode   = &result->gn;
      result->vn.v_next    = NULL;
#if 0
      result->vn.v_vfsnext = ;
      result->vn.v_vfsprev = ;
#endif
      result->vn.v_socket  = NULL;
      result->vn.v_audit   = NULL;

      nnpfs_attr2vattr (&node->attr, &result->attr, 1);

      result->gn.gn_type    = result->attr.va_type;
      result->gn.gn_flags   = 0;
      result->gn.gn_seg     = 0;
      result->gn.gn_mwrcnt  = 0;
      result->gn.gn_mrdcnt  = 0;
      result->gn.gn_rdcnt   = 0;
      result->gn.gn_wrcnt   = 0;
      result->gn.gn_excnt   = 0;
      result->gn.gn_rshcnt  = 0;
      result->gn.gn_ops     = &nnpfs_vnodeops;
      result->gn.gn_vnode   = &result->vn;
      result->gn.gn_rdev    = result->attr.va_rdev;
      result->gn.gn_chan    = 0;

      SET_DATA_FROM_XNODE(result, (struct vnode *)0);
      result->gn.gn_filocks = NULL;

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
      VNOP_HOLD(XNODE_TO_VNODE(result));
    }

  /* Init other fields */
  nnpfs_attr2vattr (&node->attr, &result->attr, 1);
  NNPFS_TOKEN_SET(result, NNPFS_ATTR_R, NNPFS_ATTR_MASK);
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
      VNOP_RELE(DATA_FROM_XNODE(node));
    }
  nnpfsp->nnodes--;
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
      VNOP_RELE(XNODE_TO_VNODE(nnpfsp->root));
      nnpfsp->root = 0;
    }

  /* There might still be a few nodes out there, invalidate them */
  for (t = nnpfsp->nodes; t; t = t->next)
    {
      t->tokens = 0;
      if (DATA_FROM_XNODE(t))
	{
	  VNOP_RELE(DATA_FROM_XNODE(t));
	  SET_DATA_FROM_XNODE(t, (struct vnode *) 0);
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
  char nm[MAXNAMLEN + 1];
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
#if 0
  if (len <= NC_NAMLEN) {
    dnlc_enter(dvp, nm, vp, NOCRED);
    return 0;
  }
#endif

  /* Be careful to HOLD first because dvp and vp
   * might be aliased to tbl.dvp or tbl.vp. */
  VNOP_HOLD(dvp);
  VNOP_HOLD(vp);
  if (tbl.dvp != 0)
    {
      VNOP_RELE(tbl.dvp);
      VNOP_RELE(tbl.vp);
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
  struct vnode *res;

  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup(0x%x, \"%s\")\n", (int) dvp, nm));

#if 0
  res = dnlc_lookup(dvp, nm, NOCRED);
#endif
  res = NULL;
  if (res)
    return res;
  else if (   (tbl.dvp == dvp)
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

#if 0
  dnlc_purge();
#endif

  if (tbl.dvp)
    {
      VNOP_RELE(tbl.dvp);
      tbl.dvp = 0;
      VNOP_RELE(tbl.vp);
      tbl.vp = 0;
    }
}

void
nnpfs_dnlc_remove(vnode_t *dvp, char *name)
{
#if 0
  dnlc_remove(dvp, name);
#endif

  if (tbl.dvp && tbl.dvp == dvp && strcmp(tbl.nm, name) == 0)
    {
      VNOP_RELE(tbl.dvp);
      tbl.dvp = 0;
      VNOP_RELE(tbl.vp);
      tbl.vp = 0;
    }
}

void
vattr2nnpfs_attr(const struct vattr *va, struct nnpfs_attr *xa)
{
    bzero ((caddr_t)xa, sizeof(*xa));
    XA_SET_MODE(xa, va->va_mode);
    XA_SET_NLINK(xa, va->va_nlink);
    XA_SET_SIZE(xa, va->va_size);
    XA_SET_UID(xa, va->va_uid);
    XA_SET_GID(xa, va->va_gid);
    XA_SET_ATIME(xa, va->va_atime.tv_sec);
    XA_SET_MTIME(xa, va->va_mtime.tv_sec);
    XA_SET_CTIME(xa, va->va_ctime.tv_sec);
    XA_SET_FILEID(xa, va->va_serialno);
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
	panic("nnpfs_attr2attr: bad value");
    }
}

void
nnpfs_attr2vattr(const struct nnpfs_attr *xa, struct vattr *va, int clear_node)
{
    if (clear_node)
	bzero((caddr_t)va, sizeof(*va));
    if (XA_VALID_MODE(xa))
	va->va_mode = xa->xa_mode;
    if (XA_VALID_NLINK(xa))
	va->va_nlink = xa->xa_nlink;
    if (XA_VALID_SIZE(xa)) {
	va->va_size  = xa->xa_size;
	va->va_blocksize = 8192;
	va->va_blocks = (xa->xa_size+8191)/8192;
    }
    if (XA_VALID_UID(xa))
	va->va_uid   = xa->xa_uid;
    if (XA_VALID_GID(xa))
	va->va_gid   = xa->xa_gid;
    if (XA_VALID_ATIME(xa)) {
	va->va_atime.tv_sec  = xa->xa_atime;
	va->va_atime.tv_nsec = 0;
    }
    if (XA_VALID_MTIME(xa)) {
	va->va_mtime.tv_sec  = xa->xa_mtime;
	va->va_mtime.tv_nsec = 0;
    }
    if (XA_VALID_CTIME(xa)) {
	va->va_ctime.tv_sec  = xa->xa_ctime;
	va->va_ctime.tv_nsec = 0;
    }
    if (XA_VALID_FILEID(xa))
	va->va_serialno = xa->xa_fileid;
    if (XA_VALID_TYPE(xa))
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
	    panic("nnpfs_attr2attr: bad value");
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
