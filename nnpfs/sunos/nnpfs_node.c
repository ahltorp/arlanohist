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

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>

#include <sys/vfs.h>
#include <sys/dir.h>
#include <sys/ucred.h>
#include <sys/dnlc.h>

#ifdef __GNUC__
__inline
void *
memcpy(void *s1, const void *s2, long unsigned int n)
{
  bcopy(s2, s1, n);
  return s1;
}
#endif

/*
 * Create a new nnpfs_node and make a VN_HOLD()!
 *
 * Also prevents creation of duplicates. This happens
 * whenever there are more than one name to a file,
 * "." and ".." are common cases.
 */
#if defined(__STDC__)
struct nnpfs_node *new_nnpfs_node(struct nnpfs *nnpfsp, struct nnpfs_msg_node *node)
#else
struct
nnpfs_node *
new_nnpfs_node(nnpfsp, node)
     struct nnpfs *nnpfsp;
     struct nnpfs_msg_node *node;
#endif
{
  struct nnpfs_node *result;

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

      /* Init vnode part */
      result->vn.v_vfsmountedhere = 0;
      result->vn.v_op = &nnpfs_vnodeops;
      result->vn.v_filocks = 0;
      DATA_FROM_XNODE(result) = (struct vnode *) 0;
      nnpfs_attr2vattr (&node->attr, &result->attr, 1);
      VN_INIT(&result->vn, nnpfsp->vfsp,
	      result->attr.va_type, result->attr.va_rdev);
      
      result->handle = node->handle;
      result->flags = 0;
      result->tokens = 0;
      
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
  nnpfs_attr2vattr (&node->attr, &result->attr, 1);
  NNPFS_TOKEN_SET(result, NNPFS_ATTR_R, NNPFS_ATTR_MASK);
  bcopy(node->id, result->id, sizeof(result->id));
  bcopy(node->rights, result->rights, sizeof(result->rights));

  return result;
}

#if defined(__STDC__)
void free_nnpfs_node(struct nnpfs_node *node)
#else
void
free_nnpfs_node(node)
     struct nnpfs_node *node;
#endif
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
  nnpfs_free(node, sizeof(*node));

  NNPFSDEB(XDEBNODE, ("free_nnpfs_node done\n"));
}

#if defined(__STDC__)
void free_all_nnpfs_nodes(struct nnpfs *nnpfsp)
#else
void
free_all_nnpfs_nodes(nnpfsp)
     struct nnpfs *nnpfsp;
#endif
{
  struct nnpfs_node *t;

  NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes starting\n"));

  nnpfs_dnlc_purge();		/* This is really a bit brutal! */
  NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes now removing root\n"));
  if (nnpfsp->root)
    {
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

#if defined(__STDC__)
struct nnpfs_node *nnpfs_node_find(struct nnpfs *nnpfsp, nnpfs_handle *handlep)
#else
struct
nnpfs_node *
nnpfs_node_find(nnpfsp, handlep)
     struct nnpfs *nnpfsp;
     nnpfs_handle *handlep;
#endif
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

#ifdef __STDC__
int nnpfs_dnlc_enter(struct vnode *dvp, char *nm, struct vnode *vp)
#else
int 
nnpfs_dnlc_enter(dvp, nm, vp)
     struct vnode *dvp;
     char *nm;
     struct vnode *vp;
#endif
{
  int len;
  
  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_enter(0x%x, \"%s\", 0x%x)\n",
		    (int) dvp, nm, (int) vp));

  len = strlen(nm);
  if (len <= NC_NAMLEN)
    return dnlc_enter(dvp, nm, vp, NOCRED);

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

#ifdef __STDC__
struct vnode *nnpfs_dnlc_lookup(struct vnode *dvp, char *nm)
#else
struct vnode *
nnpfs_dnlc_lookup(dvp, nm)
     struct vnode *dvp;
     char *nm;
#endif
{
  struct vnode *res;

  NNPFSDEB(XDEBDNLC, ("nnpfs_dnlc_lookup(0x%x, \"%s\")\n", (int) dvp, nm));

  res = dnlc_lookup(dvp, nm, NOCRED);
  if (res)
    return res;
  else if (   (tbl.dvp == dvp)
	   && (*tbl.nm == *nm)
	   && (strncmp(tbl.nm, nm, tbl.len + 1) == 0))
    return tbl.vp;
  else
    return 0;
}

#ifdef __STDC__
void nnpfs_dnlc_purge(void)
#else
void
nnpfs_dnlc_purge()
#endif
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

/*
 * Is this correct?
 */

#ifndef VNOVAL
#define VNOVAL (-1)
#endif

#ifdef __STDC__
void
vattr2nnpfs_attr(const struct vattr *va, struct nnpfs_attr *xa)
#else
void
vattr2nnpfs_attr(va, xa)
const struct vattr *va;
struct nnpfs_attr *xa;
#endif
{
    bzero (xa, sizeof(*xa));
    if (va->va_mode != (u_short)VNOVAL)
	XA_SET_MODE(xa, va->va_mode);
    if (va->va_nlink != VNOVAL)
	XA_SET_NLINK(xa, va->va_nlink);
    if (va->va_size != (u_long)VNOVAL)
	XA_SET_SIZE(xa, va->va_size);
    if (va->va_uid != (uid_t)VNOVAL)
	XA_SET_UID(xa, va->va_uid);
    if (va->va_gid != (gid_t)VNOVAL)
	XA_SET_GID(xa, va->va_gid);
    if (va->va_atime.tv_sec != VNOVAL)
	XA_SET_ATIME(xa, va->va_atime.tv_sec);
    if (va->va_mtime.tv_sec != VNOVAL)
	XA_SET_MTIME(xa, va->va_mtime.tv_sec);
    if (va->va_ctime.tv_sec != VNOVAL)
	XA_SET_CTIME(xa, va->va_ctime.tv_sec);
    if (va->va_nodeid != VNOVAL)
	XA_SET_FILEID(xa, va->va_nodeid);
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
    case VSOCK :
	xa->xa_type = NNPFS_FILE_SOCK;
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

#ifdef __STDC__
void
nnpfs_attr2vattr(const struct nnpfs_attr *xa, struct vattr *va, int clear_node)
#else
void
nnpfs_attr2vattr(xa, va, clear_node)
const struct nnpfs_attr *xa;
struct vattr *va;
int clear_node;
#endif
{
    if (clear_node)
	vattr_null(va);
    if (XA_VALID_MODE(xa))
	va->va_mode  = xa->xa_mode;
    if (XA_VALID_NLINK(xa))
	va->va_nlink = xa->xa_nlink;
    if (XA_VALID_SIZE(xa))
	va->va_size  = xa->xa_size;
    if (XA_VALID_UID(xa))
	va->va_uid   = xa->xa_uid;
    if (XA_VALID_GID(xa))
	va->va_gid   = xa->xa_gid;
    if (XA_VALID_ATIME(xa)) {
	va->va_atime.tv_sec  = xa->xa_atime;
	va->va_atime.tv_usec = 0;
    }
    if (XA_VALID_MTIME(xa)) {
	va->va_mtime.tv_sec  = xa->xa_mtime;
	va->va_mtime.tv_usec = 0;
    }
    if (XA_VALID_CTIME(xa)) {
	va->va_ctime.tv_sec  = xa->xa_ctime;
	va->va_ctime.tv_usec = 0;
    }
    if (XA_VALID_FILEID(xa)) {
	va->va_nodeid = xa->xa_fileid;
    }
    if (XA_VALID_TYPE(xa)) {
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
	case NNPFS_FILE_SOCK :
	    va->va_type = VSOCK;
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
    va->va_blocksize = VNOVAL;
}
