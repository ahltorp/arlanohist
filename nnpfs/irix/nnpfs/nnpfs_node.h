/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska H�gskolan
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

/* $Id: nnpfs_node.h,v 1.8 2004/06/13 15:05:28 lha Exp $ */

#ifndef _nnpfs_xnode_h
#define _nnpfs_xnode_h

#include <sys/types.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <nnpfs/nnpfs_attr.h>
#include <nnpfs/nnpfs_message.h>

struct nnpfs_node {
  struct vnode *vn;
  struct vnode *data;
  struct vattr attr;
  u_int flags;
  u_int tokens;
  nnpfs_handle handle;
  nnpfs_pag_t id[NNPFS_MAXRIGHTS];
  u_char rights[NNPFS_MAXRIGHTS];
  u_char anonrights;
#if IRIX_64
  bhv_desc_t bh;		/* behavior descriptor */
#endif

  struct nnpfs_node *next;
};

#define DATA_FROM_VNODE(vp) DATA_FROM_XNODE(VNODE_TO_XNODE(vp))
#define DATA_FROM_XNODE(xp) ((xp)->data)

#if IRIX_64 /* 6.4 and above */

#define BHV_TO_XNODE(bh) ((struct nnpfs_node *)BHV_PDATA(bh))

#define XNODE_TO_VNODE(xp) ((xp)->vn)
#define VNODE_TO_XNODE(vp) BHV_TO_XNODE(VNODE_TO_FIRST_BHV(vp))

#else

#define XNODE_TO_VNODE(xp) ((xp)->vn)
#define VNODE_TO_XNODE(vp) ((struct nnpfs_node *) (vp)->v_data)

#endif

#endif /* _nnpfs_xnode_h */
