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

#ifndef _nnpfs_xnode_h
#define _nnpfs_xnode_h

#include <sys/types.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <nnpfs/nnpfs_attr.h>
#include <nnpfs/nnpfs_message.h>

#ifndef KERNEL
enum vcexcl	{ NONEXCL, EXCL};		/* (non)excl create (create) */
#endif

struct nnpfs_node {
  struct vnode vn;
  struct vattr attr;
  u_int flags;
  u_int tokens;
  nnpfs_handle handle;
  nnpfs_pag_t id[NNPFS_MAXRIGHTS];
  u_char rights[NNPFS_MAXRIGHTS];

  struct nnpfs_node *next;
};

#define DATA_FROM_VNODE(vp) ((struct vnode *) (vp)->v_data)
#define DATA_FROM_XNODE(xp) DATA_FROM_VNODE(XNODE_TO_VNODE(xp))

#define XNODE_TO_VNODE(xp) (&((xp)->vn))
#define VNODE_TO_XNODE(vp) ((struct nnpfs_node *) vp)

#endif /* _nnpfs_xnode_h */
