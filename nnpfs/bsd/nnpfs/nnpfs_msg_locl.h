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

/* $Id: nnpfs_msg_locl.h,v 1.10 2007/03/28 12:05:47 tol Exp $ */

#ifndef _nnpfs_msg_locl_h
#define _nnpfs_msg_locl_h

int
nnpfs_message_installroot(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installroot * message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_installnode(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installnode * message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_installattr(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installattr * message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_installdata(struct nnpfs *nnpfsp,
			  struct nnpfs_message_installdata * message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_invalidnode(struct nnpfs *nnpfsp,
			  struct nnpfs_message_invalidnode * message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_updatefid(struct nnpfs *nnpfsp,
			struct nnpfs_message_updatefid * message,
			u_int size,
			d_thread_t *p);

int
nnpfs_message_gc(struct nnpfs *nnpfsp,
		 struct nnpfs_message_gc *message,
		 u_int size,
		 d_thread_t *p);

int
nnpfs_message_version(struct nnpfs *nnpfsp,
		      struct nnpfs_message_version *message,
		      u_int size,
		      d_thread_t *p);

int
nnpfs_message_delete_node(struct nnpfs *nnpfsp,
			  struct nnpfs_message_delete_node *message,
			  u_int size,
			  d_thread_t *p);

int
nnpfs_message_installquota(struct nnpfs *nnpfsp,
			   struct nnpfs_message_installquota *message,
			   u_int size,
			   d_thread_t *p);

#endif				       /* _nnpfs_msg_locl_h */
