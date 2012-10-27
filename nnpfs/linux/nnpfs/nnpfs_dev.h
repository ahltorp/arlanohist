/*
 * Copyright (c) 1995 - 2000, 2002, 2004 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_dev.h,v 1.15 2006/10/24 16:33:47 tol Exp $ */

#ifndef _nnpfs_dev_h
#define _nnpfs_dev_h

int nnpfs_init_device(void);

int nnpfs_message_send(struct nnpfs *nnpfsp,
		       struct nnpfs_message_header *message,
		       u_int size);

int nnpfs_message_rpc(struct nnpfs *nnpfsp,
		      struct nnpfs_message_header *message,
		      u_int size);

int nnpfs_message_rpc_async(struct nnpfs *nnpfsp,
			    struct nnpfs_message_header *message,
			    u_int size);

int nnpfs_message_receive(struct nnpfs *nnpfsp,
			  struct nnpfs_message_header *message,
			  u_int size);

int nnpfs_message_wakeup(struct nnpfs *nnpfsp,
			 struct nnpfs_message_wakeup *message,
			 u_int size);

void nnpfs_queue_inactive (struct nnpfs_node *xn);

typedef int (*predicate)(void *data);

int
nnpfs_dev_msleep(struct nnpfs *nnpfsp, wait_queue_head_t *wait_queue,
		 predicate donep, void *data);

#endif
