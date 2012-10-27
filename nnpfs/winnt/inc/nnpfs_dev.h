/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_dev.h,v 1.5 2002/10/29 16:59:01 tol Exp $ */

#ifndef _nnpfs_dev_h
#define _nnpfs_dev_h

int
init_event (struct nnpfs_channel *chan);

int
nnpfs_message_send(struct nnpfs_channel *chan,
		 struct nnpfs_message_header * message,
		 u_int size);

int
nnpfs_message_rpc(struct nnpfs_channel *chan,
		struct nnpfs_message_header * message,
		u_int size);

int
nnpfs_message_receive(struct nnpfs_channel *chan,
		    struct nnpfs_message_header *message,
		    u_int size);

int
nnpfs_message_wakeup(struct nnpfs_channel *chan,
		   struct nnpfs_message_wakeup *message,
		   u_int size);

int
nnpfs_message_wakeup_data(struct nnpfs_channel *chan,
			struct nnpfs_message_wakeup_data * message,
			u_int size);

int
nnpfs_message_installroot(struct nnpfs_channel *chan,
			struct nnpfs_message_installroot * message,
			u_int size);

int
nnpfs_message_installnode(struct nnpfs_channel *chan,
			struct nnpfs_message_installnode * message,
			u_int size);

int
nnpfs_message_installattr(struct nnpfs_channel *chan,
			struct nnpfs_message_installattr * message,
			u_int size);

int
nnpfs_message_installdata(struct nnpfs_channel *chan,
			struct nnpfs_message_installdata * message,
			u_int size);

int
nnpfs_message_invalidnode(struct nnpfs_channel *chan,
			struct nnpfs_message_invalidnode * message,
			u_int size);

int
nnpfs_message_updatefid(struct nnpfs_channel *chan,
		      struct nnpfs_message_updatefid * message,
		      u_int size);

int
nnpfs_message_gc_nodes(struct nnpfs_channel *chan,
		     struct nnpfs_message_gc_nodes * message,
		     u_int size);

int
nnpfs_message_version(struct nnpfs_channel *chan,
		    struct nnpfs_message_version *message,
		    u_int size);

void
nnpfs_check_backfile(nnpfs_node *node);

#endif /* _nnpfs_dev_h */
