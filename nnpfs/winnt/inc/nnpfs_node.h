/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
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

/* nnpfs_node.c */

#ifndef _NNPFS_NODE_H
#define _NNPFS_NODE_H 1

struct nnpfs_node *
nnpfs_node_find (struct nnpfs_channel *chan, struct nnpfs_handle *handle);

int
nnpfs_new_node (struct nnpfs_channel *chan,
		struct nnpfs_msg_node *node,
		struct nnpfs_node **npp);

void
nnpfs_free_node (struct nnpfs_node *node);

void
nnpfs_vref (struct nnpfs_node *node);

void
nnpfs_vrele (struct nnpfs_node *node);

void
nnpfs_vgone (struct nnpfs_node *node);

BOOLEAN
nnpfs_node_inuse (nnpfs_node *node, BOOLEAN flushp);

void
nnpfs_node_invalid(nnpfs_node* node);

void
nnpfs_node_gc_all(nnpfs_channel *chan, BOOLEAN force);

int
nnpfs_fhlookup (struct nnpfs_fhandle_t *fh, HANDLE *cache_node);

int
nnpfs_fhget (const char *path, struct nnpfs_fhandle_t *fh);

void
nnpfs_attr2vattr(const struct nnpfs_attr *xa, struct nnpfs_node *node);

void
vattr2nnpfs_attr(struct nnpfs_node *node, struct nnpfs_attr *xa);

void
nnpfs_close_data_handle (struct nnpfs_node *t);

int
nnpfs_open_file (nnpfs_node *node, const char *fname, HANDLE RelatedFile, 
		 int Disposition, int CreateOptions);

int
nnpfs_get_root (struct nnpfs_channel *chan);

#endif
