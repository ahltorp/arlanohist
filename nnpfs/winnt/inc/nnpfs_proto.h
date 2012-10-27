/*
 * Copyright (c) 1999, 2002, 2003 Kungliga Tekniska Högskolan
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

/* nnpfs_vops.c */

#ifndef __NNPFS_PROTO_H
#define __NNPFS_PROTO_H
#define DEFINE_IRP(x) NTSTATUS x (PDEVICE_OBJECT device, PIRP irp)

DEFINE_IRP(nnpfs_create);
DEFINE_IRP(nnpfs_close);
DEFINE_IRP(nnpfs_readwrite);
DEFINE_IRP(nnpfs_fileinfo);
DEFINE_IRP(nnpfs_flush);
DEFINE_IRP(nnpfs_dirctl);
/* DEFINE_IRP(nnpfs_devctl); */
DEFINE_IRP(nnpfs_shutdown);
DEFINE_IRP(nnpfs_cleanup);
DEFINE_IRP(nnpfs_queryvol);
DEFINE_IRP(nnpfs_fscontrol);

DEFINE_IRP(nnpfs_fsd_create);
DEFINE_IRP(nnpfs_fsd_close);
DEFINE_IRP(nnpfs_fsd_readwrite);
DEFINE_IRP(nnpfs_fsd_fileinfo);
DEFINE_IRP(nnpfs_fsd_flush);
DEFINE_IRP(nnpfs_fsd_dirctl);
DEFINE_IRP(nnpfs_fsd_devctl);
DEFINE_IRP(nnpfs_fsd_shutdown);
DEFINE_IRP(nnpfs_fsd_cleanup);
DEFINE_IRP(nnpfs_fsd_queryvol);
DEFINE_IRP(nnpfs_fsd_fscontrol);

#undef DEFINE_IRP

void
nnpfs_path_winify(char *path);

int
nnpfs_data_valid(nnpfs_node *node, nnpfs_cred *cred,
		 u_int tok, uint32_t want_offset);

NTSTATUS
nnpfs_lookup_path(struct nnpfs_channel *chan,
		char *path,
		nnpfs_node *relnode,
		nnpfs_node **node,
		nnpfs_lookup_args *args,
		nnpfs_cred *cred,
		int loop);

NTSTATUS
nnpfs_fsync(nnpfs_node *node, nnpfs_cred *cred, u_int flag);

/* nnpfs_deb.c */

LONG
nnpfs_log_new_seq (void);

void
nnpfs_log(PDEVICE_OBJECT device, ULONG UniqueId,
	NTSTATUS ErrorCode, NTSTATUS Status);

void
nnpfs_debug (unsigned long level, char *fmt, ...);

nnpfs_ccb *
nnpfs_get_ccb (void);

void
nnpfs_release_ccb (nnpfs_ccb *ccb);

struct nnpfs_link *
nnpfs_alloc_link (struct nnpfs_channel *chan, int flags, ULONG tag);

void
nnpfs_free_link (struct nnpfs_channel *chan, struct nnpfs_link *link);

void *
nnpfs_alloc (size_t size, ULONG tag);

void
nnpfs_free (void *ptr, size_t size);

size_t
strlcpy (char *dst, const char *src, size_t dst_sz);

void *
nnpfs_get_buffer(PIRP irp);

void
nnpfs_initq(struct nnpfs_link *q);

int
nnpfs_emptyq(const struct nnpfs_link *q);

int
nnpfs_onq(const struct nnpfs_link *link);

void
nnpfs_appendq(struct nnpfs_link *q, struct nnpfs_link *p);

void
nnpfs_outq(struct nnpfs_link *p);

struct nnpfs_link *
nnpfs_firstlink (struct nnpfs_link *head);

struct nnpfs_link *
nnpfs_nextlink (struct nnpfs_link *head, struct nnpfs_link *prev);

#endif
