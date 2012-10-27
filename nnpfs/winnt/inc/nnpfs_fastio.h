/*
 * Copyright (c) 2002, Stockholms Universitet
 * (Stockholm University, Stockholm Sweden)
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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NNPFS_NNPFS_FASTIO_H
#define _NNPFS_NNPFS_FASTIO_H

BOOLEAN
nnpfs_fastio_possible(FILE_OBJECT *file,
		    LARGE_INTEGER *offset,
		    ULONG length,
		    BOOLEAN wait,
		    ULONG key,
		    BOOLEAN readp,
		    IO_STATUS_BLOCK *iostatus,
		    DEVICE_OBJECT *device);

BOOLEAN
nnpfs_fastio_read(FILE_OBJECT *file,
		LARGE_INTEGER *offset,
		ULONG length,
		BOOLEAN wait,
		ULONG key,
		void *buf,
		IO_STATUS_BLOCK *iostatus,
		DEVICE_OBJECT *device);

BOOLEAN
nnpfs_fastio_write(FILE_OBJECT *file,
		 LARGE_INTEGER *offset,
		 ULONG length,
		 BOOLEAN wait,
		 ULONG key,
		 void *buf,
		 IO_STATUS_BLOCK *iostatus,
		 DEVICE_OBJECT *device);

void
nnpfs_createsec_acq(FILE_OBJECT *FileObject);

void
nnpfs_createsec_rel(FILE_OBJECT *FileObject);

NTSTATUS
nnpfs_modwrite_acq (FILE_OBJECT *file,
		    LARGE_INTEGER *end,
		    ERESOURCE **release_resource,
		    DEVICE_OBJECT *device);
NTSTATUS
nnpfs_modwrite_rel (FILE_OBJECT *file,
		    ERESOURCE *release_resource,
		    DEVICE_OBJECT *device);

BOOLEAN
nnpfs_lazywrite_acq(void *context, BOOLEAN waitp);

void
nnpfs_lazywrite_rel(void *context);

BOOLEAN
nnpfs_readahead_acq(void *context, BOOLEAN waitp);

void
nnpfs_readahead_rel(void *context);

#endif /* _NNPFS_NNPFS_FASTIO_H */
