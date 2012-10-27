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

/* $Id: nnpfs_fbuf.c,v 1.4 2002/10/29 16:59:04 tol Exp $ */

#include <nnpfs_locl.h>
#include <fbuf.h>

/*
 * Return a pointer to a copy of this file contents.
 * Create a fbuf with (fd, len, flags).
 * Returns 0 or error.
 */

int
fbuf_create (fbuf *f, HANDLE fd,
	     size_t len, fbuf_flags flags)
{
    NTSTATUS status;
    HANDLE section;
    void *buf = NULL;
    SIZE_T viewsize = 0;
    LARGE_INTEGER sectionsize;
    
    if (len != 0) {
	sectionsize.QuadPart = len;
	status = ZwCreateSection (&section, SECTION_MAP_READ, NULL,
				  &sectionsize, PAGE_READONLY, SEC_COMMIT, fd);
	if (NT_SUCCESS(status)) {
	    /* XXX map just len bytes? */
	    status = ZwMapViewOfSection (section, NtCurrentProcess(),
					 &buf, 0, viewsize, 
					 NULL, &viewsize, ViewShare,
					 0, // SEC_FILE|SEC_COMMIT, 
					 PAGE_READONLY); 

	    ZwClose(section);
	}

	if (!NT_SUCCESS(status)) {
	    nnpfs_debug(XDEBVNOPS, "fbuf_create: status %x!\n", status);
	    return status;
	}
    } else
	buf = NULL;

    f->buf   = buf;
    f->len   = viewsize;
    f->flags = flags;
    return 0;
}

/*
 * Change the size of the underlying file and the fbuf to `new_len'
 * bytes.
 * Returns 0 or error.
 */

int
fbuf_truncate (fbuf *f, size_t new_len)
{
    int ret = 0;
    return STATUS_SUCCESS;
/*    if (f->buf != NULL) {
	if (msync(f->buf, f->len, MS_ASYNC))
	    ret = errno;
	if (munmap (f->buf, f->len))
	    ret = errno;
	if (ret)
	    return ret;
    }
    ret = ftruncate (f->fd, new_len);
    if (ret < 0)
	return errno;
    return fbuf_create (f, f->fd, new_len, f->flags);
*/
}

/*
 * Undo everything we did in fbuf_create.
 * Returns 0 or error.
 */

int
fbuf_end (fbuf *f)
{
    return ZwUnmapViewOfSection(NtCurrentProcess(), f->buf);
}

/*
 * Accessor functions.
 */

size_t
fbuf_len (fbuf *f)
{
    return f->len;
}

/*
 * 
 */

void *
fbuf_buf (fbuf *f)
{
    return f->buf;
}
