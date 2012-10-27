/*
 * Copyright (c) 1995 - 2000, 2002, 2004-2006 Kungliga Tekniska Högskolan
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

/* $Id: abuf.h,v 1.2 2006/10/24 16:32:25 tol Exp $ */

#ifndef _ABUF_H_
#define _ABUF_H_

#include <fbuf.h>
#include <rx/rx.h>

int abuf_create(fbuf *f, FCacheEntry *entry, size_t len, fbuf_flags flags);
int abuf_truncate(FCacheEntry *entry, size_t new_len);
int abuf_truncate_block(FCacheEntry *entry, uint64_t offset, uint64_t blocklen);
int abuf_purge(FCacheEntry *entry);
int abuf_end(fbuf *fbuf);

size_t fbuf_len(fbuf *f);
void *fbuf_buf(fbuf *f);

int copyrx2cache(struct rx_call *call, FCacheEntry *entry, off_t off, off_t len);
int copycache2rx(FCacheEntry *entry, struct rx_call *call, off_t off, off_t len);

#endif /* _ABUF_H_ */
