/*
 * Copyright (c) 1998 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_deb.h,v 1.6 2002/09/07 10:47:57 lha Exp $ */

#ifndef _nnpfs_deb_h
#define _nnpfs_deb_h

#include <nnpfs/nnpfs_debug.h>
#include <nnpfs/nnpfs_common.h>

extern int nnpfsdeb;

#ifdef DEBUG
#  define NNPFSDEB(mask, args) do { if (mask&nnpfsdeb) printf args; } while (0)
#else
#  define NNPFSDEB(args) do { ; } while (0)
#endif

#define HAVE_XDEBDEV 1
#define HAVE_XDEBMSG 1
#define HAVE_XDEBDNLC 1
#define HAVE_XDEBNODE 1

#define HAVE_XDEBVNOPS 1
#define HAVE_XDEBVFOPS 1
#define HAVE_XDEBLKM 1
#define HAVE_XDEBSYS 1

#endif /* _nnpfs_deb_h */
