/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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

#ifndef _NNPFS_NNPFS_DEB_H
#define _NNPFS_NNPFS_DEB_H

#define NNPFSLOG_INIT_NUM		100
#define NNPFSLOG_INIT(x)		(NNPFSLOG_INIT_NUM+x)

#define NNPFSLOG_VOP_NUM		200
#define NNPFSLOG_CREATE		(NNPFSLOG_VOP_NUM+1)
#define NNPFSLOG_DEVCTL		(NNPFSLOG_VOP_NUM+2)

#define NNPFSLOG_QUERYVOL_NUM	300
#define NNPFSLOG_QUERYVOL(x)	(NNPFSLOG_QUERYVOL_NUM+x)

#define NNPFSDEB(mask, args) do { DbgPrint args; } while (0)

#if 0
#ifdef NNPFS_DEBUG
#define NNPFSDEB(mask, args) do { if (mask&nnpfsdeb) DbgPrint args; } while (0)
#else
#define NNPFSDEB(mask, args) do { ; } while (0)
#endif

#ifdef NNPFS_DEBUG
#define NNPFSBREAK() do { DbgBreakPoint(); } while (0)
#else
#define NNPFSBREAK() do { ; } while (0)
#endif
#endif
/*
 * Debugging FLAGS
 */

#include <nnpfs/nnpfs_debug.h>
#define XDEBTOL 0x2000

#endif
