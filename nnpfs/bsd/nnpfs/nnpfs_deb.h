/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska H�gskolan
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

/* $Id: nnpfs_deb.h,v 1.12 2005/10/28 14:33:40 tol Exp $ */

#ifndef _nnpfs_deb_h
#define _nnpfs_deb_h

#include <nnpfs/nnpfs_debug.h>

#define HAVE_XDEBDEV
#define HAVE_XDEBMSG
#define HAVE_XDEBDNLC
#define HAVE_XDEBNODE
#define HAVE_XDEBVNOPS
#define HAVE_XDEBVFOPS
#define HAVE_XDEBLKM
#define HAVE_XDEBSYS
#define HAVE_XDEBMEM
#define HAVE_XDEBSYS

extern unsigned int nnpfsdeb;

#if defined(KERNEL) || defined(_KERNEL)

#ifdef __APPLE__
#include <kern/clock.h>
#endif

#ifdef __APPLE__
/* #define NNPFS_DEBUG_TIME 1 */
#endif

#ifdef NNPFS_DEBUG
#ifdef NNPFS_DEBUG_TIME
#define NNPFSDEB(mask, args) do { if (mask&nnpfsdeb) { \
	uint32_t nnpfs_debug_print_seconds; \
	uint32_t nnpfs_debug_print_useconds; \
	clock_get_calendar_microtime(&nnpfs_debug_print_seconds, \
				     &nnpfs_debug_print_useconds); \
	printf("%d.%06d\n", \
		nnpfs_debug_print_seconds, \
		nnpfs_debug_print_useconds); \
	printf args; }} while (0)
#else
#define NNPFSDEB(mask, args) do { if (mask&nnpfsdeb) printf args; } while (0)
#endif
#else
#define NNPFSDEB(mask, args) do { ; } while (0)
#endif

#endif /*KERNEL */

#endif				       /* _nnpfs_deb_h */