/*
 * Copyright (c) 1995, 1996, 1997, 1998 Kungliga Tekniska Högskolan
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

#ifndef _nnpfs_common_h
#define _nnpfs_common_h

/*
 * To get u_int and friends.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <atypes.h>

/*
 * Defines for u_int32 and friends.
 */

#ifndef _PARAMS
#if defined(__STDC__) || defined(__cplusplus)
#define _PARAMS(ARGS) ARGS
#else
#define _PARAMS(ARGS) ()
#endif
#endif /* _PARAMS */

#ifndef MACRO_BEGIN
#define MACRO_BEGIN     do {
#endif
#ifndef MACRO_END
#define MACRO_END       } while (0)
#endif

#ifdef __STDC__
typedef void *opaque;
#else /* __STDC__ */
#define const
typedef char *opaque;
#endif /* __STDC__ */

extern void *nnpfs_alloc _PARAMS((u_int size));
extern void nnpfs_free _PARAMS((void *, u_int size));

#ifdef KERNEL
extern int uprintf _PARAMS((const char *format, ...));
extern int  printf _PARAMS((const char *format, ...));

extern int panic _PARAMS((const char *s));

extern int wakeup _PARAMS((const caddr_t chan));
extern int sleep _PARAMS((const caddr_t chan, int pri));
#ifdef __STDC__
#include <sys/proc.h>
#endif
extern int selwakeup _PARAMS((struct proc *p, int coll));

extern void bcopy _PARAMS((const void *from, void *to, int length));
extern int bcmp _PARAMS((const void *from, void *to, int length));
extern void bzero _PARAMS((void *, int length));

extern char *strncpy _PARAMS((char *, const char *, int));
extern int strncmp _PARAMS((const char *, const char *, int));
extern int strlen _PARAMS((const char*));

#ifdef __STDC__
#include <sys/time.h>
#include <sys/vnode.h>
#endif
extern int lookupname _PARAMS((char *, int, enum symfollow, struct vnode **, struct vnode **));

#ifdef __STDC__
#include <sys/uio.h>
#endif
extern int uiomove _PARAMS((caddr_t, int, enum uio_rw, struct uio *));

extern int 
dnlc_enter _PARAMS((struct vnode *, char *, struct vnode *, struct ucred *));
extern struct vnode *
dnlc_lookup _PARAMS((struct vnode *, char *, struct ucred *));
extern void dnlc_purge _PARAMS((void));

#endif /* KERNEL */

#endif /* _nnpfs_common_h */

