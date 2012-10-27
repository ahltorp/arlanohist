/*
 * Copyright (c) 2000-2002 Kungliga Tekniska H�gskolan
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

/*
 * For common usage of elf platforms
 *
 * $Id: lwp_elf.h,v 1.3 2003/09/21 23:52:47 lha Exp $
 */

#ifndef _C_LABEL
#if !defined(SYSV) && !defined(__ELF__) && !defined(AFS_SUN5_ENV)
#ifdef __STDC__
#define _C_LABEL(name)     _##name
#else
#define _C_LABEL(name)  _/**/name
#endif
#else /* SYSV || __ELF__ || AFS_SUN5_ENV */
#define _C_LABEL(name)  name
#endif
#endif /* _C_LABEL */

#ifndef ENTRY
#if !defined(SYSV) && !defined(__ELF__) && !defined(AFS_SUN5_ENV)
#ifdef __STDC__
#define ENTRY(name)    _##name##:
#else
#define ENTRY(name)     _/**/name/**/:
#endif
#else /* SYSV || __ELF__ || AFS_SUN5_ENV */
#define ENTRY(name)     name:
#endif
#endif /* _C_LABEL */
