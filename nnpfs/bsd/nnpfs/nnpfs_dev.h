/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_dev.h,v 1.26 2007/03/28 12:05:47 tol Exp $ */

#ifndef _nnpfs_dev_h
#define _nnpfs_dev_h

#include <nnpfs/nnpfs.h>

/*
 * These are variant dependent
 */

void nnpfs_select_wakeup(struct nnpfs *);

int nnpfs_install_device(void);
int nnpfs_uninstall_device(void);

int nnpfs_install_filesys(void);
int nnpfs_may_uninstall_filesys(void);
int nnpfs_uninstall_filesys(void);

int nnpfs_stat_filesys(void);
int nnpfs_stat_device(void);

/*
 * And these should be generic
 */

int
nnpfs_dev_msleep(struct nnpfs *chan, caddr_t waitobj, int flags, const char *msg);

void nnpfs_dev_lock(struct nnpfs *chan);
void nnpfs_dev_unlock(struct nnpfs *chan);

int nnpfs_dev_initlock(struct nnpfs *chan);
void nnpfs_dev_uninitlock(struct nnpfs *chan);

int
nnpfs_devopen_common(nnpfs_dev_t dev);

int nnpfs_devopen(nnpfs_dev_t dev, int flag, int devtype, d_thread_t *proc);
int nnpfs_devclose(nnpfs_dev_t dev, int flag, int devtype, d_thread_t *proc);
int nnpfs_devioctl(nnpfs_dev_t dev, u_long cmd, caddr_t data, int flags,
		 d_thread_t *p);

#ifdef HAVE_THREE_ARGUMENT_SELRECORD
int nnpfs_devselect(nnpfs_dev_t dev, int which, void *wql, d_thread_t *p);
#else
int nnpfs_devselect(nnpfs_dev_t dev, int which, d_thread_t *p);
#endif

int
nnpfs_devclose_common(nnpfs_dev_t dev, d_thread_t *p);

int
nnpfs_devread(nnpfs_dev_t dev, struct uio * uiop, int ioflag);

int
nnpfs_devwrite(nnpfs_dev_t dev, struct uio *uiop, int ioflag);

#ifdef HAVE_VOP_POLL
int
nnpfs_devpoll(nnpfs_dev_t dev, int events, d_thread_t * p);
#endif

int
nnpfs_message_send(struct nnpfs *chan, struct nnpfs_message_header * message, u_int size);

int
nnpfs_message_rpc(struct nnpfs *nnpfsp,
		  struct nnpfs_message_header *message, u_int size,
		  d_thread_t *proc);

int
nnpfs_message_rpc_async(struct nnpfs *nnpfsp,
			struct nnpfs_message_header *message, u_int size,
			d_thread_t *proc);

int
nnpfs_message_receive(struct nnpfs *nnpfsp,
		    struct nnpfs_message_header *message,
		    u_int size,
		    d_thread_t *p);

int
nnpfs_message_wakeup(struct nnpfs *chan,
		   struct nnpfs_message_wakeup *message,
		   u_int size,
		   d_thread_t *p);

int
nnpfs_uprintf_device(void);

int
nnpfs_is_nnpfs_dev (nnpfs_dev_t dev);

#endif /* _nnpfs_dev_h */
