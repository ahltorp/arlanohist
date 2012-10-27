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

/* $Id: nnpfs_dev.h,v 1.4 2002/09/07 10:46:44 lha Exp $ */

#ifndef _nnpfs_dev_h
#define _nnpfs_dev_h

#include <nnpfs/nnpfs_common.h>

int nnpfs_devopen(dev_t *devp, int flags, int otyp, cred_t *credp);
int nnpfs_devclose(dev_t dev, int flags, int otyp, cred_t *credp);
int nnpfs_devread(dev_t dev, struct uio *uiop, cred_t *credp);
int nnpfs_devwrite(dev_t dev, struct uio *uiop, cred_t *credp);
int nnpfs_devioctl(dev_t dev, int cmd, int arg, int mode, cred_t *credp,
		 int *rvalp);
int nnpfs_chpoll(dev_t dev, short events, int anyyet,
	       short *reventsp, struct pollhead **phpp);

int nnpfs_install_device(void);
int nnpfs_uninstall_device(void);

int nnpfs_message_send (int fd,
		      struct nnpfs_message_header *message,
		      u_int size);

int nnpfs_message_rpc (int fd,
		     struct nnpfs_message_header *message,
		     u_int size);

int nnpfs_message_receive (int fd,
			 struct nnpfs_message_header *message,
			 u_int size);

int nnpfs_message_wakeup (int fd,
			struct nnpfs_message_wakeup *message,
			u_int size);

int nnpfs_message_wakeup_data (int fd,
			     struct nnpfs_message_wakeup_data *message,
			     u_int size);

#endif /* _nnpfs_dev_h */
