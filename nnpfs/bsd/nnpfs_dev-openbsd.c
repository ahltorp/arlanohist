/*
 * Copyright (c) 1995-2005, 2007 Kungliga Tekniska Högskolan
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


#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>

RCSID("$Id: nnpfs_dev-openbsd.c,v 1.4 2007/02/08 11:24:49 tol Exp $");

void
nnpfs_dev_lock(struct nnpfs *chan) 
{
    simple_lock(&chan->dev_lock);
}

void
nnpfs_dev_unlock(struct nnpfs *chan)
{
    simple_unlock(&chan->dev_lock);
}

int
nnpfs_dev_msleep(struct nnpfs *chan, caddr_t waitobj, int flags, const char *msg)
{
    int ret;
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_msleep %p %x %s\n", waitobj, flags, msg));

    simple_unlock(&chan->dev_lock);
    ret = nnpfs_tsleep(waitobj, flags, msg);
    simple_lock(&chan->dev_lock);

    return ret;
}

int
nnpfs_dev_initlock(struct nnpfs *chan)
{
    simple_lock_init(&chan->dev_lock);
    return 0;
}

void
nnpfs_dev_uninitlock(struct nnpfs *chan)
{
}


struct cdevsw nnpfs_cdev = {
    nnpfs_devopen,
    nnpfs_devclose,
    nnpfs_devread,
    nnpfs_devwrite,
    nnpfs_devioctl,
    (dev_type_stop((*))) enodev,
    0,
#if OpenBSD >= 200405
    nnpfs_devpoll,
#else
    nnpfs_devselect,
#endif
    (dev_type_mmap((*))) enodev,
    0
};
