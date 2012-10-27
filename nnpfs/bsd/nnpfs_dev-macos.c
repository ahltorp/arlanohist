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


#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_deb.h>

RCSID("$Id: nnpfs_dev-macos.c,v 1.3 2006/10/31 12:40:03 tol Exp $");

static lck_grp_t *lockgroup = NULL;
static int lockgroup_usecount = 0;

void
nnpfs_dev_lock(struct nnpfs *chan)
{
    thread_t me = current_thread();
    lck_mtx_lock(chan->lock.lock);
    while (chan->lock.recurse > 0 && chan->lock.locker != me) {
	/* XXX PCATCH */
	(void)nnpfs_msleep(&chan->lock, chan->lock.lock, (PZERO + 1), "nnpfslock");
    }
    chan->lock.locker = me;
    nnpfs_assert(chan->lock.recurse >= 0);
    chan->lock.recurse++;

    lck_mtx_unlock(chan->lock.lock);
}

void
nnpfs_dev_unlock(struct nnpfs *chan)
{
    thread_t me = current_thread();

    lck_mtx_lock(chan->lock.lock);
    chan->lock.recurse--;
    nnpfs_assert(chan->lock.recurse >= 0);
    nnpfs_assert(chan->lock.locker == me);

    if (chan->lock.recurse == 0) {
	chan->lock.locker = NULL;
	wakeup(&chan->lock);
    }

    lck_mtx_unlock(chan->lock.lock);
}

int
nnpfs_dev_msleep(struct nnpfs *chan, caddr_t waitobj, int flags, const char *msg)
{
    thread_t me = current_thread();
    int ret;
    lck_mtx_lock(chan->lock.lock);
    int nlocks = chan->lock.recurse;
    nnpfs_assert(chan->lock.recurse >= 0);
    nnpfs_assert(chan->lock.locker == me);

    chan->lock.recurse = 0;
    chan->lock.locker = NULL;
    wakeup(&chan->lock);

    ret = nnpfs_msleep(waitobj, chan->lock.lock, flags, msg);

    while (chan->lock.recurse > 0)
	/* XXX PCATCH, flags, ret? */
	(void)nnpfs_msleep(&chan->lock, chan->lock.lock, (PZERO + 1), "nnpfslock");
    
    nnpfs_assert(chan->lock.recurse == 0);
    chan->lock.locker = me;
    chan->lock.recurse = nlocks;

    lck_mtx_unlock(chan->lock.lock);
    return ret;
}

int
nnpfs_dev_initlock(struct nnpfs *chan)
{
    thread_t me = current_thread();
    lck_mtx_t *lock;
    if (chan->lock.lock != NULL)
	panic("nnpfs_dev_initlock: already inited!");

    if (lockgroup == NULL) {
	lockgroup = lck_grp_alloc_init("nnpfs", LCK_GRP_ATTR_NULL);

	if (lockgroup == NULL)
	    return -1;
    }

    lock = lck_mtx_alloc_init(lockgroup, LCK_ATTR_NULL);
    if (lock == NULL)
	return -1;

    lockgroup_usecount++;
    lck_mtx_lock(lock);
    chan->lock.locker = me;
    chan->lock.recurse = 1;

    chan->lock.lock = lock;
    lck_mtx_unlock(lock);

    return 0;
}

void
nnpfs_dev_uninitlock(struct nnpfs *chan)
{
    thread_t me = current_thread();
    if (chan->lock.lock == NULL)
	printf("nnpfs_dev_uninitlock: not inited!\n");
    
    lck_mtx_lock(chan->lock.lock);
    nnpfs_assert(chan->lock.recurse == 1);
    nnpfs_assert(chan->lock.locker == me);

    chan->lock.recurse = 0;
    chan->lock.locker = NULL;

    lck_mtx_free(chan->lock.lock, lockgroup);
    chan->lock.lock = NULL;

    lockgroup_usecount--;

    if (lockgroup_usecount == 0) {
	lck_grp_free(lockgroup);
	lockgroup = NULL;
    }
}

struct cdevsw nnpfs_cdev = {
      nnpfs_devopen,
      nnpfs_devclose,
      nnpfs_devread,
      nnpfs_devwrite,
      nnpfs_devioctl,
      eno_stop,
      eno_reset,
      0,
      nnpfs_devselect,
      eno_mmap,
      eno_strat,
      eno_getc,
      eno_putc,
      0
};
