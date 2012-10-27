/*
 * Copyright (c) 1995 - 2007 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_dev-freebsd.c,v 1.9 2007/03/06 13:19:03 tol Exp $");

#define NNPFS_FBSD_DEVLOCK

#if 1
void
nnpfs_dev_lock(struct nnpfs *chan) 
{
    d_thread_t *me = curthread;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_lock, me=%p\n", me));

    mtx_lock(&chan->lock.lock);

    while (chan->lock.recurse > 0 && chan->lock.locker != me) {
	/* XXX PCATCH */
#if 1
	(void)nnpfs_msleep(&chan->lock, &chan->lock.lock, (PZERO + 1), "nnpfslock");
#else
	int ret = 0;
	while msleep(&chan->lock, &chan->lock.lock, (PZERO + 1), "nnpfslock", 7 * hz);
	
#endif
    }

    chan->lock.locker = me;
    nnpfs_assert(chan->lock.recurse >= 0);
    chan->lock.recurse++;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_lock, locker %p\n", chan->lock.locker));

    mtx_unlock(&chan->lock.lock);
}

void
nnpfs_dev_unlock(struct nnpfs *chan)
{
    d_thread_t *me = curthread;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_unlock, me=%p locker=%p r=%d\n", me,
		       chan->lock.locker, chan->lock.recurse));
    
    mtx_lock(&chan->lock.lock);

    chan->lock.recurse--;
    nnpfs_assert(chan->lock.recurse >= 0);
    nnpfs_assert(chan->lock.locker == me);

    if (chan->lock.recurse == 0) {
	chan->lock.locker = NULL;
	wakeup(&chan->lock);
    }

    mtx_unlock(&chan->lock.lock);
}

int
nnpfs_dev_msleep(struct nnpfs *chan, caddr_t waitobj, int flags, const char *msg)
{
    d_thread_t *me = curthread;
    int ret, nlocks;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_msleep %p %x %s, me %p\n", waitobj, flags, msg, me));

    mtx_lock(&chan->lock.lock);
    nlocks = chan->lock.recurse;
    nnpfs_assert(chan->lock.recurse >= 0);
    nnpfs_assert(chan->lock.locker == me);

    chan->lock.recurse = 0;
    chan->lock.locker = NULL;
    wakeup(&chan->lock);

    ret = nnpfs_msleep(waitobj, &chan->lock.lock, flags, msg);

    while (chan->lock.recurse > 0)
	/* XXX PCATCH, flags, ret? */
	(void)nnpfs_msleep(&chan->lock, &chan->lock.lock, (PZERO + 1), "nnpfslock");
    
    nnpfs_assert(chan->lock.recurse == 0);
    chan->lock.locker = me;
    chan->lock.recurse = nlocks;

    mtx_unlock(&chan->lock.lock);
    return ret;
}

int
nnpfs_dev_initlock(struct nnpfs *chan)
{
    d_thread_t *me = curthread;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_initlock\n"));

    if (mtx_initialized(&chan->lock.lock))
	panic("nnpfs_dev_initlock: already inited!");

    mtx_init(&chan->lock.lock, "nnpfsdevlock", NULL, MTX_DEF);

    mtx_lock(&chan->lock.lock);
    chan->lock.locker = me;
    chan->lock.recurse = 1;
    mtx_unlock(&chan->lock.lock);

    return 0;
}

void
nnpfs_dev_uninitlock(struct nnpfs *chan)
{
    d_thread_t *me = curthread;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_uninitlock\n"));

    if (!mtx_initialized(&chan->lock.lock))
	printf("nnpfs_dev_uninitlock: not inited!\n");
    
    mtx_lock(&chan->lock.lock);
    nnpfs_assert(chan->lock.recurse == 1);
    nnpfs_assert(chan->lock.locker == me);

    chan->lock.recurse = 0;
    chan->lock.locker = NULL;

    /*
     * contrary to man page, it seems we need to unlock the mutex before
     * destroying it if we use spinlocks. Default mutexes are ok.
     */

    mtx_destroy(&chan->lock.lock);
}
#else

void
nnpfs_dev_lock(struct nnpfs *chan) 
{
    int ret;
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_lock\n"));
    ret = lockmgr(&chan->dev_lock, LK_EXCLUSIVE | LK_CANRECURSE, NULL);
    nnpfs_assert(!ret);
}

void
nnpfs_dev_unlock(struct nnpfs *chan)
{
    int ret;
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_unlock\n"));
    ret = lockmgr(&chan->dev_lock, LK_RELEASE, NULL);
    nnpfs_assert(!ret);
}

int
nnpfs_dev_msleep(struct nnpfs *chan, caddr_t waitobj, int flags, const char *msg)
{
    d_thread_t *td = curthread;
    int nlocks, i, ret;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_msleep %p %x %s\n", waitobj, flags, msg));

    ret = lockstatus(&chan->dev_lock, td);
    nnpfs_assert(ret == LK_EXCLUSIVE);

    nlocks = lockcount(&chan->dev_lock);
    
    for (i = nlocks; i > 0 ; i--) {
	ret = lockmgr(&chan->dev_lock, LK_RELEASE, NULL);
	nnpfs_assert(!ret);
    }

    ret = nnpfs_msleep(waitobj, &chan->dev_lock, flags, msg);
    return ret;
}

int
nnpfs_dev_initlock(struct nnpfs *chan)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_initlock\n"));
    lockinit(&chan->dev_lock, PRIBIO /* XXX */, "nnpfsdevlock", NULL, LK_CANRECURSE | LK_NOSHARE);
    return lockmgr(&chan->dev_lock, LK_EXCLUSIVE, NULL);
}

void
nnpfs_dev_uninitlock(struct nnpfs *chan)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_uninitlock\n"));
    lockdestroy(&chan->dev_lock);
}

#endif

#ifndef NNPFS_FBSD_DEVLOCK

#ifndef D_NEEDGIANT
#define D_NEEDGIANT 0
#endif

#endif

struct cdevsw nnpfs_cdev = {
#if __FreeBSD_version >= 502103
    d_version: D_VERSION,
#endif
    d_name: "nnpfs",
    d_open: nnpfs_devopen,
    d_close: nnpfs_devclose,
    d_read: nnpfs_devread,
    d_write: nnpfs_devwrite,
    d_ioctl: nnpfs_devioctl,
#ifdef HAVE_STRUCT_CDEVSW_D_MMAP
    d_mmap: nommap,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_STRATEGY
    d_strategy: nostrategy,
#endif
    /*
     * Giant is no longer needed, nnpfs_node_find & friends are locked
     * now, verify correctness before removing.
     */
#ifdef NNPFS_FBSD_DEVLOCK
    d_flags: 0,
#else
    d_flags: D_NEEDGIANT,
#endif

#ifdef HAVE_STRUCT_CDEVSW_D_STOP
    d_stop: nostop,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_RESET
    d_reset: noreset,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_BOGORESET
    d_bogoreset: noreset,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_DEVTOTTY
    d_devtotty: nodevtotty,
#endif
#if defined(HAVE_VOP_SELECT)
    d_select: nnpfs_devselect,
#elif defined(HAVE_VOP_POLL)
    d_poll: nnpfs_devpoll,
#else
#error select or poll: that is the question
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_BOGOPARMS
    d_bogoparms: noparms,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_SPARE
    d_spare: NULL,
#endif
#if __FreeBSD_version < 600007
    d_maj: 128,			/* XXX */
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_DUMP
    d_dump: nodump,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_PSIZE
    d_psize: nopsize,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_MAXIO
    d_maxio: 0,
#endif
#ifdef HAVE_STRUCT_CDEVSW_D_BMAJ
#ifdef NOUDEV
    d_bmaj: NOUDEV
#else
    d_bmaj: NODEV
#endif
#endif /* HAVE_STRUCT_CDEVSW_D_BMAJ */
};
