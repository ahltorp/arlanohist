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

RCSID("$Id: nnpfs_dev-bsd.c,v 1.53 2007/03/28 12:05:45 tol Exp $");

int
nnpfs_devopen(nnpfs_dev_t dev, int flag, int devtype, d_thread_t *proc)
{
    NNPFSDEB(XDEBDEV, ("nnpfsopen flag = %d, devtype = %d\n", flag, devtype));
    return nnpfs_devopen_common(dev);
}

int
nnpfs_devclose(nnpfs_dev_t dev, int flag, int devtype, d_thread_t *p)
{
#ifdef NNPFS_DEBUG
    char devname[64];
#endif

    NNPFSDEB(XDEBDEV, ("nnpfs_devclose dev = %s, flag = 0x%x\n",
		     nnpfs_devtoname_r(dev, devname, sizeof(devname)),
		     flag));
    return nnpfs_devclose_common(dev, p);
}

/*
 * Not used.
 */

int
nnpfs_devioctl(nnpfs_dev_t dev, 
	     u_long cmd,
	     caddr_t data,
	     int flags,
	     d_thread_t *p)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %d, cmd = %lu, "
		       "data = %lx, flags = %x\n",
		       minor(dev), (unsigned long)cmd,
		       (unsigned long)data, flags));
    return ENOTTY;
}

static int
nnpfs_realselect(nnpfs_dev_t dev, d_thread_t *p, void *wql)
{
    struct nnpfs *chan = &nnpfs_dev[minor(dev)];
    nnpfs_dev_lock(chan);

    if (!NNPQUEUE_EMPTY(&chan->messageq)) {
	nnpfs_dev_unlock(chan);
	return 1;		       /* Something to read */
    }

#ifdef __APPLE__
    selrecord (p, (struct selinfo *)&chan->selinfo, wql);
    /* XXX assert mbz */
#elif defined(HAVE_THREE_ARGUMENT_SELRECORD)
    selrecord (p, &chan->selinfo, wql);
#else
    selrecord (p, &chan->selinfo);
#endif

    nnpfs_dev_unlock(chan);
    return 0;
}


#ifdef HAVE_VOP_POLL
int
nnpfs_devpoll(nnpfs_dev_t dev, int events, d_thread_t * p)
{
#ifdef NNPFS_DEBUG
    char devname[64];
#endif

    NNPFSDEB(XDEBDEV, ("nnpfs_devpoll dev = %s, events = 0x%x\n",
		     nnpfs_devtoname_r (dev, devname, sizeof(devname)),
		     events));

    if ((events & (POLLIN|POLLRDNORM)) == 0)
	return 0;

    return nnpfs_realselect(dev, p, NULL);
}
#endif

#if defined(HAVE_VOP_SELECT) || defined(__APPLE__)
#ifdef HAVE_THREE_ARGUMENT_SELRECORD
int
nnpfs_devselect(nnpfs_dev_t dev, int which, void *wql, struct proc * p)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_devselect dev = %d, which = %d\n", dev, which));

    if (which != FREAD)
	return 0;

    return nnpfs_realselect(dev, p, wql);
}
#else
int
nnpfs_devselect(nnpfs_dev_t dev, int which, d_thread_t * p)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_devselect dev = %d, which = %d\n", dev, which));

    if (which != FREAD)
	return 0;

    return nnpfs_realselect(dev, p, NULL);
}
#endif
#endif

void
nnpfs_select_wakeup(struct nnpfs *chan)
{
#ifdef __APPLE__
    selwakeup ((struct selinfo*)&chan->selinfo);
    /* XXX assert mbz */
#else
    selwakeup (&chan->selinfo);
#endif
}

/*
 * Install and uninstall device.
 */

#if defined(__DragonFly__)
struct cdevsw nnpfs_cdev = {
    d_name: "nnpfs",
    d_maj: 128,
    d_flags: 0,
    d_port: NULL,
    d_clone: NULL,
    old_open: nnpfs_devopen,
    old_close: nnpfs_devclose,
    old_read: nnpfs_devread,
    old_write: nnpfs_devwrite,
    old_ioctl: nnpfs_devioctl,
    old_poll: nnpfs_devpoll,
    old_mmap: nommap,
    old_strategy: nostrategy,
    old_dump: nodump,
    old_psize: nopsize
};
#endif /* __DragonFly__ */

#if defined(__APPLE__)
extern int nnpfs_dev_major;
#include <miscfs/devfs/devfs.h>

static void *devfs_handles[NNNPFS];

#endif

extern struct cdevsw nnpfs_cdev;

int
nnpfs_install_device(void)
{
    int i;

#if defined(__APPLE__)
    nnpfs_dev_major = cdevsw_add(-1, &nnpfs_cdev);
    if (nnpfs_dev_major == -1) {
	NNPFSDEB(XDEBDEV, ("failed installing cdev\n"));
	return ENFILE;
    }

    for (i = 0; i < NNNPFS; ++i)
	devfs_handles[i] = devfs_make_node(makedev(nnpfs_dev_major, i),
					   DEVFS_CHAR,
					   UID_ROOT, GID_WHEEL, 0600,
					   "nnpfs%d", i);

    NNPFSDEB(XDEBDEV, ("done installing cdev !\n"));
    NNPFSDEB(XDEBDEV, ("Char device number %d\n", nnpfs_dev_major));
#endif

    for (i = 0; i < NNNPFS; i++) {
	struct nnpfs *chan = &nnpfs_dev[i];

	if (nnpfs_dev_initlock(chan))
	    return -1;

	chan->status = 0;
	nnpfs_dev_unlock(chan);
    }
    return 0;
}

int
nnpfs_uninstall_device(void)
{
    int i;
    struct nnpfs *chan;
    int ret = 0;

    for (i = 0; i < NNNPFS; i++) {
	chan = &nnpfs_dev[i];
	if (chan->status & CHANNEL_OPENED) {
#if defined(__DragonFly__)
            nnpfs_devclose(make_adhoc_dev(&nnpfs_cdev, i), 0, 0, NULL);
#elif defined(__FreeBSD__)
            nnpfs_devclose(chan->dev, 0, 0, NULL);
#else
	    nnpfs_devclose(makedev(0, i), 0, 0, NULL);
#endif
	}
	nnpfs_dev_lock(chan);
	nnpfs_dev_uninitlock(chan);
    }

#if defined(__APPLE__)
    for (i = 0; i < NNNPFS; ++i)
	devfs_remove (devfs_handles[i]);

    ret = cdevsw_remove(nnpfs_dev_major, &nnpfs_cdev);
    if (ret == -1) {
	NNPFSDEB(XDEBLKM, ("nnpfs_uninstall_device error %d\n", ret));
    } else if (ret == nnpfs_dev_major) {
	ret = 0;
    } else {
	NNPFSDEB(XDEBLKM, ("nnpfs_uninstall_device unexpected error error %d\n",
			   ret));
    }
#endif

    NNPFSDEB(XDEBLKM, ("nnpfs_uninstall_device error %d\n", ret));
    return ret;
}

int
nnpfs_stat_device(void)
{
    return nnpfs_uprintf_device();
}

#if !defined(_LKM) && !defined(KLD_MODULE) && !defined(__APPLE__)
int
nnpfs_is_nnpfs_dev(nnpfs_dev_t dev)
{
    return nnpfs_major(dev) <= nchrdev &&
	cdevsw[nnpfs_major(dev)].d_open == nnpfs_devopen &&
	nnpfs_minor(dev) >= 0 && nnpfs_minor(dev) < NNNPFS;
}
#endif
