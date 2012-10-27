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

RCSID("$Id: nnpfs_dev-common.c,v 1.82 2007/11/25 20:17:00 tol Exp $");

struct nnpfs nnpfs_dev[NNNPFS];

/* helper struct for sending messages without sleeping */
struct async_link {
    struct nnpfs_link this_link;
    struct nnpfs_message_header msg;
};

/*
 * Only allow one open.
 */
int
nnpfs_devopen_common(nnpfs_dev_t dev)
{
    struct nnpfs *chan;

    if (minor(dev) < 0 || minor(dev) >= NNNPFS)
	return ENXIO;

    chan = &nnpfs_dev[minor(dev)];

    nnpfs_dev_lock(chan);

    /* Only allow one reader/writer */
    if (chan->status & (CHANNEL_OPENED | CHANNEL_CLOSING)) {
	nnpfs_dev_unlock(chan);
	NNPFSDEB(XDEBDEV, ("nnpfs_devopen: already open\n"));
	return EBUSY;
    }

    chan->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE, M_NNPFS_MSG);

    /* initalize the queues */
    NNPFSDEB(XDEBDEV, ("nnpfs_devopen before queue init\n"));
    NNPQUEUE_INIT(&chan->messageq);
    NNPQUEUE_INIT(&chan->sleepq);

    chan->proc = NULL;
    chan->status |= CHANNEL_OPENED;

    nnpfs_dev_unlock(chan);

    return 0;
}

#if defined(__APPLE__)
#define nnpfs_vfs_busy(mp, flags, lock, proc) 0
#define nnpfs_vfs_unbusy(mp, proc)
#elif defined(HAVE_THREE_ARGUMENT_VFS_BUSY)
#define nnpfs_vfs_busy(mp, flags, lock, proc) vfs_busy((mp), (flags), (lock))
#define nnpfs_vfs_unbusy(mp, proc) vfs_unbusy((mp))
#elif defined(HAVE_FOUR_ARGUMENT_VFS_BUSY)
#define nnpfs_vfs_busy(mp, flags, lock, proc) vfs_busy((mp), (flags), (lock), (proc))
#define nnpfs_vfs_unbusy(mp, proc) vfs_unbusy((mp), (proc))
#else
#define nnpfs_vfs_busy(mp, flags, lock, proc) vfs_busy((mp), (flags))
#define nnpfs_vfs_unbusy(mp, proc) vfs_unbusy((mp))
#endif

/*
 * Wakeup all sleepers and cleanup.
 */
int
nnpfs_devclose_common(nnpfs_dev_t dev, d_thread_t *proc)
{
    struct nnpfs *chan = &nnpfs_dev[minor(dev)];
    struct nnpfs_link *first;
    
    nnpfs_dev_lock(chan);

    /* Sanity check, paranoia? */
    if (!(chan->status & CHANNEL_OPENED))
	panic("nnpfs_devclose never opened?");

    chan->status |= CHANNEL_CLOSING;
    chan->status &= ~CHANNEL_OPENED;

    /* No one is going to read those messages so empty queue! */
    while (!NNPQUEUE_EMPTY(&chan->messageq)) {
	NNPFSDEB(XDEBDEV, ("before outq(messageq)\n"));

	first = NNPQUEUE_FIRST(&chan->messageq);
	NNPQUEUE_REMOVE(first, &chan->messageq, qentry);
	if (first->error_or_size != 0)
	    nnpfs_free(first, first->error_or_size, M_NNPFS_LINK);

	NNPFSDEB(XDEBDEV, ("after outq(messageq)\n"));
    }

    /* Wakeup those waiting for replies that will never arrive. */
    while (!NNPQUEUE_EMPTY(&chan->sleepq)) {
	NNPFSDEB(XDEBDEV, ("before outq(sleepq)\n"));
	first = NNPQUEUE_FIRST(&chan->sleepq);
	NNPQUEUE_REMOVE(first, &chan->sleepq, qentry);
	first->error_or_size = ENODEV;
	wakeup((caddr_t) first);
	NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
    }

    if (chan->status & CHANNEL_WAITING)
	wakeup((caddr_t) chan);

    if (chan->status & NNPFS_QUOTAWAIT)
	wakeup((caddr_t)&chan->appendquota);

#ifdef __APPLE__ /* XXX should be nnpfs_dev_lock_cancel */
    wakeup((caddr_t)&chan->lock);
#endif

    if (chan->message_buffer) {
	nnpfs_free(chan->message_buffer, NNPFS_MAX_MSG_SIZE, M_NNPFS_MSG);
	chan->message_buffer = NULL;
    }

    /*
     * Free all nnpfs nodes.
     */

    if (chan->mp != NULL) {
	if (nnpfs_vfs_busy(chan->mp, 0, NULL, proc)) {
	    NNPFSDEB(XDEBNODE, ("nnpfs_dev_close: vfs_busy() --> BUSY\n"));
	    nnpfs_dev_unlock(chan);
	    return EBUSY;
	}

	nnpfs_dev_unlock(chan);
	nnpfs_free_all_nodes(chan, FORCECLOSE, 0);
	nnpfs_dev_lock(chan);
    
	nnpfs_vfs_unbusy(chan->mp, proc);
    }
    
    /* free all freed nodes */
    while (!NNPQUEUE_EMPTY(&chan->freehead)) {
	struct nnpfs_node *xn = NNPQUEUE_FIRST(&chan->freehead);
	nnpfs_free_node(chan, xn);
    }

#if 0 /* __APPLE__, but they don't refcount nnpfs_curproc/current_proc() */
    if (chan->proc != NULL)
	proc_rele(chan->proc);
#endif

    chan->proc = NULL;

    nnpfs_vfs_context_rele(chan->ctx);
    memset(&chan->ctx, 0, sizeof(chan->ctx));

    chan->status &= ~CHANNEL_CLOSING;

    nnpfs_dev_unlock(chan);

    return 0;
}

#ifdef NNPFS_DEBUG
/*
 * debugging glue for CURSIG
 */

static long
nnpfs_cursig (d_thread_t *p)
{
#if defined(HAVE_FREEBSD_THREAD)
#ifndef CURSIG
    return 0; /* XXX we would like to use sig_ffs, but that isn't
	       * exported */
#else
    return CURSIG(p->td_proc);
#endif
#else
#if defined(__NetBSD__) && __NetBSD_Version__ >= 106130000
    return 0; /* XXX CURSIG operates on a struct lwp */
#elif !defined(CURSIG)
    return 0;
#else
    return CURSIG(p);
#endif
#endif
}
#endif

/*
 * Move messages from kernel to user space.
 */

int
nnpfs_devread(nnpfs_dev_t dev, struct uio * uiop, int ioflag)
{
    struct nnpfs *chan = &nnpfs_dev[minor(dev)];
    struct nnpfs_link *first;
    int error = 0;
#ifdef NNPFS_DEBUG
    char devname[64];
#endif

    nnpfs_dev_lock(chan);

    NNPFSDEB(XDEBDEV, ("nnpfs_devread dev = %s\n",
		     nnpfs_devtoname_r(dev, devname, sizeof(devname))));

    if (chan->proc == NULL)
	chan->proc = nnpfs_curproc();

 again:

    if (!NNPQUEUE_EMPTY(&chan->messageq)) {
	while (!NNPQUEUE_EMPTY(&chan->messageq)) {
	    /* Remove message */
	    first = NNPQUEUE_FIRST(&chan->messageq);
	    NNPFSDEB(XDEBDEV, ("nnpfs_devread: first = %lx size = %u\n",
			       (unsigned long)first,
			       first->message->size));
	    
	    if (first->message->size > nnpfs_uio_resid(uiop))
		break;

	    error = uiomove((caddr_t) first->message, first->message->size, 
			    uiop);
	    if (error)
		break;
	    
	    NNPQUEUE_REMOVE(first, &chan->messageq, qentry);
	    
	    if (first->error_or_size != 0)
		nnpfs_free(first, first->error_or_size, M_NNPFS_LINK);
	}
    } else {
	int ret;
	chan->status |= CHANNEL_WAITING;

	ret = nnpfs_dev_msleep(chan, (caddr_t) chan,
			       (PZERO + 1) | PCATCH, "nnpfsread");
	if (ret) {
	    NNPFSDEB(XDEBMSG,
		     ("caught signal nnpfs_devread\n"));
	    error = EINTR;
	} else if ((chan->status & CHANNEL_WAITING) == 0) {
	    goto again;
	} else
	    error = EIO;
    }
    
    nnpfs_dev_unlock(chan);
    
    NNPFSDEB(XDEBDEV, ("nnpfs_devread done error = %d\n", error));

    return error;
}

/*
 * Move messages from user space to kernel space,
 * wakeup sleepers, insert new data in VFS.
 */
int
nnpfs_devwrite(nnpfs_dev_t dev, struct uio *uiop, int ioflag)
{
    struct nnpfs *chan = &nnpfs_dev[minor(dev)];
    char *p;
    int ret, error = 0;
    u_int cnt;
    struct nnpfs_message_header *msg_buf;
    d_thread_t *pp;
#ifdef NNPFS_DEBUG
    char devname[64];
#endif

    nnpfs_dev_lock(chan);

    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite dev = %s\n",
		       nnpfs_devtoname_r (dev, devname, sizeof(devname))));

    if (chan->proc == NULL)
	chan->proc = nnpfs_curproc();

    pp = chan->proc;

    cnt = nnpfs_uio_resid(uiop);
    error = uiomove((caddr_t) chan->message_buffer, NNPFS_MAX_MSG_SIZE, uiop);
    if (error != 0) {
	printf("nnpfs_devwrite: uiomove -> %d\n", error);
	nnpfs_dev_unlock(chan);
	return error;
    }

    cnt -= nnpfs_uio_resid(uiop);

    /*
     * This thread handles the received message.
     */

    p = (char *)chan->message_buffer;
    while (cnt > 0) {
	msg_buf = (struct nnpfs_message_header *)p;
	if (cnt < msg_buf->size) {
	    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite badly formed message\n"));
	    error = EINVAL;
	    break;
	}
	ret = nnpfs_message_receive(chan,
				     msg_buf,
				     msg_buf->size,
				     pp);
	if (ret)
	    error = ret;

	p += msg_buf->size;
	cnt -= msg_buf->size;
    }

    nnpfs_dev_unlock(chan);

    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite error = %d\n", error));
    return error;
}

/*
 * Send a message to user space.
 */
int
nnpfs_message_send(struct nnpfs *chan,
		   struct nnpfs_message_header *message, u_int size)
{
    struct async_link *t;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_send opcode = %d\n", message->opcode));

    if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
	return ENODEV;

    /* Prepare message and copy it later */
    message->size = size;
    message->sequence_num = chan->nsequence++;

    t = nnpfs_alloc(sizeof(t->this_link) + size, M_NNPFS_LINK);
    t->this_link.error_or_size = sizeof(t->this_link) + size;
    bcopy(message, &t->msg, size);

    t->this_link.message = &t->msg;
    NNPQUEUE_INSERT_TAIL(&chan->messageq, &t->this_link, qentry);
    if (chan->status & CHANNEL_WAITING) {
	chan->status &= ~CHANNEL_WAITING;
	wakeup((caddr_t) chan);
    }
    nnpfs_select_wakeup(chan);

    return 0;
}

#if defined(SWEXIT)
#define NNPFS_P_EXIT SWEXIT
#elif defined(P_WEXIT)
#define NNPFS_P_EXIT P_WEXIT
#elif defined(__APPLE__)
/* don't need it */
#else
#error what is your exit named ?
#endif

#if defined(HAVE_STRUCT_PROC_P_SIGMASK) || defined(HAVE_STRUCT_PROC_P_SIGCTX) || defined(HAVE_STRUCT_PROC_P_SIGWAITMASK) || defined(HAVE_FREEBSD_THREAD)
static void
nnpfs_block_sigset (sigset_t *sigset)
{

#if defined(__sigaddset)
#define nnpfs_sig_block(ss,signo) __sigaddset((ss), (signo))
#elif defined(SIGADDSET)
#define nnpfs_sig_block(ss,signo) SIGADDSET(*(ss), (signo))
#else
#define nnpfs_sig_block(ss,signo) *(ss) |= sigmask(signo)
#endif

    nnpfs_sig_block(sigset, SIGIO);
    nnpfs_sig_block(sigset, SIGALRM);
    nnpfs_sig_block(sigset, SIGVTALRM);
    nnpfs_sig_block(sigset, SIGCHLD);
#ifdef SIGINFO
    nnpfs_sig_block(sigset, SIGINFO);
#endif
#undef nnpfs_sig_block
}
#endif

/*
 * Send a message to user space and wait for reply.
 */

static int
nnpfs_message_rpc_int(struct nnpfs *chan,
		      struct nnpfs_message_header *message, u_int size,
		      d_thread_t *proc, int async)
{
    int ret;
    struct nnpfs_link *this_message;
    struct nnpfs_link *this_process;
    struct nnpfs_message_header *msg;
#if defined(HAVE_STRUCT_PROC_P_SIGMASK) || defined(HAVE_STRUCT_PROC_P_SIGCTX) || defined(HAVE_FREEBSD_THREAD)
    sigset_t oldsigmask;
#endif
    int catch;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode = %d\n", message->opcode));
        
    if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
	return ENODEV;
    
    if (size < sizeof(struct nnpfs_message_wakeup)) {
	printf("NNPFS PANIC Error: Message to small to receive wakeup, opcode = %d\n", message->opcode);
	return ENOMEM;
    }

    if (!async) {
	if (proc == NULL)
	    proc = nnpfs_curproc();
	
#ifdef HAVE_FREEBSD_THREAD
	if (chan->proc != NULL && chan->proc->td_proc != NULL &&
	    proc->td_proc != NULL &&
	    proc->td_proc->p_pid == chan->proc->td_proc->p_pid) {
	    printf("nnpfs_message_rpc: deadlock avoided "
		   "pid = %u == %u\n", proc->td_proc->p_pid, chan->proc->td_proc->p_pid);
#if 0
	    psignal (proc, SIGABRT);
#endif
	    return EDEADLK;
	}
	
#else /* !HAVE_FREEBSD_THREAD */
	
	if (chan->proc != NULL && proc == chan->proc) {
	    printf("nnpfs_message_rpc: deadlock avoided\n");
#if 0
	    psignal (proc, SIGABRT);
#endif
	    return EDEADLK;
	}
#endif /* !HAVE_FREEBSD_THREAD */
    }
    
    this_message = nnpfs_alloc(sizeof(*this_message), M_NNPFS_LINK);

    if (async) {
	struct async_link *t;
	t = nnpfs_alloc(sizeof(t->this_link) + size, M_NNPFS_LINK);

	this_process = &t->this_link;
	msg = &t->msg;
	this_process->error_or_size = sizeof(t->this_link) + size;
	this_message->error_or_size = sizeof(*this_message);
    } else {
	this_process = nnpfs_alloc(sizeof(struct nnpfs_link), M_NNPFS_LINK);
	msg = nnpfs_alloc(size, M_NNPFS_MSG);
	this_process->error_or_size = 0;
	this_message->error_or_size = 0;
    }

    bcopy(message, msg, size);
    msg->size = size;
    msg->sequence_num = chan->nsequence++;

    this_message->message = msg;
    this_process->message = msg;
    NNPQUEUE_INSERT_TAIL(&chan->messageq, this_message, qentry);
    NNPQUEUE_INSERT_TAIL(&chan->sleepq, this_process, qentry);

    /*
     * Wakeup daemon that might be blocking select()/poll().
     */
    
    nnpfs_select_wakeup(chan);

    /*
     * Wakeup blocking read in nnpfs_devread
     */

    if (chan->status & CHANNEL_WAITING) {
	chan->status &= ~CHANNEL_WAITING;
	wakeup((caddr_t) chan);
    }

    if (async) {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc_async done\n"));
	return 0;
    }
    
    /*
     * Remove signals from the sigmask so no IO will wake us up from
     * tsleep(). We don't want to wake up from since program (emacs,
     * bash & co can't handle them.
     */

#ifdef __DragonFly__
    if (proc->td_proc != NULL) {
        oldsigmask = proc->td_proc->p_sigmask;
        nnpfs_block_sigset (&proc->td_proc->p_sigmask);
    }
#elif defined(HAVE_FREEBSD_THREAD)
    /* FreeBSD 5.1 */
    oldsigmask = proc->td_sigmask;
    nnpfs_block_sigset (&proc->td_sigmask);
#elif HAVE_STRUCT_PROC_P_SIGMASK
    /* NetBSD 1.5, Darwin 1.3, FreeBSD 4.3, 5.0, OpenBSD 2.8 */
    oldsigmask = proc->p_sigmask;
    nnpfs_block_sigset (&proc->p_sigmask);
#elif defined(HAVE_STRUCT_PROC_P_SIGCTX)
#if __NetBSD_Version__ >= 399001400 
    /* NetBSD 3.99.14 */
    oldsigmask = proc->l_proc->p_sigctx.ps_sigmask;
    nnpfs_block_sigset (&proc->l_proc->p_sigctx.ps_sigmask);
#else
    /* NetBSD 1.6 */
    oldsigmask = proc->p_sigctx.ps_sigmask;
    nnpfs_block_sigset (&proc->p_sigctx.ps_sigmask);
#endif
#endif

    /*
     * if we are exiting we should not try to catch signals, since
     * there might not be enough context left in the process to handle
     * signal delivery, and besides, most BSD-variants ignore all
     * signals while closing anyway.
     */

    catch = 0;
#ifdef __APPLE__
    /* XXX */
    if (0)
#elif defined(HAVE_FREEBSD_THREAD)
    if (proc->td_proc && !(proc->td_proc->p_flag & NNPFS_P_EXIT))
#elif __NetBSD_Version__ >= 399001400 /* NetBSD 3.99.14 */
    if (!(proc->l_proc->p_flag & NNPFS_P_EXIT))
#else
    if (!(proc->p_flag & NNPFS_P_EXIT))
#endif
	catch |= PCATCH;

    /*
     * We have to check if we have a receiver here too because the
     * daemon could have terminated before we sleep. This seems to
     * happen sometimes when rebooting.  */

    if (!(chan->status & CHANNEL_OPENED)) {
	NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc: channel went away\n"));
	this_process->error_or_size = EINTR;
    } else {
	ret = nnpfs_dev_msleep(chan, (caddr_t)this_process,
			       (PZERO + 1) | catch, "nnpfs");
	if (ret != 0) {
	    NNPFSDEB(XDEBMSG, ("caught signal (%d): %ld\n", ret, nnpfs_cursig(proc)));
	    this_process->error_or_size = EINTR;
	}
    }

#ifdef __DragonFly__
    if (proc->td_proc != NULL)
        proc->td_proc->p_sigmask = oldsigmask;
#elif defined(HAVE_FREEBSD_THREAD)
    proc->td_sigmask = oldsigmask;
#elif HAVE_STRUCT_PROC_P_SIGMASK
    proc->p_sigmask = oldsigmask;
#elif defined(HAVE_STRUCT_PROC_P_SIGCTX)
#if defined(__NetBSD__) && __NetBSD_Version__ >= 399001400 /* 3.99.14 */
    proc->l_proc->p_sigctx.ps_sigmask = oldsigmask;
#else
    proc->p_sigctx.ps_sigmask = oldsigmask;
#endif
#endif

    /*
     * Caught signal, got reply message or device was closed.
     * Need to clean up both messageq and sleepq.
     */
    if (NNPQUEUE_ON(&chan->messageq, this_message, qentry))
	NNPQUEUE_REMOVE(this_message, &chan->messageq, qentry);
    
    if (NNPQUEUE_ON(&chan->sleepq, this_process, qentry))
	NNPQUEUE_REMOVE(this_process, &chan->sleepq, qentry);
    
    ret = this_process->error_or_size;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc this_process->error_or_size = %d\n",
		       this_process->error_or_size));
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc error = %d\n",
		       ((struct nnpfs_message_wakeup *) (this_process->message))->error));

    bcopy(msg, message, size);

    nnpfs_free(this_message, sizeof(*this_message), M_NNPFS_LINK);
    nnpfs_free(this_process, sizeof(*this_process), M_NNPFS_LINK);
    nnpfs_free(msg, size, M_NNPFS_MSG);

    return ret;
}

int
nnpfs_message_rpc(struct nnpfs *nnpfsp,
		  struct nnpfs_message_header *message, u_int size,
		  d_thread_t *proc)
{
    return nnpfs_message_rpc_int(nnpfsp, message, size, proc, FALSE);
}

int
nnpfs_message_rpc_async(struct nnpfs *nnpfsp,
			struct nnpfs_message_header *message, u_int size,
			d_thread_t *proc)
{
    return nnpfs_message_rpc_int(nnpfsp, message, size, proc, TRUE);
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
int
nnpfs_message_receive(struct nnpfs *nnpfsp,
		    struct nnpfs_message_header *message,
		    u_int size,
		    d_thread_t *p)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_receive opcode = %d\n", message->opcode));

    /* Dispatch and coerce message type */
    switch (message->opcode) {
    case NNPFS_MSG_WAKEUP:
	return nnpfs_message_wakeup(nnpfsp,
				  (struct nnpfs_message_wakeup *) message,
				  message->size,
				  p);
    case NNPFS_MSG_INSTALLROOT:
	return nnpfs_message_installroot(nnpfsp,
				 (struct nnpfs_message_installroot *) message,
				       message->size,
				       p);
    case NNPFS_MSG_INSTALLNODE:
	return nnpfs_message_installnode(nnpfsp,
				 (struct nnpfs_message_installnode *) message,
				       message->size,
				       p);
    case NNPFS_MSG_INSTALLATTR:
	return nnpfs_message_installattr(nnpfsp,
				 (struct nnpfs_message_installattr *) message,
				       message->size,
				       p);
    case NNPFS_MSG_INSTALLDATA:
	return nnpfs_message_installdata(nnpfsp,
				 (struct nnpfs_message_installdata *) message,
				       message->size,
				       p);
    case NNPFS_MSG_INVALIDNODE:
	return nnpfs_message_invalidnode(nnpfsp,
				 (struct nnpfs_message_invalidnode *) message,
				       message->size,
				       p);
    case NNPFS_MSG_UPDATEFID:
	return nnpfs_message_updatefid(nnpfsp,
				     (struct nnpfs_message_updatefid *)message,
				     message->size,
				     p);
    case NNPFS_MSG_GC:
	return nnpfs_message_gc(nnpfsp,
				(struct nnpfs_message_gc *)message,
				message->size,
				p);
    case NNPFS_MSG_DELETE_NODE:
	return nnpfs_message_delete_node(nnpfsp,
					 (struct nnpfs_message_delete_node *)message,
					 message->size,
					 p);
    case NNPFS_MSG_INSTALLQUOTA:
	return nnpfs_message_installquota(nnpfsp,
				  (struct nnpfs_message_installquota *)message,
					  message->size,
					  p);
	
    case NNPFS_MSG_VERSION:
	return nnpfs_message_version(nnpfsp,
				     (struct nnpfs_message_version *)message,
				     message->size,
				     p);
    default:
	printf("NNPFS PANIC Warning nnpfs_dev: Unknown message opcode == %d\n",
	       message->opcode);
	return EINVAL;
    }
}

/*
 * Transfer return value from async rpc to the affected node.
 * This should only happen for putdata for now.
 */

static void
async_return(struct nnpfs *chan,
	     struct nnpfs_message_header *req_header,
	     struct nnpfs_message_wakeup *reply)
{
    struct nnpfs_node *node;
    struct nnpfs_message_putdata *request;
    int error;
    
    NNPFSDEB(XDEBDEV, ("nnpfs async_return\n"));
    
    nnpfs_assert(req_header->opcode == NNPFS_MSG_PUTDATA); /* for now */

#if 0
    /* XXX optimization, disable for testing */
    if (!reply->error)
	return;
#endif

    request = (struct nnpfs_message_putdata *)req_header;
    error = nnpfs_node_find(chan, &request->handle, &node);
    if (error) {
	if (error == ENOENT)
	    NNPFSDEB(XDEBMSG, ("nnpfs async_return: node not found\n"));
	else if (error == EISDIR)
	    NNPFSDEB(XDEBMSG, ("nnpfs async_return: node deleted\n"));
	return;
    }

    if (!node->async_error)
	node->async_error = reply->error;
}

int
nnpfs_message_wakeup(struct nnpfs *chan,
		     struct nnpfs_message_wakeup *message,
		     u_int size,
		     d_thread_t *p)
{
    struct nnpfs_link *t;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup error: %d\n", message->error));

    NNPQUEUE_FOREACH(t, &chan->sleepq, qentry) {
	if (t->message->sequence_num == message->sleepers_sequence_num) {
	    int linksize = t->error_or_size;
	    if (linksize) {
		/* async rpc */
		async_return(chan, t->message, message);
		NNPQUEUE_REMOVE(t, &chan->sleepq, qentry);
		nnpfs_free(t, linksize, M_NNPFS_LINK);
		break;
	    }

	    if (t->message->size < size) {
		printf("NNPFS PANIC Error: Could not wakeup requestor with opcode = %d properly, to small receive buffer.\n", t->message->opcode);
		t->error_or_size = ENOMEM;
	    } else {
		bcopy(message, t->message, size);
	    }

	    wakeup((caddr_t) t);
	    break;
	}
    }

    return 0;
}

/*
 *
 */
int
nnpfs_uprintf_device(void)
{
#if 0
    int i;

    for (i = 0; i < NNNPFS; i++) {
	uprintf("nnpfs_dev[%d] = {\n", i);
	uprintf("messageq.first = %lx ", NNPQUEUE_FIRST(&nnpfs_dev[i].messageq));
	uprintf("sleepq.first = %lx ", NNPQUEUE_FIRST(&nnpfs_dev[i].sleepq));
	uprintf("nsequence = %d status = %d\n",
		nnpfs_dev[i].nsequence,
		nnpfs_dev[i].status);
	uprintf("}\n");
    }
#endif
    return 0;
}
