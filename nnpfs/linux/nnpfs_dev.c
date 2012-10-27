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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

#define __NO_VERSION__

#include <nnpfs/nnpfs_locl.h>
#include <linux/poll.h>
#include <linux/mount.h>

#ifdef RCSID
RCSID("$Id: nnpfs_dev.c,v 1.117 2006/10/24 16:33:36 tol Exp $");
#endif

#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

/* helper struct for sending messages without sleeping */
struct async_link {
    struct nnpfs_link this_link; /* keep this first in struct */
    struct nnpfs_message_header msg;
};

static void
nnpfs_initq(struct nnpfs_link *q)
{
    q->next = q;
    q->prev = q;
    init_waitqueue_head(&(q->wait_queue));
    q->woken = 0;
}

/* Is this queue empty? */
#define nnpfs_emptyq(q) ((q)->next == (q))

/* Is this link on any queue? Link *must* be inited! */
#define nnpfs_onq(link) ((link)->next != 0 || (link)->prev != 0)

/* Append q with p */
static void
nnpfs_appendq(struct nnpfs_link *q, struct nnpfs_link *p)     
{
    p->next = q;
    p->prev = q->prev;
    p->prev->next = p;
    q->prev = p;
}

static void
nnpfs_outq(struct nnpfs_link *p)     
{
    p->next->prev = p->prev;
    p->prev->next = p->next;
    p->next = p->prev = 0;
}

/*
 * Enqueue the `message' of `size' to the `nnpfsp' for later processing.
 * Caller must hold channel_sem, and channel must be open.
 */

static int
enqueue_message (struct nnpfs *nnpfsp,
		 struct nnpfs_message_header *message,
		 u_int size)
{
    struct async_link *t;

    /* Prepare message and copy it later */

    message->size = size;

    t = nnpfs_alloc(sizeof(t->this_link) + size, NNPFS_MEM_SENDRPC);
    if (t == NULL)
	return -ENOMEM;
    t->this_link.error_or_size = sizeof(t->this_link) + size;

    memmove(&t->msg, message, size);
    t->this_link.message = &t->msg;

    t->msg.sequence_num = nnpfsp->nsequence++;
    NNPFSDEB(XDEBMSG, ("enqueue_message seq = %d\n", t->msg.sequence_num));

    nnpfs_appendq(&nnpfsp->messageq, &t->this_link);
    init_waitqueue_head(&(t->this_link.wait_queue));

    return 0;
}

/*
 * add `xn' to the list of inactive nodes.
 *
 * Increases reference count if inode is put on queue.
 * Caller must hold inactive_sem.
 */

void
nnpfs_queue_inactive(struct nnpfs_node *xn)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_XNODE(xn);

    NNPFSDEB(XDEBDEV, ("nnpfs_queue_inactive\n"));

    BUG_ON((nnpfsp->status & NNPFS_DEVOPEN) == 0);
    BUG_ON((xn->flags & NNPFS_LIMBO) == 0);
    BUG_ON(!list_empty(&xn->inactive_list));

    igrab(XNODE_TO_VNODE(xn));
    list_add (&xn->inactive_list, &nnpfsp->inactive_list);

    wake_up_all(&nnpfsp->wait_queue);
}

/*
 * send of inactive messages for all queued nodes on `nnpfsp'
 *
 * Caller must hold channel_sem and not hold inactive_sem. Channel
 * must be open.
 */

static void
nnpfs_process_inactive_queue (struct nnpfs *nnpfsp)
{
    int i = 0;
    int ret;

    down(&nnpfsp->inactive_sem);

    for (;;) {
	struct list_head *lh = nnpfsp->inactive_list.next;
	struct nnpfs_node *xn;
	struct nnpfs_message_inactivenode msg;

	if (lh == &nnpfsp->inactive_list)
	    break;

	++i;

	xn = list_entry (lh, struct nnpfs_node, inactive_list);
	list_del_init(&xn->inactive_list);
	
	BUG_ON((xn->flags & NNPFS_LIMBO) == 0);

	up(&nnpfsp->inactive_sem);

	msg.header.opcode = NNPFS_MSG_INACTIVENODE;
	msg.handle        = xn->handle;
	msg.flag          = NNPFS_NOREFS | NNPFS_DELETE;
	
	ret = enqueue_message (nnpfsp, &msg.header, sizeof(msg));

	if (!ret)
	    iput(XNODE_TO_VNODE(xn));

	down(&nnpfsp->inactive_sem);

 	if (ret) {
	    NNPFSDEB(XDEBDEV, ("nnpfs_process_inactive_queue: "
			       "failed enqueue-ing msg %d\n", ret));
	    
	    /*
	     * Nodes are only put on the list at the time that
	     * NNPFS_LIMBO is set, and at most once.  The inactive
	     * list is bypassed if not NNPFS_DEVOPEN.
	     */

	    BUG_ON(!list_empty(&xn->inactive_list));
	    list_add (&xn->inactive_list, &nnpfsp->inactive_list);
	}
	
    }

    up(&nnpfsp->inactive_sem);

    if (i)
	NNPFSDEB(XDEBDEV, ("nnpfs_process_inactive_queue: done (%d)\n", i));
}

/*
 * throw away all inactive nodes on `nnpfsp'
 *
 * Called with channel_sem held.
 */

static void
nnpfs_empty_inactive_queue (struct nnpfs *nnpfsp)
{
    int i = 0;

    down(&nnpfsp->inactive_sem);

    for (;;) {
	struct list_head *lh = nnpfsp->inactive_list.next;
	struct nnpfs_node *xn;

	if (lh == &nnpfsp->inactive_list)
	    break;

	++i;

	xn = list_entry (lh, struct nnpfs_node, inactive_list);
	list_del_init (&xn->inactive_list);

	BUG_ON((xn->flags & NNPFS_LIMBO) == 0);

	up(&nnpfsp->inactive_sem);
	iput(XNODE_TO_VNODE(xn));
	down(&nnpfsp->inactive_sem);
    }

    up(&nnpfsp->inactive_sem);

    if (i)
	NNPFSDEB(XDEBDEV, ("nnpfs_empty_inactive_queue: done (%d)\n", i));
}

/*
 * Only allow one open.
 */
static int
nnpfs_devopen(struct inode *inode, struct file *file)
{
    struct nnpfs *nnpfsp = &nnpfs[MINOR(inode->i_rdev)];
    int ret = 0;
    
    NNPFSDEB(XDEBDEV, ("nnpfs_devopen dev = %d, flags = %d\n",
		       inode->i_rdev, file->f_flags));
    
    if (MINOR(inode->i_rdev) >= NNNPFS)
	return -ENXIO;

    down(&nnpfsp->channel_sem);

    /* Only allow one reader/writer */
    if (nnpfsp->status & NNPFS_DEVOPEN) {
	ret = -EBUSY;
	goto out;
    }

    nnpfsp->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE, NNPFS_MEM_MSGBUF);
    if (nnpfsp->message_buffer == NULL) {
	ret = -ENOMEM;
	goto out;
    }
    
    down(&nnpfsp->inactive_sem);
    nnpfsp->status |= NNPFS_DEVOPEN;
    up(&nnpfsp->inactive_sem);

 out:
    up(&nnpfsp->channel_sem);
    return ret;
}

/*
 * Try to invalidate all our inodes, dcache, etc.
 *
 * XXX mutex
 */

static void
nnpfs_invalidate_all(struct nnpfs *nnpfsp)
{
    NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes starting\n"));

    shrink_dcache_sb(nnpfs->sb);
    invalidate_inodes(nnpfs->sb);
    
    NNPFSDEB(XDEBNODE, ("free_all_nnpfs_nodes done\n"));
}

static int
nnpfs_devclose(struct inode * inode, struct file * file)
{
    struct nnpfs *nnpfsp = &nnpfs[MINOR(inode->i_rdev)];
    struct nnpfs_link *first;

    NNPFSDEB(XDEBDEV, ("nnpfs_devclose dev = %d, flags = %d\n",
		       inode->i_rdev, file->f_flags));
    
    down(&nnpfsp->channel_sem);
    
    /* Sanity check, paranoia? */
    if (!(nnpfsp->status & NNPFS_DEVOPEN))
	panic("nnpfs_devclose never opened?");
    
    down(&nnpfsp->inactive_sem);
    nnpfsp->status &= ~NNPFS_DEVOPEN;
    up(&nnpfsp->inactive_sem);
    
    /* No one is going to read those messages so empty queue! */
    while (!nnpfs_emptyq(&nnpfsp->messageq)) {
	NNPFSDEB(XDEBDEV, ("before outq(messageq)\n"));
	first = nnpfsp->messageq.next;
	nnpfs_outq(first);
	if (first->error_or_size != 0)
	    nnpfs_free(first, NNPFS_MEM_SENDRPC);
	NNPFSDEB(XDEBDEV, ("after outq(messageq)\n"));
    }

    /* Wakeup those waiting for replies that will never arrive. */
    while (!nnpfs_emptyq(&nnpfsp->sleepq)) {
	NNPFSDEB(XDEBDEV, ("before outq(sleepq)\n"));
	first = nnpfsp->sleepq.next;
	nnpfs_outq(first);
	up(&nnpfsp->channel_sem);
	first->error_or_size = -ENODEV;
	first->woken = 1;
	wake_up_all(&first->wait_queue);
	NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
	down(&nnpfsp->channel_sem);
    }

    mntput(nnpfsp->cacheroot);
    dput(nnpfsp->cachedir);
    nnpfsp->cacheroot = NULL;
    nnpfsp->cachedir = NULL;

    if (nnpfsp->message_buffer) {
	nnpfs_free(nnpfsp->message_buffer, NNPFS_MEM_MSGBUF);
	nnpfsp->message_buffer = NULL;
    }

    nnpfs_empty_inactive_queue(nnpfsp);
    nnpfs_invalidate_all(nnpfsp);

    nnpfsp->status &= ~NNPFS_ROOTINSTALLED;

    up(&nnpfsp->channel_sem);

    return 0;
}

/*
 * Move messages from kernel to user space.
 */

static ssize_t
nnpfs_devread(struct file *file, char *buf, size_t count, loff_t *ppos)
{
    nnpfs_dev_t dev = file->f_dentry->d_inode->i_rdev;
    struct nnpfs *nnpfsp = &nnpfs[MINOR(dev)];
    struct nnpfs_link *first;
    int ret = 0, error = 0;
    
    NNPFSDEB(XDEBDEV, ("nnpfs_devread: m = %p, m->prev = %p, m->next = %p\n",
		       &nnpfsp->messageq, nnpfsp->messageq.prev,
		       nnpfsp->messageq.next));
    
    down(&nnpfsp->channel_sem);

    nnpfs_process_inactive_queue (nnpfsp);

    while (!nnpfs_emptyq (&nnpfsp->messageq)) {
	first = nnpfsp->messageq.next;
	NNPFSDEB(XDEBDEV, ("nnpfs_devread: first = %p, "
			   "first->prev = %p, first->next = %p\n",
			   first, first->prev, first->next));
	
	if (first->message->size > count)
	    break;

	NNPFSDEB(XDEBDEV, ("nnpfs_devread: message->size = %u\n",
			   first->message->size));
	
	if (copy_to_user (buf, first->message, first->message->size)) {
	    error = -EFAULT;
	    break;
	}

	buf += first->message->size;
	count -= first->message->size;
	ret += first->message->size;
	
	nnpfs_outq(first);
	
	if (first->error_or_size != 0)
	    nnpfs_free(first, NNPFS_MEM_SENDRPC);
    }
    up(&nnpfsp->channel_sem);
    
    if (error)
	return error;

    *ppos += ret;
    return ret;
}

/*
 * Move messages from user space to kernel space,
 * wakeup sleepers, insert new data in VFS.
 */

static ssize_t
nnpfs_devwrite(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
    nnpfs_dev_t dev;
    struct nnpfs *nnpfsp;
    char *p = NULL;
    struct nnpfs_message_header *msg_buf;
    int ret, error = 0;
    size_t left;

    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite\n"));
    
    dev = file->f_dentry->d_inode->i_rdev;
    nnpfsp = &nnpfs[MINOR(dev)];

    down(&nnpfsp->channel_sem);
    if (nnpfsp->status & NNPFS_DEVWRITE) {
	printk("nnpfs_devwrite: busy\n");
	error = -EBUSY;
    } else {
	nnpfsp->status |= NNPFS_DEVWRITE;
	p = nnpfsp->message_buffer;
    }
    up(&nnpfsp->channel_sem);

    if (error) {
	NNPFSDEB(XDEBDEV, ("nnpfs_devwrite -> %d\n", error));
	return error;
    }

    if (count > NNPFS_MAX_MSG_SIZE)
	count = NNPFS_MAX_MSG_SIZE;
    if (copy_from_user(p, buf, count)) {
	printk("nnpfs_devwrite: fault\n");
	error = -EFAULT;
	goto out;
    }
    
    /*
     * This thread handles the received message.
     */
    
    left = count;
    while (left > 0) {
	msg_buf = (struct nnpfs_message_header *)p;
	
	if (left < msg_buf->size
	    || msg_buf->size < sizeof (struct nnpfs_message_header)) {
	    printk("nnpfs_devwrite: badly formed message\n");
	    error = -EINVAL;
	    break;
	}
	ret = nnpfs_message_receive (nnpfsp, msg_buf,
				     msg_buf->size);
	if (ret)
	    error = ret;

	p += msg_buf->size;
	left -= msg_buf->size;
    }
 out:

    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite error = %d\n", error));
    
    down(&nnpfsp->channel_sem);
    nnpfsp->status &= ~NNPFS_DEVWRITE;
    up(&nnpfsp->channel_sem);

    if (error)
	return error;

    *ppos += count;
    return count;
}

/*
 * Not used.
 */
static int
nnpfs_devioctl(struct inode *inode, struct file *file,
	       unsigned int cmd, unsigned long arg)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %d, flags = %d\n",
		       inode->i_rdev, file->f_flags));
    return -EINVAL;
}

static unsigned int
nnpfs_devpoll(struct file *file, poll_table *wait)
{
    nnpfs_dev_t dev = file->f_dentry->d_inode->i_rdev;
    struct nnpfs *nnpfsp = &nnpfs[MINOR(dev)];
    int ret = 0;
    
    poll_wait(file, &nnpfsp->wait_queue, wait);
    
    down(&nnpfsp->channel_sem);

    nnpfs_process_inactive_queue (nnpfsp);

    if (!nnpfs_emptyq(&nnpfsp->messageq))
	ret = POLLIN;
    up(&nnpfsp->channel_sem);

    return ret;
}

/*
 * Send a message to user space.
 */

int
nnpfs_message_send(struct nnpfs *nnpfsp,
		   struct nnpfs_message_header *message, u_int size)
{
    int ret;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_send opcode = %d\n", message->opcode));
    
    down(&nnpfsp->channel_sem);

    if (!(nnpfsp->status & NNPFS_DEVOPEN)) {	/* No receiver? */
	up(&nnpfsp->channel_sem);
	return -ENODEV;
    }

    nnpfs_process_inactive_queue(nnpfsp);

    ret = enqueue_message (nnpfsp, message, size);
    wake_up_all(&nnpfsp->wait_queue);

    up(&nnpfsp->channel_sem);

    return ret;
}

static inline int
sigissignaled(struct task_struct *t, int signal)
{
    return (sigismember(&current->pending.signal, signal)
	|| sigismember(&current->signal->shared_pending.signal, signal));
}

/*
 * Send a message to user space and wait for reply.
 */

static int
nnpfs_message_rpc_int(struct nnpfs *nnpfsp,
		      struct nnpfs_message_header *message,
		      u_int size,
		      int async)
{
    int ret;
    struct nnpfs_link *this_message;
    struct nnpfs_link *this_process;
    struct nnpfs_message_header *msg;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode = %d\n", message->opcode));
    
    if (size < sizeof(struct nnpfs_message_wakeup)) {
	printk(KERN_EMERG "NNPFS Panic: "
	       "Message too small to receive wakeup, opcode = %d\n",
	       message->opcode);
	return -ENOMEM;
    }
    
    this_message = nnpfs_alloc(sizeof(*this_message), NNPFS_MEM_SENDRPC);
    if (!this_message)
	return -ENOMEM;

    if (async) {
	struct async_link *t;
	t = nnpfs_alloc(sizeof(t->this_link) + size, NNPFS_MEM_SENDRPC);
	if (!t) {
	    nnpfs_free(this_message, NNPFS_MEM_SENDRPC);
	    return -ENOMEM;
	}
	this_process = &t->this_link;
	msg = &t->msg;
	this_process->error_or_size = sizeof(t->this_link) + size;
	this_message->error_or_size = sizeof(*this_message);
    } else {
	this_process = nnpfs_alloc(sizeof(struct nnpfs_link), NNPFS_MEM_SENDRPC);
	msg = nnpfs_alloc(size, NNPFS_MEM_SENDRPC);

	if (!this_process || ! msg) {
	    nnpfs_free(this_message, NNPFS_MEM_SENDRPC);
	    nnpfs_free(this_process, NNPFS_MEM_SENDRPC);
	    nnpfs_free(msg, NNPFS_MEM_SENDRPC);
	    return -ENOMEM;
	}

	this_process->error_or_size = 0;
	this_message->error_or_size = 0;
    }

    memcpy(msg, message, size);
    msg->size = size;

    init_waitqueue_head(&(this_message->wait_queue));
    init_waitqueue_head(&(this_process->wait_queue));

    this_message->message = msg;
    this_process->message = msg;

    down(&nnpfsp->channel_sem);
    
    if ((nnpfsp->status & NNPFS_DEVOPEN) == 0) {
	up(&nnpfsp->channel_sem);
	nnpfs_free(this_message, NNPFS_MEM_SENDRPC);
	nnpfs_free(this_process, NNPFS_MEM_SENDRPC);
	if (!async)
	    nnpfs_free(msg, NNPFS_MEM_SENDRPC);
	return -ENODEV;
    }

    nnpfs_process_inactive_queue(nnpfsp);

    msg->sequence_num = nnpfsp->nsequence++;
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc seq = %d\n", msg->sequence_num));
    
    nnpfs_appendq(&nnpfsp->messageq, this_message);
    nnpfs_appendq(&nnpfsp->sleepq, this_process);
    
    this_process->woken = 0;

    wake_up_all(&nnpfsp->wait_queue);

    if (async) {
	up(&nnpfsp->channel_sem);
	NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc_async done\n"));
	return 0;
    }

    {
	sigset_t set;
	sigset_t oldset;
	siginitsetinv(&set,
		      sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGKILL));
	sigprocmask(SIG_BLOCK, &set, &oldset);

	up(&nnpfsp->channel_sem);
	wait_event_interruptible(this_process->wait_queue,
				 this_process->woken);
	down(&nnpfsp->channel_sem);

	sigprocmask(SIG_SETMASK, &oldset, NULL);
    }

    if (!this_process->woken) {
	int i;

	NNPFSDEB(XDEBMSG, ("caught signal:"));
	for (i = 1; i <= _NSIG; ++i)
	    if (sigissignaled(current, i))
		NNPFSDEB(XDEBMSG, ("%d ", i));
	NNPFSDEB(XDEBMSG, ("\n"));
	this_process->error_or_size = -EINTR;
    }
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc wakeup: seq = %d\n",
		       msg->sequence_num));
    /*
     * Caught signal, got reply message or device was closed.
     * Need to clean up both messageq and sleepq.
     */
    if (nnpfs_onq(this_message)) {
	nnpfs_outq(this_message);
    }
    if (nnpfs_onq(this_process)) {
	nnpfs_outq(this_process);
    }
    up(&nnpfsp->channel_sem);
    ret = this_process->error_or_size;
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode this_process"
		       "->error_or_size = %d\n", this_process->error_or_size));
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode "
		       "((nnpfs_message_wakeup*)"
		       "(this_process->message))->error = %d\n",
		       NNPFS_MSG_WAKEUP_ERROR(this_process->message)));
    
    memcpy(message, msg, size);
    
    nnpfs_free (this_message, NNPFS_MEM_SENDRPC);
    nnpfs_free (this_process, NNPFS_MEM_SENDRPC);
    nnpfs_free (msg, NNPFS_MEM_SENDRPC);

    if (ret < -1000 || ret > 0) {
	printk(KERN_EMERG
	       "NNPFS Panic: nnpfs_message_rpc was about to return error %d\n",
	       ret);
	return -EINVAL;
    }

    return ret;
}

int
nnpfs_message_rpc(struct nnpfs *nnpfsp, struct nnpfs_message_header *message,
		  u_int size)
{
    return nnpfs_message_rpc_int(nnpfsp, message, size, 0);
}

int
nnpfs_message_rpc_async(struct nnpfs *nnpfsp, struct nnpfs_message_header *message,
			u_int size)
{
    return nnpfs_message_rpc_int(nnpfsp, message, size, 1);
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
int
nnpfs_message_receive(struct nnpfs *nnpfsp,
		      struct nnpfs_message_header *message, u_int size)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_receive opcode = %d\n", 
		       message->opcode));
    
    /* Dispatch and coerce message type */
    switch (message->opcode) {
    case NNPFS_MSG_WAKEUP:
	return nnpfs_message_wakeup(nnpfsp,
				    (struct nnpfs_message_wakeup *)
				    message,
				    message->size);
    case NNPFS_MSG_INSTALLROOT:
	return nnpfs_message_installroot(nnpfsp,
					 (struct nnpfs_message_installroot *)
					 message,
					 message->size);
    case NNPFS_MSG_INSTALLNODE:
	return nnpfs_message_installnode(nnpfsp,
					 (struct nnpfs_message_installnode *)
					 message, 
					 message->size);
    case NNPFS_MSG_INSTALLATTR:
	return nnpfs_message_installattr(nnpfsp,
					 (struct nnpfs_message_installattr *)
					 message, 
					 message->size);
    case NNPFS_MSG_INSTALLDATA:
	return nnpfs_message_installdata(nnpfsp,
					 (struct nnpfs_message_installdata *)
					 message, 
					 message->size);
    case NNPFS_MSG_INVALIDNODE:
	return nnpfs_message_invalidnode(nnpfsp,
					 (struct nnpfs_message_invalidnode *)
					 message, 
					 message->size);
    case NNPFS_MSG_UPDATEFID:
	return nnpfs_message_updatefid(nnpfsp,
				       (struct nnpfs_message_updatefid *)
				       message,
				       message->size);
    case NNPFS_MSG_GC:
	return nnpfs_message_gc(nnpfsp,
				(struct nnpfs_message_gc *)
				message,
				message->size);
    case NNPFS_MSG_VERSION:
	return nnpfs_message_version(nnpfsp,
				     (struct nnpfs_message_version *)
				     message,
				     message->size);
    case NNPFS_MSG_DELETE_NODE:
	return nnpfs_message_delete_node(nnpfsp,
					 (struct nnpfs_message_delete_node *)
					 message,
					 message->size);
	
    case NNPFS_MSG_INSTALLQUOTA:
	return nnpfs_message_installquota(nnpfsp,
					  (struct nnpfs_message_installquota *)
					  message,
					  message->size);
	
    default:
	printk(KERN_EMERG 
	       "NNPFS Panic: nnpfs_dev: Unknown message opcode == %d\n",
	       message->opcode);
	return -EINVAL;
    }
}

/*
 * Transfer return value from async rpc to the affected node.
 * This should only happen for putdata for now.
 */

static void
async_return(struct nnpfs *nnpfsp,
	     struct nnpfs_message_header *req_header,
	     struct nnpfs_message_wakeup *reply)
{
    struct nnpfs_node *node;
    struct nnpfs_message_putdata *request;
    int error;
    
    NNPFSDEB(XDEBDEV, ("nnpfs async_return\n"));
    
    BUG_ON(req_header->opcode != NNPFS_MSG_PUTDATA); /* for now */

#if 0
    /* XXX optimization, disable for testing */
    if (!reply->error)
	return;
#endif

    request = (struct nnpfs_message_putdata *)req_header;
    error = nnpfs_node_find(nnpfsp, &request->handle, &node);
    if (error) {
	if (error == -ENOENT)
	    NNPFSDEB(XDEBMSG, ("nnpfs async_return: node not found\n"));
	else if (error == -EISDIR)
	    NNPFSDEB(XDEBMSG, ("nnpfs async_return: node deleted\n"));
	return;
    }

    if (!node->async_error)
	node->async_error = reply->error;

    iput(XNODE_TO_VNODE(node));
}

#if 0
static void
check_message(struct nnpfs_message_header *message)
{
    uint32_t opcode = message->opcode;
    int bad = 0;

#if 0
    printk("wakeup %d, opcode %d\n", message->sequence_num,
	   opcode);
#endif
    if (opcode < NNPFS_MSG_GETROOT || opcode > NNPFS_MSG_PIOCTL
	|| opcode == NNPFS_MSG_INSTALLROOT
	|| opcode == NNPFS_MSG_INSTALLNODE
	|| opcode == NNPFS_MSG_INSTALLATTR
	|| opcode == NNPFS_MSG_INSTALLDATA
	|| opcode == NNPFS_MSG_INVALIDNODE
	|| opcode == NNPFS_MSG_INACTIVENODE)
	bad = 1;

    if (message->pad1 != NNPFS_MSG_MAGIC)
	bad = 1;

    if (message->size < sizeof(*message)
	|| message->size > sizeof(struct nnpfs_message_pioctl))
	bad = 1;
    
    
    if (bad) {
	printk("wakeup %d, opcode %d, magic %x, size %u\n",
	       message->sequence_num, opcode, message->pad1,
	       message->size);
	BUG();
    }
	
}
#endif

int
nnpfs_message_wakeup(struct nnpfs *nnpfsp,
		     struct nnpfs_message_wakeup *message, u_int size)
{
    struct nnpfs_link *sleepq;
    struct nnpfs_link *t;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup error: %d seq = %d\n",
		       message->error, message->sleepers_sequence_num));

    down(&nnpfsp->channel_sem);

    sleepq = &nnpfsp->sleepq;
    /* sleepq->next is really first element in q */
    for (t = sleepq->next; t != sleepq; t = t->next)
	if (t->message->sequence_num == message->sleepers_sequence_num) {
	    int linksize = t->error_or_size;
	    if (linksize) {
		/* async rpc */
		async_return(nnpfsp, t->message, message);
		nnpfs_outq(t);
		nnpfs_free(t, NNPFS_MEM_SENDRPC);
		break;
	    }
	    if (t->message->size < size) {
		printk(KERN_EMERG 
		       "NNPFS Panic: Could not wakeup requestor with "
		       "opcode = %d properly, too small receive buffer.\n",
		       t->message->opcode);
		t->error_or_size = -ENOMEM;
	    } else {
		memmove(t->message, message, size);
		if (message->error < 0 || message->error > 1000)
		    t->error_or_size = -EPROTO;
		else
		    t->error_or_size = -message->error;
	    }
	    t->woken = 1;
	    wake_up_all(&t->wait_queue);
	    break;
	}
#if 0
    if (t == sleepq) /* happens when user interrupts the operation */
	printk("nnpfs_message_wakeup: seq %u not found\n", 
	       message->sleepers_sequence_num);
#endif

    up(&nnpfsp->channel_sem);

    return 0;
}

struct file_operations nnpfs_fops = {
    owner:		THIS_MODULE,
    read:		nnpfs_devread,
    write:		nnpfs_devwrite,
    poll:		nnpfs_devpoll,
    ioctl:		nnpfs_devioctl,
    release:		nnpfs_devclose,
    open:		nnpfs_devopen,
};

int
nnpfs_init_device(void)
{
    int i;
    
    for (i = 0; i < NNNPFS; i++) {
	NNPFSDEB(XDEBDEV, ("before initq(messageq and sleepq)\n"));
	init_waitqueue_head(&(nnpfs[i].wait_queue));
	nnpfs_initq(&nnpfs[i].messageq);
	nnpfs_initq(&nnpfs[i].sleepq);
	init_MUTEX(&nnpfs[i].inactive_sem);
	init_MUTEX(&nnpfs[i].channel_sem);
	INIT_LIST_HEAD(&nnpfs[i].inactive_list);
	nnpfs[i].nnodes = 0;
    }
    return 0;
}

void
nnpfs_print_sleep_queue(void)
{
#if 0
    int i;

    for (i = 0; i < NNNPFS; ++i) {
	struct nnpfs *nnpfsp = &nnpfs[i];
	struct nnpfs_link *sleepq = &nnpfsp->sleepq;
	struct nnpfs_link *t = nnpfsp->sleepq.next; /* Really first in q */

	printk("Sleeping queue %d :", i);
	for (; t != sleepq; t = t->next) {
	    printk(" %d", t->message->sequence_num);
	    
	    if (!list_empty(&t->wait_queue.task_list)) {
		const wait_queue_t *w = (const wait_queue_t *)
		    list_entry(t->wait_queue.task_list.next,
			       wait_queue_t, task_list);
		
		printk(" (pid %d)", w->task->pid);
	    }
	}
    }
#endif
}

/*
 * our wait wrapper, with synchronisation and all.
 *
 * Caller must hold channel_sem.
 */

int
nnpfs_dev_msleep(struct nnpfs *nnpfsp, wait_queue_head_t *wait_queue,
		 predicate donep, void *data)
{
    sigset_t oldset;
    sigset_t set;
    int ret;

    siginitsetinv(&set,
		  sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGKILL));
    sigprocmask(SIG_BLOCK, &set, &oldset);
    
    do {
	up(&nnpfsp->channel_sem);
	ret = wait_event_interruptible(*wait_queue, donep(data));
	down(&nnpfsp->channel_sem);
    } while (!ret && !donep(data));
    
    sigprocmask(SIG_SETMASK, &oldset, NULL);

    return ret;
}
