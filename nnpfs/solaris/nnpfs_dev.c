/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska Högskolan
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
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

RCSID("$Id: nnpfs_dev.c,v 1.30 2004/06/13 15:06:14 lha Exp $");

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */
struct nnpfs_link {
    struct nnpfs_link *prev, *next;
    struct nnpfs_message_header *message;
    kmutex_t mutex;
    kcondvar_t cv;
    u_int error_or_size;		/* error on sleepq and size on messageq */
};  

/*
 * LOCKING: If message_mutex and sleep_mutex will be entered both, 
 * message_mutex must be entered first.
 */

struct nnpfs_channel {
    dev_info_t *dip;
    struct nnpfs_link messageq;	/* Messages not yet read */
    kmutex_t message_mutex;	/* hold when changing/looking messageq */
    struct nnpfs_link sleepq;	/* Waiting for reply message */
    kmutex_t sleep_mutex;	/* hold when changing/looking sleepq */
    u_int nsequence;		/* next sequence number */
    struct pollhead pollhead;	/* structure used for poll */
    struct nnpfs_message_header *message_buffer; /* working buffer */
    kmutex_t msg_buf_mutex;	/* hold when using message_buffer */
    int status;			/* status flags for this device */
#define CHANNEL_OPENED	0x1
};

static void *nnpfs_dev_state;

static struct nnpfs_channel *
nnpfs_inst2chan(int fd)
{
    return(struct nnpfs_channel *)ddi_get_soft_state(nnpfs_dev_state, fd);
}

static void
nnpfs_initq(struct nnpfs_link *q)
{
    q->next = q;
    q->prev = q;
}

/* Is this queue empty? */
static int
nnpfs_emptyq(struct nnpfs_link *q)
{
    return q->next == q;
}

/* Is this link on any queue? Link *must* be inited! */
static int
nnpfs_onq(struct nnpfs_link *q)
{
    return q->next != 0 || q->prev != 0;
}

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
 * Only allow one open.
 */
int
nnpfs_devopen(dev_t *devp, int flags, int otyp, cred_t *credp)
{
    struct nnpfs_channel *chan;
    
    NNPFSDEB(XDEBDEV, ("nnpfs_devopen dev = %ld, flags = %d, otyp = %d\n",
		     *devp, flags, otyp));
    
    if (otyp != OTYP_CHR)
	return EINVAL;
    
    chan = nnpfs_inst2chan(getminor(*devp));
    if (chan == NULL)
	return ENXIO;
    
    /* Only allow one reader/writer */
    if (chan->status & CHANNEL_OPENED)
	return EBUSY;
    else
	chan->status |= CHANNEL_OPENED;
  
    return 0;
}

/*
 * Wakeup all sleepers and cleanup.
 */
int
nnpfs_devclose(dev_t dev, int flags, int otyp, cred_t *credp)
{
    struct nnpfs_channel *chan;
    struct nnpfs_link *first;

    NNPFSDEB(XDEBDEV, ("nnpfs_devclose dev = %ld, flags = %d, otyp = %d\n",
		     dev, flags, otyp));

    chan = nnpfs_inst2chan(getminor(dev));
    if (chan == NULL)
	return ENXIO;

    /* Sanity check, paranoia? */
    if (!(chan->status & CHANNEL_OPENED))
	panic("nnpfs_devclose never opened?");

    chan->status &= ~CHANNEL_OPENED;

    mutex_enter(&chan->message_mutex);

    /* No one is going to read those messages so empty queue! */
    while (!nnpfs_emptyq(&chan->messageq)) {
	NNPFSDEB(XDEBDEV, ("before outq(messageq)\n"));
	first = chan->messageq.next;
	nnpfs_outq(first);
	if (first->error_or_size != 0)
	    nnpfs_free(first, first->error_or_size);
	NNPFSDEB(XDEBDEV, ("after outq(messageq)\n"));
    }
    mutex_exit(&chan->message_mutex);
    mutex_enter(&chan->sleep_mutex);
    /* Wakeup those waiting for replies that will never arrive. */
    while (!nnpfs_emptyq(&chan->sleepq)) {
	NNPFSDEB(XDEBDEV, ("before outq(sleepq)\n"));
	first = chan->sleepq.next;
	mutex_enter(&first->mutex);
	nnpfs_outq(first);
	first->error_or_size = ENODEV;
	cv_signal(&first->cv);
	mutex_exit(&first->mutex);
	NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
    }
  
    mutex_exit(&chan->sleep_mutex);

    /* Free all nnpfs_nodes. */
    free_all_nnpfs_nodes(&nnpfs[getminor(dev)]);
    return 0;
}

/*
 * Move messages from kernel to user space.
 */
int
nnpfs_devread(dev_t dev, struct uio *uiop, cred_t *credp)
{
    struct nnpfs_channel *chan;
    struct nnpfs_link *first;
    int error = 0;

    NNPFSDEB(XDEBDEV, ("nnpfs_devread dev = %ld\n", dev));

    chan = nnpfs_inst2chan(getminor(dev));
    if (chan == NULL)
	return ENXIO;

    mutex_enter(&chan->message_mutex);
    while (!nnpfs_emptyq (&chan->messageq)) {
	/* Remove message */
	first = chan->messageq.next;

	ASSERT(first->message->size != 0);

	if (first->message->size > uiop->uio_resid)
	    break;

	error = uiomove((caddr_t) first->message, first->message->size,
			UIO_READ, uiop);
	if (error)
	    break;
	nnpfs_outq(first);

	if (first->error_or_size != 0)
	    nnpfs_free(first, first->error_or_size);
    }
    mutex_exit(&chan->message_mutex);
    return error;
}

/*
 * Move messages from user space to kernel space,
 * wakeup sleepers, insert new data in VFS.
 */
int
nnpfs_devwrite(dev_t dev, struct uio *uiop, cred_t *credp)
{
    struct nnpfs_channel *chan;
    char *p;
    int error;
    u_int cnt;
    struct nnpfs_message_header *msg_buf;

    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite dev = %ld\n", dev));

    chan = nnpfs_inst2chan(getminor(dev));
    if (chan == NULL)
	return ENXIO;

    mutex_enter(&chan->msg_buf_mutex);

    ASSERT(chan->message_buffer != NULL);

    cnt = uiop->uio_resid;
    error = uiomove((caddr_t) chan->message_buffer, NNPFS_MAX_MSG_SIZE,
		    UIO_WRITE, uiop);
    if (error != 0) {
	mutex_exit(&chan->msg_buf_mutex);
	return error;
    }
  
    cnt -= uiop->uio_resid;

    /*
     * This thread handles the received message.
     */

    for (p = (char *)chan->message_buffer;
	 cnt > 0;
	 p += msg_buf->size, cnt -= msg_buf->size) {
	msg_buf = (struct nnpfs_message_header *)p;

	ASSERT(msg_buf);
	ASSERT(msg_buf->size);

	error = nnpfs_message_receive (getminor(dev),
				     msg_buf,
				     msg_buf->size);
    }
    mutex_exit(&chan->msg_buf_mutex);
    NNPFSDEB(XDEBDEV, ("nnpfs_devwrite error = %d\n", error));
    return error;
}

/*
 * Not used.
 */
int
nnpfs_devioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	     int *rvalp)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %ld, cmd = %d\n", dev, cmd));
    return EINVAL;
}

/*
 * Are there any messages on this filesystem?
 */
int
nnpfs_chpoll(dev_t dev, short events, int anyyet,
	   short *reventsp, struct pollhead **phpp)
{
    struct nnpfs_channel *chan;

    NNPFSDEB(XDEBDEV, ("nnpfs_chpoll dev = %ld, events = %d, anyyet = %d\n",
		     dev, events, anyyet));

    chan = nnpfs_inst2chan(getminor(dev));
    if (chan == NULL)
	return ENXIO;

    *reventsp = 0;
    *phpp = NULL;

    if (!(events & POLLRDNORM))
	return 0;

    mutex_enter(&chan->message_mutex);
    if (!nnpfs_emptyq(&chan->messageq)) {
	*reventsp |= POLLRDNORM;
    } else {
	*reventsp = 0;
	if (!anyyet)
	    *phpp = &chan->pollhead;
    }
    mutex_exit(&chan->message_mutex);
    return 0;
}

/*
 * Send a message to user space.
 */
int
nnpfs_message_send(int fd, struct nnpfs_message_header *message, u_int size)
{
    struct nnpfs_channel *chan;
    struct {
	struct nnpfs_link this_message;
	struct nnpfs_message_header msg;
    } *t;

    ASSERT(message != NULL);

    chan = nnpfs_inst2chan(fd);
    if (chan == NULL)
	return ENXIO;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_send opcode = %d\n", message->opcode));

    if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
	return ENODEV;
  
    /* Prepare message and copy it later */
    ASSERT(size != 0);

    message->size = size;
    message->sequence_num = chan->nsequence++;

    t = nnpfs_alloc(sizeof(t->this_message) + size);
    ASSERT(t != NULL);

    t->this_message.error_or_size = sizeof(t->this_message) + size;
    bcopy((caddr_t)message, (caddr_t)&t->msg, size);

    t->this_message.message = &t->msg;
    mutex_enter(&chan->message_mutex);
    nnpfs_appendq(&chan->messageq, &t->this_message);
    mutex_exit(&chan->message_mutex);
    pollwakeup(&chan->pollhead, POLLRDNORM);
    return 0;
}

/*
 * Send a message to user space and wait for reply.
 */

int
nnpfs_message_rpc(int fd, struct nnpfs_message_header *message, u_int size)
{
    struct nnpfs_channel *chan;
    struct nnpfs_link *this_message;
    struct nnpfs_link *this_process;
    struct nnpfs_message_header *msg;
    int ret;
    k_sigset_t blocked_signals;
    k_sigset_t save_t_hold;
    proc_t *p = curproc;
    
    ASSERT(message != NULL);
    
    chan = nnpfs_inst2chan(fd);
    if (chan == NULL)
	return ENXIO;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode = %d\n", message->opcode));
    
    if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
	return ENODEV;
    
    if (size < sizeof(struct nnpfs_message_wakeup)) {
	printf("NNPFS PANIC Error: "
	       "Message to small to receive wakeup, opcode = %d\n", 
	       message->opcode);
	return ENOMEM;
    }
    this_message = nnpfs_alloc(sizeof(struct nnpfs_link));
    this_process = nnpfs_alloc(sizeof(struct nnpfs_link));
    bzero (this_message, sizeof(struct nnpfs_link));
    bzero (this_process, sizeof(struct nnpfs_link));
    msg = nnpfs_alloc(size);
    bcopy((caddr_t)message, (caddr_t)msg, size);
    
    mutex_init(&this_process->mutex, "this_process", MUTEX_DRIVER, NULL);
    cv_init(&this_process->cv, "this_process", CV_DRIVER, NULL);
    
    ASSERT(size != 0);
    
    msg->size = size;
    msg->sequence_num = chan->nsequence++;
    this_message->error_or_size = 0;
    this_message->message = msg;
    this_process->error_or_size = 0;
    this_process->message = msg;
    
    mutex_enter(&chan->message_mutex);
    nnpfs_appendq(&chan->messageq, this_message);
    NNPFSDEB(XDEBMSG, ("messageq = %x, next = %x"
		     "first: %d:%u\n",
		     (int)&chan->messageq, (int)&chan->messageq.next,
		     chan->messageq.next->message->opcode,
		     chan->messageq.next->message->size));
    mutex_exit(&chan->message_mutex);

    mutex_enter(&chan->sleep_mutex);
    nnpfs_appendq(&chan->sleepq, this_process);
    mutex_exit(&chan->sleep_mutex);
    
    pollwakeup(&chan->pollhead, POLLRDNORM);
    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc before sleep\n"));
    mutex_enter(&this_process->mutex);

    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGALRM);
    sigaddset(&blocked_signals, SIGPOLL);
    sigaddset(&blocked_signals, SIGVTALRM);

    mutex_enter (&p->p_lock);
    save_t_hold = curthread->t_hold;
    sigorset(&curthread->t_hold, &blocked_signals);
    mutex_exit (&p->p_lock);

    if(cv_wait_sig(&this_process->cv, &this_process->mutex) == 0) {
	NNPFSDEB(XDEBMSG, ("caught signal: aborting\n"));
	this_process->error_or_size = EINTR;
    }

    mutex_enter (&p->p_lock);
    curthread->t_hold = save_t_hold;
    mutex_exit (&p->p_lock);

    NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc after sleep\n"));
    /*
     * Caught signal, got reply message or device was closed.
     * Need to clean up both messageq and sleepq.
     */
    mutex_enter(&chan->message_mutex);
    if (nnpfs_onq(this_message)) {
	nnpfs_outq(this_message);
    }
    mutex_exit(&chan->message_mutex);
    mutex_enter(&chan->sleep_mutex);
    if (nnpfs_onq(this_process)) {
	nnpfs_outq(this_process);
    }
    mutex_exit(&chan->sleep_mutex);
    ret = this_process->error_or_size;
    
    cv_destroy (&this_process->cv);
    mutex_exit(&this_process->mutex);
    mutex_destroy(&this_process->mutex);
    
    bcopy((caddr_t)msg, (caddr_t)message, size);
    
    nnpfs_free(this_message, sizeof(*this_message));
    nnpfs_free(this_process, sizeof(*this_process));
    nnpfs_free(msg, size);
    
    return ret;
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
int
nnpfs_message_receive(int fd, struct nnpfs_message_header *message, u_int size)
{
    ASSERT(message != NULL);
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_receive opcode = %d\n", message->opcode));
    
    /* Dispatch and coerce message type */
    switch (message->opcode) {
    case NNPFS_MSG_WAKEUP:
	return nnpfs_message_wakeup(fd, 
				  (struct nnpfs_message_wakeup *) message, 
				  message->size);
    case NNPFS_MSG_WAKEUP_DATA:
	return nnpfs_message_wakeup_data(fd,
				       (struct nnpfs_message_wakeup_data *)message,
				       message->size);
    case NNPFS_MSG_INSTALLROOT:
	return nnpfs_message_installroot(fd, 
				       (struct nnpfs_message_installroot *)message,
				       message->size);
    case NNPFS_MSG_INSTALLNODE:
	return nnpfs_message_installnode(fd, 
				       (struct nnpfs_message_installnode *) message,
				       message->size);
    case NNPFS_MSG_INSTALLATTR:
	return nnpfs_message_installattr(fd,
				       (struct nnpfs_message_installattr *) message,
				       message->size);
    case NNPFS_MSG_INSTALLDATA:
	return nnpfs_message_installdata(fd,
				       (struct nnpfs_message_installdata *)message,
				       message->size);
    case NNPFS_MSG_INVALIDNODE:
	return nnpfs_message_invalidnode(fd,
				       (struct nnpfs_message_invalidnode *)message,
				       message->size);
    case NNPFS_MSG_UPDATEFID:
	return nnpfs_message_updatefid (fd,
				      (struct nnpfs_message_updatefid *) message,
				      message->size);
    case NNPFS_MSG_GC_NODES:
	return nnpfs_message_gc_nodes (fd,
				     (struct nnpfs_message_gc_nodes *) message,
				     message->size);
    case NNPFS_MSG_VERSION:
	return nnpfs_message_version (fd,
				    (struct nnpfs_message_version *) message,
				    message->size);
    default:
	printf("NNPFS PANIC Warning nnpfs_dev: Unknown message opcode == %d\n",
	       message->opcode);
	return EINVAL;
    }
}

int
nnpfs_message_wakeup(int fd, struct nnpfs_message_wakeup *message, u_int size)
{
    struct nnpfs_channel *chan;
    struct nnpfs_link *sleepq;
    struct nnpfs_link *t;
    
    ASSERT(message != NULL);
    
    chan = nnpfs_inst2chan(fd);
    if (chan == NULL)
	return ENXIO;
    
    mutex_enter(&chan->sleep_mutex);
    sleepq = &chan->sleepq;
    t = chan->sleepq.next; /* Really first in q */
    NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup\n"));
    
    for (; t != sleepq; t = t->next) {
	ASSERT(t->message != NULL);
	if (t->message->sequence_num == message->sleepers_sequence_num)
	{
	    if (t->message->size < size)
	    {
		printf("NNPFS PANIC Error:"
		       " Could not wakeup requestor"
		       " with opcode = %d properly,"
		       " to small receive buffer.\n",
		       t->message->opcode);
		t->error_or_size = ENOMEM;
	    }
	    else
		bcopy((caddr_t)message, (caddr_t)t->message, size);
	    mutex_enter(&t->mutex);
	    cv_signal (&t->cv);
	    mutex_exit (&t->mutex);
	    break;
	}
    }
    mutex_exit(&chan->sleep_mutex);
    
    return 0;
}

int
nnpfs_message_wakeup_data(int fd,
			struct nnpfs_message_wakeup_data * message,
			u_int size)
{
    struct nnpfs_channel *chan;
    struct nnpfs_link *sleepq;
    struct nnpfs_link *t;

    ASSERT(message != NULL);

    chan = nnpfs_inst2chan(fd);
    if (chan == NULL)
	return ENXIO;

    mutex_enter(&chan->sleep_mutex);
    sleepq = &chan->sleepq;
    t = chan->sleepq.next; /* Really first in q */
    NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup_data\n"));

    for (; t != sleepq; t = t->next) {
	ASSERT(t->message != NULL);
	if (t->message->sequence_num == message->sleepers_sequence_num) {
	    if (t->message->size < size) {
		printf("NNPFS PANIC Error: Could not wakeup requestor with " 
		       "opcode = %d properly, to small receive buffer.\n", 
		       t->message->opcode);
		t->error_or_size = ENOMEM;
	    } else
		bcopy((caddr_t)message, (caddr_t)t->message, size);
	    mutex_enter(&t->mutex);
	    cv_signal (&t->cv);
	    mutex_exit (&t->mutex);
	    break;
	}
    }
    mutex_exit(&chan->sleep_mutex);

    return 0;
}

int
nnpfs_dev_init(void)
{
    int ret;

    ret = ddi_soft_state_init(&nnpfs_dev_state,
			      sizeof(struct nnpfs_channel), NNNPFS);

    return ret;
}

int
nnpfs_dev_fini(void)
{
    ddi_soft_state_fini(&nnpfs_dev_state);
    return 0;
}

static int
nnpfs_dev_getinfo(dev_info_t *dip,
		ddi_info_cmd_t infocmd,
		void *arg,
		void **result)
{
    int ret;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_getinfo\n"));

    switch(infocmd) {
    case DDI_INFO_DEVT2INSTANCE : {
	dev_t dev = (dev_t)arg;
	*result = (void *)getminor(dev);
	ret = DDI_SUCCESS;
	break;
    }
    case DDI_INFO_DEVT2DEVINFO : {
	dev_t dev = (dev_t)arg;
	struct nnpfs_channel *chan;

	chan = nnpfs_inst2chan(getminor(dev));
	if (chan == NULL) {
	    *result = NULL;
	    ret = DDI_FAILURE;
	} else {
	    *result = chan->dip;
	    ret = DDI_SUCCESS;
	}
	break;
    }
    default :
	ret = DDI_FAILURE;
	break;
    }
    return ret;
}

static int
nnpfs_dev_probe (dev_info_t *dip)
{
    NNPFSDEB(XDEBDEV, ("nnpfs_dev_probe\n"));

    return DDI_PROBE_SUCCESS;
}

static int
nnpfs_dev_attach(dev_info_t *dip,
	       ddi_attach_cmd_t cmd)
{
    int ret;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_attach\n"));

    switch(cmd) {
    case DDI_ATTACH : {
	int instance = ddi_get_instance(dip);
	struct nnpfs_channel *state;

	ret = ddi_soft_state_zalloc(nnpfs_dev_state, instance);
	if (ret != DDI_SUCCESS)
	    break;
	state = nnpfs_inst2chan(instance);

	ret = ddi_create_minor_node(dip, "", S_IFCHR, instance, NULL, 0);
	if (ret != DDI_SUCCESS) {
	    ddi_soft_state_free(nnpfs_dev_state, instance);
	    break;
	}
	
	state->dip = dip;
	nnpfs_initq(&state->messageq);
	nnpfs_initq(&state->sleepq);
	mutex_init (&state->message_mutex, "nnpfs:messageq", MUTEX_DRIVER, NULL);
	mutex_init (&state->sleep_mutex, "nnpfs:sleepq", MUTEX_DRIVER, NULL);
	mutex_init (&state->msg_buf_mutex, "nnpfs:msg buf", MUTEX_DRIVER, NULL);
	state->nsequence = 0;
	state->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE);
	ASSERT(state->message_buffer != NULL);
	state->status = 0;
	/* how is the pollhead supposed to be initialized? */
	bzero((caddr_t)&state->pollhead, sizeof(state->pollhead));

	ddi_report_dev(dip);
	ret = DDI_SUCCESS;
	break;
    }	
#ifdef DDI_PM_RESUME
    case DDI_PM_RESUME :
#endif
    case DDI_RESUME :
	ret = DDI_SUCCESS;
	break;
    default :
	ret = DDI_FAILURE;
	break;
    }
    return ret;
}

static int
nnpfs_dev_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
    int ret;

    NNPFSDEB(XDEBDEV, ("nnpfs_dev_detach\n"));

    switch (cmd) {
    case DDI_DETACH : {
	int instance = ddi_get_instance(dip);
	struct nnpfs_channel *state;

	state = nnpfs_inst2chan(instance);
	mutex_destroy(&state->message_mutex);
	mutex_destroy(&state->sleep_mutex);
	mutex_destroy(&state->msg_buf_mutex);
	ASSERT(state->message_buffer != NULL);
	nnpfs_free(state->message_buffer, NNPFS_MAX_MSG_SIZE);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(nnpfs_dev_state, instance);
	ret = DDI_SUCCESS;
	break;
    }
    case DDI_PM_SUSPEND :
    case DDI_SUSPEND :
	ret = DDI_SUCCESS;
	break;
    default :
	ret = DDI_FAILURE;
	break;
    }
    return ret;
}

static struct cb_ops nnpfs_cb_ops = {
    nnpfs_devopen,		/* open */
    nnpfs_devclose,		/* close */
    nodev,			/* strategy */
    nodev,			/* print */
    nodev,			/* dump */
    nnpfs_devread,		/* read */
    nnpfs_devwrite,		/* write */
    nnpfs_devioctl,		/* ioctl */
    nodev,			/* devmap */
    nodev,			/* mmap */
    nodev,			/* segmap */
    nnpfs_chpoll,			/* chpoll */
    nodev,			/* prop_op */
    NULL,			/* cb_str */
    D_NEW | D_MP,		/* flag */
    0,				/* rev */
    nodev,			/* aread */
    nodev			/* awrite */
};

static struct dev_ops nnpfs_dev_ops = {
    DEVO_REV,			/* rev */
    0,				/* refcnt */
    nnpfs_dev_getinfo,		/* getinfo */
    nulldev,			/* identify */
    nnpfs_dev_probe,		/* probe */
    nnpfs_dev_attach,		/* attach */
    nnpfs_dev_detach,		/* detach */
    nodev,			/* reset */
    &nnpfs_cb_ops,		/* cb_ops */
    NULL,			/* bus_ops */
    NULL			/* power */
};

struct modldrv nnpfs_modldrv = {
    &mod_driverops,
    "nnpfs cdev driver",
    &nnpfs_dev_ops
};
