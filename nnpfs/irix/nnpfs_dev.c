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

RCSID("$Id: nnpfs_dev.c,v 1.12 2004/06/13 15:03:54 lha Exp $");

unsigned nnpfs_devdevflag = D_MP;
char *nnpfs_devmversion = M_VERSION;

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */
struct nnpfs_link {
  struct nnpfs_link *prev, *next;
  struct nnpfs_message_header *message;
  mutex_t mutex;
  sv_t cv;    
  u_int error_or_size;		/* error on sleepq and size on messageq */
};  

struct nnpfs_channel {
  struct nnpfs_link messageq;	/* Messages not yet read */
  struct nnpfs_link sleepq;	/* Waiting for reply message */
  u_int nsequence;
  struct pollhead *pollhead;
  struct proc *selecting_proc;
  struct nnpfs_message_header *message_buffer;
  int status;
#define CHANNEL_OPENED	0x1
};

static struct nnpfs_channel nnpfs_channel[NNNPFS];

static void
nnpfs_initq(struct nnpfs_link *q)
{
  q->next = q;
  q->prev = q;
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

  if (geteminor(*devp) < 0 || geteminor(*devp) >= NNNPFS)
      return ENXIO;

  chan = &nnpfs_channel[geteminor(*devp)];

  /* Only allow one reader/writer */
  if (chan->status & CHANNEL_OPENED)
    return EBUSY;
  else
    chan->status |= CHANNEL_OPENED;

  chan->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE);

  ASSERT(chan->message_buffer != NULL);

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

  if (geteminor(dev) < 0 || geteminor(dev) >= NNNPFS)
      return ENXIO;

  chan = &nnpfs_channel[geteminor(dev)];

  /* Sanity check, paranoia? */
  if (!(chan->status & CHANNEL_OPENED))
    panic("nnpfs_devclose never opened?");

  chan->status &= ~CHANNEL_OPENED;

  /* No one is going to read those messages so empty queue! */
  while (!nnpfs_emptyq(&chan->messageq)) {
      NNPFSDEB(XDEBDEV, ("before outq(messageq)\n"));
      first = chan->messageq.next;
      nnpfs_outq(first);
      if (first->error_or_size != 0)
	nnpfs_free(first, first->error_or_size);
      NNPFSDEB(XDEBDEV, ("after outq(messageq)\n"));
  }

  /* Wakeup those waiting for replies that will never arrive. */
  while (!nnpfs_emptyq(&chan->sleepq)) {
      NNPFSDEB(XDEBDEV, ("before outq(sleepq)\n"));
      first = chan->sleepq.next;
      MUTEX_LOCK(&first->mutex, -1);
      nnpfs_outq(first);
      first->error_or_size = ENODEV;
      SV_SIGNAL(&first->cv);
      MUTEX_UNLOCK(&first->mutex);
      NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
  }
  
  if (chan->message_buffer) {
      nnpfs_free(chan->message_buffer, NNPFS_MAX_MSG_SIZE);
      chan->message_buffer = 0;
  }
      
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

  if (geteminor(dev) < 0 || geteminor(dev) >= NNNPFS)
      return ENXIO;

  chan = &nnpfs_channel[geteminor(dev)];

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

  if (geteminor(dev) < 0 || geteminor(dev) >= NNNPFS)
      return ENXIO;

  chan = &nnpfs_channel[geteminor(dev)];

  cnt = uiop->uio_resid;
  error = uiomove((caddr_t) chan->message_buffer, NNPFS_MAX_MSG_SIZE,
		  UIO_WRITE, uiop);
  if (error != 0)
    return error;
  
  cnt -= uiop->uio_resid;

  /*
   * This thread handles the received message.
   */

  ASSERT(chan->message_buffer != NULL);

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
  NNPFSDEB(XDEBDEV, ("nnpfs_devwrite error = %d\n", error));
  return error;
}

/*
 * Not used.
 */
int
nnpfs_devioctl(dev_t dev, int cmd, int arg, int mode, cred_t *credp,
	     int *rvalp)
{
  NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %ld, cmd = %d\n", dev, cmd));
  return EINVAL;
}

/*
 * Are there any messages on this filesystem?
 */
int
nnpfs_devpoll(dev_t dev, short events, int anyyet,
	    short *reventsp, struct pollhead **phpp)
{
  struct nnpfs_channel *chan;

  NNPFSDEB(XDEBDEV, ("nnpfs_poll dev = %ld, events = %d, anyyet = %d\n",
		   dev, events, anyyet));

  if (geteminor(dev) < 0 || geteminor(dev) >= NNNPFS)
      return ENXIO;

  chan = &nnpfs_channel[geteminor(dev)];

  if (!(events & POLLRDNORM))
      return 0;

  if (!nnpfs_emptyq(&chan->messageq)) {
      *reventsp = POLLRDNORM;
  } else {
      *reventsp = 0;
      if (!anyyet)
	  *phpp = chan->pollhead;
  }
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

  chan = &nnpfs_channel[fd];

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
  nnpfs_appendq(&chan->messageq, &t->this_message);
  pollwakeup(chan->pollhead, POLLRDNORM);
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

  ASSERT(message != NULL);

  chan = &nnpfs_channel[fd];

  NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode = %d\n", message->opcode));

  if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
    return ENODEV;
  
  if (size < sizeof(struct nnpfs_message_wakeup)) {
      printf("NNPFS PANIC Error: Message to small to receive wakeup, opcode = %d\n", message->opcode);
      return ENOMEM;
  }
  this_message = nnpfs_alloc(sizeof(struct nnpfs_link));
  this_process = nnpfs_alloc(sizeof(struct nnpfs_link));
  msg = nnpfs_alloc(size);
  bcopy((caddr_t)message, (caddr_t)msg, size);

  MUTEX_INIT (&this_process->mutex, MUTEX_DEFAULT, "this_process");
  SV_INIT(&this_process->cv, SV_DEFAULT, "this_process");

  ASSERT(size != 0);

  msg->size = size;
  msg->sequence_num = chan->nsequence++;
  this_message->error_or_size = 0;
  this_message->message = msg;
  this_process->message = msg;
  nnpfs_appendq(&chan->messageq, this_message);
  nnpfs_appendq(&chan->sleepq, this_process);
  pollwakeup(chan->pollhead, POLLRDNORM);
  this_process->error_or_size = 0;
  NNPFSDEB(XDEBMSG, ("messageq = %x, next = %x"
		   "first: %d:%u\n",
		   (int)&chan->messageq, (int)&chan->messageq.next,
		   chan->messageq.next->message->opcode,
		   chan->messageq.next->message->size));
  NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc before sleep\n"));
  MUTEX_LOCK(&this_process->mutex, -1);
  if (SV_WAIT_SIG(&this_process->cv, &this_process->mutex, 0) == 0) {
      NNPFSDEB(XDEBMSG, ("caught signal\n"));
      this_process->error_or_size = EINTR;
  }
  NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc after sleep\n"));
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
  ret = this_process->error_or_size;

  sv_destroy(&this_process->cv);
#if 0
  MUTEX_UNLOCK (&this_process->mutex);
#endif
  MUTEX_DESTROY (&this_process->mutex);

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
    return nnpfs_message_wakeup(fd, (struct nnpfs_message_wakeup *) message, message->size);
  case NNPFS_MSG_WAKEUP_DATA:
    return nnpfs_message_wakeup_data(fd,
				   (struct nnpfs_message_wakeup_data *) message,
				   message->size);
  case NNPFS_MSG_INSTALLROOT:
    return nnpfs_message_installroot(fd, (struct nnpfs_message_installroot *) message, message->size);
  case NNPFS_MSG_INSTALLNODE:
    return nnpfs_message_installnode(fd, (struct nnpfs_message_installnode *) message, message->size);
  case NNPFS_MSG_INSTALLATTR:
    return nnpfs_message_installattr(fd, (struct nnpfs_message_installattr *) message, message->size);
  case NNPFS_MSG_INSTALLDATA:
    return nnpfs_message_installdata(fd, (struct nnpfs_message_installdata *) message, message->size);
  case NNPFS_MSG_INVALIDNODE:
    return nnpfs_message_invalidnode(fd, (struct nnpfs_message_invalidnode *) message, message->size);
  case NNPFS_MSG_UPDATEFID:
    return nnpfs_message_updatefid(fd, (struct nnpfs_message_updatefid *) message, message->size);
  case NNPFS_MSG_GC_NODES:
    return nnpfs_message_gc_nodes(fd, (struct nnpfs_message_gc_nodes *) message, message->size);
  case NNPFS_MSG_VERSION:
    return nnpfs_message_version(fd, (struct nnpfs_message_version *) message, message->size);
  default:
    printf("NNPFS PANIC Warning nnpfs_dev: Unknown message opcode == %d\n", message->opcode);
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

  chan = &nnpfs_channel[fd];

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
	MUTEX_LOCK(&t->mutex, -1);
	SV_SIGNAL (&t->cv);
	MUTEX_UNLOCK(&t->mutex);
	break;
      }
  }

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

    chan = &nnpfs_channel[fd];

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
		bcopy(message, t->message, size);
	    MUTEX_LOCK(&t->mutex, -1);
	    SV_SIGNAL (&t->cv);
	    MUTEX_UNLOCK(&t->mutex);
	    break;
	}
    }

    return 0;
}

int
nnpfs_install_device(void)
{
    int ret = 0;
    int i;

    printf ("nnpfs_install_device\n");

    printf ("nnpfs_devopen = %x, nnpfs_devclose = %x, nnpfs_devread = %x, "
	    "nnpfs_devwrite = %x, nnpfs_devioctl = %x\n",
	    nnpfs_devopen, nnpfs_devclose, nnpfs_devread,
	    nnpfs_devwrite, nnpfs_devioctl);

    printf ("[18]. open = %x, close = %x, read = %x, "
	    "write = %x, ioctl = %x\n",
	    cdevsw[18].d_open,
	    cdevsw[18].d_close,
	    cdevsw[18].d_read,
	    cdevsw[18].d_write,
	    cdevsw[18].d_ioctl);

    for (i = 0; i < NNNPFS; i++) {
	NNPFSDEB(XDEBDEV, ("before initq(messageq and sleepq)\n"));
	nnpfs_initq(&nnpfs_channel[i].messageq);
	nnpfs_initq(&nnpfs_channel[i].sleepq);
	nnpfs_channel[i].pollhead = phalloc (KM_SLEEP);
    }
#if 0
    ret = ddi_soft_state_init(&nnpfs_dev_state,
			      sizeof(struct nnpfs_channel), NNNPFS);
#endif

    return ret;
}

int
nnpfs_uninstall_device(void)
{
    int i;

    printf ("nnpfs_uninstall_device\n");

    for (i = 0; i < NNNPFS; ++i) {
	phfree (nnpfs_channel[i].pollhead);
    }

#if 0
    ddi_soft_state_fini(&nnpfs_dev_state);
#endif
    return 0;
}
