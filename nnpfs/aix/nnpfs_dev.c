/*
 * Copyright (c) 1998 - 2000 Kungliga Tekniska Högskolan
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

RCSID("$Id: nnpfs_dev.c,v 1.9 2004/06/13 15:02:55 lha Exp $");

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */
struct nnpfs_link {
  struct nnpfs_link *prev, *next;
  struct nnpfs_message_header *message;
  Simple_lock simple_lock;
  int event_word;
#if 0
  kmutex_t mutex;
  kcondvar_t cv;
#endif
  u_int error_or_size;		/* error on sleepq and size on messageq */
};  

struct nnpfs_channel {
  dev_t dev;
  struct nnpfs_link messageq;	/* Messages not yet read */
  struct nnpfs_link sleepq;	/* Waiting for reply message */
  u_int nsequence;
  int selectingp;
  struct nnpfs_message_header *message_buffer;
  int status;
#define CHANNEL_OPENED	0x1
};

static struct nnpfs_channel nnpfs_channel[NNNPFS];

static void *nnpfs_dev_state;

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
 *
 */

static int
nnpfs_devconfig (dev_t dev,
	       int cmd,
	       struct uio *uiop)
{
  NNPFSDEB(XDEBDEV, ("nnpfs_devconfig dev = %ld, cmd = %d\n",
		   dev, cmd));
  return ENOSYS;
}


/*
 * Only allow one open.
 */

int
nnpfs_devopen(dev_t dev,
	    ulong devflag,
	    chan_t foo_chan,
	    int ext)
{
  struct nnpfs_channel *chan;

  NNPFSDEB(XDEBDEV, ("nnpfs_devopen dev = %ld, flags = %d\n",
		   dev, devflag));

  chan = &nnpfs_channel[minor(dev)];

  /* Only allow one reader/writer */
  if (chan->status & CHANNEL_OPENED)
    return EBUSY;
  else
    chan->status |= CHANNEL_OPENED;

  chan->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE);

  ASSERT(chan->message_buffer != NULL);

  chan->dev = dev;

  return 0;
}

/*
 * Wakeup all sleepers and cleanup.
 */

static int
nnpfs_devclose(dev_t dev, chan_t foo_chan)
{
  struct nnpfs_channel *chan;
  struct nnpfs_link *first;

  NNPFSDEB(XDEBDEV, ("nnpfs_devclose dev = %ld\n"));

  chan = &nnpfs_channel[minor(dev)];

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
      
      simple_lock (&first->simple_lock);
      nnpfs_outq (first);
      first->error_or_size = ENODEV;
      e_wakeup (&first->event_word);
      simple_unlock (&first->simple_lock);
	  

#if 0
      mutex_enter(&first->mutex);
      nnpfs_outq(first);
      first->error_or_size = ENODEV;
      e_wakeup (&first->ew);

      cv_signal(&first->cv);
      mutex_exit(&first->mutex);
#endif
      NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
  }
  
  if (chan->message_buffer) {
      nnpfs_free(chan->message_buffer, NNPFS_MAX_MSG_SIZE);
      chan->message_buffer = 0;
  }
      
  /* Free all nnpfs_nodes. */
  free_all_nnpfs_nodes(&nnpfs[minor(dev)]);
  return 0;
}

/*
 * Move messages from kernel to user space.
 */

static int
nnpfs_devread(dev_t dev, struct uio *uiop, chan_t foo_chan, int ext)
{
  struct nnpfs_channel *chan;
  struct nnpfs_link *first;
  int error = 0;

  NNPFSDEB(XDEBDEV, ("nnpfs_devread dev = %ld\n", dev));

  chan = &nnpfs_channel[minor(dev)];

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

static int
nnpfs_devwrite(dev_t dev, struct uio *uiop, chan_t foo_chan, int ext)
{
  struct nnpfs_channel *chan;
  char *p;
  int error;
  u_int cnt;
  struct nnpfs_message_header *msg_buf;

  NNPFSDEB(XDEBDEV, ("nnpfs_devwrite dev = %ld\n", dev));

  chan = &nnpfs_channel[minor(dev)];

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

      error = nnpfs_message_receive (minor(dev),
				   msg_buf,
				   msg_buf->size);
  }
  NNPFSDEB(XDEBDEV, ("nnpfs_devwrite error = %d\n", error));
  return error;
}

/*
 * Not used.
 */

static int
nnpfs_devioctl(dev_t dev,
	     int cmd,
	     int arg,
	     ulong devflag,
	     chan_t foo_chan,
	     int ext)
{
  NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %ld, cmd = %d\n", dev, cmd));
  return EINVAL;
}

/*
 * Are there any messages on this filesystem?
 */

static int
nnpfs_devselect (dev_t dev,
	       ushort events,
	       ushort *reventsp,
	       int foo_chan)
{
  struct nnpfs_channel *chan;

  NNPFSDEB(XDEBDEV, ("nnpfs_devselect dev = %ld, events = %d\n",
		   dev, events));

  chan = &nnpfs_channel[minor(dev)];

  if (!(events & POLLIN)) {
      *reventsp = 0;
      return 0;
  }

  if (!nnpfs_emptyq(&chan->messageq)) {
      *reventsp |= POLLIN;
  } else {
      *reventsp = 0;
      if (!(events & POLLSYNC))
	  chan->selectingp = 1;
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
  t->this_message.event_word = EVENT_NULL;
  nnpfs_appendq(&chan->messageq, &t->this_message);
  selnotify (chan->dev, 0, POLLIN);
#if 0
  pollwakeup(&chan->pollhead, POLLRDNORM);
#endif
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

  lock_alloc (&this_process->simple_lock, LOCK_ALLOC_PAGED, 0, -1);
  simple_lock_init (&this_process->simple_lock);
  this_process->event_word = EVENT_NULL;

#if 0
  mutex_init(&this_process->mutex, "this_process", MUTEX_DRIVER, NULL);
  cv_init(&this_process->cv, "this_process", CV_DRIVER, NULL);
#endif

  ASSERT(size != 0);

  msg->size = size;
  msg->sequence_num = chan->nsequence++;
  this_message->error_or_size = 0;
  this_message->message = msg;
  this_process->message = msg;
  nnpfs_appendq(&chan->messageq, this_message);
  nnpfs_appendq(&chan->sleepq, this_process);
  this_message->event_word = EVENT_NULL;
  selnotify (chan->dev, 0, POLLIN);
#if 0
  pollwakeup(&chan->pollhead, POLLRDNORM);
#endif
  this_process->error_or_size = 0;
  NNPFSDEB(XDEBMSG, ("messageq = %x, next = %x"
		   "first: %d:%u\n",
		   (int)&chan->messageq, (int)&chan->messageq.next,
		   chan->messageq.next->message->opcode,
		   chan->messageq.next->message->size));
  NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc before sleep\n"));

  simple_lock (&this_process->simple_lock);
  if (e_sleep_thread (&this_process->event_word,
		      &this_process->simple_lock,
		      LOCK_SIMPLE | INTERRUPTIBLE) == THREAD_INTERRUPTED) {
      NNPFSDEB(XDEBMSG, ("caught signal\n"));
      this_process->error_or_size = EINTR;
  }


#if 0
  mutex_enter(&this_process->mutex);
  if(cv_wait_sig(&this_process->cv, &this_process->mutex) == 0) {
      NNPFSDEB(XDEBMSG, ("caught signal\n"));
      this_process->error_or_size = EINTR;
  }
#endif

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

#if 0
  cv_destroy (&this_process->cv);
  mutex_exit(&this_process->mutex);
#endif

  simple_unlock (&this_process->simple_lock);
  lock_free (&this_process->simple_lock);
#if 0
  mutex_destroy(&this_process->mutex);
#endif

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
    return nnpfs_message_updatefid(fd, (struct nnpfs_message_updatefid *)message, message->size);
  case NNPFS_MSG_GC_NODES:
    return nnpfs_message_gc_nodes(fd, (struct nnpfs_message_gc_nodes *)message, message->size);
  case NNPFS_MSG_VERSION:
    return nnpfs_message_version(fd, (struct nnpfs_message_version *)message, message->size);
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
	simple_lock (&t->simple_lock);
	e_wakeup (&t->event_word);
	simple_unlock (&t->simple_lock);

#if 0
	mutex_enter(&t->mutex);
	cv_signal (&t->cv);
	mutex_exit (&t->mutex);
#endif
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
	    simple_lock (&t->simple_lock);
	    e_wakeup (&t->event_word);
	    simple_unlock (&t->simple_lock);
#if 0
	    mutex_enter(&t->mutex);
	    cv_signal (&t->cv);
	    mutex_exit (&t->mutex);
#endif
	    break;
	}
    }

    return 0;
}

extern int nodev();

static struct devsw nnpfs_devsw = {
    nnpfs_devopen,
    nnpfs_devclose,
    nnpfs_devread,
    nnpfs_devwrite,
    nnpfs_devioctl,
    nodev,			/* strategy */
    NULL,
    (int (*)())nnpfs_devselect,
    nnpfs_devconfig,
    nodev,			/* print */
    nodev,			/* dump */
    nodev,			/* mpx */
    nodev,			/* revoke */
    NULL,			/* d_dsdptr */
    NULL,			/* d_selptr */
    0,				/* d_opts */
};

/*
 * XXX - Always allocate (100, 0)
 */

static int nnpfs_dev_major = 100;

int
nnpfs_install_device (void)
{
    int i;
    int ret;

    ret = devswadd (makedev(nnpfs_dev_major, 0), &nnpfs_devsw);
    if (ret)
	return ret;
    
    for (i = 0; i < NNNPFS; i++) {
	NNPFSDEB(XDEBDEV, ("before initq(messageq and sleepq)\n"));
	nnpfs_initq(&nnpfs_channel[i].messageq);
	nnpfs_initq(&nnpfs_channel[i].sleepq);
	nnpfs_channel[i].status = 0;
	nnpfs_channel[i].selectingp = 0;
    }
    return 0;
}

int
nnpfs_uninstall_device (void)
{
    int i;
    dev_t dev;
    struct nnpfs_channel *chan;

    for (i = 0; i < NNNPFS; i++) {
	dev = makedev(nnpfs_dev_major, i);
	chan = &nnpfs_channel[minor(dev)];
	if (chan->status & CHANNEL_OPENED)
	    nnpfs_devclose(dev, 0);
    }
    return devswdel (dev);
}
