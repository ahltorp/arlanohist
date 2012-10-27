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

#include <sys/errno.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnnpfs.h>

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */
struct nnpfs_link {
  struct nnpfs_link *prev, *next;
  struct nnpfs_message_header *message;
  u_int error_or_size;		/* error on sleepq and size on messageq */
};  

struct nnpfs_channel {
  struct nnpfs_link messageq;	/* Messages not yet read */
  struct nnpfs_link sleepq;	/* Waiting for reply message */
  u_int nsequence;
  struct proc *selecting_proc;
  struct nnpfs_message_header *message_buffer;
  int status;
#define CHANNEL_OPENED	0x1
};

static struct nnpfs_channel nnpfs_channel[NNNPFS];

#if defined(__STDC__)
static void nnpfs_initq(struct nnpfs_link *q)
#else
static void
nnpfs_initq(q)
     struct nnpfs_link *q;
#endif
{
  q->next = q;
  q->prev = q;
}

/* Is this queue empty? */
#define nnpfs_emptyq(q) ((q)->next == (q))

/* Is this link on any queue? Link *must* be inited! */
#define nnpfs_onq(link) ((link)->next != 0 || (link)->prev != 0)

/* Append q with p */
#if defined(__STDC__)
static void nnpfs_appendq(struct nnpfs_link *q, struct nnpfs_link *p)     
#else
static void
nnpfs_appendq(q, p)
     struct nnpfs_link *q, *p;
#endif
{
  p->next = q;
  p->prev = q->prev;
  p->prev->next = p;
  q->prev = p;
}

#if defined(__STDC__)
static void nnpfs_outq(struct nnpfs_link *p)     
#else
static void
nnpfs_outq(p)
     struct nnpfs_link *p;
#endif
{
  p->next->prev = p->prev;
  p->prev->next = p->next;
  p->next = p->prev = 0;
}

/*
 * Only allow one open.
 */
#if defined(__STDC__)
int nnpfs_devopen(dev_t dev, int flags)
#else
int
nnpfs_devopen(dev, flags)
     dev_t dev;
     int flags;
#endif
{
  struct nnpfs_channel *chan;

  NNPFSDEB(XDEBDEV, ("nnpfs_devopen dev = %d, flags = %d\n", dev, flags));

  if (minor(dev) < 0 || minor(dev) >= NNNPFS)
    return ENXIO;

  chan = &nnpfs_channel[minor(dev)];

  /* Only allow one reader/writer */
  if (chan->status & CHANNEL_OPENED)
    return EBUSY;
  else
    chan->status |= CHANNEL_OPENED;

  chan->message_buffer = nnpfs_alloc(NNPFS_MAX_MSG_SIZE);

  return 0;
}

/*
 * Wakeup all sleepers and cleanup.
 */
#if defined(__STDC__)
int nnpfs_devclose(dev_t dev, int flags)
#else
int
nnpfs_devclose(dev, flags)
     dev_t dev;
     int flags;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[minor(dev)];
  struct nnpfs_link *first;

  NNPFSDEB(XDEBDEV, ("nnpfs_devclose dev = %d, flags = %d\n", dev, flags));

  /* Sanity check, paranoia? */
  if (!(chan->status & CHANNEL_OPENED))
    panic("nnpfs_devclose never opened?");

  chan->status &= ~CHANNEL_OPENED;

  /* No one is going to read those messages so empty queue! */
  while (!nnpfs_emptyq(&chan->messageq))
    {
      NNPFSDEB(XDEBDEV, ("before outq(messageq)\n"));
      first = chan->messageq.next;
      nnpfs_outq(first);
      if (first->error_or_size != 0)
	nnpfs_free(first, first->error_or_size);
      NNPFSDEB(XDEBDEV, ("after outq(messageq)\n"));
    }

  /* Wakeup those waiting for replies that will never arrive. */
  while (!nnpfs_emptyq(&chan->sleepq))
    {
      NNPFSDEB(XDEBDEV, ("before outq(sleepq)\n"));
      first = chan->sleepq.next;
      nnpfs_outq(first);
      first->error_or_size = ENODEV;
      wakeup((caddr_t) first);
      NNPFSDEB(XDEBDEV, ("after outq(sleepq)\n"));
    }
  
  if (chan->message_buffer)
    {
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
#if defined(__STDC__)
int nnpfs_devread(dev_t dev, struct uio *uiop)
#else
int
nnpfs_devread(dev, uiop)
     dev_t dev;
     struct uio *uiop;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[minor(dev)];
  struct nnpfs_link *first;
  int error = 0;

  NNPFSDEB(XDEBDEV, ("nnpfs_devread dev = %d\n", dev));

  while (!nnpfs_emptyq (&chan->messageq)) {
      /* Remove message */
      first = chan->messageq.next;

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
#if defined(__STDC__)
int nnpfs_devwrite(dev_t dev, struct uio *uiop)
#else
int
nnpfs_devwrite(dev, uiop)
     dev_t dev;
     struct uio *uiop;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[minor(dev)];
  char *p;
  int error;
  u_int cnt;
  struct nnpfs_message_header *msg_buf;

  NNPFSDEB(XDEBDEV, ("nnpfs_devwrite dev = %d\n", dev));

  cnt = uiop->uio_resid;
  error = uiomove((caddr_t) chan->message_buffer, NNPFS_MAX_MSG_SIZE,
		  UIO_WRITE, uiop);
  if (error != 0)
    return error;
  
  cnt -= uiop->uio_resid;

  /*
   * This thread handles the received message.
   */

  for (p = (char *)chan->message_buffer;
       cnt > 0;
       p += msg_buf->size, cnt -= msg_buf->size) {
      msg_buf = (struct nnpfs_message_header *)p;
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
#if defined(__STDC__)
int nnpfs_devioctl(dev_t dev, int cmd, caddr_t data, int flags)
#else
int
nnpfs_devioctl(dev, cmd, data, flags)
     dev_t dev;
     int cmd;
     caddr_t data;
     int flags;
#endif
{
  NNPFSDEB(XDEBDEV, ("nnpfs_devioctl dev = %d, flags = %d\n", dev, flags));
  return EINVAL;
}

/*
 * Are there any messages on this filesystem?
 */
#if defined(__STDC__)
int nnpfs_devselect(dev_t dev, int rw)
#else
int
nnpfs_devselect(dev, rw)
     dev_t dev;
     int rw;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[minor(dev)];

  NNPFSDEB(XDEBDEV, ("nnpfs_devselect dev = %d, rw = %d\n", dev, rw));

  if (rw != FREAD)
    return 0;

  if (!nnpfs_emptyq(&chan->messageq))
    return 1;			/* Something to read */

  /*
   * No need to handle a "collission" since we only allow one
   * concurrent open. */
  chan->selecting_proc = u.u_procp; 
  return 0;
}

/*
 * Send a message to user space.
 */
#if defined(__STDC__)
int nnpfs_message_send(int fd, struct nnpfs_message_header *message, u_int size)
#else
int
nnpfs_message_send(fd, message, size)
     int fd;
     struct nnpfs_message_header *message;
     u_int size;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[fd];
  struct {
    struct nnpfs_link this_message;
    struct nnpfs_message_header msg;
  } *t;

  NNPFSDEB(XDEBMSG, ("nnpfs_message_send opcode = %d\n", message->opcode));

  if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
    return ENODEV;
  
  /* Prepare message and copy it later */
  message->size = size;
  message->sequence_num = chan->nsequence++;

  t = nnpfs_alloc(sizeof(t->this_message) + size);
  t->this_message.error_or_size = sizeof(t->this_message) + size;
  bcopy(message, &t->msg, size);

  t->this_message.message = &t->msg;
  nnpfs_appendq(&chan->messageq, &t->this_message);
  if (   chan->selecting_proc != 0
      && chan->selecting_proc->p_wchan == (caddr_t) &selwait)
    {
      selwakeup(chan->selecting_proc, 0); /* There is only one to wakeup */
      chan->selecting_proc = 0;
    }
  return 0;
}

/*
 * Send a message to user space and wait for reply.
 */
#if defined(__STDC__)
int nnpfs_message_rpc(int fd, struct nnpfs_message_header *message, u_int size)
#else
int
nnpfs_message_rpc(fd, message, size)
     int fd;
     struct nnpfs_message_header *message;
     u_int size;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[fd];
  struct nnpfs_link this_message;
  struct nnpfs_link this_process;

  NNPFSDEB(XDEBMSG, ("nnpfs_message_rpc opcode = %d\n", message->opcode));

  if (!(chan->status & CHANNEL_OPENED))	/* No receiver? */
    return ENODEV;
  
  if (size < sizeof(struct nnpfs_message_wakeup))
    {
      printf("NNPFS PANIC Error: Message to small to receive wakeup, opcode = %d\n", message->opcode);
      return ENOMEM;
    }

  message->size = size;
  message->sequence_num = chan->nsequence++;
  this_message.error_or_size = 0;
  this_message.message = message;
  this_process.message = message;
  nnpfs_appendq(&chan->messageq, &this_message);
  nnpfs_appendq(&chan->sleepq, &this_process);
  if (   chan->selecting_proc != 0
      && chan->selecting_proc->p_wchan == (caddr_t) &selwait)
    {
      selwakeup(chan->selecting_proc, 0); /* There is only one to wakeup */
      chan->selecting_proc = 0;
    }
  this_process.error_or_size = 0;
  if (sleep((caddr_t) &this_process, (PZERO + 1)|PCATCH))
    {
      NNPFSDEB(XDEBMSG, ("caught signal\n"));
      this_process.error_or_size = EINTR;
    }
  /*
   * Caught signal, got reply message or device was closed.
   * Need to clean up both messageq and sleepq.
   */
  if (nnpfs_onq(&this_message))
    {
      nnpfs_outq(&this_message);
    }
  if (nnpfs_onq(&this_process))
    {
      nnpfs_outq(&this_process);
    }
  return this_process.error_or_size;
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
#if defined(__STDC__)
int nnpfs_message_receive(int fd, struct nnpfs_message_header *message, u_int size)
#else
int
nnpfs_message_receive(fd, message, size)
     int fd;
     struct nnpfs_message_header *message;
     u_int size;
#endif
{
  NNPFSDEB(XDEBMSG, ("nnpfs_message_receive opcode = %d\n", message->opcode));

  /* Dispatch and coerce message type */
  switch (message->opcode) {
  case NNPFS_MSG_WAKEUP:
    return nnpfs_message_wakeup(fd, (struct nnpfs_message_wakeup *) message, message->size);
  case NNPFS_MSG_WAKEUP_DATA:
    return nnpfs_message_wakeup_data(fd, (struct nnpfs_message_wakeup_data *) message, message->size);
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
  default:
    printf("NNPFS PANIC Warning nnpfs_dev: Unknown message opcode == %d\n", message->opcode);
    return EINVAL;
  }
}

#if defined(__STDC__)
int nnpfs_message_wakeup(int fd, struct nnpfs_message_wakeup *message, u_int size)
#else
int
nnpfs_message_wakeup(fd, message, size)
     int fd;
     struct nnpfs_message_wakeup *message;
     u_int size;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[fd];
  struct nnpfs_link *sleepq = &chan->sleepq;
  struct nnpfs_link *t = chan->sleepq.next; /* Really first in q */

  NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup\n"));

  for (; t != sleepq; t = t->next)
    if (t->message->sequence_num == message->sleepers_sequence_num)
      {
	if (t->message->size < size)
	  {
	    printf("NNPFS PANIC Error: Could not wakeup requestor with opcode = %d properly, to small receive buffer.\n", t->message->opcode);
	    t->error_or_size = ENOMEM;
	  }
	else
	  bcopy(message, t->message, size);
	wakeup((caddr_t) t);
	break;
      }

  return 0;
}

#if defined(__STDC__)
int nnpfs_message_wakeup_data(int fd,
			    struct nnpfs_message_wakeup_data *message,
			    u_int size)
#else
int
nnpfs_message_wakeup_dat(fd, message, size)
     int fd;
     struct nnpfs_message_wakeup_data *message;
     u_int size;
#endif
{
  struct nnpfs_channel *chan = &nnpfs_channel[fd];
  struct nnpfs_link *sleepq = &chan->sleepq;
  struct nnpfs_link *t = chan->sleepq.next; /* Really first in q */

  NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup_data\n"));

  for (; t != sleepq; t = t->next)
    if (t->message->sequence_num == message->sleepers_sequence_num)
      {
	if (t->message->size < size)
	  {
	    printf("NNPFS PANIC Error: Could not wakeup requestor with opcode = %d properly, to small receive buffer.\n", t->message->opcode);
	    t->error_or_size = ENOMEM;
	  }
	else
	  bcopy(message, t->message, size);
	wakeup((caddr_t) t);
	break;
      }

  return 0;
}

/*
 *
 */
#if defined(__STDC__)
static int nnpfs_uprintf_device(void)
#else
static
int
nnpfs_uprintf_device()
#endif
{
#if 1
  int i;
  for (i = 0; i < NNNPFS; i++)
    {
      uprintf("nnpfs_channel[%d] = {\n", i);
      uprintf("messageq.next = 0x%x ", (u_int) nnpfs_channel[i].messageq.next);
      uprintf("messageq.prev = 0x%x ", (u_int) nnpfs_channel[i].messageq.prev);
      uprintf("sleepq.next = 0x%x ", (u_int) nnpfs_channel[i].sleepq.next);
      uprintf("sleepq.prev = 0x%x ", (u_int) nnpfs_channel[i].sleepq.prev);
      uprintf("nsequence = %d selecting_proc = 0x%x status = %d\n",
	      nnpfs_channel[i].nsequence,
	      (u_int) nnpfs_channel[i].selecting_proc,
	      nnpfs_channel[i].status);
      uprintf("}\n");
    }
#endif
  return 0;
}

/*
 * Install and uninstall device.
 */
#if defined(__STDC__)
int nnpfs_install_device(void)
#else
int
nnpfs_install_device()
#endif
{
  int i;
  for (i = 0; i < NNNPFS; i++)
    {
      NNPFSDEB(XDEBDEV, ("before initq(messageq and sleepq)\n"));
      nnpfs_initq(&nnpfs_channel[i].messageq);
      nnpfs_initq(&nnpfs_channel[i].sleepq);
    }
  return 0;
}

#if defined(__STDC__)
int nnpfs_uninstall_device(void)
#else
int
nnpfs_uninstall_device()
#endif
{
  /* Check for open, mounted and active vnodes */
  return 0;
}

#if defined(__STDC__)
int nnpfs_vdstat_device(void)
#else
int
nnpfs_vdstat_device()
#endif
{
  return nnpfs_uprintf_device();
}
