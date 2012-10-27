/*
 * Copyright (c) 1999, 2000, 2002-2004 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_dev.c,v 1.15 2004/06/13 15:07:11 lha Exp $ */

#include <nnpfs_locl.h>
#include <nnpfs_errno.h>
#include <nnpfs_proto.h>

typedef struct nnpfs_msg_item {
    PIO_WORKITEM witem;
    IRP *irp;
} nnpfs_msg_item;

void
nnpfs_getmsg_proc(DEVICE_OBJECT *device, nnpfs_msg_item *mitem);

void
nnpfs_wakemsg(nnpfs_channel *chan);

void
xlist_dev_debug(nnpfs_channel *chan) {
#if 0
    struct nnpfs_link *prev = NULL;
    struct nnpfs_link *curr = NULL;

    /* XXX locking */
    XLIST_FOREACH(&chan->messageq, curr, link) {
	ASSERT(prev == XLIST_PREV(curr, link));
	prev = curr;
    }
    ASSERT(prev == XLIST_TAIL(&chan->messageq));
    
    prev = curr = NULL;

    XLIST_FOREACH(&chan->sleepq, curr, link) {
	ASSERT(prev == XLIST_PREV(curr, link));
	prev = curr;
    }
    ASSERT(prev == XLIST_TAIL(&chan->sleepq));
#endif
}

BOOLEAN
nnpfs_opcode_valid(char *buf, unsigned len)
{
    struct nnpfs_message_header *msg;
    char *p = buf;

    while (p < buf + len) {
	msg = (struct nnpfs_message_header *)p;
	if (msg->size != len)
	    nnpfs_debug(XDEBDEV,
			"nnpfs_opcode_valid: opcode %x, msg->size %x, len %x\n",
			msg->opcode, msg->size, len);
	if (msg->opcode >= NNPFS_MSG_COUNT
	    || msg->opcode < 0
	    || msg->size > NNPFS_MAX_MSG_SIZE) {
	    nnpfs_debug(XDEBDEV, "nnpfs_opcode_valid: FALSE\n");
	    return FALSE;
	}

	p += msg->size;
    }
    return TRUE;
}

NTSTATUS
nnpfs_errno2ntstatus(unsigned errno)
{
    switch (errno) {
    case 0: 
	return STATUS_SUCCESS;
    case NNPFS_EPERM:
	return STATUS_ACCESS_VIOLATION;
    case NNPFS_ENOENT:
	return STATUS_NO_SUCH_FILE;
    case NNPFS_ENOMEM:
	return STATUS_NO_MEMORY;
    case NNPFS_EACCES:
	return STATUS_ACCESS_VIOLATION;
    case NNPFS_EEXIST:
	return STATUS_OBJECT_NAME_COLLISION;
    case NNPFS_ENODEV:
	return STATUS_NO_SUCH_DEVICE;
    case NNPFS_ENOTDIR:
	return STATUS_NOT_A_DIRECTORY;
    case NNPFS_EISDIR:
	return STATUS_FILE_IS_A_DIRECTORY;
    case NNPFS_ENOSPC:
	return STATUS_DISK_FULL;
    }
    return STATUS_UNSUCCESSFUL;
}


/*
 *
 */

int
nnpfs_message_wakeup(struct nnpfs_channel *chan,
		     struct nnpfs_message_wakeup * message,
		     u_int size)
{
    struct nnpfs_link *t;

    if (message->error)
	nnpfs_debug(XDEBMSG, "nnpfs_message_wakeup: error %d\n", message->error);

    KeWaitForSingleObject (&chan->sleep_sem, Executive,
			   KernelMode, FALSE, NULL);

    XLIST_FOREACH(&chan->sleepq, t, link) {
	if (t->message->sequence_num == message->sleepers_sequence_num) {
	    if (t->message->size < size) {
		DbgPrint ("NNPFS PANIC Error: "
			  "Could not wakeup requestor with opcode = %d "
			  "properly, too small receive buffer.\n",
			  t->message->opcode);
		t->error_or_size = STATUS_NO_MEMORY;
	    } else
		RtlCopyMemory (t->message, message, size);

	    KeSetEvent (&t->event, 0, FALSE);
	    break;
	}
    }

    KeReleaseSemaphore (&chan->sleep_sem, 0, 1, FALSE);

    if (message->error)
	message->error = STATUS_INVALID_HANDLE;

    return STATUS_SUCCESS;
}

/*
 *
 */

int
nnpfs_message_wakeup_data(struct nnpfs_channel *chan,
			  struct nnpfs_message_wakeup_data * message,
			  u_int size)
{
    struct nnpfs_link *t;

    if (message->error)
	nnpfs_debug(XDEBMSG, "nnpfs_message_wakeup_data error: %d\n", message->error);

    KeWaitForSingleObject (&chan->sleep_sem, Executive,
			   KernelMode, FALSE, NULL);

    XLIST_FOREACH(&chan->sleepq, t, link) {
	if (t->message->sequence_num == message->sleepers_sequence_num) {
	    if (t->message->size < size) {
		DbgPrint ("NNPFS PANIC Error: "
			  "Could not wakeup requestor with opcode = %d "
			  "properly, to small receive buffer.\n",
			  t->message->opcode);
		t->error_or_size = STATUS_NO_MEMORY;
	    } else
		RtlCopyMemory (t->message, message, size);

	    KeSetEvent (&t->event, 0, FALSE);
	    break;
	}
    }

    KeReleaseSemaphore (&chan->sleep_sem, 0, 1, FALSE);

    if (message->error)
	message->error = STATUS_INVALID_HANDLE;

    return STATUS_SUCCESS;
}

/*
 * Send a message to user space and wait for reply.
 */

int
nnpfs_message_rpc(struct nnpfs_channel *chan,
		  struct nnpfs_message_header * message,
		  u_int size)
{
    int ret;
    struct nnpfs_link *this_message;
    struct nnpfs_link *this_process;
    struct nnpfs_message_header *msg = NULL;

    nnpfs_debug (XDEBMSG, "nnpfs_message_rpc opcode = %d\n", message->opcode);
    
    /* no need for synchronisation */
    if (!NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN))
    	return STATUS_NO_SUCH_DEVICE;

    if (size < sizeof(struct nnpfs_message_wakeup)) {
	DbgPrint ("NNPFS PANIC Error: "
		  "Message to small to receive wakeup, opcode = %d\n",
		  message->opcode);
	return STATUS_NO_MEMORY;
    }

    this_message = nnpfs_alloc_link (chan, NNPFS_LINK_RPC, 'dmr1');
    this_process = nnpfs_alloc_link (chan, NNPFS_LINK_RPC, 'dmr2');
    msg = nnpfs_alloc(size, 'dmr3');
    
    if (this_message == NULL || this_process == NULL || msg == NULL) {
	if (this_message != NULL)
	    nnpfs_free_link(chan, this_message);
	if (this_process != NULL)
	    nnpfs_free_link(chan, this_process);
	if (msg != NULL)
	    nnpfs_free(msg, size);
	return STATUS_NO_MEMORY;
    }

    bcopy(message, msg, size);

    msg->size = size;
    msg->sequence_num = chan->nsequence++; /* XXX locking */
    this_message->error_or_size = 0;
    this_message->message = msg;
    this_process->message = msg;

    KeInitializeEvent (&this_process->event, SynchronizationEvent, FALSE);

    xlist_dev_debug(chan);
    KeWaitForSingleObject (&chan->message_sem, Executive,
			   KernelMode, FALSE, NULL);
    XLIST_ADD_TAIL(&chan->messageq, this_message, link);
    xlist_dev_debug(chan);
    KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);

    KeWaitForSingleObject (&chan->sleep_sem, Executive,
			   KernelMode, FALSE, NULL);
    XLIST_ADD_TAIL(&chan->sleepq, this_process, link);
    KeReleaseSemaphore (&chan->sleep_sem, 0, 1, FALSE);

    KeSetEvent (&chan->pending_event, 0, FALSE);
    this_process->error_or_size = 0; /* why here? */

    /* (no need for synchronisation) */
    if (NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN)) {
	void *waitobjs[2] = {&this_process->event, &chan->wake_event};
	NTSTATUS ret;

	nnpfs_debug(XDEBMSG, "nnpfs_message_rpc: KeWait\n");
	ret = KeWaitForMultipleObjects(2, (void*)waitobjs, WaitAny,
				       Executive, KernelMode, FALSE,
				       NULL, NULL); /* XXX alertable? */
	nnpfs_debug(XDEBMSG, "nnpfs_message_rpc: KeWait returned %X\n", ret);

	if (ret != STATUS_WAIT_0)
	    /* hmm, our event wasn't signaled, time to abort */
	    this_process->error_or_size = STATUS_IO_DEVICE_ERROR;
	// STATUS_UNEXPECTED_IO_ERROR is unknown to MS-DOS
    }

    /*
     * Caught signal, got reply message or device was closed.
     * Need to clean up both messageq and sleepq.
     */

    KeWaitForSingleObject (&chan->message_sem, Executive,
			   KernelMode, FALSE, NULL);
    if (XLIST_ONQ(&chan->messageq, this_message, link))
	XLIST_REMOVE(&chan->messageq, this_message, link);

    KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);

    KeWaitForSingleObject (&chan->sleep_sem, Executive,
			   KernelMode, FALSE, NULL);
    if (XLIST_ONQ(&chan->sleepq, this_process, link))
	XLIST_REMOVE(&chan->sleepq, this_process, link);

    KeReleaseSemaphore (&chan->sleep_sem, 0, 1, FALSE);

    ret = this_process->error_or_size;

    nnpfs_debug (XDEBMSG, 
		 "nnpfs_message_rpc error_or_size = %d, wakeup->error = %d\n",
		 this_process->error_or_size, 
		 ((struct nnpfs_message_wakeup *)(this_process->message))->error);
    
    {
	unsigned *e = &((struct nnpfs_message_wakeup *)(this_process->message))->error; 
	if (ret == 0 && *e)
	    *e = nnpfs_errno2ntstatus(*e);
    }

    bcopy(msg, message, size);

    nnpfs_free_link (chan, this_message);
    nnpfs_free_link (chan, this_process);
    nnpfs_free (msg, size);

    return ret;
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
int
nnpfs_message_receive(struct nnpfs_channel *chan,
		      struct nnpfs_message_header *message,
		      u_int size)
{
    /* Dispatch and coerce message type */
    switch (message->opcode) {
    case NNPFS_MSG_WAKEUP:
	return nnpfs_message_wakeup(chan,
				    (struct nnpfs_message_wakeup *)
				    message,
				    message->size);
    case NNPFS_MSG_WAKEUP_DATA:
	return nnpfs_message_wakeup_data(chan,
					 (struct nnpfs_message_wakeup_data *)
					 message,
					 message->size);
    case NNPFS_MSG_INSTALLROOT:
	return nnpfs_message_installroot(chan,
					 (struct nnpfs_message_installroot *)
					 message,
					 message->size);
    case NNPFS_MSG_INSTALLNODE:
	return nnpfs_message_installnode(chan,
					 (struct nnpfs_message_installnode *)
					 message,
					 message->size);
    case NNPFS_MSG_INSTALLATTR:
	return nnpfs_message_installattr(chan,
					 (struct nnpfs_message_installattr *)
					 message,
					 message->size);
    case NNPFS_MSG_INSTALLDATA:
	return nnpfs_message_installdata(chan,
					 (struct nnpfs_message_installdata *)
					 message,
					 message->size);
    case NNPFS_MSG_INVALIDNODE:
	return nnpfs_message_invalidnode(chan,
					 (struct nnpfs_message_invalidnode *)
					 message,
					 message->size);
    case NNPFS_MSG_UPDATEFID:
	return nnpfs_message_updatefid(chan,
				       (struct nnpfs_message_updatefid *)
				       message,
				       message->size);
    case NNPFS_MSG_GC_NODES:
	return nnpfs_message_gc_nodes(chan,
				      (struct nnpfs_message_gc_nodes *)
				      message,
				      message->size);
    case NNPFS_MSG_VERSION:
	return nnpfs_message_version(chan,
				     (struct nnpfs_message_version *)
				     message,
				     message->size);
    case NNPFS_MSG_DELETE_NODE:
	return STATUS_SUCCESS;

    default:
	nnpfs_debug (XDEBDEV, "NNPFS PANIC "
		     "Warning nnpfs_chan: Unknown message opcode == %x\n",
		     message->opcode);
	DbgBreakPoint();
	return STATUS_INVALID_PARAMETER;
    }
}

/*
 * Send a message to user space.
 */

int
nnpfs_message_send (struct nnpfs_channel *chan,
		    struct nnpfs_message_header *message,
		    u_int size)
{
    struct nnpfs_link *this_message;
    struct nnpfs_message_header *msg;
    int ret;

    ASSERT(message != NULL);

    nnpfs_debug(XDEBMSG, "nnpfs_message_send opcode = %d, size %x\n",
		message->opcode, size);

    /* no need for synchronisation? */
    if (!NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN)) {
	nnpfs_debug(XDEBMSG, "nnpfs_message_send(%d): channel not open!\n",
		    message->opcode);
	return STATUS_NO_SUCH_DEVICE;
    }

    /* Prepare message and copy it later */
    ASSERT(size != 0);

    message->size = size;
    message->sequence_num = chan->nsequence++; /* XXX locking */

    this_message = nnpfs_alloc_link(chan, 0, 'dms1');
    msg = nnpfs_alloc(size, 'dms2');

    if (this_message == NULL || msg == NULL) {
	if (this_message != NULL)
	    nnpfs_free_link(chan, this_message);
	else
	    nnpfs_free(msg, size);
	return STATUS_NO_MEMORY;
    }

    this_message->error_or_size = 0;
    msg->size = size;
    bcopy(message, msg, size);

    this_message->message = msg;

    KeWaitForSingleObject (&chan->message_sem, Executive,
			   KernelMode, FALSE, NULL);
    XLIST_ADD_TAIL(&chan->messageq, this_message, link);
    xlist_dev_debug(chan);
    KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);

    KeSetEvent (&chan->pending_event, 0, FALSE);
    /*    pollwakeup(&chan->pollhead, POLLRDNORM);*/
    return 0;
}

/*
 * Move messages from user space to kernel, 
 * take appropriate action
 */

static int
nnpfs_devwrite (struct nnpfs_channel *chan, char *msg, u_int cnt)
{
    char *p;
    int error;
    int remain = cnt; /* XXX large sizes? */
    struct nnpfs_message_header *msg_buf;
    
    if (msg == 0)
	return STATUS_INVALID_PARAMETER;

    FsRtlEnterFileSystem();
    
    /*
     * This thread handles the received message.
     */
    for (p = msg; remain > 0;) {
	msg_buf = (struct nnpfs_message_header *)p;

	p += msg_buf->size;
	remain -= msg_buf->size;

	error = nnpfs_message_receive (chan,
				       msg_buf,
				       msg_buf->size);
    }

    FsRtlExitFileSystem();

    return error;
}

/*
 * Move messages from kernel to user space.
 *
 * Locking: message_sem is aquired and released externally
 */

static NTSTATUS
nnpfs_devread(struct nnpfs_channel *chan, unsigned char *buf, u_int *size)
{
    struct nnpfs_link *first;
    xlist_dev_debug(chan);

    while (!XLIST_EMPTY(&chan->messageq)) {
	/* Remove message */
	first = XLIST_HEAD(&chan->messageq);
	xlist_dev_debug(chan);
	nnpfs_debug(XDEBDEV, "nnpfs_devread: message->size = %u, op %d\n",
		    first->message->size, first->message->opcode);
	
	if (first->message->size > *size)
	    break;
	
	memcpy (buf, first->message, first->message->size);
	buf += first->message->size;
	*size -= first->message->size;
	
	xlist_dev_debug(chan);
	XLIST_REMOVE(&chan->messageq, first, link);
	xlist_dev_debug(chan);
	
	/* if we're not waiting for reply, link & msg can be discarded */
	/* XXX locking */
	if (!NNPFS_TESTFLAGS (first->flags, NNPFS_LINK_RPC)) {
	    nnpfs_free(first->message, first->message->size);
	    nnpfs_free_link(chan, first);
	}
    }

    nnpfs_debug (XDEBDEV, "nnpfs_devread done\n");

    return STATUS_SUCCESS;
}

void
nnpfs_getmsg_cancel(DEVICE_OBJECT *device, IRP *irp) {
    KIRQL irql = irp->CancelIrql;
    nnpfs_channel *chan = &NNPFSGlobalData;
    
    IoSetCancelRoutine(irp, NULL); /* XXX race? */
    IoReleaseCancelSpinLock(irql);

    nnpfs_debug(XDEBDEV, "CANCEL!\n");
    
    /* wake _all_ sleepers */
    nnpfs_wakemsg(chan);

    /* we let nnpfs_getmsg complete the queued, signaled irp */
}

/*
 * pend the irp, post workitem, return pending
 */

NTSTATUS
nnpfs_getmsg_pend(nnpfs_channel *chan, DEVICE_OBJECT *device, IRP *irp) {
    PIO_WORKITEM witem;
    nnpfs_msg_item *mitem;
    nnpfs_debug (XDEBDEV, "nnpfs_getmsg_pend\n");
    
    if (!NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN)) {
	NNPFS_SETFLAGS(chan->flags, NNPFSCHAN_FLAGS_OPEN);
	KeClearEvent(&chan->wake_event);
    }

    witem = IoAllocateWorkItem(device);
    if (witem == NULL)
	return STATUS_INSUFFICIENT_RESOURCES;

    mitem = nnpfs_alloc(sizeof(nnpfs_msg_item), 'dgp1');
    if (mitem == NULL) {
	IoFreeWorkItem(witem);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    mitem->witem = witem;
    mitem->irp = irp;
    IoMarkIrpPending(irp);
    IoSetCancelRoutine(irp, nnpfs_getmsg_cancel); /* XXX */
    
    /* complete the processing (wait really) in system thread, async */
    /* XXX delayed work queue? */
    IoQueueWorkItem(witem, nnpfs_getmsg_proc, CriticalWorkQueue, mitem);
    
    return STATUS_PENDING;
}

NTSTATUS
nnpfs_getmsg(nnpfs_channel *chan, IRP *irp, BOOLEAN pending)
{
    IO_STACK_LOCATION *io_stack;
    FILE_OBJECT *file;
    unsigned char *buf;
    u_int orig_len, out_len = 0;
    u_int len, loop = 0;
    NTSTATUS status = STATUS_SUCCESS;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    buf = irp->AssociatedIrp.SystemBuffer;
    file = io_stack->FileObject;

    xlist_dev_debug(chan);

    while (out_len == 0 && NT_SUCCESS(status)) {
	loop++;
	xlist_dev_debug(chan);
	
	nnpfs_debug (XDEBDEV, "nnpfs_getmsg - wait1(msg_sem)\n");
	KeWaitForSingleObject (&chan->message_sem, Executive,
			       KernelMode, FALSE, NULL);	
	if (XLIST_EMPTY(&chan->messageq)) {
	    KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);
	    
	    if (pending) {
		/* we are async, irp is pended - it's ok to block */
		
		if (irp->Cancel) {
		    status = STATUS_CANCELLED;
		    break;
		}
		
		nnpfs_debug (XDEBDEV, "nnpfs_getmsg - wait2(global)\n");
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&chan->lock, TRUE);
		
		if (chan->pending_count != 0) {
		    ExReleaseResourceLite(&chan->lock);
		    FsRtlExitFileSystem();
		    status = STATUS_DEVICE_BUSY;
		    break;
		}
		chan->pending_count++;

		ExReleaseResourceLite(&chan->lock);
		FsRtlExitFileSystem();
		
		nnpfs_debug (XDEBDEV, "nnpfs_getmsg - wait for pending_event\n");
		KeWaitForSingleObject(&chan->pending_event, 
				      Executive,
				      KernelMode,
				      FALSE,
				      NULL);
		
		nnpfs_debug (XDEBDEV, "nnpfs_getmsg - wait3(global)\n");
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&chan->lock, TRUE);

		ASSERT(chan->pending_count == 1);
		chan->pending_count--;

		ExReleaseResourceLite(&chan->lock);
		FsRtlExitFileSystem();
		
		if (irp->Cancel) {
		    status = STATUS_CANCELLED;
		    break;
		}

		nnpfs_debug (XDEBDEV, "nnpfs_getmsg - wait4(msg_sem)\n");
		KeWaitForSingleObject (&chan->message_sem, Executive,
				       KernelMode, FALSE, NULL);
	    } else {
		/* 
		 * we're called from dispatch but no work to do yet
		 * -- pend it
		 */
		status = nnpfs_getmsg_pend(chan, io_stack->DeviceObject, irp);
		nnpfs_debug (XDEBDEV, "nnpfs_getmsg - pend done\n");
		break;
	    }
	    xlist_dev_debug(chan);
	}
	orig_len = 
	    io_stack->Parameters.DeviceIoControl.OutputBufferLength;
	len = orig_len;
	status = nnpfs_devread (chan, buf, &len);
	out_len = orig_len - len;
	if (out_len == 0)
	    nnpfs_debug (XDEBDEV,
			 "nnpfs_getmsg - release2, out_len = %x"
			 ", loop = %d, status %d\n",
			 out_len, loop, status);
	else
	    nnpfs_opcode_valid(buf, out_len);
	KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);
    }

    if (status != STATUS_PENDING) {
	IoSetCancelRoutine(irp, NULL);
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = out_len;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    nnpfs_debug (XDEBDEV, "nnpfs_getmsg - returning status %d\n", status);
    return status;
}


void
nnpfs_getmsg_proc(DEVICE_OBJECT *device, nnpfs_msg_item *mitem)
{
    IRP *irp = mitem->irp;

    nnpfs_debug (XDEBDEV, "nnpfs_getmsg_proc\n");
    nnpfs_getmsg(&NNPFSGlobalData, irp, TRUE); /* blocking call */
    
    IoFreeWorkItem(mitem->witem);
    nnpfs_free(mitem, sizeof (*mitem));
}

void
nnpfs_wakemsg(nnpfs_channel *chan) {
    uint32_t sequence_num;
    struct nnpfs_link *first;
    BOOLEAN done = FALSE;

    nnpfs_debug (XDEBDEV, "nnpfs_wakemsg\n");

    FsRtlEnterFileSystem();
    ExAcquireResourceExclusiveLite(&chan->lock, FALSE);

    /* mark the device closed */
    NNPFS_RESETFLAGS(chan->flags, NNPFSCHAN_FLAGS_OPEN); 

    /* wake up sleepers */
    KeSetEvent(&chan->wake_event, 0, FALSE);
    if (chan->root) {
	nnpfs_vrele(chan->root);
	chan->root = NULL;
    }
    ExReleaseResourceLite(&chan->lock);

    KeWaitForSingleObject (&chan->message_sem, Executive,
			   KernelMode, FALSE, NULL);
    /* No one is going to read those messages so empty queue! */
    nnpfs_debug (XDEBDEV, "nnpfs_wakemsg: cleaning messageq\n");
    XLIST_FOREACH(&chan->messageq, first, link) {
	if (!NNPFS_TESTFLAGS(first->flags, NNPFS_LINK_RPC)) {
	    xlist_dev_debug(chan);
	    nnpfs_free(first->message, first->message->size);
	    nnpfs_free_link(chan, first);
	}
    }
    KeReleaseSemaphore (&chan->message_sem, 0, 1, FALSE);

    ExAcquireResourceSharedLite(&chan->lock, TRUE);
    if (chan->pending_count) {
	ASSERT(chan->pending_count == 1);

	/* wake up the hanging getmsg irp */
	KeSetEvent (&chan->pending_event, 0, FALSE);
    }
    ExReleaseResourceLite(&chan->lock);
    
    /* forced clearing of our cache */
    nnpfs_node_gc_all(chan, TRUE);

    /* paranoia */
    {
	nnpfs_node *node;
	ExAcquireFastMutex(&chan->NodeListMutex);
	
	XLIST_FOREACH(&chan->nodes, node, lru_entry)
	    if (NNPFS_TOKEN_GOT(node,
				NNPFS_OPEN_MASK | NNPFS_ATTR_MASK
				|NNPFS_DATA_MASK | NNPFS_LOCK_MASK)
		|| NNPFS_VALID_DATAHANDLE(node))
		nnpfs_debug (XDEBDEV,
			     "nnpfs_wakemsg: node %X, tokens %X, data:%X\n",
			     node, NNPFS_TOKEN_GOT(node,
						   NNPFS_OPEN_MASK | NNPFS_ATTR_MASK
						   |NNPFS_DATA_MASK | NNPFS_LOCK_MASK),
			     DATA_FROM_XNODE(node));

	ExReleaseFastMutex(&chan->NodeListMutex);
    }
    FsRtlExitFileSystem();
}

/*
 * Send the pioctl to arlad
 */

static int
nnpfs_pioctl (nnpfs_channel *chan,
	      nnpfs_pioctl_args *args, 
	      u_int inlength,
	      u_int *outlength)
{
    NTSTATUS status;
    struct nnpfs_message_pioctl msg;
    struct nnpfs_message_wakeup_data *msg2;
    nnpfs_node *node;
    nnpfs_cred *cred = NULL; /* XXX */
    char *path;

    if (args->insize > NNPFS_MSG_MAX_DATASIZE
	|| args->insize < 0
	||(u_int)
	(&args->msg[args->insize + args->pathsize] - (char *)args) > inlength
	|| args->outsize > *outlength) {
	nnpfs_debug(XDEBDEV,
		    "nnpfs_dev_pioctl: strange in packet: op %d, sz %d\n",
		    args->opcode, args->insize);
	return STATUS_INVALID_PARAMETER;
    }

    FsRtlEnterFileSystem();

    if (args->pathsize > 0) {
	path = args->msg + args->insize;
	
	/* XXX check length of path, terminated, etc */
	nnpfs_path_winify(path);
	
	ASSERT(chan->root); /* XXX */
	/* XXX followsymlinks */
	status = nnpfs_lookup_path(chan, path, NULL, &node, NULL, cred, 0);
	if (!NT_SUCCESS(status))
	    goto out;
    
	if (node != NULL) {
	    msg.handle = node->handle;
	    nnpfs_vrele(node);
	}
    }

    if (args->insize != 0)
	RtlCopyMemory(msg.msg, args->msg, args->insize);

    msg.header.opcode = NNPFS_MSG_PIOCTL;
    msg.header.size = sizeof(msg);
    msg.opcode = args->opcode;

    msg.insize = args->insize;
    msg.outsize = args->outsize;
    msg.cred.uid = NNPFS_ANONYMOUSID;
    msg.cred.pag = 0;
	
    status = nnpfs_message_rpc(chan, &msg.header, sizeof(msg)); /* XXX */
    msg2 = (struct nnpfs_message_wakeup_data *) &msg;

    if (NT_SUCCESS(status))
	status = msg2->error;
    if (status == STATUS_NO_SUCH_DEVICE)
	status = STATUS_INVALID_PARAMETER;

    if (NT_SUCCESS(status) && msg2->header.opcode == NNPFS_MSG_WAKEUP_DATA) {
	u_int len;

	len = msg2->len;
	if (len > args->outsize)
	    len = args->outsize;
	if (len > NNPFS_MSG_MAX_DATASIZE)
	    len = NNPFS_MSG_MAX_DATASIZE;

	if (len > 0)
	    RtlCopyMemory(args, msg2->msg, len);
	*outlength = len;
    }
 out:
    FsRtlExitFileSystem();

    return status;
}

/*
 *
 */

NTSTATUS 
nnpfs_fsd_devctl (DEVICE_OBJECT *device, IRP *irp)
{ 
    IO_STACK_LOCATION *io_stack;
    struct nnpfs_channel *chan = &NNPFSGlobalData;
    unsigned char *buf;
    NTSTATUS status = STATUS_SUCCESS;
    u_int info = 0;
    u_int inlen, outlen;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT (io_stack);

    buf = irp->AssociatedIrp.SystemBuffer;
    inlen = io_stack->Parameters.DeviceIoControl.InputBufferLength;

    if (irp->MdlAddress != NULL) {
	status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    /* XXX access control.
     *   pioctl should be open for all, other superuser only 
     */

    switch (io_stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_NNPFS_PUTMSG:
	nnpfs_debug (XDEBDEV, "IOCTL_NNPFS_PUTMSG\n");
	status = nnpfs_devwrite (chan, buf, inlen);
	break;

    case IOCTL_NNPFS_WAKEMSG:
	nnpfs_debug (XDEBDEV, "IOCTL_NNPFS_WAKEMSG\n");
	
	/* wake _all_ sleepers */
	nnpfs_wakemsg(chan);
	break;

    case IOCTL_NNPFS_GETMSG:
    {
	BOOLEAN blockp = 
	    io_stack->FileObject->Flags & FO_SYNCHRONOUS_IO ? TRUE : FALSE;

	nnpfs_debug (XDEBDEV, "IOCTL_NNPFS_GETMSG\n");
	
	/* nnpfs_getmsg pends or completes irp */
	status = nnpfs_getmsg(chan, irp, blockp);
	return status;
    }
    case IOCTL_NNPFS_PIOCTL:
    {
	outlen = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
	nnpfs_debug (XDEBDEV, "IOCTL_NNPFS_PIOCTL\n");
    
	status = nnpfs_pioctl(chan, (nnpfs_pioctl_args *)buf, inlen, &outlen);
	if (NT_SUCCESS(status))
	    info = outlen;
	break;
    }
    default:
	nnpfs_debug (XDEBDEV, "nnpfs_devctl: unknown code %X\n",
		     io_stack->Parameters.DeviceIoControl.IoControlCode);
	break;
    }
    
 out:
    /* XXX we cannot have been cancelled, right? */
    if (status != STATUS_PENDING) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    return status;
}
