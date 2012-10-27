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

#include <dummer.h>

/* RCSID("$Id: nnpfs_message.c,v 1.2 2006/10/24 16:33:26 tol Exp $"); */


#define NNPFSDEB(level, args) do {printf args;} while (0)

static int nsequence = 0;

int32_t sleep_seq = NOSEQ;
int32_t wakeup_seq = NOSEQ;
int32_t wakeup_error = 0;

/*
 * Send a message to daemon, remember "where" to continue execution
 */
int
nnpfs_message_rpc(struct nnpfs_message_header *message, u_int size)
{
    int ret;
    if (sleep_seq != NOSEQ)
	printf("nnpfs_message_rpc: previous seq not NOSEQ!\n");

    ret = nnpfs_message_send(message, size);
    sleep_seq = message->sequence_num;
    state = SLEEPING;

    return ret;
}

/*
 * Send a message to daemon
 */
int
nnpfs_message_send(struct nnpfs_message_header *message, u_int size)
{
    ssize_t ret;
    int32_t slen = htonl(size);
    char out_len[4];

    /* NNPFSDEB(XDEBMSG, ("nnpfs_message_send opcode = %d\n", message->opcode)); */

    message->size = size;
    message->sequence_num = nsequence++;

    memcpy(out_len, &slen, sizeof(slen));
    if (send(nnpfsp->fd, out_len, sizeof(out_len), 0) != sizeof(out_len)) {
	printf("write len failed %d\n", errno);
	return -1;
    }
    ret = send(nnpfsp->fd, message, size, 0);
    if (ret < 0)
	printf("write failed %d\n", errno);

    return 0;
}

static int
nnpfs_message_wakeup(struct nnpfs_message_wakeup *message,
		     u_int size)
{
    /* NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup error: %d\n", message->error)); */
    
    wakeup_error = message->error;
    wakeup_seq = message->sleepers_sequence_num;

    assert(wakeup_error == 0);

    return 0;
}

static int
nnpfs_message_wakeup_data(struct nnpfs_message_wakeup_data *message,
			  u_int size)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_wakeup_data error: %d\n", message->error));

    wakeup_error = message->error;
    wakeup_seq = message->sleepers_sequence_num;

    /* XXX save data for the user */

    return 0;
}

static int
nnpfs_message_installroot(struct nnpfs_message_installroot * message,
			  u_int size)
{
    int error = 0;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installroot (%d,%d,%d,%d)\n",
		       message->node.handle.a,
		       message->node.handle.b,
		       message->node.handle.c,
		       message->node.handle.d));
    
    if (nnpfsp->root != NULL) {
	printf("PANIC nnpfs_message_installroot: called again!\n");
	error = EBUSY;
    } else {
	error = nnpfs_new_node(&message->node, &nnpfsp->root);
    }

    return error;
}

static int
nnpfs_message_installnode(struct nnpfs_message_installnode * message,
			  u_int size)
{
    struct nnpfs_node *n, *dp;
    int error = 0;
    
    printf("nnpfs_message_installnode (%d,%d,%d,%d)\n",
	   message->node.handle.a, message->node.handle.b,
	   message->node.handle.c, message->node.handle.d);

    error = nnpfs_node_find(&message->parent_handle, &dp);
    if (error) {
	if (error == EISDIR)
	    printf("installnode: parent node deleted\n");
	else if (error == ENOENT)
	    printf("NNPFS PANIC WARNING! nnpfs_message_installnode: no parent\n");
	
	return error;
    }

    if (dp) {
	error = nnpfs_new_node(&message->node, &n);
	if (error)
	    return error;
	
	nnpfs_dnlc_enter(dp, message->name, n);
    } else {
	printf("NNPFS PANIC WARNING! nnpfs_message_installnode: no node\n");
	error = ENOENT;
    }

    return error;
}

static int
nnpfs_message_installattr(struct nnpfs_message_installattr * message,
			  u_int size)
{
    struct nnpfs_node *t;
    int error = 0;
    
    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr (%d,%d,%d,%d) \n",
		       message->node.handle.a,
		       message->node.handle.b,
		       message->node.handle.c,
		       message->node.handle.d));
    error = nnpfs_node_find(&message->node.handle, &t);
    if (error) {
	if (error == EISDIR) {
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: node deleted\n"));
	} else if (error == ENOENT) {
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: no such node\n"));
	    error = 0;
	}
	return error;
    }

    t->tokens = message->node.tokens;
    if (t->writers == 0)          /* XXX readers? */
	t->attr = message->node.attr;

    return error;
}

static int
nnpfs_message_installdata(struct nnpfs_message_installdata * message,
			  u_int size)
{
    struct nnpfs_node *t;
    int error = 0;

    printf("nnpfs_message_installdata (%d,%d,%d,%d) @%" PRIx64 "\n",
	   message->node.handle.a, message->node.handle.b,
	   message->node.handle.c, message->node.handle.d,
	   message->offset);

    error = nnpfs_node_find(&message->node.handle, &t);
    if (error) {
	if (error == ENOENT) {
	    printf("NNPFS PANIC WARNING! nnpfs_message_installdata failed\n");
	    printf("Reason: No node to install the data into!\n");
	} else if (error == EISDIR) {
	    printf("installdata: node deleted\n");
	}
	return error;
    }

    t->tokens = message->node.tokens;
    if (t->writers == 0)          /* XXX readers? */
	t->attr = message->node.attr;
    t->index = message->cache_id;

    if (message->offset != NNPFS_NO_OFFSET)
	nnpfs_node_block_setvalid(t, message->offset);

    return error;
}

static int
nnpfs_message_invalidnode(struct nnpfs_message_invalidnode * message,
			  u_int size)
{
    int error;
    struct nnpfs_node *node;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode (%d,%d,%d,%d)\n",
		       message->handle.a,
		       message->handle.b,
		       message->handle.c,
		       message->handle.d));
    
    error = nnpfs_node_find(&message->handle, &node);
    if (error) {
	if (error == ENOENT)
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: no such node\n"));
	else if (error == EISDIR)
	    NNPFSDEB(XDEBMSG, ("nnpfs_message_invalidnode: node deleted\n"));
	
	return error;
    }

    /* If open for writing, return immediately. Last close:er wins! */
    if (node->writers > 0)
	return 0;

    /* If node is in use, mark as stale */
    if (node->readers > 0 &&
	(XA_VALID_TYPE(&node->attr) && node->attr.xa_type != NNPFS_FILE_DIR)) {
	node->flags |= NNPFS_STALE;
	return 0;
    }
    nnpfs_reclaim(node);

    return 0;
}

static int
nnpfs_message_updatefid(struct nnpfs_message_updatefid * message,
			u_int size)
{
    int error = 0;

    NNPFSDEB(XDEBMSG, ("nnpfs_message_updatefid (%d,%d,%d,%d) (%d,%d,%d,%d)\n",
		       message->old_handle.a,
		       message->old_handle.b,
		       message->old_handle.c,
		       message->old_handle.d,
		       message->new_handle.a,
		       message->new_handle.b,
		       message->new_handle.c,
		       message->new_handle.d));
    return error;
}

static int
nnpfs_message_gc(struct nnpfs_message_gc *message, u_int size)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_gc\n"));

    return 0;
}


/*
 * Probe what version of nnpfs this support
 */

static int
nnpfs_message_version(struct nnpfs_message_version *message,
		      u_int size)
{
    struct nnpfs_message_wakeup msg;
    int ret;
    int done = 0;

    /* sanity check before we look at it */
    if (size == sizeof(*message) && message->version == NNPFS_VERSION) {
	nnpfsp->blocksize = message->blocksize;
	done = 1;
    }	
    ret = NNPFS_VERSION;

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;

    ret = nnpfs_message_send((struct nnpfs_message_header *) &msg,
			     sizeof(msg));
    if (!ret && done)
	state = READY;

    return ret;
}

/*
 *
 */

static int
nnpfs_message_delete_node(struct nnpfs_message_delete_node *message,
			  u_int size)
{
    struct nnpfs_node *node;
    int ret = nnpfs_node_find(&message->handle, &node);
    if (ret == ENOENT) {
	printf("nnpfs_message_delete_node: no such node\n");
	return ENOENT;
    }

    if (node->flags & NNPFS_LIMBO) {
	NNPFSDEB(XDEBMSG, ("delete_node: free node\n"));
	nnpfs_free_node(node);
    } else {
	NNPFSDEB(XDEBMSG, ("delete_node: not deleted"));
    }

    return 0;
}

/*
 * For each message type there is a message handler
 * that implements its action, nnpfs_message_receive
 * invokes the correct function.
 */
int
nnpfs_message_receive(struct nnpfs_message_header *message,
		      u_int size)
{
    /* Dispatch and coerce message type */
    switch (message->opcode) {
    case NNPFS_MSG_WAKEUP:
	return nnpfs_message_wakeup((struct nnpfs_message_wakeup *) message,
				    message->size);
    case NNPFS_MSG_WAKEUP_DATA:
	return nnpfs_message_wakeup_data((struct nnpfs_message_wakeup_data *) message,
					 message->size);
    case NNPFS_MSG_INSTALLROOT:
	return nnpfs_message_installroot((struct nnpfs_message_installroot *) message,
					 message->size);
    case NNPFS_MSG_INSTALLNODE:
	return nnpfs_message_installnode((struct nnpfs_message_installnode *) message,
					 message->size);
    case NNPFS_MSG_INSTALLATTR:
	return nnpfs_message_installattr((struct nnpfs_message_installattr *) message,
					 message->size);
    case NNPFS_MSG_INSTALLDATA:
	return nnpfs_message_installdata((struct nnpfs_message_installdata *) message,
					 message->size);
    case NNPFS_MSG_INVALIDNODE:
	return nnpfs_message_invalidnode((struct nnpfs_message_invalidnode *) message,
					 message->size);
    case NNPFS_MSG_UPDATEFID:
	return nnpfs_message_updatefid((struct nnpfs_message_updatefid *)message,
				       message->size);
    case NNPFS_MSG_GC:
	return nnpfs_message_gc((struct nnpfs_message_gc *)message,
				message->size);
    case NNPFS_MSG_DELETE_NODE:
	return nnpfs_message_delete_node((struct nnpfs_message_delete_node *)message,
					 message->size);
    case NNPFS_MSG_VERSION:
	return nnpfs_message_version((struct nnpfs_message_version *)message,
				     message->size);
    default:
	printf("NNPFS PANIC Warning nnpfs dev: Unknown message opcode == %d\n",
	       message->opcode);
	return EINVAL;
    }
}
