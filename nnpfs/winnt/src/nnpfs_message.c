/*
 * Copyright (c) 1995 - 2004 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_message.c,v 1.12 2004/05/13 08:32:23 tol Exp $ */

#include <nnpfs_locl.h>


char *
nnpfs_strerror (NTSTATUS status)
{
    switch (status) {
    case STATUS_SUCCESS:
	return "SUCCESS";
    case STATUS_OBJECT_TYPE_MISMATCH:
	return "OBJECT_TYPE_MISMATCH";
    case STATUS_ACCESS_DENIED:
	return "ACCESS_DENIED";
    case STATUS_INVALID_HANDLE:
	return "INVALID_HANDLE";
    case STATUS_ACCESS_VIOLATION:
	return "ACCESS_VIOLATION";
    }
    return "unknown error";
}

/*
 *
 */

int
nnpfs_message_installroot(struct nnpfs_channel *chan,
			  struct nnpfs_message_installroot * message,
			  u_int size)
{
    int error = 0;
    
    nnpfs_debug(XDEBMSG, "nnpfs_message_installroot (%d,%d,%d,%d)\n",
		message->node.handle.a,
		message->node.handle.b,
		message->node.handle.c,
		message->node.handle.d);
    
    if (chan->root != NULL) {
	DbgPrint ("NNPFS PANIC WARNING! "
		  "nnpfs_message_installroot: called again!\n");
	error = STATUS_DEVICE_BUSY;
    } else {
	error = nnpfs_new_node(chan, &message->node, &chan->root);
	if (error)
	    return error;

	/* XXX locking */
	chan->root->flags |= NNPFS_FCB_ROOT_DIRECTORY;
    }
    return error;
}

/*
 *
 */


int
nnpfs_message_installnode(struct nnpfs_channel *chan,
			  struct nnpfs_message_installnode * message,
			  u_int size)
{
    int error = 0;
    struct nnpfs_node *n, *dp;

    nnpfs_debug(XDEBMSG, "nnpfs_message_installnode (%d,%d,%d,%d)\n",
		message->node.handle.a,
		message->node.handle.b,
		message->node.handle.c,
		message->node.handle.d);

    dp = nnpfs_node_find(chan, &message->parent_handle);
    if (dp) {
	error = nnpfs_new_node(chan, &message->node, &n);
	if (error) {
	    nnpfs_vrele (dp);
	    return error;
	}

	nnpfs_dnlc_enter(dp, message->name, n);
	nnpfs_vrele (n);
	nnpfs_vrele (dp);
    } else {
	DbgPrint ("NNPFS PANIC WARNING! nnpfs_message_installnode: no parent\n");
	error = STATUS_NO_SUCH_FILE;
    }
    if (error)
	nnpfs_debug(XDEBMSG, "nnpfs_message_installnode: returning %d\n", error);
    
    return error;
}

/*
 *
 */

int
nnpfs_message_installattr(struct nnpfs_channel *chan,
			  struct nnpfs_message_installattr * message,
			  u_int size)
{
    int error = STATUS_SUCCESS;
    struct nnpfs_node *t;

    nnpfs_debug(XDEBMSG, "nnpfs_message_installattr (%d,%d,%d,%d) \n",
		message->node.handle.a,
		message->node.handle.b,
		message->node.handle.c,
		message->node.handle.d);

    t = nnpfs_node_find(chan, &message->node.handle);
    if (t != NULL) {
	t->tokens = message->node.tokens;
	if (NNPFS_TOKEN_GOT(t, NNPFS_DATA_MASK) && !NNPFS_VALID_DATAHANDLE(t)) {
	    DbgPrint ("nnpfs_message_installattr(%X): tokens and no data\n",
		      t);
	    NNPFS_TOKEN_CLEAR (t, NNPFS_DATA_R|NNPFS_DATA_W , NNPFS_DATA_MASK);
	}

	if (!NNPFS_TOKEN_GOT(t, NNPFS_DATA_R) && NNPFS_VALID_DATAHANDLE(t)) {
	    DbgPrint ("nnpfs_message_installattr(%X): data and no token\n",
		      t);
	}

	nnpfs_attr2vattr(&message->node.attr, t);

#if 0 /* XXX sync xa_size with CC_FILE_SIZES? */
	CcSetFileSizes(XNODE_TO_VNODE(t), t->attr.va_size);
#endif
	bcopy(message->node.id, t->id, sizeof(t->id));
	bcopy(message->node.rights, t->rights, sizeof(t->rights));
	t->anonrights = message->node.anonrights;
	nnpfs_vrele (t);
    } else {
	nnpfs_debug(XDEBMSG, "nnpfs_message_installattr: no such node\n");
    }

    return error;
}

void
nnpfs_check_backfile(nnpfs_node *node)
{
    FILE_OBJECT *file;
    FILE_OBJECT *backfile = node->backfile;
    FSRTL_COMMON_FCB_HEADER *fcb;
    LARGE_INTEGER offset;

    if (node->attr.xa_type != NNPFS_FILE_DIR && node->attr.xa_size != 0) {
	offset.QuadPart = 0;
	/* XXX acquire backfile exclusively */
	
	if (node->attr.xa_type == NNPFS_FILE_LNK) {
	    CcFlushCache(backfile->SectionObjectPointer, &offset,
			 node->attr.xa_size, NULL); /* XXX */
	} else {
	    BOOLEAN ret;
	    ASSERT(node->offset % PAGE_SIZE == 0
		   || node->offset == node->attr.xa_size);
	    
	    CcFlushCache(backfile->SectionObjectPointer, &offset,
			 node->offset, NULL); /* XXX */
	    
	    ret = CcPurgeCacheSection(backfile->SectionObjectPointer, &offset,
				      node->offset, FALSE); /* XXX */
	    ASSERT(ret);
	}
	/* XXX release backfile */
    }
}

/*
 *
 */

int
nnpfs_message_installdata(struct nnpfs_channel *chan,
			  struct nnpfs_message_installdata *message,
			  u_int size)
{
    struct nnpfs_node *t;
    OBJECT_HANDLE_INFORMATION obj_info;
    int error = 0;

    nnpfs_debug(XDEBMSG, "nnpfs_message_installdata (%d,%d,%d,%d)\n",
		message->node.handle.a,
		message->node.handle.b,
		message->node.handle.c,
		message->node.handle.d);

    t = nnpfs_node_find(chan, &message->node.handle);
    if (t != NULL) {
/*	nnpfs_cache_handle fh = message->cache_handle;*/

/*  	if (NNPFS_VALID_DATAHANDLE(t)) */
/*  	    nnpfs_close_data_handle (t); */

	ExAcquireResourceExclusiveLite(&t->MainResource, TRUE);
	nnpfs_debug (XDEBMSG, "nnpfs_message_installdata: got Main\n");
    
	if (message->flag & NNPFS_ID_INVALID_DNLC)
	    /* XXX check that it is a dir */
	    nnpfs_dnlc_drop_children(t);
	    
	if (!NNPFS_VALID_DATAHANDLE(t)) {
	    ASSERT(!NNPFS_TOKEN_GOT(t, NNPFS_DATA_MASK));
	    error = nnpfs_open_file (t, message->cache_name, NULL,
				     FILE_OPEN, FILE_NON_DIRECTORY_FILE);
	}
	
	if (NT_SUCCESS(error)) {
	    t->tokens = message->node.tokens;
	    nnpfs_attr2vattr(&message->node.attr, t);
#if 0
	    nnpfs_set_vp_size(XNODE_TO_VNODE(t), t->attr.va_size);
	    if (XNODE_TO_VNODE(t)->v_type == VDIR
		&& (message->flag & NNPFS_ID_INVALID_DNLC))
		dnlc_cache_purge (XNODE_TO_VNODE(t));
#endif
	    bcopy(message->node.id, t->id, sizeof(t->id));
	    bcopy(message->node.rights, t->rights, sizeof(t->rights));
	    t->anonrights = message->node.anonrights;

	    /* XXX cover for arlad bugs */
	    // if (t->attr.xa_type == NNPFS_FILE_REG && t->attr.xa_size != 0) 
	    t->offset = message->offset;
	    nnpfs_check_backfile(t);
	} else {
	    DbgPrint("NNPFS PANIC WARNING! nnpfs_message_installdata failed!\n");
	    DbgPrint("Reason: lookup failed on cache file '%s', error = %X\n",
		     message->cache_name, error);
	}

	ExReleaseResourceLite(&t->MainResource);
	nnpfs_debug (XDEBMSG, "nnpfs_message_installdata: released Main\n");
	nnpfs_vrele (t);
    } else {
	DbgPrint("NNPFS PANIC WARNING! nnpfs_message_installdata failed (%X)\n",
		 error);
	DbgPrint("Reason: No node to install the data into!\n");
	error = STATUS_NO_SUCH_FILE;
    }
    
    return error;
}

/*
 *
 */

int
nnpfs_message_invalidnode(struct nnpfs_channel *chan,
			  struct nnpfs_message_invalidnode * message,
			  u_int size)
{
    int error = 0;
    struct nnpfs_node *t;

    nnpfs_debug(XDEBMSG, "nnpfs_message_invalidnode (%d,%d,%d,%d)\n",
		message->handle.a,
		message->handle.b,
		message->handle.c,
		message->handle.d);
    
    t = nnpfs_node_find(chan, &message->handle);
    if (t != NULL) {
	/* XXX standard windows semantics say that it can be opened again
	 * as long as there are open handles, right? ignore for now
	 */
	
	/* XXX
	 * normally: "writers -> don't touch the data. Last close:er wins!"
	 * but we mark as stale anyway, let write clear STALE?
	 */

	ExAcquireResourceExclusiveLite(&t->MainResource, TRUE);
	nnpfs_debug (XDEBMSG, "nnpfs_message_invalidnode: got Main\n");
	
	if (!nnpfs_node_inuse(t, FALSE) || t->attr.xa_type != NNPFS_FILE_REG)
	    nnpfs_node_invalid(t);
	
	t->flags |= NNPFS_STALE;
	
	ExReleaseResourceLite(&t->MainResource);
	nnpfs_debug (XDEBMSG, "nnpfs_message_invalidnode: released Main\n");
	nnpfs_vrele (t); /* discards node when possible */
    } else {
	DbgPrint("NNPFS PANIC WARNING! nnpfs_message_invalidnode: no node!\n");
	// error = STATUS_NO_SUCH_FILE;
    }

    return error;
}

/*
 *
 */

int
nnpfs_message_updatefid(struct nnpfs_channel *chan,
			struct nnpfs_message_updatefid * message,
			u_int size)
{
    int error = 0;
    struct nnpfs_node *t;

    nnpfs_debug(XDEBMSG, "nnpfs_message_updatefid (%d,%d,%d,%d)\n",
		message->old_handle.a,
		message->old_handle.b,
		message->old_handle.c,
		message->old_handle.d);

    t = nnpfs_node_find (chan, &message->old_handle);
    if (t != NULL) {
	t->handle = message->new_handle;

	nnpfs_vrele (t);
    } else {
	DbgPrint ("NNPFS PANIC WARNING! nnpfs_message_updatefid: no node!\n");
	error = STATUS_NO_SUCH_FILE;
    }
    return error;
}

/*
 *
 */

static void
nnpfs_message_gc_node (struct nnpfs_node *node)
{
    /* the node is vref:d, so refcount is hopefully >=1 */
    ASSERT (node->refcount >= 1);

    /* This node is on the freelist */
    if (!nnpfs_node_inuse(node, FALSE) && node->refcount == 1) {
	nnpfs_debug(XDEBMSG, "nnpfs_message_gc_node: unrefed, size=%x\n",
		    node->offset);
	node->flags |= NNPFS_STALE;
    } else {
	nnpfs_debug(XDEBMSG,
		    "nnpfs_message_gc_node: USED, node=%X,size=%x\n",
		    node, node->offset);
    }
    nnpfs_vrele(node);
}

int
nnpfs_message_gc_nodes(struct nnpfs_channel *chan,
		       struct nnpfs_message_gc_nodes *message,
		       u_int size)
{
    nnpfs_debug(XDEBMSG, "nnpfs_message_gc\n");

    if (message->len == 0) {
	/* gc all unref:d nodes */
	nnpfs_node_gc_all(chan, FALSE);
    } else {
	struct nnpfs_node *t;
	unsigned int i;

	for (i = 0; i < message->len; i++) {
	    t = nnpfs_node_find (chan, &message->handle[i]);
	    if (t == NULL)
		continue;

	    nnpfs_message_gc_node(t);
	}
    }
    nnpfs_debug(XDEBMSG, "nnpfs_message_gc: done\n");


    return STATUS_SUCCESS;
}

/*
 *
 */

int
nnpfs_message_version(struct nnpfs_channel *chan,
		      struct nnpfs_message_version *message,
		      u_int size)
{
    struct nnpfs_message_wakeup msg;
    int ret;

    nnpfs_debug(XDEBMSG, "nnpfs_message_version\n");

    ret = NNPFS_VERSION;

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;

    ret = nnpfs_message_send(chan, (struct nnpfs_message_header *) &msg,
			     sizeof(msg));
    nnpfs_debug(XDEBMSG, "nnpfs_message_version: done\n");
    return ret;
}

