/*
 * Copyright (c) 1999, 2000, 2002, 2003 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_vops.c,v 1.19 2003/07/01 14:21:49 tol Exp $ */

#include <nnpfs_locl.h>
#include <fdir.h>

int
nnpfs_lookup(struct nnpfs_node *dir,
	     const char *name,
	     struct nnpfs_node **node,
	     nnpfs_lookup_args *args,
	     nnpfs_cred *cred,
	     int loop);

NTSTATUS
nnpfs_lookup_path(struct nnpfs_channel *chan,
		  char *name,
		  nnpfs_node *relnode,
		  nnpfs_node **node,
		  nnpfs_lookup_args *args,
		  nnpfs_cred *cred,
		  int loop);

void
nnpfs_handle2fid(nnpfs_handle *handle, VenusFid *fid)
{
    fid->Cell       = handle->a;
    fid->fid.Volume = handle->b;
    fid->fid.Vnode  = handle->c;
    fid->fid.Unique = handle->d;
}

void
nnpfs_fid2handle(VenusFid *fid, nnpfs_handle *handle)
{
    handle->a = fid->Cell;
    handle->b = fid->fid.Volume;
    handle->c = fid->fid.Vnode;
    handle->d = fid->fid.Unique;;
}

/*
 * convert unicode string to what we're used to
 */ 

NTSTATUS
nnpfs_unicode2unix(UNICODE_STRING *uc_string, char *buf, unsigned buflen)
{
    ANSI_STRING a_string;
    NTSTATUS status;
    status = RtlUnicodeStringToAnsiString(&a_string, uc_string, TRUE);
    if (status != STATUS_SUCCESS)
	return status;
    
    if (a_string.Length > buflen - 1)
	return status = STATUS_INVALID_PARAMETER;
    
    memcpy(buf, a_string.Buffer, a_string.Length);
    buf[a_string.Length] = '\0';
    RtlFreeAnsiString(&a_string);

    return STATUS_SUCCESS;
}

#if 0
#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

NNPFS_OPEN_N[RW] - (data might change)
    NNPFS_{ATTR,DATA}_[RW]
    we forget about locks for the time being

#endif

uint32_t
nnpfs_access2tokens(ACCESS_MASK mask)
{
    /* assume we want statinfo at least. zero is no good, loop danger... */
    uint32_t tokens = NNPFS_ATTR_R; 
    
    if (mask & (FILE_READ_DATA
		|FILE_EXECUTE
		|FILE_READ_ATTRIBUTES
		|READ_CONTROL))
	tokens |= NNPFS_OPEN_NR;
    if (mask & (FILE_WRITE_DATA
		|FILE_WRITE_ATTRIBUTES))
	tokens |= NNPFS_OPEN_NW;

    /* XXX insert/delete/statinfo? */

    return tokens;
}

/*
 * check if desired access appears to be granted, TRUE means yes.
 */

BOOLEAN
nnpfs_accessp(nnpfs_node *node, ACCESS_MASK mask) {
    if (node->flags & NNPFS_FCB_DUMMY)
	return TRUE;
    return TRUE;
}

/*
 * make up a dummy node, mark it as strange
 * used for opening bad symlinks (for delete) and device node
 */

NTSTATUS
nnpfs_get_dummynode(nnpfs_channel *chan, nnpfs_node **n, int devnodep)
{
    struct nnpfs_message_installroot msg;
    NTSTATUS status;

    RtlZeroMemory(&msg, sizeof(msg));
    msg.node.anonrights = NNPFS_RIGHT_R;
    msg.node.handle.a = -1;
    if (devnodep) {
	/* XXX the reverse is in nnpfs_dev.c, message sending. should be in cleanup()? */
	/* XXX locking */
	if (!NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN)) {
	    NNPFS_SETFLAGS(chan->flags, NNPFSCHAN_FLAGS_OPEN);
	    KeClearEvent(&chan->wake_event);
	    DbgPrint ("NNPFS get_dummynode: cleared wake_event\n");
	}
    } else {
	msg.node.handle.b = -1;    
    }

    /* XXX maybe we should store devnode in our nnpfs_channel? */
    
    status = nnpfs_new_node(chan, &msg.node, n);
    nnpfs_debug (XDEBVNOPS, "nnpfs_get_dummynode(%d): got node %p (%d)\n",
		 devnodep, n, status);

    if (NT_SUCCESS(status))
	(*n)->flags |= NNPFS_FCB_DUMMY;
    
    return status;
}

static void
nnpfs_handle_stale(nnpfs_node *node)
{
    if ((node->flags & NNPFS_STALE) == 0)
	return;

    /* check if there are any mappings */
    /* XXX lock node */

    ExAcquireResourceExclusiveLite(&node->MainResource, TRUE);
    nnpfs_debug (XDEBVNOPS, "nnpfs_handle_stale(%p): got Main\n", node);
   
    if (!nnpfs_node_inuse(node, TRUE)) {
	BOOLEAN ret;
	/* not used, go ahead */

	/* get rid of data -- it should already be flushed */
	ret = CcPurgeCacheSection(&node->section_objects, NULL, 0, TRUE);
	if (ret) {
	    node->flags &= ~NNPFS_STALE;
	    if (NNPFS_VALID_DATAHANDLE(node))
		nnpfs_close_data_handle (node);
	    NNPFS_TOKEN_CLEAR(node, ~0,
			      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
			      NNPFS_DATA_MASK | NNPFS_LOCK_MASK);
	} else {
	    nnpfs_debug (XDEBVNOPS,
			 "nnpfs_handle_stale(%X): cache purge failed\n",
			 node);
	}

	nnpfs_debug (XDEBVNOPS,
		     "nnpfs_handle_stale(%X): cleared STALE tokens\n", node);
    } else {
	nnpfs_debug (XDEBVNOPS,
		     "nnpfs_handle_stale(%X): still STALE\n", node);
    }
    ExReleaseResourceLite(&node->MainResource);
    nnpfs_debug (XDEBVNOPS, "nnpfs_handle_stale(%p): released Main\n", node);
}

static int
nnpfs_open_valid(struct nnpfs_node *node, nnpfs_cred *cred, u_int tok)
{
    struct nnpfs_channel *chan = node->chan;
    int error = 0;

    nnpfs_handle_stale(node);

    do {
	if (!NNPFS_TOKEN_GOT(node, tok)) {
	    struct nnpfs_message_open msg;

	    nnpfs_debug(XDEBVNOPS, "nnpfs_open_valid: node = %X, tok = %x\n",
			node, tok);
	    
	    msg.header.opcode = NNPFS_MSG_OPEN;
	    msg.cred.uid = 0;
	    msg.cred.pag = 0;
	    msg.handle = node->handle;
	    msg.tokens = tok;
	    error = nnpfs_message_rpc(chan, &msg.header, sizeof(msg));
	    if (error == 0)
		error = ((struct nnpfs_message_wakeup *) &msg)->error;
	} else {
	    goto done;
	}
    } while (error == 0);
    
 done:
    return error;
}

/*
 * get valid attributes
 */ 

static int
nnpfs_attr_valid(struct nnpfs_node *node, nnpfs_cred *cred, u_int tok)
{
    struct nnpfs_channel *chan = node->chan;
    int error = 0;
  
//    nnpfs_pag_t pag = nnpfs_get_pag(cred);

    do {
        if (!NNPFS_TOKEN_GOT(node, tok)) {
//      if (!NNPFS_TOKEN_GOT(xn, tok) && nnpfs_has_pag(xn, pag)) {
//	if (!XA_VALID_TYPE(&node->attr)) {
            struct nnpfs_message_getattr msg;
            msg.header.opcode = NNPFS_MSG_GETATTR;
            msg.cred.uid = 0; /* XXX cred->cr_uid; */
            msg.cred.pag = 0; /* XXX pag */
            msg.handle = node->handle;
            error = nnpfs_message_rpc(chan, &msg.header, sizeof(msg));
            if (error == 0)
                error = ((struct nnpfs_message_wakeup *) &msg)->error;
        } else {
            goto done;
        }
    } while (error == 0);

 done:
    return error;
}


/*
 * make sure we have valid data
 */

int
nnpfs_data_valid(nnpfs_node *node, nnpfs_cred *cred,
		 u_int tok, uint32_t want_offset)
{
    struct nnpfs_channel *chan = node->chan;
    struct nnpfs_message_getdata msg;
    int error = 0;
    uint32_t offset;
    tok |= NNPFS_ATTR_R;
    
    do {
	BOOLEAN unlocked = FALSE;
	offset = want_offset;
        if (NNPFS_TOKEN_GOT(node, tok)
	    && offset > node->attr.xa_size)
            offset = node->attr.xa_size;
	
/*          nnpfs_debug(XDEBVNOPS, "nnpfs_data_valid: offset: want %ld has %ld, " */
/*  		  "tokens: want %lx has %lx length: %ld\n", */
/*  		  (long) offset, (long) node->offset, */
/*  		  (long) tok, (long) node->tokens, */
/*  		  (long) node->attr.xa_size); */
	
        if (NNPFS_TOKEN_GOT(node, tok)
	    && (offset <= node->offset || node->attr.xa_type == NNPFS_FILE_DIR))
	    break;
	
//	if (!NNPFS_VALID_DATAHANDLE(node)) {
	msg.header.opcode = NNPFS_MSG_GETDATA;
	msg.cred.uid = 0; /* XXX cred->cr_uid;*/
	msg.cred.pag = 0; /* XXX nnpfs_get_pag(cred);*/
	msg.handle = node->handle;
	msg.tokens = tok;
	msg.offset = offset;

        nnpfs_debug(XDEBVNOPS, "nnpfs_data_valid: offset: want %ld has %ld, "
		    "tokens: want %lx has %lx length: %ld\n",
		    (long) offset, (long) node->offset,
		    (long) tok, (long) node->tokens,
		    (long) node->attr.xa_size);

	ASSERT(!ExIsResourceAcquiredExclusiveLite(&node->MainResource));
	
	if (ExIsResourceAcquiredSharedLite(&node->MainResource) > 0) {
	    ExReleaseResourceLite(&node->MainResource);
	    unlocked = TRUE;
	} else {
	    nnpfs_debug(XDEBVNOPS, "nnpfs_data_valid(%p): not locked!", node);
	}
	
	/* exclusive resources are shared too */
	ASSERT(ExIsResourceAcquiredSharedLite(&node->MainResource) == 0);
	ASSERT(ExIsResourceAcquiredSharedLite(&node->PagingIoResource) == 0);

	error = nnpfs_message_rpc(chan, &msg.header, sizeof(msg));
	if (unlocked)
	    ExAcquireResourceSharedLite(&node->MainResource, TRUE);

	if (error == 0)
	    error = ((struct nnpfs_message_wakeup *) &msg)->error;

    } while (error == 0);
    
    return error;
}


/*
 * get windows file attributes 
 */

unsigned long
nnpfs_get_wattr(struct nnpfs_attr *xa)
{
    unsigned long wattr = 0;

    /* XXX valid attr? */
    if (XA_VALID_TYPE(xa)) {
        switch(xa->xa_type) {
        case NNPFS_FILE_NON:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: non\n");
	    break;
	case NNPFS_FILE_REG:
	    wattr |= FILE_ATTRIBUTE_NORMAL;
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: normal\n");
	    break;
	case NNPFS_FILE_DIR:
	    wattr |= FILE_ATTRIBUTE_DIRECTORY;		
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: directory\n");
	    break;
	case NNPFS_FILE_BLK:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: blk\n");
	    break;
	case NNPFS_FILE_CHR:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: chr\n");
	    break;
	case NNPFS_FILE_LNK:
//	    XA_VALID_MODE(xa)
	    wattr |= FILE_ATTRIBUTE_NORMAL;
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: lnk\n");
	    break;
	case NNPFS_FILE_SOCK:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: sock\n");
	    break;
	case NNPFS_FILE_FIFO:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: fifo\n");
	    break;
	case NNPFS_FILE_BAD:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: bad\n");
	    break;
        default :
	    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: weird (%x)\n", xa->xa_type);
	}
    } else {
	nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: no type!\n");
    }
    if ((xa->xa_mode & 0222) == 0)
	wattr |= FILE_ATTRIBUTE_READONLY;

    nnpfs_debug (XDEBVNOPS, "nnpfs_get_wattr: returning %x\n", wattr);
    return wattr;
}

/*
 * get nt time (100ns-intervals since Jan 1, 1601)
 */

/* XXX RtlSecondsSince1970ToTime, RtlTimeToSecondsSince1970 */

#define NTTIME_EPOCH 0x019DB1DED53E8000L

LARGE_INTEGER
nnpfs_unix2nt_time(uint32_t unix_time)
{
    LARGE_INTEGER ut;
    ut.QuadPart = unix_time * (LONGLONG)10000000 + NTTIME_EPOCH;
    return ut;
}

/*
 * get unix time (seconds since Jan 1, 1970)
 */

uint32_t
nnpfs_nt2unix_time(LARGE_INTEGER *nt_time)
{
    return (uint32_t)((nt_time->QuadPart - NTTIME_EPOCH) / (LONGLONG)10000000);
}

void
nnpfs_getattrs(struct nnpfs_attr *xa,
	       LARGE_INTEGER *ctime,
	       LARGE_INTEGER *mtime,
	       LARGE_INTEGER *atime,
	       LARGE_INTEGER *size,
	       ULONG *attributes)
{
    if (ctime != NULL)
	*ctime = nnpfs_unix2nt_time(xa->xa_ctime);
    if (mtime != NULL)
	*mtime = nnpfs_unix2nt_time(xa->xa_mtime);
    if (atime != NULL)
	*atime = nnpfs_unix2nt_time(xa->xa_atime);
    if (size != NULL)
	size->QuadPart = (LONGLONG)xa->xa_size;
    if (attributes != NULL)
	*attributes = nnpfs_get_wattr(xa);
}

NTSTATUS
nnpfs_new_entry(nnpfs_node *dir,
		nnpfs_node **node,
		const char *name,
		unsigned long attributes,
		unsigned long options, 
		nnpfs_cred *cred) /* attrs, options, seccontext */
{
    union {
	struct nnpfs_message_header header;
	struct nnpfs_message_create create;
	struct nnpfs_message_mkdir mkdir;
    } msg;
    int size;
    int status = 0;
    *node = NULL;

    nnpfs_debug(XDEBVNOPS, "nnpfs_new_entry: (%X, %s)\n", dir, name);

    if (options & FILE_DIRECTORY_FILE
	&& options & FILE_NON_DIRECTORY_FILE)
	return STATUS_INVALID_PARAMETER;
    if (options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE) == 0)
	return STATUS_INVALID_PARAMETER;
	    
    if (options & FILE_DIRECTORY_FILE) {
	msg.mkdir.header.opcode = NNPFS_MSG_MKDIR;
	msg.mkdir.parent_handle = dir->handle;
	if (strlcpy(msg.mkdir.name, name,
		    sizeof(msg.mkdir.name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;
	
	XA_CLEAR(&msg.mkdir.attr); /* XXX */
//	XA_SET_MODE(&msg.mkdir.attr, 0644);
	msg.mkdir.cred.uid = NNPFS_ANONYMOUSID;
	msg.mkdir.cred.pag = 0;

	size = sizeof(msg.mkdir);
    } else {
	msg.create.header.opcode = NNPFS_MSG_CREATE;
	msg.create.parent_handle = dir->handle;
	if (strlcpy(msg.create.name, name,
		    sizeof(msg.create.name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;
	XA_CLEAR(&msg.create.attr); /* XXX */
	if (attributes & FILE_ATTRIBUTE_READONLY)
	    XA_SET_MODE(&msg.create.attr, 0444);
	else
	    XA_SET_MODE(&msg.create.attr, 0644);
	
	msg.create.mode = 0;		       /* ignored */
	msg.create.cred.uid = NNPFS_ANONYMOUSID;
	msg.create.cred.pag = 0;

	size = sizeof(msg.create);
    }
    status = nnpfs_message_rpc(dir->chan, &msg.header, size);

    if (status == 0)
	status = ((struct nnpfs_message_wakeup *) &msg)->error;
    
#if 0
    if (status == EEXIST)
	status = 0;
#endif
    
    if (NT_SUCCESS(status))
	/* get the new node */
	status = nnpfs_lookup(dir, name, node, NULL, cred, 0);

    if (!NT_SUCCESS(status)) {
	*node = NULL;
	nnpfs_debug(XDEBVNOPS, "nnpfs_new_entry: status = %d\n", status);
    }

    return status;
}

NTSTATUS
nnpfs_remove_entry(nnpfs_node *dir,
		   nnpfs_node *node,
		   const char *name,
		   nnpfs_cred *cred)
{
    union {
	struct nnpfs_message_header header;
	struct nnpfs_message_create remove;
	struct nnpfs_message_mkdir rmdir;
    } msg;
    int size;
    int error;

    nnpfs_debug(XDEBVNOPS, "nnpfs_remove_entry: %s\n", name);

    if (node->attr.xa_type == NNPFS_FILE_DIR) {
	if (strlcpy(msg.rmdir.name, name,
		    sizeof(msg.rmdir.name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;
	
	msg.rmdir.header.opcode = NNPFS_MSG_RMDIR;
	msg.rmdir.parent_handle = dir->handle;
	msg.rmdir.cred.uid = NNPFS_ANONYMOUSID;
	msg.rmdir.cred.pag = 0;

	size = sizeof(msg.rmdir);
    } else {
	if (strlcpy(msg.remove.name, name,
		    sizeof(msg.remove.name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;
	
	msg.remove.header.opcode = NNPFS_MSG_REMOVE;
	msg.remove.parent_handle = dir->handle;
	msg.remove.cred.uid = NNPFS_ANONYMOUSID;
	msg.remove.cred.pag = 0;
	
	size = sizeof(msg.remove);
    }

    error = nnpfs_message_rpc(dir->chan, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;
    
    if (error == 0) {
	nnpfs_dnlc_uncache(node);
	node->flags |= NNPFS_STALE;
    }

    return error;
}

NTSTATUS
nnpfs_check_truncate(nnpfs_node *node, unsigned long size)
{
    return STATUS_SUCCESS; /* XXX ask VM/Cc */
}

NTSTATUS
nnpfs_setattr(nnpfs_node *node, struct nnpfs_attr *xa, nnpfs_cred *cred)
{
    nnpfs_channel *chan = node->chan;
    struct nnpfs_attr *orig = &node->attr;
    NTSTATUS status = 0;

    nnpfs_debug(XDEBVNOPS, "nnpfs_setattr(%X)\n", node);

#if 0
#define CHECK_NNPFSATTR(A, cast) (xa->A == cast VNOVAL || xa->A == node->attr.A)
    if (CHECK_NNPFSATTR(xa_mode,(mode_t)) &&
	CHECK_NNPFSATTR(xa_nlink,(short)) &&
	CHECK_NNPFSATTR(xa_size,(xa_size_t)) &&
	CHECK_NNPFSATTR(xa_uid,(uid_t)) &&
	CHECK_NNPFSATTR(xa_gid,(gid_t)) &&
	CHECK_NNPFSATTR(xa_mtime.tv_sec,(unsigned int)) &&
	CHECK_NNPFSATTR(xa_fileid,(long)) &&
	CHECK_NNPFSATTR(xa_type,(enum vtype)))
	return 0;		/* Nothing to do */
#undef CHECK_NNPFSATTR
#endif

#if 0
    if (NNPFS_TOKEN_GOT(node, NNPFS_ATTR_W)) {
	/* Update attributes and mark them dirty. */
	node->flags |= NNPFS_ATTR_DIRTY;
	status = STATUS_INVALID_PARAMETER;     /* XXX not yet implemented */
	goto done;
    } else 
#endif
    {
	struct nnpfs_message_putattr msg;

	msg.header.opcode = NNPFS_MSG_PUTATTR;
	msg.cred.uid = NNPFS_ANONYMOUSID;
	msg.cred.pag = 0;
	msg.handle = node->handle;
	msg.attr = *xa;
	if (NNPFS_TOKEN_GOT(node, NNPFS_DATA_R)) {
	    if (node->attr.xa_type == NNPFS_FILE_REG) {
		if (XA_VALID_SIZE(xa))
		    XA_SET_SIZE(&msg.attr, xa->xa_size);
		else
		    XA_SET_SIZE(&msg.attr, node->attr.xa_size);
	    }
	    if (XA_VALID_MTIME(xa))
		XA_SET_MTIME(&msg.attr, xa->xa_mtime);
	    else
		XA_SET_MTIME(&msg.attr, node->attr.xa_mtime);
	}

	if (XA_VALID_SIZE(xa)) {
	    /* XXX we need to check with VM that size change is allowed*/
	    status = nnpfs_check_truncate(node, xa->xa_size);
	    if (!NT_SUCCESS(status))
		return status;
	}

	NNPFS_TOKEN_CLEAR(node, NNPFS_ATTR_VALID, NNPFS_ATTR_MASK);
	status = nnpfs_message_rpc(chan, &msg.header, sizeof(msg));
	if (status == 0)
	    status = ((struct nnpfs_message_wakeup *)&msg)->error;
    }

    return status;
}


NTSTATUS
nnpfs_rename(nnpfs_node *sourcedir,
	     nnpfs_node *node,
	     const char *name,
	     nnpfs_node *targetdir,
	     const char *newname,
	     nnpfs_cred *cred)
{
    int status;

    nnpfs_debug(XDEBVNOPS, "nnpfs_rename: %s %s\n", name, newname);

#if 0
    if ((fvp->v_mount != tdvp->v_mount)
	|| (tvp && (fvp->v_mount != tvp->v_mount))) {
	return  EXDEV;
    }
#endif

    {
	struct nnpfs_message_rename msg;

	msg.header.opcode = NNPFS_MSG_RENAME;
	msg.old_parent_handle = sourcedir->handle;
	if (strlcpy(msg.old_name, name, sizeof(msg.old_name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;
	msg.new_parent_handle = targetdir->handle;
	if (strlcpy(msg.new_name, newname,
		    sizeof(msg.new_name)) >= NNPFS_MAX_NAME)
	    return STATUS_NAME_TOO_LONG;

	msg.cred.uid = NNPFS_ANONYMOUSID;
	msg.cred.pag = 0;

	status = nnpfs_message_rpc(node->chan, &msg.header, sizeof(msg));
	if (status == 0)
	    status = ((struct nnpfs_message_wakeup *) &msg)->error;

    }

    nnpfs_debug(XDEBVNOPS, "nnpfs_rename: status = %d\n", status);

    if (status == 0)
	nnpfs_dnlc_uncache(node);

    return status;
}

NTSTATUS
nnpfs_link(nnpfs_node *dir,
	   nnpfs_node *node,
	   const char *name,
	   nnpfs_cred *cred)
{
    struct nnpfs_message_link msg;
    int status;

    nnpfs_debug(XDEBVNOPS, "nnpfs_link: %s\n", name);

    msg.header.opcode = NNPFS_MSG_LINK;
    msg.parent_handle = dir->handle;
    msg.from_handle   = node->handle;
    if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return STATUS_NAME_TOO_LONG;
    
    msg.cred.uid = NNPFS_ANONYMOUSID;
    msg.cred.pag = 0;
    
    status = nnpfs_message_rpc(node->chan, &msg.header, sizeof(msg));
    if (status == 0)
	status = ((struct nnpfs_message_wakeup *) &msg)->error;
    
    nnpfs_debug(XDEBVNOPS, "nnpfs_link: status = %d\n", status);

    return status;
}

NTSTATUS
nnpfs_get_devnode(nnpfs_node **n) {
    struct nnpfs_message_installroot msg;
    NTSTATUS status;

    /* ugly: we make up a device node */
    /* XXX maybe we should store it in our nnpfs_channel? */

    RtlZeroMemory(&msg, sizeof(msg));
    msg.node.anonrights = NNPFS_RIGHT_R;
    msg.node.handle.a = -1;
    
    status = nnpfs_new_node(&NNPFSGlobalData, &msg.node, n);
    nnpfs_debug (XDEBVNOPS, "nnpfs_get_devnode: made up devnode %p (%d)\n",
		 n, status);
    
    return status;
}

/*
 * translate unix-ish path to win-ish representation
 * useful for symlinks
 * 
 * modifies contents and possibly length of input string
 */

void
nnpfs_path_winify(char *path) {
    char *p;
    int len;
    /* translate / to \ */
    for (p = path; *p; p++)
	if (*p == '/')
	    *p = '\\';

    len = p - path;

    /* XXX this mapping should be in the registry */
    /* translate /afs to <nothing> */
    if (!strncmp(path, "\\afs", 4)) /* XXX */
	RtlCopyBytes(path, path + 4, len - 4 + 1);
}

/*
 * read and lookup symlink node
 */

NTSTATUS
nnpfs_lookup_symlink (nnpfs_node *dir,
		      nnpfs_node *link,
		      nnpfs_node **node,
		      nnpfs_lookup_args *args,
		      nnpfs_cred *cred,
		      int loop)
{
    NTSTATUS status;
    char path[NNPFS_MAX_NAME]; /* XXX */

    nnpfs_debug(XDEBVNOPS, "nnpfs_lookup_symlink(%X, %X, %d)\n",
		dir, link, loop);

    /* read link contents */
    status = nnpfs_data_valid(link, cred, NNPFS_DATA_R, link->attr.xa_size);
    if (NT_SUCCESS(status)) {
	LARGE_INTEGER offset = {0};
	IO_STATUS_BLOCK iosb;
	status = ZwReadFile(DATA_FROM_XNODE(link),
			    NULL, NULL, NULL, &iosb,
			    path, sizeof(path), &offset, NULL);
	if (status == STATUS_PENDING) /* XXX why */
	    status = ZwWaitForSingleObject(DATA_FROM_XNODE(link),
					   FALSE, NULL);
	if (NT_SUCCESS(status)) {
	    path[iosb.Information] = '\0';
	    nnpfs_debug(XDEBVNOPS,
			"nnpfs_lookup_symlink(%X): read %s\n", link, path);
	} else {
	    nnpfs_debug(XDEBVNOPS,
			"nnpfs_lookup_symlink: read failed (%x)!\n", status);
	}
    } else {
	nnpfs_debug(XDEBVNOPS, "nnpfs_lookup_symlink: no data (%x)!\n", status);
    }    

    nnpfs_vrele(link);
    
    if (NT_SUCCESS(status)) {
	nnpfs_path_winify(path);
	
	/* call nnpfs_lookup_path recursively w/ loop = loop + 1 */
	if (path[0] == '\\')
	    /* if absolute path, forget dir and start over w/ root */
	    status = nnpfs_lookup_path(dir->chan, path, NULL,
				       node, args, cred, loop + 1);
	else
	    status = nnpfs_lookup_path(dir->chan, path, dir,
				       node, args, cred, loop + 1);
    }

    nnpfs_debug(XDEBVNOPS, 
		"nnpfs_lookup_symlink(%X): returning %X!\n", link, status);

    return status;
}

/*
 * lookup component 'name' in dir 'dir'
 */

int
nnpfs_lookup(struct nnpfs_node *dir,
	     const char *name,
	     struct nnpfs_node **node,
	     nnpfs_lookup_args *args,
	     nnpfs_cred *cred,
	     int loop)
{
    struct nnpfs_message_getnode msg;
    struct nnpfs_node *n, *xn;
    int error = 0;
  
    if (name[0] == '\0') {
	nnpfs_vref(dir);
	*node = dir;
	error = 0;
	goto done;
    }
    
    do {
#ifdef notdef_but_correct
	error = nnpfs_access(dir, VEXEC, cred);
	if (error != 0)
	    goto done;
#endif
	error = nnpfs_dnlc_lookup(dir, name, &n);
	if (NT_SUCCESS(error) && n == NULL) {
	    fbuf the_fbuf;
	    
	    error = nnpfs_data_valid(dir, cred, NNPFS_DATA_R,
				     dir->attr.xa_size);
	    if (NT_SUCCESS(error))
		error = fbuf_create (&the_fbuf, DATA_FROM_XNODE(dir),
				     dir->attr.xa_size, FBUF_READ);
	    if (NT_SUCCESS(error)) {
		VenusFid dirfid, nodefid;

		nnpfs_handle2fid(&dir->handle, &dirfid);
		error = fdir_lookup(&the_fbuf, &dirfid, name, &nodefid);
		fbuf_end(&the_fbuf);

		if (NT_SUCCESS(error)) {
		    nnpfs_handle handle;
		    nnpfs_fid2handle(&nodefid, &handle);
		    n = nnpfs_node_find(dir->chan, &handle);
		    nnpfs_debug(XDEBVNOPS,
				"nnpfs_lookup(%s): found node(%d %d %d %d) = %X\n",
				name, handle.a, handle.b, handle.c, handle.d, n);
		} else
		    nnpfs_debug(XDEBVNOPS,
				"nnpfs_lookup(%s): fdir_lookup(%d %d %d %d) "
				"failed (%X)\n", name, 
				dir->handle.a, dir->handle.b,
				dir->handle.c, dir->handle.d, error);
	    }
	}

	if (NT_SUCCESS(error) && n == NULL) {
	    msg.header.opcode = NNPFS_MSG_GETNODE;
	    msg.cred.uid = 0; /* XXX cred->cr_uid;*/
	    msg.cred.pag = 0; /* XXX nnpfs_get_pag(cred); */
	    msg.parent_handle = dir->handle;
	    if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
		error = STATUS_NAME_TOO_LONG;
	    else
		error = nnpfs_message_rpc(dir->chan, &msg.header, sizeof(msg));
	    if (error == 0)
		error = ((struct nnpfs_message_wakeup *) &msg)->error;
	    if (error == STATUS_NO_SUCH_FILE)
		nnpfs_dnlc_enter (dir, name, NULL);
	} else {
	    *node = n;
	    goto done;
	}
    } while (error == 0);

 done:

    /* if we have a node: check if requested type & dispo, follow symlinks?
     * if we don't: check if we should create one
     */

    xn = *node;
    if (xn == NULL) {
	if (error == STATUS_NO_SUCH_FILE
	    && args != NULL
	    && args->flags & NNPFS_LOOKUP_CREATE 
	    && args->flags & NNPFS_LOOKUP_TAIL) {
	    /* time to create that file */
	    error = nnpfs_new_entry(dir, &xn, name, args->attributes,
				    args->options, cred);		
	    if (NT_SUCCESS(error))
		args->information = FILE_CREATED;
	}
    } else {
	/* we found a node */
	
	/* follow links, create if requested
	 * supercede - remove data file & create new
	 * overwrite - truncate
	 * check if we should return EEXIST
	 */
	
	if (NT_SUCCESS(error) 
	    && !nnpfs_attr_valid(xn, cred, NNPFS_ATTR_R)
	    && xn->attr.xa_type == NNPFS_FILE_LNK) {
	    if (args != NULL && args->flags & NNPFS_LOOKUP_GETLINK) {
		nnpfs_vref(xn);
		args->pathinfo.link = xn;
		args->flags &= ~NNPFS_LOOKUP_GETLINK;
	    }
	    error =
		nnpfs_lookup_symlink(dir, xn, &n, args, cred, loop);
	    
	    /* link node is always vrele:d by nnpfs_lookup_symlink() */
	    if (NT_SUCCESS(error))
		xn = n;
	    else
		xn = NULL;
	}
	if (xn && args != NULL) {
	    if (args->disposition == FILE_SUPERSEDE) {
		/* XXX check access first */ 
		
		if (xn->attr.xa_type == NNPFS_FILE_DIR) {
		    nnpfs_vrele(xn);
		    xn = NULL;
		    error = STATUS_FILE_IS_A_DIRECTORY;
		} else {
		    /* remove original node, create new one */
		    error = nnpfs_remove_entry(dir, xn, name, cred);
		}
		if (NT_SUCCESS(error))
		    error = nnpfs_new_entry(dir, &xn, name, args->attributes,
					    args->options, cred);
		if (NT_SUCCESS(error))
		    args->information = FILE_SUPERSEDED;
	    } else if (args->disposition == FILE_OVERWRITE
		       || args->disposition == FILE_OVERWRITE_IF) {
		/* XXX check access first */ 
		if (xn->attr.xa_type == NNPFS_FILE_DIR) {
		    nnpfs_vrele(xn);
		    xn = NULL;
		    error = STATUS_FILE_IS_A_DIRECTORY;
		} else {
		    /* truncate */
		    struct nnpfs_attr xa = xn->attr;
		    XA_CLEAR(&xa);
		    XA_SET_SIZE(&xa, 0);

		    /* XXX set timestamps or smth? */
		    error = nnpfs_setattr(xn, &xa, cred);
		}
		if (NT_SUCCESS(error))
		    args->information = FILE_OVERWRITTEN;
	    } else if (args->disposition == FILE_CREATE) {
		nnpfs_vrele(xn);
		xn = NULL;
		error = STATUS_OBJECT_NAME_COLLISION;
		args->information = FILE_EXISTS;
	    } else {
		args->information = FILE_OPENED;
	    }
	}
    }
    
    *node = xn;
//    nnpfs_debug(XDEBVNOPS, "nnpfs_lookup(%s) = %d\n", name, error);
    return error;
}


/*
 * look up path 'name' in 'chan'
 */

NTSTATUS
nnpfs_lookup_path(struct nnpfs_channel *chan,
		  char *path,
		  nnpfs_node *relnode,
		  nnpfs_node **node,
		  nnpfs_lookup_args *args,
		  nnpfs_cred *cred,
		  int loop)
{
    char buf[NNPFS_MAX_NAME];
    char *n = buf;
    char *rest;
    struct nnpfs_node *d;
    struct nnpfs_node *xn = NULL;
    int ret = STATUS_SUCCESS;
    
    /* we don't like symlink loops */
    if (loop > NNPFS_MAX_SYMLINKS)
	return STATUS_OBJECT_PATH_INVALID;
    
    if (relnode != NULL) {
	if (path[0] == '\\') {
	    nnpfs_debug(XDEBVNOPS, "nnpfs_lookup_path (%s) is weird!\n", path);
	    return STATUS_OBJECT_PATH_INVALID;
	}
	if (strlcpy(buf, path, NNPFS_MAX_NAME) >= NNPFS_MAX_NAME) /* XXX */
	    return STATUS_NAME_TOO_LONG;
	
	d = relnode;
    } else {
	if (path[0] != '\\') {
	    nnpfs_debug(XDEBVNOPS, "nnpfs_lookup_path (%s) is weird!\n", path);
	    return STATUS_OBJECT_PATH_INVALID;
	}
	
	if (strlcpy(buf, path + 1, NNPFS_MAX_NAME) >= NNPFS_MAX_NAME) /* XXX */
	    return STATUS_NAME_TOO_LONG;
	
	d = chan->root;
    }
    nnpfs_vref(d);
    
    while (n) {
	/* find first component */
	rest = strchr(n, '\\');
	if (rest != NULL) {
	    *rest = '\0';
	    rest++;
	    ret = nnpfs_lookup(d, n, &xn, NULL, cred, loop);
	    if (ret == STATUS_NO_SUCH_FILE)
		ret = STATUS_OBJECT_PATH_NOT_FOUND;
	} else {
	    /* XXX are the flags exclusive? */
	    if (args != NULL) {
		/* mark in args that this is the last component */
		args->flags |= NNPFS_LOOKUP_TAIL;
	    }

	    xn = NULL;
	    ret = nnpfs_lookup(d, n, &xn, args, cred, loop);

	    if (args != NULL
		&& args->flags & NNPFS_LOOKUP_GETDIR
		&& loop == 0) {
		strcpy(args->pathinfo.name, n);
		args->pathinfo.parent = d;
		*node = xn;
		return ret;
	    }
	}

	nnpfs_vrele(d);
	if (!NT_SUCCESS(ret))
	    return ret;
	d = xn;
	n = rest;
    }
    *node = xn;
    return ret;
}

/*
 dispositions(values):
 FILE_SUPERSEDE
 FILE_OPEN
 FILE_CREATE
 FILE_OPEN_IF
 FILE_OVERWRITE
 FILE_OVERWRITE_IF
 
 options(flags):
 FILE_DIRECTORY_FILE
 FILE_NON_DIRECTORY_FILE
 FILE_OPEN_BY_FILE_ID
 FILE_DELETE_ON_CLOSE
 
 FILE_SEQUENTIAL_ONLY
 FILE_RANDOM_ACCESS
 FILE_WRITE_THROUGH
 FILE_NO_INTERMEDIATE_BUFFERING

 returninfo(values):
 FILE_SUPERSEDED
 FILE_OPENED
 FILE_CREATED
 FILE_OVERWRITTEN
 FILE_EXISTS
 FILE_DOES_NOT_EXIST
*/

/*
 * Create/open entry
 */

#define FSD_WRAPPER(name, fsd_name) NTSTATUS \
(fsd_name)(PDEVICE_OBJECT device, PIRP irp) { \
    NTSTATUS status; \
    FsRtlEnterFileSystem(); \
    status = (name)(device, irp); \
    FsRtlExitFileSystem(); \
    return status; \
}

FSD_WRAPPER(nnpfs_create, nnpfs_fsd_create);

NTSTATUS 
nnpfs_create (PDEVICE_OBJECT device, PIRP irp)
{
    IO_STACK_LOCATION 	*io_stack;
    FILE_OBJECT		*file, *related_file;
    unsigned long       options, disposition, returninfo = 0;
    BOOLEAN             opentargetp, createp, deletep, dummyp = FALSE;
    BOOLEAN             execp = FALSE;
    BOOLEAN		delete_on_closep;
    ACCESS_MASK         accessmask;
    unsigned short	shareaccess;
    uint32_t            opentokens;
    ANSI_STRING		fname_a;
    CHAR		fname_unix[1024];
    NTSTATUS		status;
    struct nnpfs_node	*node = NULL;
    nnpfs_ccb		*ccb = NULL;
    struct nnpfs_channel  *chan = &NNPFSGlobalData;
    nnpfs_path_info       *pathinfo = NULL;
    nnpfs_cred         *cred = NULL;

    related_file = NULL;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    /* XXX keep a table mapping PFILE_OBJECTs => PISID? */

    file = io_stack->FileObject;
    ASSERT (file);

    options = io_stack->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    disposition = (io_stack->Parameters.Create.Options >> 24) & 0xFF;
    accessmask = io_stack->Parameters.Create.SecurityContext->DesiredAccess;
    shareaccess	= io_stack->Parameters.Create.ShareAccess;

    opentargetp = (io_stack->Flags & SL_OPEN_TARGET_DIRECTORY) ? TRUE : FALSE;
    if (disposition == FILE_CREATE
	|| disposition == FILE_SUPERSEDE
	|| disposition == FILE_OPEN_IF
	|| disposition == FILE_OVERWRITE_IF)
	createp = TRUE;
    else
	createp = FALSE;

    delete_on_closep = (options & FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;
    deletep = (accessmask & DELETE || delete_on_closep) ? TRUE : FALSE;

    status = nnpfs_unicode2unix(&file->FileName, fname_unix, sizeof(fname_unix));
    if (!NT_SUCCESS(status))
	goto out;
    
    nnpfs_debug (XDEBVNOPS, "nnpfs_create(%s), disp %x, opt %x, acc %x, fo %x\n",
		 fname_unix, disposition, options, accessmask, file);

    if (file->FileName.Length == 0) {
	status = nnpfs_get_dummynode(chan, &node, TRUE);
	dummyp = TRUE;
    } else {
	nnpfs_lookup_args args;
	status = nnpfs_get_root (chan);
	if (!NT_SUCCESS(status)) {
	    irp->IoStatus.Status = status;
	    IoCompleteRequest(irp, IO_NO_INCREMENT);
	    nnpfs_debug (XDEBVNOPS, "nnpfs_create: no root!\n");
	    return status;
	}

	RtlZeroMemory(&args, sizeof(args));
	if (opentargetp || deletep || TRUE)
	    /* XXX rename might happen when opened for write? */
	    args.flags |= NNPFS_LOOKUP_GETDIR;
	if (deletep)
	    args.flags |= NNPFS_LOOKUP_GETLINK;
	if (createp) {
	    args.flags |= NNPFS_LOOKUP_CREATE;
	    args.attributes =
		io_stack->Parameters.Create.FileAttributes
		& FILE_ATTRIBUTE_VALID_FLAGS;
	}
	args.options = options;
	args.disposition = disposition;

	if (file->RelatedFileObject) {
	    nnpfs_ccb *ccb = (nnpfs_ccb *) file->RelatedFileObject->FsContext2;
	    status = nnpfs_lookup_path (chan, fname_unix, ccb->node,
					&node, &args, NULL, 0);
	} else {
	    status = nnpfs_lookup_path (chan, fname_unix, NULL,
					&node, &args, NULL, 0);
	}
	
	if (createp && node && args.information == FILE_CREATED)
	    returninfo = FILE_CREATED;
	else if (node)
	    returninfo = FILE_OPENED;

	if (deletep
	    && args.pathinfo.parent != NULL
	    && node == NULL) {
	    status = nnpfs_get_dummynode(chan, &node, FALSE);
	    if (node != NULL)
		dummyp = TRUE;
	}

	if (opentargetp) { 
	    /* return the directory node, but with filename (weird) */
	    
	    if (node)
		nnpfs_vrele(node);
	    node = args.pathinfo.parent;
	    args.pathinfo.parent = NULL;

	    if (args.pathinfo.link != NULL)
		nnpfs_vrele(args.pathinfo.link);

	    /* put last component in FileObject->FileName */
	    file->FileName.Length =
	        (unsigned short)swprintf(file->FileName.Buffer, L"%S",
					 args.pathinfo.name);

	    /* XXX I suppose we should check the actual return code */
	    returninfo =
		NT_SUCCESS(status) ? FILE_EXISTS : FILE_DOES_NOT_EXIST;
	    status = STATUS_SUCCESS;
	}

	if (!NT_SUCCESS(status) || !(args.flags & NNPFS_LOOKUP_GETDIR)) {
	    if (args.pathinfo.link != NULL)
		nnpfs_vrele(args.pathinfo.link);
	    if (args.pathinfo.parent != NULL)
		nnpfs_vrele(args.pathinfo.parent);
	    ASSERT(node == NULL);
	    if (node != NULL)
		nnpfs_vrele(node);
	    node = NULL;
	} else {
	    pathinfo = nnpfs_alloc(sizeof(nnpfs_path_info), 'vcd1');
	    if (pathinfo == NULL) {
		status = STATUS_NO_MEMORY;
		if (args.pathinfo.link != NULL)
		    nnpfs_vrele(args.pathinfo.link);
		nnpfs_vrele(args.pathinfo.parent);
		goto out;
	    }
	    *pathinfo = args.pathinfo;
	}
    }
    nnpfs_debug (XDEBVNOPS, "nnpfs_create: node=%p\n", node);

    opentokens = nnpfs_access2tokens(accessmask);

    if (node != NULL) {
	BOOLEAN dirp = node->attr.xa_type == NNPFS_FILE_DIR ? TRUE : FALSE;
	if (dirp) {
	    /* we've got a directory */
	    if (options & FILE_NON_DIRECTORY_FILE)
		status = STATUS_FILE_IS_A_DIRECTORY;
	} else {
	    /* we've got a file */
	    if (options & FILE_DIRECTORY_FILE)
		status = STATUS_NOT_A_DIRECTORY;
	}

	if (!NT_SUCCESS(status)) {
	    /* not the requested kind of node, abort */
	    nnpfs_vrele(node);
	    node = NULL;
	}
    }

    /* we assume that the node is locked exclusively */
    if (node != NULL && node->handlecount > 0) {
	status = IoCheckShareAccess(accessmask, shareaccess, file,
				    &node->share_access, TRUE);
	if (!NT_SUCCESS(status)) {
	    nnpfs_vrele(node);
	    node = NULL;
	}
    }

    /* call MmFlushImageSection if opened for delete/modification */
    if (node != NULL 
	&& ((accessmask & FILE_WRITE_DATA) || delete_on_closep)) {
	if (!MmFlushImageSection(&node->section_objects, MmFlushForWrite )) {
	    if (delete_on_closep)
		status = STATUS_CANNOT_DELETE;
	    else
		status = STATUS_SHARING_VIOLATION;
	    nnpfs_vrele(node);
	    node = NULL;
	}
    }

    if (node != NULL 
	&& accessmask & FILE_EXECUTE
	&& options & FILE_NON_DIRECTORY_FILE) {
	node->flags |= NNPFS_FCB_EXECUTE;
	execp = TRUE;
    }
	
    if (node && !dummyp) {
	status = nnpfs_open_valid(node, cred, opentokens);
	if (status != STATUS_SUCCESS) {
	    /* nnpfs_debug (XDEBVNOPS, "nnpfs_create: open failed, "
	       "status %X\n", status);*/
	    IoRemoveShareAccess(file, &node->share_access);
	    nnpfs_vrele(node);
	    node = NULL;
	} else {
	    nnpfs_debug (XDEBVNOPS, "nnpfs_create: got data\n", node);
	}
    }

    if (node == NULL)
	goto out;
    
    ASSERT(NT_SUCCESS(status));

    if (execp && !dummyp) {
	/* make sure we have all data resident */
	status = nnpfs_data_valid(node, cred, NNPFS_DATA_R, node->attr.xa_size);
	if (NT_SUCCESS(status))
	    nnpfs_check_backfile(node);
    }
    if (NT_SUCCESS(status))
	ccb = nnpfs_get_ccb();
    if (ccb == NULL) {
	nnpfs_vrele(node);
	status = STATUS_INSUFFICIENT_RESOURCES;
	returninfo = 0;
	goto out;
    }

    ccb->node = node;
    ccb->opentokens = opentokens;
    ccb->cred = cred;
    if (pathinfo != NULL) {
	if (options & FILE_DELETE_ON_CLOSE)
	    file->DeletePending = TRUE;
	ccb->pathinfo = pathinfo;
    }
    pathinfo = NULL;

    file->FsContext = node;
    file->FsContext2 = ccb;
    file->PrivateCacheMap = (void *)1;
    file->SectionObjectPointer = &node->section_objects;
    
    if (node->handlecount == 0)
	IoSetShareAccess(accessmask, shareaccess, file, &node->share_access);

//    nnpfs_vref(node); lookup did that */
    node->handlecount++;

 out:
    if (NT_SUCCESS(status))
	ASSERT(node && ccb);

    if (pathinfo != NULL) {
	if (pathinfo->link != NULL)
	    nnpfs_vrele(pathinfo->link);
	nnpfs_vrele(pathinfo->parent);
	nnpfs_free(pathinfo, sizeof(*pathinfo));
    }

    if (status != STATUS_SUCCESS 
	&& status != STATUS_NO_SUCH_FILE
	&& status != STATUS_OBJECT_PATH_NOT_FOUND)
	nnpfs_debug (XDEBVNOPS, "nnpfs_create: returning %X, info %X\n",
		     status, returninfo);
    else
	nnpfs_debug (XDEBVNOPS, "nnpfs_create: returning %X, info %X\n",
		     status, returninfo);

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = returninfo;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}


/*
 * This is really a cleanup function that is called
 * when the file isn't cached anymore.
 */

FSD_WRAPPER(nnpfs_close, nnpfs_fsd_close);

NTSTATUS 
nnpfs_close (PDEVICE_OBJECT device, PIRP irp)
{
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    nnpfs_debug (XDEBVNOPS, "nnpfs_close(%X), fo %x\n", node, file);

    ASSERT (ccb && node);
    
    nnpfs_release_ccb (ccb);
    nnpfs_vrele(node);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/*
 * simple I/O completion - just free the irp we've allocated
 */

NTSTATUS
nnpfs_free_irp(DEVICE_OBJECT *device, IRP *irp, void *context)
{
    nnpfs_node *node = (nnpfs_node *)context;

    *irp->UserIosb = irp->IoStatus;
    KeSetEvent(irp->UserEvent, 0, FALSE);

    IoFreeIrp(irp);

    /* don't let anybody touch this irp, it's gone now */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * common dispatch routine for read/write
 */

FSD_WRAPPER(nnpfs_readwrite, nnpfs_fsd_readwrite);

NTSTATUS 
nnpfs_readwrite (DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER offset;
    ULONG buflen;
    unsigned char *buf = NULL;
    int synchronousp, pagingp, nocachep, writep;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);

    file = io_stack->FileObject;
    ASSERT (file);
    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    pagingp = irp->Flags & IRP_PAGING_IO;
    nocachep = irp->Flags & IRP_NOCACHE;
    synchronousp = file->Flags & FO_SYNCHRONOUS_IO;
    writep = io_stack->MajorFunction == IRP_MJ_WRITE ? 1 : 0;
    
    if (writep) {
	buflen = io_stack->Parameters.Write.Length;
	offset = io_stack->Parameters.Write.ByteOffset;
    } else {
	buflen = io_stack->Parameters.Read.Length;
	offset = io_stack->Parameters.Read.ByteOffset;
    }

    if (offset.HighPart == 0xffffffff) {
	if (offset.LowPart == FILE_WRITE_TO_END_OF_FILE) {
	    status = nnpfs_attr_valid(node, ccb->cred, NNPFS_ATTR_R);
	    if (NT_SUCCESS(status)) {
		offset.LowPart = node->attr.xa_size;
		offset.HighPart = 0;
	    }
	} else if (offset.LowPart == FILE_USE_FILE_POINTER_POSITION) {
	    offset = file->CurrentByteOffset;
	} else {
	    status = STATUS_END_OF_FILE;
	}
    } else if (offset.HighPart != 0) {
	status = STATUS_END_OF_FILE;
    }

    nnpfs_debug (XDEBVNOPS, "nnpfs_readwrite(%X): %c, len=%x, offset=%x\n",
		 node, writep ? 'w' : 'r', buflen, offset);

    if (NT_SUCCESS(status)) {
	if (node->attr.xa_type == NNPFS_FILE_DIR) {
	    status = STATUS_INVALID_DEVICE_REQUEST;
	} else {
	    /* XXX this is seriously dangerous in paging path... */
	    if (writep)
		status = nnpfs_data_valid(node, ccb->cred, NNPFS_DATA_W,
					  node->attr.xa_size);
	    else 
		status = nnpfs_data_valid(node, ccb->cred, NNPFS_DATA_R,
					  offset.LowPart + buflen);
	}
    }

    if (!NT_SUCCESS(status)) {
	nnpfs_debug(XDEBVNOPS, "nnpfs_readwrite: no data (%X)!\n", status);
    } else if (pagingp) {

	/* XXX need to think about paging resources
	 *  - perhaps acquire backfile paging resources in some callback?
	 *
	 * also, for mmap mods after close() we need to flush to server
	 * perhaps post one delayed workitem, keep track of latest flush?
	 */	    

	ExAcquireResourceSharedLite(&node->PagingIoResource, TRUE);

	/* note - paging writes beyond EOF are to be truncated,
	 * but the underlying FSD takes care of that
	 */

	ASSERT(irp->MdlAddress);
 	buf = nnpfs_get_buffer(irp);
	if (buf) {
	    CCHAR stacksize;
	    IO_STACK_LOCATION *new_stack;
	    IRP *newirp;
	    KEVENT event;
	    FILE_OBJECT *backfile = node->backfile;
	    DEVICE_OBJECT *backdevice = backfile->Vpb->DeviceObject;
	    KeInitializeEvent(&event, NotificationEvent, FALSE);

	    stacksize = backdevice->StackSize + 1; // hope enough
	    newirp = IoAllocateIrp(stacksize, FALSE);
	    ASSERT(newirp); /* XXX */
	    new_stack = IoGetNextIrpStackLocation(newirp);
	    
	    new_stack->DeviceObject = backdevice;
	    new_stack->FileObject = backfile;
	    new_stack->Flags = io_stack->Flags;	
	    new_stack->MajorFunction = io_stack->MajorFunction;
	    new_stack->MinorFunction = io_stack->MinorFunction;

	    if (writep)
		new_stack->Parameters.Write = io_stack->Parameters.Write;
	    else
		new_stack->Parameters.Read = io_stack->Parameters.Read;
	    
	    newirp->RequestorMode = KernelMode;
	    newirp->Tail.Overlay.Thread = PsGetCurrentThread();
	    newirp->Flags =                                 //irp->Flags;
		IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO; 
	    newirp->MdlAddress = irp->MdlAddress;
	    newirp->UserEvent = &event;
	    newirp->UserIosb = &irp->IoStatus;

	    IoSetCompletionRoutine(newirp, nnpfs_free_irp, node,
				   TRUE, TRUE, TRUE);

	    nnpfs_debug (XDEBVNOPS,
			 "nnpfs_readwrite(%X): %c PAGING, flags %x\n",
			 node, writep ? 'w' : 'r', irp->Flags);

	    status = IoCallDriver(backdevice, newirp);
	    if (status != STATUS_PENDING && status != STATUS_SUCCESS)
		nnpfs_debug (XDEBVNOPS,
			     "nnpfs_readwrite(%X): CallDriver->%X\n",
			     node, status);
	    else
		status = KeWaitForSingleObject(&event, Executive,
					       KernelMode, FALSE, NULL);

	    if (NT_SUCCESS(status))
		status = irp->IoStatus.Status;

	    if (NT_SUCCESS(status) && !writep)
		ASSERT(irp->IoStatus.Information > 0);

	} else {
	    status = STATUS_INVALID_USER_BUFFER; /* user? not really */
	    nnpfs_debug (XDEBVNOPS,
			 "nnpfs_readwrite(%X): %c PAGING w/ bad buffer!\n",
			 node, writep ? 'w' : 'r');
	}
	ExReleaseResourceLite(&node->PagingIoResource);
    } else {
 	buf = nnpfs_get_buffer(irp);
	if (buf) {
	    BOOLEAN ret;
	    if (writep) {
		ret = nnpfs_fastio_write(file, &offset, buflen, TRUE,
					 0, buf, &irp->IoStatus, device); 
		status = ret ? irp->IoStatus.Status : STATUS_UNSUCCESSFUL;
	    } else {
		ret = nnpfs_fastio_read(file, &offset, buflen, TRUE,
					0, buf, &irp->IoStatus, device); 
		status = ret ? irp->IoStatus.Status : STATUS_UNSUCCESSFUL;
	    }
	} else {
	    status = STATUS_INVALID_USER_BUFFER;
	}
    }    

    if (!NT_SUCCESS(status)) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
    } 

    if (NT_SUCCESS(irp->IoStatus.Status))
	nnpfs_debug (XDEBVNOPS, "nnpfs_readwrite: %c %d bytes (%X, %X)\n",
		     writep ? 'w' : 'r', irp->IoStatus.Information,
		     irp->IoStatus.Status, status);
    else if (status == STATUS_END_OF_FILE)
	nnpfs_debug(XDEBVNOPS, "nnpfs_readwrite: %c failed (%X)!\n",
		    writep ? 'w' : 'r', irp->IoStatus.Status);
    else
	nnpfs_debug(XDEBVNOPS, "nnpfs_readwrite: %c failed (%X)!\n",
		    writep ? 'w' : 'r', irp->IoStatus.Status);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
     
    return status;
}

NTSTATUS
nnpfs_fileinfo_basic(PIRP irp, nnpfs_node *node, void *b, 
		     unsigned buflen, unsigned *size)
{
    PFILE_BASIC_INFORMATION buf = (PFILE_BASIC_INFORMATION) b;
    unsigned local_size = sizeof(FILE_BASIC_INFORMATION);
    NTSTATUS status = STATUS_SUCCESS;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb             *ccb;

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: %c Basic\n",
		 size == NULL ? 'w' : 'r');

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    if (size == NULL) {
	/* this is a set info operation */
	struct nnpfs_attr attr;

	io_stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(io_stack);
	
	file = io_stack->FileObject;
	ccb = (nnpfs_ccb *) file->FsContext2;

	status = nnpfs_attr_valid(node, ccb->cred, NNPFS_ATTR_R);
	if (!NT_SUCCESS(status))
	    return status;

	/* we don't have CreationTime -- ignore */

	XA_CLEAR(&attr);
	if (buf->ChangeTime.QuadPart != 0)
	    XA_SET_CTIME(&attr, nnpfs_nt2unix_time(&buf->ChangeTime));
	if (buf->LastWriteTime.QuadPart != 0)
	    XA_SET_MTIME(&attr, nnpfs_nt2unix_time(&buf->LastWriteTime));
	if (buf->LastAccessTime.QuadPart != 0)
	    XA_SET_ATIME(&attr, nnpfs_nt2unix_time(&buf->LastAccessTime));
	if (buf->FileAttributes & FILE_ATTRIBUTE_READONLY)
	    XA_SET_MODE(&attr, node->attr.xa_mode & ~0222);

	status = nnpfs_setattr(node, &attr, ccb->cred);

    } else {
	/* this is a query info operation */
	*size = local_size;

	/* we don't have CreationTime -- zero */
	buf->CreationTime.QuadPart = (LONGLONG)0;
	nnpfs_getattrs(&node->attr, &buf->LastAccessTime, &buf->LastWriteTime,
		       &buf->ChangeTime, NULL, &buf->FileAttributes);
    }

    return status;
}

NTSTATUS
nnpfs_fileinfo_standard(PIRP irp, nnpfs_node *node, void *b,
			unsigned buflen, unsigned *size)
{
    PFILE_STANDARD_INFORMATION buf = (PFILE_STANDARD_INFORMATION) b;
    unsigned local_size = sizeof(FILE_STANDARD_INFORMATION);
    IO_STACK_LOCATION	*io_stack;

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Standard\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);

    buf->AllocationSize.QuadPart = node->attr.xa_size;
    buf->EndOfFile.HighPart = 0;
    buf->EndOfFile.LowPart = node->attr.xa_size;
    buf->NumberOfLinks = node->attr.xa_nlink;
    buf->DeletePending = io_stack->FileObject->DeletePending;
    buf->Directory = (node->attr.xa_type == NNPFS_FILE_DIR) ? TRUE : FALSE;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_name(PIRP irp, nnpfs_node *node, void *b, 
		    unsigned buflen, unsigned *size)
{
    PFILE_NAME_INFORMATION buf = (PFILE_NAME_INFORMATION) b;
    unsigned local_size = sizeof(FILE_NAME_INFORMATION);
    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Name\n");
    *size = 0;

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;
    
    buf->FileNameLength = 6;
    local_size += buf->FileNameLength - sizeof(WCHAR);
    if (buflen < local_size) {
	*size = sizeof(FILE_NAME_INFORMATION);
	return STATUS_BUFFER_OVERFLOW;
    } else {
	*size = local_size;
    }

    RtlCopyMemory(buf->FileName, L"foo", buf->FileNameLength);
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_internal(PIRP irp, nnpfs_node *node, void *b, 
			unsigned buflen, unsigned *size)
{
    PFILE_INTERNAL_INFORMATION buf = (PFILE_INTERNAL_INFORMATION) b;
    unsigned local_size = sizeof(FILE_INTERNAL_INFORMATION);
    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Internal\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }
    
    buf->IndexNumber.QuadPart = 0;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_ea(PIRP irp, nnpfs_node *node, void *b, 
		  unsigned buflen, unsigned *size)
{
    PFILE_EA_INFORMATION buf = (PFILE_EA_INFORMATION) b;
    unsigned local_size = sizeof(FILE_EA_INFORMATION);
    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Ea\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }
    
    buf->EaSize = 0;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_position(PIRP irp, nnpfs_node *node, void *b, 
			unsigned buflen, unsigned *size)
{
    PFILE_POSITION_INFORMATION buf = (PFILE_POSITION_INFORMATION) b;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    unsigned local_size = sizeof(FILE_POSITION_INFORMATION);
    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Position\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }

    buf->CurrentByteOffset = file->CurrentByteOffset;

    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_network_open(PIRP irp, nnpfs_node *node, void *b, 
			    unsigned buflen, unsigned *size)
{
    PFILE_NETWORK_OPEN_INFORMATION buf = (PFILE_NETWORK_OPEN_INFORMATION) b;
    unsigned local_size = sizeof(FILE_NETWORK_OPEN_INFORMATION);
    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: NetworkOpen\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }
    
    /* we don't have CreationTime -- zero */
    buf->CreationTime.QuadPart = (LONGLONG)0;
    nnpfs_getattrs(&node->attr, &buf->LastAccessTime, &buf->LastWriteTime,
		   &buf->ChangeTime, &buf->AllocationSize,
		   &buf->FileAttributes);
    buf->EndOfFile = buf->AllocationSize;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_attr_tag(PIRP irp, nnpfs_node *node, void *b, 
			unsigned buflen, unsigned *size)
{
    PFILE_ATTRIBUTE_TAG_INFORMATION buf = (PFILE_ATTRIBUTE_TAG_INFORMATION) b;
    unsigned local_size = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);
    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: AttributeTag\n");
    if (buflen < local_size) {
	*size = 0;
	return STATUS_INFO_LENGTH_MISMATCH;
    } else {
	*size = local_size;
    }

    buf->FileAttributes = nnpfs_get_wattr(&node->attr);;
    buf->ReparseTag = 0;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_disposition(PIRP irp, void *b, unsigned buflen)
{
    PFILE_DISPOSITION_INFORMATION buf = (PFILE_DISPOSITION_INFORMATION) b;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb             *ccb;
    unsigned local_size = sizeof(FILE_DISPOSITION_INFORMATION);

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Disposition\n");

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ccb = (nnpfs_ccb *) file->FsContext2;

    /* XXX check access, validity of request */
    file->DeletePending = buf->DeleteFile;
    
    return STATUS_SUCCESS;
}

NTSTATUS
nnpfs_fileinfo_rename(PIRP irp, void *b, unsigned buflen)
{
    PFILE_RENAME_INFORMATION buf = (PFILE_RENAME_INFORMATION) b;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file, *relative_file;
    nnpfs_ccb             *ccb;
    nnpfs_node            *targetdir;
    char                 name[NNPFS_MAX_NAME + 1];
    char                *p;
    NTSTATUS             status;
    unsigned local_size = sizeof(FILE_RENAME_INFORMATION);

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Rename\n");

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    if (buf->FileNameLength / 2 >= NNPFS_MAX_NAME) /* XXX */
	return STATUS_NAME_TOO_LONG;

    /* XXX check access, validity of request */

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ccb = (nnpfs_ccb *) file->FsContext2;
    relative_file = io_stack->Parameters.SetFile.FileObject;
    if (relative_file == NULL)
	targetdir = ccb->pathinfo->parent;
    else
	targetdir = ((nnpfs_ccb *) relative_file->FsContext2)->node;

    sprintf(name, "%S", buf->FileName);
    name[buf->FileNameLength / 2] = '\0'; 

    nnpfs_debug (XDEBVNOPS,
		 "nnpfs_fileinfo: Rename(%X) - root %X, tdir %X, name %s\n",
		 ccb->node, buf->RootDirectory, targetdir, name);

    p = strrchr(name, '\\'); /* we could probably do this more efficiently */
    /* XXX trailing '\'? */ 
    /* XXX check ReplaceIfExists? */ 
    status = nnpfs_rename(ccb->pathinfo->parent,
			  ccb->node, 
			  ccb->pathinfo->name,
			  targetdir,
			  p == NULL ? name : p + 1,
			  ccb->cred);

    return status;
}

NTSTATUS
nnpfs_fileinfo_link(PIRP irp, void *b, unsigned buflen)
{
    PFILE_LINK_INFORMATION buf = (PFILE_LINK_INFORMATION) b;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file, *relative_file;
    nnpfs_ccb             *ccb;
    nnpfs_node            *targetdir;
    char                 name[NNPFS_MAX_NAME + 1];
    char                *p;
    NTSTATUS             status;
    unsigned local_size = sizeof(FILE_LINK_INFORMATION);

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Link\n");

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    if (buf->FileNameLength / 2 >= NNPFS_MAX_NAME) /* XXX */
	return STATUS_NAME_TOO_LONG;

    /* XXX check access, validity of request */

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ccb = (nnpfs_ccb *) file->FsContext2;
    targetdir = ccb->pathinfo->parent;

    relative_file = io_stack->Parameters.SetFile.FileObject;
    if (relative_file != NULL 
	&& ((nnpfs_ccb *) relative_file->FsContext2)->node != targetdir)
	return STATUS_NOT_SAME_DEVICE;

    sprintf(name, "%S", buf->FileName);
    name[buf->FileNameLength / 2] = '\0'; 

    nnpfs_debug (XDEBVNOPS,
		 "nnpfs_fileinfo: Link(%X) - root %X, tdir %X, name %s\n",
		 ccb->node, buf->RootDirectory, targetdir, name);

    p = strrchr(name, '\\');
    /* XXX trailing '\'? */ 
    /* XXX check ReplaceIfExists? */ 
    status = nnpfs_link(targetdir,
			ccb->node, 
			p == NULL ? name : p + 1,
			ccb->cred);

#if 0
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
#endif

    return status;
}

NTSTATUS
nnpfs_fileinfo_all(PIRP irp, nnpfs_node *node, void *b, 
		   unsigned buflen, unsigned *size)
{
    NTSTATUS status;
    unsigned local_size = 0;
    unsigned len = buflen;
    PFILE_ALL_INFORMATION all_buf           = (PFILE_ALL_INFORMATION) b;
    PFILE_BASIC_INFORMATION basic_buf       = &all_buf->BasicInformation;
    PFILE_STANDARD_INFORMATION standard_buf = &all_buf->StandardInformation;
    PFILE_INTERNAL_INFORMATION internal_buf = &all_buf->InternalInformation;
    PFILE_EA_INFORMATION ea_buf             = &all_buf->EaInformation;
    PFILE_POSITION_INFORMATION position_buf = &all_buf->PositionInformation;
    PFILE_NAME_INFORMATION name_buf         = &all_buf->NameInformation;
    
    status = nnpfs_fileinfo_basic(irp, node, basic_buf, len, &local_size);
    len -= local_size;
    *size += local_size;

    if (!NT_SUCCESS(status))
	return status;

    status = nnpfs_fileinfo_standard(irp, node, standard_buf, len, &local_size);
    len -= local_size;
    *size += local_size;

    if (!NT_SUCCESS(status))
	return status;

    status = nnpfs_fileinfo_internal(irp, node, internal_buf, len, &local_size);
    len -= local_size;
    *size += local_size;

    if (!NT_SUCCESS(status))
	return status;

    status = nnpfs_fileinfo_ea(irp, node, ea_buf, len, &local_size);
    len -= local_size;
    *size += local_size;

    if (!NT_SUCCESS(status))
	return status;

    len = buflen - ((char *)position_buf - (char *)all_buf);
    *size = (char *)position_buf - (char *)all_buf;
    status = nnpfs_fileinfo_position(irp, node, position_buf, len, &local_size);
    if (!NT_SUCCESS(status))
	return status;

    /* access, mode, alignment are filled in by object manager */

    len = buflen - ((char *)name_buf - (char *)all_buf);
    *size = (char *)name_buf - (char *)all_buf;
    status = nnpfs_fileinfo_name(irp, node, name_buf, len, &local_size);
    *size += local_size;
    
    return status;
}

NTSTATUS
nnpfs_fileinfo_eof(PIRP irp, nnpfs_node *node, void *b, unsigned buflen)
{
    PFILE_END_OF_FILE_INFORMATION buf = (PFILE_END_OF_FILE_INFORMATION) b;
    unsigned local_size = sizeof(FILE_END_OF_FILE_INFORMATION);
    NTSTATUS status = STATUS_SUCCESS;
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb             *ccb;
    struct nnpfs_attr     attr;

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: EOF\n");

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    /* we don't support large files */
    if (buf->EndOfFile.HighPart != 0)
	return STATUS_INVALID_PARAMETER;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ccb = (nnpfs_ccb *) file->FsContext2;
    
    status = nnpfs_attr_valid(node, ccb->cred, NNPFS_ATTR_R);
    if (!NT_SUCCESS(status))
	return status;
    
    XA_CLEAR(&attr);
    XA_SET_SIZE(&attr, buf->EndOfFile.LowPart);
    status = nnpfs_setattr(node, &attr, ccb->cred);
    
    return status;
}

/*
 * set allocation size - we just ignore this one
 */

NTSTATUS
nnpfs_fileinfo_alloc(PIRP irp, nnpfs_node *node, void *b, unsigned buflen)
{
    unsigned local_size = sizeof(FILE_ALLOCATION_INFORMATION);

    nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: Allocation\n");

    if (buflen < local_size)
	return STATUS_INFO_LENGTH_MISMATCH;

    return STATUS_SUCCESS;
}

/*
 *
 */

FSD_WRAPPER(nnpfs_fileinfo, nnpfs_fsd_fileinfo);

NTSTATUS 
nnpfs_fileinfo (DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    FILE_INFORMATION_CLASS info_class;
    int                 get_info_p = TRUE;
    ULONG               buflen;
    ULONG               size = 0;
    NTSTATUS            status = STATUS_INVALID_INFO_CLASS;
    int ret;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    ASSERT (ccb && node);

    if (io_stack->MajorFunction != IRP_MJ_QUERY_INFORMATION)
	get_info_p = FALSE;
    info_class = io_stack->Parameters.QueryFile.FileInformationClass;
    buflen = io_stack->Parameters.QueryFile.Length;

    ret = nnpfs_attr_valid(node, ccb->cred, NNPFS_ATTR_R);
    if (ret) {
	nnpfs_debug (XDEBVNOPS, "nnpfs_fileinfo: no attr!\n");
	status = ret;
	goto done;
    }    

//    RtlZeroMemory(irp->AssociatedIrp.SystemBuffer, buflen);
    if (get_info_p) {
	switch (info_class) {
	case FileBasicInformation:
	    status = nnpfs_fileinfo_basic(irp, node,
					  irp->AssociatedIrp.SystemBuffer,
					  buflen, &size);
	    break;
	case FileStandardInformation:
	    status = nnpfs_fileinfo_standard(irp, node,
					     irp->AssociatedIrp.SystemBuffer,
					     buflen, &size);
	    break;
	case FileNameInformation:
	    status = nnpfs_fileinfo_name(irp, node,
					 irp->AssociatedIrp.SystemBuffer,
					 buflen, &size);
	    break;
	case FileInternalInformation:
	    status = nnpfs_fileinfo_internal(irp, node,
					     irp->AssociatedIrp.SystemBuffer,
					     buflen, &size);
	    break;
	case FileEaInformation:
	    status = nnpfs_fileinfo_ea(irp, node,
				       irp->AssociatedIrp.SystemBuffer,
				       buflen, &size);
	    break;
	case FilePositionInformation:
	    status = nnpfs_fileinfo_position(irp, node,
					     irp->AssociatedIrp.SystemBuffer,
					     buflen, &size);
	    break;
	case FileAllInformation:
	    status = nnpfs_fileinfo_all(irp, node,
					irp->AssociatedIrp.SystemBuffer,
					buflen, &size);
	    break;
	case FileNetworkOpenInformation:
	    status = nnpfs_fileinfo_network_open(irp, node,
						 irp->AssociatedIrp.SystemBuffer,
						 buflen, &size);
	    break;
	case FileAttributeTagInformation:
	    status = nnpfs_fileinfo_attr_tag(irp, node,
					     irp->AssociatedIrp.SystemBuffer,
					     buflen, &size);
	}
    } else {
	ASSERT(io_stack->MajorFunction == IRP_MJ_SET_INFORMATION);

	switch (info_class) {
	case FileBasicInformation:
	    status = nnpfs_fileinfo_basic(irp, node,
					  irp->AssociatedIrp.SystemBuffer,
					  buflen, NULL);
	    break;
	case FileDispositionInformation:
	    status = nnpfs_fileinfo_disposition(irp,
						irp->AssociatedIrp.SystemBuffer,
						buflen);
	    break;
	case FileRenameInformation:
	    status = nnpfs_fileinfo_rename(irp,
					   irp->AssociatedIrp.SystemBuffer,
					   buflen);
	    break;
	case FileLinkInformation:
	    status = nnpfs_fileinfo_link(irp,
					 irp->AssociatedIrp.SystemBuffer,
					 buflen);
	    break;
	case FileEndOfFileInformation:
	    status = nnpfs_fileinfo_eof(irp, node,
					irp->AssociatedIrp.SystemBuffer, buflen);
	    break;
	case FileAllocationInformation:
	    status = nnpfs_fileinfo_alloc(irp, node,
					  irp->AssociatedIrp.SystemBuffer,
					  buflen);
	    break;
	}
    }
    if (status == STATUS_INVALID_INFO_CLASS) {
	switch (info_class) {
#define CASEPRINT(infotype) case infotype: \
nnpfs_debug(XDEBVNOPS, "nnpfs_fileinfo: %c " #infotype "\n", \
get_info_p ? 'r' : 'w'); \
break;
	
	    CASEPRINT(FileDirectoryInformation);
	    CASEPRINT(FileFullDirectoryInformation);
	    CASEPRINT(FileBothDirectoryInformation);
	    CASEPRINT(FileBasicInformation);
	    CASEPRINT(FileStandardInformation);
	    CASEPRINT(FileInternalInformation);
	    CASEPRINT(FileEaInformation);
	    CASEPRINT(FileAccessInformation);
	    CASEPRINT(FileNameInformation);
	    CASEPRINT(FileRenameInformation);
	    CASEPRINT(FileLinkInformation);
	    CASEPRINT(FileNamesInformation);
	    CASEPRINT(FileDispositionInformation);
	    CASEPRINT(FilePositionInformation);
	    CASEPRINT(FileFullEaInformation);
	    CASEPRINT(FileModeInformation);
	    CASEPRINT(FileAlignmentInformation);
	    CASEPRINT(FileAllInformation);
	    CASEPRINT(FileAllocationInformation);
	    CASEPRINT(FileEndOfFileInformation);
	    CASEPRINT(FileAlternateNameInformation);
	    CASEPRINT(FileStreamInformation);
	    CASEPRINT(FilePipeInformation);
	    CASEPRINT(FilePipeLocalInformation);
	    CASEPRINT(FilePipeRemoteInformation);
	    CASEPRINT(FileMailslotQueryInformation);
	    CASEPRINT(FileMailslotSetInformation);
	    CASEPRINT(FileCompressionInformation);
	    CASEPRINT(FileObjectIdInformation);
	    CASEPRINT(FileCompletionInformation);
	    CASEPRINT(FileMoveClusterInformation);
	    CASEPRINT(FileQuotaInformation);
	    CASEPRINT(FileReparsePointInformation);
	    CASEPRINT(FileNetworkOpenInformation);
	    CASEPRINT(FileAttributeTagInformation);
	    CASEPRINT(FileTrackingInformation);
	    
#undef CASEPRINT
	    
	default:
	    nnpfs_debug(XDEBVNOPS,
			"nnpfs_fileinfo: %c unknown type %x\n",
			info_class, get_info_p ? 'r' : 'w');
	    break;
	}
    }

 done:    
    irp->IoStatus.Status = status;
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
	irp->IoStatus.Information = size;
    } else {
	irp->IoStatus.Information = 0;
	nnpfs_debug(XDEBVNOPS, "nnpfs_fileinfo: returning %X\n", status);
    }
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
nnpfs_fsync(nnpfs_node *node, nnpfs_cred *cred, u_int flag)
{
    int error;
    struct nnpfs_message_putdata msg;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK iosb;
    BOOLEAN ret;

    offset.QuadPart = 0;

    /* acquire backfile exclusively */
    /* according to Nagar, this doesn't flush, just discards cached data */
    ret = CcPurgeCacheSection(node->backfile->SectionObjectPointer, &offset,
			      node->offset, FALSE);
    /* release backfile locks */

    if (!ret) {
	nnpfs_debug(XDEBVNOPS,
		    "nnpfs_fsync(%X): CcPurge failed!\n", node);
	return STATUS_SHARING_VIOLATION;
    }

    /* XXX perhaps acquire until putdata complete? */

    /* flush modified data to backing file (disk) where daemon can see it */
    CcFlushCache(&node->section_objects, NULL, 0, &iosb);

    ASSERT(NT_SUCCESS(iosb.Status));

    msg.header.opcode = NNPFS_MSG_PUTDATA;
    msg.cred.uid = NNPFS_ANONYMOUSID;
    msg.cred.pag = 0;

    msg.handle = node->handle;
    msg.attr   = node->attr;
    msg.flag   = flag;
    error = nnpfs_message_rpc(node->chan, &msg.header, sizeof(msg));
    if (error == 0)
	error = ((struct nnpfs_message_wakeup *) &msg)->error;

    if (error == 0)
	node->flags &= ~(NNPFS_DATA_DIRTY|NNPFS_ATTR_DIRTY);

    return error;
}

/*
 *
 */

FSD_WRAPPER(nnpfs_flush, nnpfs_fsd_flush);

NTSTATUS 
nnpfs_flush (DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    NTSTATUS            status;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    nnpfs_debug (XDEBVNOPS, "nnpfs_flush\n");

    CcFlushCache(&node->section_objects, NULL, 0, &irp->IoStatus);

    status = irp->IoStatus.Status;
    if (NT_SUCCESS(status))
	status = nnpfs_fsync(node, ccb->cred, NNPFS_FSYNC);

    if (!NT_SUCCESS(status)) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
     
    return status;
}

long nnpfs_efilter(EXCEPTION_POINTERS *e)
{
    NTSTATUS	ecode;
    long	ret = EXCEPTION_EXECUTE_HANDLER;

    ecode = e->ExceptionRecord->ExceptionCode;
    
    if ((ecode == STATUS_IN_PAGE_ERROR) && (e->ExceptionRecord->NumberParameters >= 3)) {
	ecode = e->ExceptionRecord->ExceptionInformation[2];
    }

    if (!(FsRtlIsNtstatusExpected(ecode))) {
	ret = EXCEPTION_CONTINUE_SEARCH;
    }

    return ret;
}

typedef struct {
    int class;
    union {
	FILE_DIRECTORY_INFORMATION *dirinfo;
	FILE_FULL_DIR_INFORMATION *fulldir;
	FILE_BOTH_DIR_INFORMATION *bothdir;
	FILE_NAMES_INFORMATION *names;
	void *buf;
    } u;
    ULONG *lastbuf;
    int bufsize;
    struct nnpfs_node *node;
    nnpfs_cred *cred;
    UNICODE_STRING *searchpattern;
    NTSTATUS status;
} nnpfs_readdir_arg;

/*
 * 
 */

static int
nnpfs_convert_dirent(VenusFid *fid, const char *fname, void *arg)
{
    ANSI_STRING	   fname_a;
    UNICODE_STRING fname_u;
    int size;
    NTSTATUS status = STATUS_SUCCESS;
    nnpfs_readdir_arg *info = (nnpfs_readdir_arg *)arg;
    struct nnpfs_node *node;
    struct nnpfs_attr *xa;
    struct nnpfs_attr dummy_attr;
    struct nnpfs_msg_node msg_node = {0};

    RtlInitAnsiString(&fname_a, fname);
    status = RtlAnsiStringToUnicodeString(&fname_u, &fname_a, TRUE);
    if (!NT_SUCCESS(status)) {
	nnpfs_debug (XDEBVNOPS, "nnpfs_convert_dirent: ansi2uni failed!\n");
	info->status = status;
	if (info->searchpattern == NULL)
	    nnpfs_vrele(info->node);
	return -1; /* break out of readdir iteration */
    }	

    if (info->searchpattern) {
	if (!FsRtlIsNameInExpression(info->searchpattern,
				     &fname_u, FALSE, NULL)) {
	    /* doesn't match, continue */
	    RtlFreeUnicodeString(&fname_u);
	    return 0;
	}
	nnpfs_fid2handle(fid, &msg_node.handle);
	
	node = nnpfs_node_find (&NNPFSGlobalData, &msg_node.handle);
	if (node == NULL) {
	    status = nnpfs_lookup(info->node, fname, &node, NULL, NULL, 0);
	    if (!NT_SUCCESS(status)) {
		/* this could be a bad symlink, try fallback on link node */
		node = nnpfs_node_find (&NNPFSGlobalData, &msg_node.handle);
		if (node == NULL)
		    nnpfs_debug (XDEBVNOPS, "nnpfs_convert_dirent(%s): "
				 "no node %x!\n", fname, status);
	    }
	} else {
	    if (node->attr.xa_type == NNPFS_FILE_LNK) {
		/* We keep a spare copy of our original node in case 
		 * the symlink is broken. 
		 * nnpfs_lookup_symlink() always vrele():s the link node
		 * so we need to vref() it once more.
		 */
		nnpfs_node *n = node;
		nnpfs_vref(n);
		node = NULL;
		status = nnpfs_lookup_symlink(info->node, n, &node,
					      NULL, NULL, 0);
		if (node == NULL)
		    node = n;
		else
		    nnpfs_vrele(n);
	    }
	}
    } else {
	node = info->node;
    }

    if (node)
	status = nnpfs_attr_valid(node, info->cred, NNPFS_ATTR_R);
    if (NT_SUCCESS(status)) {
	xa = &node->attr;
    } else {
	/* we don't have a node (permission denied?), make smth up */
	nnpfs_debug (XDEBVNOPS, "nnpfs_convert_dirent(%s): no attr %x!\n",
		     fname, status);
	RtlZeroMemory(&dummy_attr, sizeof(dummy_attr));
	xa = &dummy_attr;
	XA_SET_TYPE(xa, NNPFS_FILE_REG);
    }
    
    if (status == STATUS_NO_SUCH_FILE)
	/* Probably a broken symlink, but the entry is in the directory,
	 * so we report it anyway
	 */
	status = STATUS_SUCCESS;

    switch (info->class) {
    case FileDirectoryInformation:
	size = sizeof(FILE_DIRECTORY_INFORMATION)
	    + fname_u.Length - sizeof(WCHAR);
	size = AlignPointer(size);
	
	if (size > info->bufsize)
	    info->bufsize = 0;
	else {
	    info->u.dirinfo->FileIndex = 0;
	    
	    /* we don't have CreationTime -- zero */
	    info->u.dirinfo->CreationTime.QuadPart = (LONGLONG)0;
	    nnpfs_getattrs(xa, &info->u.dirinfo->LastAccessTime,
			   &info->u.dirinfo->LastWriteTime,
			   &info->u.dirinfo->ChangeTime,
			   &info->u.dirinfo->AllocationSize,
			   &info->u.dirinfo->FileAttributes);
	    info->u.dirinfo->EndOfFile = info->u.dirinfo->AllocationSize;

	    info->u.dirinfo->FileNameLength = fname_u.Length;
	    RtlCopyBytes(info->u.dirinfo->FileName,
			 fname_u.Buffer, fname_u.Length);
	}
	break;
    case FileFullDirectoryInformation:
	size = sizeof(FILE_FULL_DIR_INFORMATION)
	    + fname_u.Length - sizeof(WCHAR);
	size = AlignPointer(size);
    
	if (size > info->bufsize)
	    info->bufsize = 0;
	else {
	    info->u.fulldir->FileIndex = 0;

	    /* we don't have CreationTime -- zero */
	    info->u.fulldir->CreationTime.QuadPart = (LONGLONG)0;
	    nnpfs_getattrs(xa, &info->u.fulldir->LastAccessTime,
			   &info->u.fulldir->LastWriteTime,
			   &info->u.fulldir->ChangeTime,
			   &info->u.fulldir->AllocationSize,
			   &info->u.fulldir->FileAttributes);
	    info->u.fulldir->EndOfFile = info->u.fulldir->AllocationSize;

	    info->u.fulldir->FileNameLength = fname_u.Length;
	    info->u.fulldir->EaSize = 0;
	    RtlCopyBytes(info->u.fulldir->FileName,
			 fname_u.Buffer, fname_u.Length);
	}
	break;
    case FileBothDirectoryInformation:
	size = sizeof(FILE_BOTH_DIR_INFORMATION)
	    + fname_u.Length - sizeof(WCHAR);
	size = AlignPointer(size);

	if (size > info->bufsize)
	    info->bufsize = 0;
	else {
	    info->u.bothdir->FileIndex = 0;

	    /* we don't have CreationTime -- zero */
	    info->u.bothdir->CreationTime.QuadPart = (LONGLONG)0;
	    nnpfs_getattrs(xa, &info->u.bothdir->LastAccessTime,
			   &info->u.bothdir->LastWriteTime,
			   &info->u.bothdir->ChangeTime,
			   &info->u.bothdir->AllocationSize,
			   &info->u.bothdir->FileAttributes);
	    info->u.bothdir->EndOfFile = info->u.bothdir->AllocationSize;

	    info->u.bothdir->FileNameLength = fname_u.Length;
	    info->u.bothdir->EaSize = 0;
	    info->u.bothdir->ShortNameLength = 0;

	    RtlCopyBytes(info->u.bothdir->FileName,
			 fname_u.Buffer, fname_u.Length);
	}
	break;
    case FileNamesInformation:
	size = sizeof(FILE_NAMES_INFORMATION)
	    + fname_u.Length - sizeof(WCHAR);
	size = AlignPointer(size);

	if (size > info->bufsize)
	    info->bufsize = 0;
	else {
	    info->u.names->FileNameLength = fname_u.Length;
	    RtlCopyBytes(info->u.names->FileName,
			 fname_u.Buffer, fname_u.Length);
	}
    }
    RtlFreeUnicodeString(&fname_u);

    if (node)
	nnpfs_vrele(node);
    info->status = status;

    if (info->bufsize <= 0) {
	if (info->lastbuf == info->u.buf && NT_SUCCESS(status))
	    info->status = STATUS_INFO_LENGTH_MISMATCH;
	return -1; /* break out of readdir iteration */
    }
    info->lastbuf = info->u.buf;
    *((ULONG *)info->u.buf) = size; /* NextEntryOffset */
    (char *)info->u.buf += size;
    info->bufsize -= size;
    nnpfs_debug (XDEBVNOPS, "nnpfs_convert_dirent: got %s!\n", fname);
    return 0;
}

static int
nnpfs_get_single_entry(VenusFid *fid, const char *fname, void *arg)
{
    nnpfs_readdir_arg *info = (nnpfs_readdir_arg *)arg;
    int ret = nnpfs_convert_dirent(fid, fname, arg);

    if (info->lastbuf == info->u.buf)
	return ret;
    
    return 1; /* no more entries needed */
}

/*
 * readdir
 */

FSD_WRAPPER(nnpfs_dirctl, nnpfs_fsd_dirctl);

NTSTATUS 
nnpfs_dirctl (PDEVICE_OBJECT device, PIRP irp)
{
    IO_STACK_LOCATION		*io_stack;
    unsigned long		buflen = 0;
    unsigned long		offset = 0;
    UNICODE_STRING		*pattern = NULL;
    FILE_INFORMATION_CLASS 	infoclass;
    unsigned long		fileindex = 0;
    ULONG			flags = 0;
    NTSTATUS			status = STATUS_SUCCESS;
    unsigned char		*buf = NULL;
    nnpfs_readdir_arg             arg;
    EXTENDED_IO_STACK_LOCATION	*eio_stack;
    FILE_OBJECT			*file;
    nnpfs_ccb			*ccb = NULL;
    struct nnpfs_node		*node = NULL;
    
    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    eio_stack = (EXTENDED_IO_STACK_LOCATION *) io_stack;
    irp->IoStatus.Information = 0;

    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    try {
	switch (io_stack->MinorFunction) {
	case IRP_MN_QUERY_DIRECTORY:
	    buflen = eio_stack->Parameters.QueryDirectory.Length;
	    pattern = eio_stack->Parameters.QueryDirectory.FileName;
	    infoclass =
		eio_stack->Parameters.QueryDirectory.FileInformationClass;
	    fileindex = eio_stack->Parameters.QueryDirectory.FileIndex;
	    flags = eio_stack->Flags;
	    
	    nnpfs_debug(XDEBVNOPS, "nnpfs_dirctl: "
			"buflen: %d File_Info: %d flags: %x\n",
			buflen, infoclass, flags);
//	    nnpfs_debug(XDEBVNOPS, "nnpfs_dirctl: fileindex: %d\n",
//		      fileindex);
	    
	    if (pattern == NULL) {
		if (ccb->SearchPattern.Buffer == NULL) {
		    ccb->SearchPattern.Length =	sizeof(WCHAR);
		    ccb->SearchPattern.MaximumLength = sizeof(L"*");
		    ccb->SearchPattern.Buffer =
			nnpfs_alloc(sizeof(L"*"), 'vdc1');
		    
		    /* XXX where do we free? */

		    if (ccb->SearchPattern.Buffer == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		    }

		    *ccb->SearchPattern.Buffer = '*';
		}
		pattern = &ccb->SearchPattern;
	    } else {
		unsigned len = pattern->Length;
		nnpfs_debug(XDEBVNOPS,
			    "nnpfs_dirctl: search pattern(%d): %c%c%c%c\n",
			    len, pattern->Buffer[0],
			    len > 2 ? pattern->Buffer[1]:' ',
			    len > 4 ? pattern->Buffer[2]:' ',
			    len > 6 ? pattern->Buffer[3]:' ');

		if (ccb->SearchPattern.Buffer == NULL) {
		    ccb->SearchPattern.Length = pattern->Length;
		    ccb->SearchPattern.MaximumLength = pattern->Length;
		    ccb->SearchPattern.Buffer =
			nnpfs_alloc(pattern->Length, 'vdc2');
		    
		    /* XXX we should free when deallocating the ccb */

		    if (ccb->SearchPattern.Buffer == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		    }

		    RtlCopyUnicodeString(&ccb->SearchPattern, pattern);
		}
	    }

	    /* Where to start */

	    if (fileindex) {
		offset = fileindex;
	    } else if ((flags & SL_RESTART_SCAN) == SL_RESTART_SCAN) {
		offset = 0;
	    } else {
		offset = ccb->ByteOffset;
	    }

	    buf = nnpfs_get_buffer(irp);
	    RtlZeroMemory(buf, buflen);

//	    nnpfs_debug(XDEBVNOPS, "nnpfs_dirctl: irp->flags: %x\n", irp->Flags);
	    
	    switch (infoclass) {
	    case FileDirectoryInformation:
	    case FileFullDirectoryInformation:
	    case FileBothDirectoryInformation:
	    case FileNamesInformation:
	    {
		fdir_readdir_func func;
		VenusFid fid;
		fbuf the_fbuf;
		
		if (flags & SL_RETURN_SINGLE_ENTRY)
		    func = nnpfs_get_single_entry;
		else
		    func = nnpfs_convert_dirent;
		    
		arg.u.buf = buf;
		arg.lastbuf = (ULONG *)buf;
		arg.class = infoclass;
		arg.status = offset ? STATUS_NO_MORE_FILES : STATUS_NO_SUCH_FILE;
		arg.bufsize = buflen;
		arg.cred = ccb->cred;

		nnpfs_handle2fid(&node->handle, &fid);
		
		if (FsRtlDoesNameContainWildCards(pattern)) {
		    status = nnpfs_data_valid(node, ccb->cred, NNPFS_DATA_R,
					      node->attr.xa_size);
		    if (!NT_SUCCESS(status)) {
			nnpfs_debug(XDEBVNOPS, "dirctl: no data!\n");
			break;
		    }

		    if (NT_SUCCESS(status))
			status = fbuf_create(&the_fbuf, DATA_FROM_XNODE(node),
					     node->attr.xa_size, FBUF_READ); 
		    if (NT_SUCCESS(status)) {
			arg.searchpattern = pattern;
			arg.node = node;
			status = fdir_readdir(&the_fbuf, func, &arg,
					      fid, &offset);
			fbuf_end(&the_fbuf);
		    }
		    if (NT_SUCCESS(status))
			status = arg.status;
		} else {
		    char fname[1024];
		    nnpfs_node *n;
		    
		    if (offset) {
			/* there shouldn't be more than one file
			 * with this name...
			 */
			status = STATUS_NO_MORE_FILES;
		    } else {
			status = nnpfs_unicode2unix(pattern,
						    fname, sizeof(fname));
			if (NT_SUCCESS(status)) {
			    nnpfs_lookup_args args;
			    RtlZeroMemory(&args, sizeof(args));
			    /* XXX disposition 0 is FILE_SUPERSEDE, 
			     * so we set it to some illegal value instead
			     */
			    args.disposition = FILE_MAXIMUM_DISPOSITION + 1; 
			    args.flags = NNPFS_LOOKUP_GETLINK;
			    status = nnpfs_lookup(node, fname, &n, &args, NULL, 0);
			    if (args.pathinfo.link != NULL) {
				if (n == NULL)
				    n = args.pathinfo.link;
				else
				    nnpfs_vrele(args.pathinfo.link);
			    }
			}
			if (NT_SUCCESS(status)) {
			    arg.node = n;
			    arg.searchpattern = NULL;
			    nnpfs_convert_dirent(&fid, fname, &arg); 
			    /* XXX check status */
			    /* nnpfs_convert_dirent vrele():s */
			    
			    offset = 1; /* not exactly true, just a marker */
			}
		    }
		}
		
		*arg.lastbuf = 0;
		
		break;
	    }
	    default:
		nnpfs_debug(XDEBVNOPS, "dirctl: strange request %x\n",
			    io_stack->MinorFunction);
		status = STATUS_INVALID_DEVICE_REQUEST;
	    }
	    
	    if (status == STATUS_SUCCESS) {
		irp->IoStatus.Information = (char *)arg.u.buf - (char *)buf;
		ccb->ByteOffset = offset;
	    }
	    
	    break;
	case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
#if 0
	    status = NNPFSNotifyChangeDirectory(PtrIrpContext, PtrIrp, 
						PtrIoStackLocation, PtrFileObject,
						PtrFCB, PtrCCB);
#endif
	    status = STATUS_NOT_IMPLEMENTED;
	    break;
	default:
	    status = STATUS_INVALID_DEVICE_REQUEST;
	    break;
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);	    
	return status;
    } except (nnpfs_efilter(GetExceptionInformation())) {
	status = STATUS_INVALID_DEVICE_REQUEST;
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
    }
}

/*
 *
 */

FSD_WRAPPER(nnpfs_shutdown, nnpfs_fsd_shutdown);

NTSTATUS 
nnpfs_shutdown (PDEVICE_OBJECT device, PIRP irp)
{
    nnpfs_debug (XDEBVNOPS, "nnpfs_shutdown\n");

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
     
    return STATUS_SUCCESS;
}

/*
 * This is really a close function that is called when
 * the user closes the filehandle.
 */

FSD_WRAPPER(nnpfs_cleanup, nnpfs_fsd_cleanup);

NTSTATUS 
nnpfs_cleanup (PDEVICE_OBJECT device, PIRP irp)
{
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    BOOLEAN		ret;
    
    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    nnpfs_debug (XDEBVNOPS, "nnpfs_cleanup(%X)\n", node);

    ASSERT (ccb && node); /* XXX */
    ASSERT (node->chan->magic == NNPFS_DEV_DATA_MAGIC);

    if (file->PrivateCacheMap == (void *)1)
	file->PrivateCacheMap = NULL;
    ret = CcUninitializeCacheMap(file, NULL, NULL); /*XXX truncatesize*/
    if (!ret)
	nnpfs_debug (XDEBVNOPS,
		     "nnpfs_cleanup(%X): uninit cachemap failed\n", node);

    if (ccb->flags & NNPFS_CCB_MODIFIED)
	nnpfs_fsync(node, ccb->cred, NNPFS_WRITE);
    
    /* XXX
     * we are not informed when mmap:s are munmap:ed, so we need to poll
     * to be able to inform daemon of the changes after the last one
     *
     * for now: check mapping (possibly flush) on 
     * create, STALE+vrele, ...?
     */

    node->handlecount--;

    /* check ccb->link and deletion status */
    if (ccb->pathinfo != NULL) {
	if (file->DeletePending == TRUE) {
	    /* XXX we do this unix style, the windows way is to postpone
	     * actual delete until last handle is closed?
	     */
	    if (ccb->pathinfo->link == NULL) {
		nnpfs_remove_entry(ccb->pathinfo->parent, node,
				   ccb->pathinfo->name, ccb->cred);
	    } else {
		nnpfs_remove_entry(ccb->pathinfo->parent, ccb->pathinfo->link,
				   ccb->pathinfo->name, ccb->cred);
		nnpfs_vrele(ccb->pathinfo->link);
	    }
	} else if (ccb->pathinfo->link != NULL) {
	    nnpfs_vrele(ccb->pathinfo->link);
	}
	if (ccb->pathinfo->parent != NULL)
	    /* can be for opentargetdir? */
	    nnpfs_vrele(ccb->pathinfo->parent);
	nnpfs_free(ccb->pathinfo, sizeof(ccb->pathinfo));
    }

    IoRemoveShareAccess(file, &node->share_access);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
     
    return STATUS_SUCCESS;
}

/*
 *
 */

FSD_WRAPPER(nnpfs_queryvol, nnpfs_fsd_queryvol);

NTSTATUS 
nnpfs_queryvol (PDEVICE_OBJECT device, PIRP irp)
{ 
    IO_STACK_LOCATION	*io_stack;
    FILE_OBJECT		*file;
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    FILE_INFORMATION_CLASS info_class;
    int                 get_info_p = TRUE;
    ULONG               buflen;
    ULONG               size = 0;
    NTSTATUS            status = STATUS_INVALID_PARAMETER;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);
    
    file = io_stack->FileObject;
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    node = ccb->node;

    ASSERT (ccb && node);

    if (io_stack->MajorFunction != IRP_MJ_QUERY_VOLUME_INFORMATION)
	get_info_p = FALSE;
    info_class = io_stack->Parameters.QueryVolume.FsInformationClass;
    buflen = io_stack->Parameters.QueryVolume.Length;

    if (get_info_p) {
	RtlZeroMemory(irp->AssociatedIrp.SystemBuffer, buflen);

	switch (info_class) {
	case FileFsVolumeInformation:
	{
	    PFILE_FS_VOLUME_INFORMATION buf =
		(PFILE_FS_VOLUME_INFORMATION) irp->AssociatedIrp.SystemBuffer;
	    int namelen = sizeof(NNPFS_DEV_NAME);
	    size = sizeof(FILE_FS_VOLUME_INFORMATION);
	    

	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Volume\n");

	    if (buflen < size) {
		size = 0;
		status = STATUS_BUFFER_OVERFLOW;
		break;
	    }

	    if (buflen < (size + namelen - sizeof(WCHAR))) {
		namelen = buflen - size + sizeof(WCHAR);
		status = STATUS_BUFFER_OVERFLOW;
	    } else {
		status = STATUS_SUCCESS;
	    }
	    size += namelen - sizeof(WCHAR);

	    buf->VolumeCreationTime.QuadPart = 0;
	    buf->VolumeSerialNumber = 4711;
	    buf->VolumeLabelLength = namelen;
	    buf->SupportsObjects = FALSE;
	    RtlCopyBytes(buf->VolumeLabel, NNPFS_DEV_NAME,
			 buf->VolumeLabelLength);
	}
	break;
	case FileFsSizeInformation:
	{
	    PFILE_FS_SIZE_INFORMATION buf =
		(PFILE_FS_SIZE_INFORMATION) irp->AssociatedIrp.SystemBuffer;
	    size = sizeof(FILE_FS_SIZE_INFORMATION);

	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Size\n");

	    if (buflen < size) {
		size = 0;
		status = STATUS_BUFFER_OVERFLOW;
		break;
	    }
	    
	    buf->TotalAllocationUnits.QuadPart = (LONGLONG)1024;
	    buf->AvailableAllocationUnits.QuadPart = (LONGLONG)0;
	    buf->SectorsPerAllocationUnit = 4;
	    buf->BytesPerSector = 512;
	    
	    status = STATUS_SUCCESS;
	}
	break;
	case FileFsDeviceInformation:
	{
	    PFILE_FS_DEVICE_INFORMATION buf =
		(PFILE_FS_DEVICE_INFORMATION) irp->AssociatedIrp.SystemBuffer;
	    size = sizeof(FILE_FS_DEVICE_INFORMATION);

	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Device\n");

	    if (buflen < size) {
		size = 0;
		status = STATUS_BUFFER_OVERFLOW;
		break;
	    }
	    
	    buf->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
	    // FILE_DEVICE_NETWORK_FILE_SYSTEM;
	    buf->Characteristics = FILE_REMOTE_DEVICE;
	    
	    status = STATUS_SUCCESS;
	}
	break;
	case FileFsAttributeInformation:
	{	 
	    PFILE_FS_ATTRIBUTE_INFORMATION buf =
		(PFILE_FS_ATTRIBUTE_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	    int namelen = sizeof(NNPFS_DEV_NAME);
	    size = sizeof(FILE_FS_ATTRIBUTE_INFORMATION);

	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Attribute\n");

	    if (buflen < size) {
		size = 0;
		status = STATUS_BUFFER_OVERFLOW;
		break;
	    }
	    
	    if (buflen < (size + namelen - sizeof(WCHAR))) {
		namelen = buflen - size + sizeof(WCHAR);
		status = STATUS_BUFFER_OVERFLOW;
	    } else {
		status = STATUS_SUCCESS;
	    }
	    size += namelen - sizeof(WCHAR);

	    buf->FileSystemAttributes =
		FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
	    buf->MaximumComponentNameLength = NNPFS_MAX_NAME; 
	    buf->FileSystemNameLength = namelen;
	    RtlCopyBytes(buf->FileSystemName, NNPFS_DEV_NAME,
			 buf->FileSystemNameLength);
	}
	break;
	case FileFsLabelInformation:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Label\n");
	    break;
	    
	case FileFsControlInformation:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: Control\n");
	    break;
	    
	case FileFsFullSizeInformation:
	{
	    PFILE_FS_FULL_SIZE_INFORMATION buf =
		(PFILE_FS_FULL_SIZE_INFORMATION)
		irp->AssociatedIrp.SystemBuffer;
	    size = sizeof(FILE_FS_FULL_SIZE_INFORMATION);

	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: FullSize\n");

	    if (buflen < size) {
		size = 0;
		status = STATUS_BUFFER_OVERFLOW;
		break;
	    }

/*	    sbp->f_blocks = 4711*4711;
	    sbp->f_bfree = 4711*4711;
	    sbp->f_bavail = 4711*4711;
	    sbp->f_files = 4711; */

	    buf->TotalAllocationUnits.QuadPart = (LONGLONG)4711*4711;
	    buf->CallerAvailableAllocationUnits.QuadPart = (LONGLONG)0;
	    buf->ActualAvailableAllocationUnits.QuadPart = (LONGLONG)0;
	    buf->SectorsPerAllocationUnit = 4;
	    buf->BytesPerSector = 512;
	    status = STATUS_SUCCESS;
	}
	break;
	case FileFsObjectIdInformation:
	    nnpfs_debug (XDEBVNOPS, "nnpfs_queryvol: ObjectId\n");
	    break;
	    
	default:
	    nnpfs_debug (XDEBVNOPS,
			 "nnpfs_queryvol: unknown type %x\n", info_class);
	    break;
	}
    }

    irp->IoStatus.Status = status;
    if (NT_SUCCESS(status)) {
	irp->IoStatus.Information = size;
    } else {
	irp->IoStatus.Information = size;
	nnpfs_debug(XDEBVNOPS, "nnpfs_queryvol: returning %X\n", status);
    }
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    
    return status;
}

/*
 *
 */

FSD_WRAPPER(nnpfs_fscontrol, nnpfs_fsd_fscontrol);

NTSTATUS 
nnpfs_fscontrol (PDEVICE_OBJECT device, PIRP irp)
{ 
    EXTENDED_IO_STACK_LOCATION *io_stack;
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

    io_stack = (PEXTENDED_IO_STACK_LOCATION)IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);

    switch (io_stack->MinorFunction) {
    case IRP_MN_USER_FS_REQUEST:
    {
	unsigned code = io_stack->Parameters.FileSystemControl.FsControlCode;
	
	switch (code) {
	case FSCTL_IS_VOLUME_MOUNTED:
	    nnpfs_debug(XDEBVNOPS, "nnpfs_fscontrol: FSCTL_IS_VOLUME_MOUNTED\n");
	    status = STATUS_INVALID_PARAMETER; /* XXX */
	    break;
	default:
	    nnpfs_debug(XDEBVNOPS, "nnpfs_fscontrol: userfsreq %d\n", code);
	    break;
	}
	break;
    }
    case IRP_MN_MOUNT_VOLUME:
	nnpfs_debug (XDEBVNOPS, "nnpfs_fscontrol: mount\n");
	break;
    case IRP_MN_VERIFY_VOLUME:
	nnpfs_debug (XDEBVNOPS, "nnpfs_fscontrol: verify\n");
	break;
    case IRP_MN_LOAD_FILE_SYSTEM:
	nnpfs_debug (XDEBVNOPS, "nnpfs_fscontrol: load fs\n");
	break;
    default:
	nnpfs_debug (XDEBVNOPS, "nnpfs_fscontrol: unknown\n");
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    
    return status;
}
