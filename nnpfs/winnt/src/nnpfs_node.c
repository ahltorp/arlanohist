/*
 * Copyright (c) 1995 - 2003 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_node.c,v 1.9 2003/07/01 14:18:12 tol Exp $ */

#include <nnpfs_locl.h>

int reflimit = 15;

BOOLEAN
nnpfs_node_mapped (nnpfs_node *node, BOOLEAN flushp)
{
    LARGE_INTEGER size;
    BOOLEAN ret;

    /* we assume there are no open handles,
     * and that the node is properly locked
     */

    /* check if there are any mappings */
    if ((node->fcb.Flags & FSRTL_FLAG_USER_MAPPED_FILE) == 0) {
	/* not used, go ahead */

	/* get rid of data -- it should already be flushed */
	ret = CcPurgeCacheSection(&node->section_objects, NULL, 0, TRUE);
	return !ret;
    }

    size.QuadPart = 0;
    if (MmCanFileBeTruncated(&node->section_objects, &size)) {
	NTSTATUS status = STATUS_SUCCESS;

	if (node->flags & NNPFS_FCB_WRITEMAPPED) {
	    if (!flushp)
		return TRUE;

	    status = nnpfs_fsync(node, &node->writemapper, NNPFS_WRITE);

	    if (NT_SUCCESS(status)) {
		RtlZeroMemory(&node->writemapper, sizeof(node->writemapper));
		node->flags &= ~NNPFS_FCB_WRITEMAPPED;
	    } else {
		nnpfs_debug(XDEBMSG,
			    "nnpfs_node_mapped(%X): fsync->%X\n",
			    node, status);
	    }
	}
	if (NT_SUCCESS(status)) {
	    ret = CcPurgeCacheSection(&node->section_objects, NULL, 0, TRUE);
	    node->fcb.Flags &= ~FSRTL_FLAG_USER_MAPPED_FILE; /* XXX always? */
	    return !ret;
	}
    }
    return TRUE;
}

BOOLEAN
nnpfs_node_inuse (nnpfs_node *node, BOOLEAN flushp)
{
    /* XXX lock node */
    if (node->handlecount == 0 
	&& !nnpfs_node_mapped(node, flushp))
	return FALSE;

    return TRUE;
}

/*
 * XXX smp
 */

void
nnpfs_vref (nnpfs_node *node)
{
    ASSERT (node->refcount >= 0);
    InterlockedIncrement(&node->refcount);
    nnpfs_debug (XDEBREF, "nnpfs_vref(%p): refcount->%d\n",
		 node, node->refcount);
}

/*
 * XXX smp
 */

void
nnpfs_vrele (struct nnpfs_node *node)
{
    int lockedp = 0;

    nnpfs_debug (XDEBREF, "nnpfs_vrele(%p): refcount->%d\n",
		 node, node->refcount - 1);

    if (node->flags & NNPFS_STALE) {
	lockedp = 1;

	ExAcquireResourceExclusiveLite(&node->MainResource, TRUE);
	nnpfs_debug (XDEBNODE, "nnpfs_vrele(%p): got Main\n", node);
	
	/* try to uncache the node */
	nnpfs_node_inuse(node,
			 FALSE); /* XXX avoids deadlock if daemon called */
	
	/* XXX danger? */
	ExAcquireFastMutex(&node->chan->NodeListMutex);
	if (node->refcount == 1) {
	    nnpfs_vgone(node); /* releases NodeListMutex & MainResource*/
	    return;
	}
    } 
    InterlockedDecrement(&node->refcount);

    ASSERT (node->refcount >= 0);
    ASSERT (node->refcount < reflimit);
    if (lockedp) {
	ExReleaseFastMutex(&node->chan->NodeListMutex);
	ExReleaseResourceLite(&node->MainResource);
	nnpfs_debug (XDEBNODE, "nnpfs_vrele(%p): released Main\n", node);
    }
}

/*
 * nnpfs_vgone
 * node is considered unused, free it and inform daemon
 *
 * we own NodeListMutex and MainResource exclusively
 */

void
nnpfs_vgone (struct nnpfs_node *node)
{
    struct nnpfs_message_inactivenode msg;
    nnpfs_channel *chan = node->chan;

    nnpfs_debug (XDEBNODE, "nnpfs_vgone(%p)\n", node);

    ASSERT(node->refcount == 1); /* vref:d */

    msg.header.opcode = NNPFS_MSG_INACTIVENODE;
    msg.handle = node->handle;
    msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;

    /* XXX update lru */
    nnpfs_node_invalid(node);
    nnpfs_free_node(node);
    ExReleaseFastMutex(&node->chan->NodeListMutex);
	    
    nnpfs_message_send(chan, &msg.header, sizeof(msg));
}

/* 
 * clear all cached info on this node 
 */

void
nnpfs_node_invalid(nnpfs_node* node) {
    nnpfs_dnlc_uncache(node);
    if (NNPFS_VALID_DATAHANDLE(node))
	nnpfs_close_data_handle (node);
    NNPFS_TOKEN_CLEAR(node, ~0,
		      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
		      NNPFS_DATA_MASK | NNPFS_LOCK_MASK);
}

/*
 * gc all available nodes
 *  if force == TRUE: throw _everything_ cached
 */

void
nnpfs_node_gc_all(nnpfs_channel *chan, BOOLEAN force) {
    nnpfs_node *node, *next;

    nnpfs_debug(XDEBNODE, "nnpfs_node_gc_all: force=%d\n", force);

    ExAcquireFastMutex(&chan->NodeListMutex); /* XXX dangerous? */
    
    node = XLIST_HEAD(&chan->nodes);
    while (node) {
	next = XLIST_NEXT(node, lru_entry);
	ExReleaseFastMutex(&chan->NodeListMutex);

	nnpfs_vref(node);

	if (node->refcount == 1 || force == TRUE) {
	    ExAcquireResourceExclusiveLite(&node->MainResource, TRUE);
	    nnpfs_debug (XDEBNODE,
			 "nnpfs_node_gc_all(%p): got Main\n", node);
	    node->flags |= NNPFS_STALE;
	    nnpfs_node_invalid(node);
	    ExReleaseResourceLite(&node->MainResource);
	    nnpfs_debug (XDEBNODE,
			 "nnpfs_node_gc_all(%p): released Main\n", node);
	}

	nnpfs_vrele(node);

	node = next;
	ExAcquireFastMutex(&chan->NodeListMutex);
    }
    ExReleaseFastMutex(&chan->NodeListMutex);
}

void
nnpfs_node_list (struct nnpfs_channel *chan)
{
    nnpfs_node *node;

    ExAcquireFastMutex(&chan->NodeListMutex);

    XLIST_FOREACH(&chan->nodes, node, lru_entry)
	nnpfs_debug(XDEBNODE, "list: found %x %x %x %x\n",
		    node->handle.a, node->handle.b, node->handle.c, node->handle.d);

    ExReleaseFastMutex(&chan->NodeListMutex);
    
    return;
}

/*
 * Find a node on channel `chan´ that has `handle´. If not found
 * return NULL
 */

static struct nnpfs_node *
nnpfs_node_find_lock (struct nnpfs_channel *chan, struct nnpfs_handle *handle)
{
    struct nnpfs_node *node;
    
    XLIST_FOREACH(&chan->nodes, node, lru_entry)
	if (nnpfs_handle_eq (&node->handle, handle)) {
	    nnpfs_vref (node);
	    return node;
	}
    
    return NULL;
}

/*
 * Find a node on channel `chan´ that have `handle´. If not found
 * return NULL
 */

struct nnpfs_node *
nnpfs_node_find (struct nnpfs_channel *chan, struct nnpfs_handle *handle)
{
    struct  nnpfs_node *node;

    ExAcquireFastMutex(&chan->NodeListMutex);
    node = nnpfs_node_find_lock (chan, handle);
    ExReleaseFastMutex(&chan->NodeListMutex);

    return node;
}


/*
 * Allocate a nnpfs_node structure for either a zone or non-paged pool.
 * Set approprivate flags. NodeListMutex and ZoneAllocationMutex
 * might be locked
 */

int
nnpfs_new_node (struct nnpfs_channel *chan,
		struct nnpfs_msg_node *node,
		struct nnpfs_node **npp)
{
    struct nnpfs_node *result;
    BOOLEAN zonep = TRUE;

    ExAcquireFastMutex (&chan->NodeListMutex);

    result = nnpfs_node_find_lock (chan, &node->handle);
    if (result == NULL) {
	ExAcquireFastMutex (&chan->ZoneAllocationMutex);
	
	if (!ExIsFullZone (&chan->NodeZoneHeader)) {
	    result = ExAllocateFromZone (&chan->NodeZoneHeader);
	    ExReleaseFastMutex (&chan->ZoneAllocationMutex);
	} else {
	    ExReleaseFastMutex(&chan->ZoneAllocationMutex);
	    result = nnpfs_alloc(sizeof(*result), 'nnn1');
	    zonep = FALSE;

	    nnpfs_debug(XDEBNODE, "nnpfs_new_node: allocated %p\n", result);
	}

	if (result == NULL) /* XXX */
	    NNPFSPanic (STATUS_INSUFFICIENT_RESOURCES, sizeof(*result), 0);
	
	RtlZeroMemory(result, sizeof(*result));
	nnpfs_vref (result);

	result->fcb.NodeTypeCode = (USHORT) NNPFS_TYPE_FCB;
	result->fcb.NodeByteSize = sizeof(nnpfs_node);
	result->fcb.IsFastIoPossible = FastIoIsPossible; /* XXX */
	result->fcb.Resource = &(result->MainResource);
	result->fcb.PagingIoResource = &(result->PagingIoResource);

	/* indicate that we don't maintain ValidDataLength */
	result->fcb.ValidDataLength.LowPart  = 0xffffffff;
	result->fcb.ValidDataLength.HighPart = 0x7fffffff;

	/* result->section_object.DataSectionObject = NULL;
	   result->section_object.SharedCacheMap = NULL;
	   result->section_object.ImageSectionObject = NULL; // zeroed */
	
	ExInitializeResourceLite(&(result->MainResource));
	ExInitializeResourceLite(&(result->PagingIoResource));

	/*
	 * Enter on list
	 */
	
	XLIST_ADD_HEAD(&chan->nodes, result, lru_entry);
	
	result->chan = chan;
    }

    /*
     * Install attributes AllocationSize FileSize
     */

    nnpfs_attr2vattr(&node->attr, result);
#if 0
    result->vn->v_type = result->attr.va_type;
#endif
    result->tokens = node->tokens;
//    NNPFS_TOKEN_SET(result, NNPFS_ATTR_R, NNPFS_ATTR_MASK);
    bcopy(node->id, result->id, sizeof(result->id));
    bcopy(node->rights, result->rights, sizeof(result->rights));
//    DATA_FROM_XNODE(result) = NULL;
    result->handle = node->handle;

    if (!zonep)
	NNPFS_SETFLAGS(result->flags, NNPFS_FCB_NOT_FROM_ZONE);

    ExReleaseFastMutex (&chan->NodeListMutex);

    *npp = result;

//    nnpfs_node_list(chan);

    return STATUS_SUCCESS;
}

/*
 * Free node
 * Called with NodeListMutex held
 */

void
nnpfs_free_node (struct nnpfs_node *node)
{
    struct nnpfs_channel *chan = node->chan;

    ASSERT(node);

    nnpfs_debug(XDEBNODE, "nnpfs_free_node(%x %x %x %x)\n", node->handle.a, node->handle.b, node->handle.c, node->handle.d);

    if (NNPFS_TOKEN_GOT(node, NNPFS_DATA_MASK))
	nnpfs_close_data_handle (node);

    /*
     * Remove from list
     */

    XLIST_REMOVE(&chan->nodes, node, lru_entry);

    /* XXX return values */
    ExDeleteResourceLite(&node->MainResource);
    ExDeleteResourceLite(&node->PagingIoResource);
    node->refcount = -17;

    if (! NNPFS_TESTFLAGS(node->flags, NNPFS_FCB_NOT_FROM_ZONE)) {
	ExAcquireFastMutex(&chan->ZoneAllocationMutex);
	
	ExFreeToZone(&chan->NodeZoneHeader, node);

	ExReleaseFastMutex(&chan->ZoneAllocationMutex);
    } else {
	ExFreePool(node);
    }

    return;
}


/*
 * we should own MainResource exclusively here
 */

void
nnpfs_close_data_handle (struct nnpfs_node *node)
{
    ASSERT (DATA_FROM_XNODE(node));
    ASSERT (ExIsResourceAcquiredExclusiveLite(&node->MainResource));
    
    nnpfs_debug(XDEBNODE, 
		"nnpfs_close_data_handle(%X): %d %d %d %d\n", node,
		node->handle.a, node->handle.b,
		node->handle.c, node->handle.d);

    ObDereferenceObject(node->backfile);
    ZwClose (DATA_FROM_XNODE(node));
    DATA_FROM_XNODE(node) = NULL;
    node->backfile = NULL;
}

/*
 *
 */

int
nnpfs_fhlookup (struct nnpfs_fhandle_t *fh, HANDLE *cache_node)
{
    return STATUS_SUCCESS;
}

/*
 *
 */

int
nnpfs_fhget (const char *path, struct nnpfs_fhandle_t *fh)
{
    return STATUS_SUCCESS;
}

/*
 * open the specified cache file
 * we should own MainResource exclusively here
 */

int
nnpfs_open_file (nnpfs_node *node, const char *fname, HANDLE RelatedFile, 
		 int Disposition, int CreateOptions)
{
    char buf[1024]; /* XXX */
    ANSI_STRING fname_a;
    UNICODE_STRING fname_u;
    OBJECT_ATTRIBUTES objattr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    OBJECT_HANDLE_INFORMATION obj_info;
    int status;

    nnpfs_debug (XDEBNODE, "nnpfs_open_file: %x (%s), %x, %d, %d\n",
		 fname, fname ? fname : "", RelatedFile, 
		 Disposition, CreateOptions);
	
    ASSERT (ExIsResourceAcquiredExclusiveLite(&node->MainResource));

    strcpy(buf, "\\??\\");
    strncat(buf, fname, 1024 - 4 - 1);
    RtlInitAnsiString(&fname_a, buf); /* no need to free */
    status = RtlAnsiStringToUnicodeString(&fname_u, &fname_a, TRUE);
    if (NT_SUCCESS(status)) {
	InitializeObjectAttributes(&objattr, &fname_u,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL, NULL);
	status = ZwOpenFile(&handle, FILE_ALL_ACCESS & (~SYNCHRONIZE),
			    &objattr, &iosb,
			    FILE_SHARE_READ|FILE_SHARE_WRITE, CreateOptions);
    }
    if (NT_SUCCESS(status)) {
	FILE_OBJECT *file;
	DATA_FROM_XNODE(node) = handle;
	ObReferenceObjectByHandle(handle, FILE_ALL_ACCESS & (~SYNCHRONIZE),
				  NULL, KernelMode, &file, NULL);
	ASSERT(file);

	node->backfile = file;
    } else {
	nnpfs_debug (XDEBNODE, "nnpfs_open_file: create->%x\n", status);
    }
    RtlFreeUnicodeString(&fname_u);
    return status;
}

/*
 * open the specified cache file using an open handle
 * we should own MainResource exclusively
 */

int
nnpfs_open_fh (nnpfs_node *node, nnpfs_cache_handle *handle)
{
    HANDLE fh;
    FILE_OBJECT *file;
    nnpfs_debug (XDEBNODE, "nnpfs_open_fh\n");
	
    ASSERT (ExIsResourceAcquiredExclusiveLite(&node->MainResource));

    RtlCopyMemory (&fh, handle, sizeof(fh));

    DATA_FROM_XNODE(node) = fh;
    ObReferenceObjectByHandle(fh, FILE_ALL_ACCESS & (~SYNCHRONIZE),
			      NULL, KernelMode, &file, NULL);
    ASSERT(file);
    
    node->backfile = file;

    return STATUS_SUCCESS;
}

/*
 *
 */

void
vattr2nnpfs_attr (struct nnpfs_node *node, struct nnpfs_attr *xa)
{
    bzero(xa, sizeof(*xa));
#if 0
    if (va->va_mode != (mode_t)VNOVAL)
	XA_SET_MODE(xa, va->va_mode);
    if (va->va_nlink != VNOVAL)
	XA_SET_NLINK(xa, va->va_nlink);
    if (va->va_size != VNOVAL)
	XA_SET_SIZE(xa, va->va_size);
    if (va->va_uid != VNOVAL)
	XA_SET_UID(xa, va->va_uid);
    if (va->va_gid != VNOVAL)
	XA_SET_GID(xa, va->va_gid);
    if (va->va_atime.tv_sec != VNOVAL)
	XA_SET_ATIME(xa, va->va_atime.tv_sec);
    if (va->va_mtime.tv_sec != VNOVAL)
	XA_SET_MTIME(xa, va->va_mtime.tv_sec);
    if (va->va_ctime.tv_sec != VNOVAL)
	XA_SET_CTIME(xa, va->va_ctime.tv_sec);
    if (va->va_fileid != VNOVAL)
	XA_SET_FILEID(xa, va->va_fileid);
    switch (va->va_type) {
    case VNON:
	xa->xa_type = NNPFS_FILE_NON;
	break;
    case VREG:
	xa->xa_type = NNPFS_FILE_REG;
	break;
    case VDIR:
	xa->xa_type = NNPFS_FILE_DIR;
	break;
    case VBLK:
	xa->xa_type = NNPFS_FILE_BLK;
	break;
    case VCHR:
	xa->xa_type = NNPFS_FILE_CHR;
	break;
    case VLNK:
	xa->xa_type = NNPFS_FILE_LNK;
	break;
    case VSOCK:
	xa->xa_type = NNPFS_FILE_SOCK;
	break;
    case VFIFO:
	xa->xa_type = NNPFS_FILE_FIFO;
	break;
    case VBAD:
	xa->xa_type = NNPFS_FILE_BAD;
	break;
    default:
	panic("nnpfs_attr2attr: bad value");
    }
#endif
}

#define SET_TIMEVAL(X, S, N) \
	do { (X)->tv_sec = (S); (X)->tv_nsec = (N); } while(0)

void
nnpfs_attr2vattr(const struct nnpfs_attr *xa, struct nnpfs_node *node)
{
    /* XXX convert to win-ish format? */
    node->attr = *xa;
    node->fcb.AllocationSize.QuadPart = xa->xa_size;
    node->fcb.FileSize.QuadPart = xa->xa_size;
}

/*
 *
 */

int
nnpfs_get_root (struct nnpfs_channel *chan)
{
#ifdef ROOTFAKE 
    struct nnpfs_message_installroot msg;
#else
    struct nnpfs_message_getroot msg;
#endif
    int error;

    do {
	if (chan->root != NULL)
	    return 0;

	msg.header.opcode = NNPFS_MSG_GETROOT;
	msg.cred.uid = 0; /* XXX */
	msg.cred.pag = 0; /* XXX */
	nnpfs_debug (XDEBNODE, "nnpfs_get_root: rpc\n");
	error = nnpfs_message_rpc(chan, &msg.header, sizeof(msg));
	nnpfs_debug (XDEBNODE, "nnpfs_get_root: error = %d\n", error);
	if (error == 0)
	    error = ((struct nnpfs_message_wakeup *) & msg)->error;
    } while (error == 0);
    return error;
}
