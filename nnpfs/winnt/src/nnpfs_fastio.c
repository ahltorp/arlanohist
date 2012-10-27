/*
 * Copyright (c) 2002, 2003 Stockholms Universitet
 * (Stockholm University, Stockholm Sweden)
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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: nnpfs_fastio.c,v 1.3 2003/07/01 14:12:14 tol Exp $ */

#include <nnpfs_locl.h>


BOOLEAN
nnpfs_fastio_possible(FILE_OBJECT *file,
		      LARGE_INTEGER *offset,
		      ULONG length,
		      BOOLEAN wait,
		      ULONG key,
		      BOOLEAN readp,
		      IO_STATUS_BLOCK *iostatus,
		      DEVICE_OBJECT *device) 
{
    ASSERT(file);
    ASSERT(file->FsContext);
    nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_possible(%X)\n", file->FsContext);
    return FALSE;
}

BOOLEAN
nnpfs_fastio_initmap(FILE_OBJECT *file, nnpfs_node *node)
{
    ASSERT(file->PrivateCacheMap == (void *)1);
    
    /* XXX acquire exclusive? */
    file->PrivateCacheMap = NULL;
    CcInitializeCacheMap(file, (CC_FILE_SIZES *)&node->fcb.AllocationSize,
			 FALSE, &node->chan->cc_callbacks, node);
    return TRUE; /* XXX false if failed to acquire resource? */
}

BOOLEAN
nnpfs_fastio_read(FILE_OBJECT *file,
		  LARGE_INTEGER *offset,
		  ULONG length,
		  BOOLEAN wait,
		  ULONG key,
		  void *buffer,
		  IO_STATUS_BLOCK *iostatus,
		  DEVICE_OBJECT *device)
{
    BOOLEAN ret;
    nnpfs_ccb *ccb;
    nnpfs_node *node;
    char *buf = (char *)buffer;
    NTSTATUS status = STATUS_SUCCESS;

    ASSERT(file);
    
    node = file->FsContext;
    ccb = file->FsContext2;
    ASSERT(node);
    ASSERT(ccb);

    nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_read(%X): fo %x off %x, len %x\n",
		node, file, offset->LowPart, length);

    FsRtlEnterFileSystem();
    if (!ExAcquireResourceSharedLite(&node->MainResource, wait)) {
	FsRtlExitFileSystem();
	return FALSE;
    }

    if (file->PrivateCacheMap == (void *)1)
	nnpfs_fastio_initmap(file, node);

    if (node->attr.xa_type == NNPFS_FILE_DIR) {
	status = STATUS_INVALID_DEVICE_REQUEST;
    } else if (offset->HighPart != 0 
	       || offset->LowPart >= node->attr.xa_size) {
	status = STATUS_END_OF_FILE;
    } else {
	status = nnpfs_data_valid(node, ccb->cred, NNPFS_DATA_R,
				  offset->LowPart + length);
    }
    
    if (NT_SUCCESS(status)) {
	unsigned long len;
	BOOLEAN ret;

	ASSERT(buf);

	if (offset->LowPart + length > node->attr.xa_size)
	    len = node->attr.xa_size - offset->LowPart;
	else
	    len = length;
	
	ret = CcCopyRead(file, offset, len, wait, buffer, iostatus);
	if (!ret) {
	    if (NT_SUCCESS(iostatus->Status))
		status = STATUS_UNSUCCESSFUL;
	    
	    nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_read: CcCopyRead (%X)!\n", 
			iostatus->Status);
	    FsRtlExitFileSystem();
	    return ret;
	}

	if (NT_SUCCESS(status))
	    status = iostatus->Status;

	if (NT_SUCCESS(status))	
	    file->CurrentByteOffset.QuadPart =
		offset->QuadPart + iostatus->Information;
    } else {
	nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_read: no data (%X)!\n", status);
    }

    ExReleaseResourceLite(&node->MainResource);
    FsRtlExitFileSystem();

    if (!NT_SUCCESS(status)) {
	iostatus->Status = status;
	iostatus->Information = 0;
    }

    if (NT_SUCCESS(iostatus->Status))
	nnpfs_debug (XDEBVNOPS, "nnpfs_fastio_read: read %d bytes (%X, %X)\n",
		     iostatus->Information, iostatus->Status, status);
    else if (status == STATUS_END_OF_FILE)
	nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_read: failed (%X)!\n",
		    iostatus->Status);
    else
	nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_read: failed (%X)!\n",
		    iostatus->Status);

    /*
      acquire nnpfs/node resources
      check offset (do we have the data installed?), tokens. waitp?
      
      set up caching? (do we need backfile resources for this?)

      FsRtlCopyRead();

      release nnpfs/node resources      
    */

    return TRUE;
}


BOOLEAN
nnpfs_fastio_write(FILE_OBJECT *file,
		   LARGE_INTEGER *offset,
		   ULONG length,
		   BOOLEAN wait,
		   ULONG key,
		   void *buffer,
		   IO_STATUS_BLOCK *iostatus,
		   DEVICE_OBJECT *device)
{
    nnpfs_ccb *ccb;
    nnpfs_node *node;
    char *buf = (char *)buffer;
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER newsize, oldsize;
    ASSERT(file);

    node = file->FsContext;
    ccb = file->FsContext2;
    ASSERT(node);
    ASSERT(ccb);

    nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_write(%X): fo %x off %x, len %x\n",
		node, file, offset->LowPart, length);

    /*
      acquire nnpfs/node resources
      check offset (do we have the data installed?), tokens. waitp?

      set up caching? (do we need backfile resources for this?)

      FsRtlCopyWrite();

      release nnpfs/node resources      
    */

    if (file->PrivateCacheMap == (void *)1)
	nnpfs_fastio_initmap(file, node);

    if (node->attr.xa_type == NNPFS_FILE_DIR) {
	status = STATUS_INVALID_DEVICE_REQUEST;
    } else {
	ASSERT (offset->HighPart == 0);
	status = nnpfs_data_valid(node, ccb->cred, NNPFS_DATA_W,
				  node->attr.xa_size);
    }
    
    newsize.QuadPart = offset->LowPart + length;
    if (newsize.HighPart != 0) {
	iostatus->Status = STATUS_END_OF_FILE;
	return FALSE;
    }

    oldsize.QuadPart = node->attr.xa_size;
    if (newsize.LowPart > oldsize.LowPart) {
	/* we're extending the file size */
	IO_STATUS_BLOCK iosb;
	FILE_END_OF_FILE_INFORMATION info;

	info.EndOfFile = newsize;
	status = ZwSetInformationFile(DATA_FROM_XNODE(node), &iosb, &info,
				      sizeof(info), FileEndOfFileInformation);
	if (NT_SUCCESS(status)) {
	    /* perhaps one should call CcZeroData() here, but the
	     * effects look so disgusting that I don't do
	     * that. Backing file will supply zeroes anyway, perhaps
	     * less efficient?
	     */

	    /* XXX how do we handle failures? failed writes? */
	    if (newsize.LowPart > oldsize.LowPart) {
		unsigned long size = newsize.LowPart;
		node->fcb.AllocationSize.LowPart = size;
		node->fcb.FileSize.LowPart = size;
	    }
	    CcSetFileSizes(file, (CC_FILE_SIZES *)&node->fcb.AllocationSize);
	}
    }
    

    if (NT_SUCCESS(status)) {
	/* XXX try - catch! */
	BOOLEAN ret = CcCopyWrite(file, offset, length, wait, buf);
	if (!ret) {
	    nnpfs_debug(XDEBVNOPS,
			"nnpfs_fastio_write: CcCopyWrite->false\n");
	    if (newsize.LowPart > oldsize.LowPart) {
		unsigned long size = oldsize.LowPart;
		node->fcb.AllocationSize.LowPart = size;
		node->fcb.FileSize.LowPart = size;
	    }
	    CcSetFileSizes(file, (CC_FILE_SIZES *)&node->fcb.AllocationSize);

	    return ret;
	}

	/* success */
	file->CurrentByteOffset.QuadPart = offset->QuadPart + length;
	iostatus->Information = length;

	node->flags |= NNPFS_DATA_DIRTY;
	ccb->flags |= NNPFS_CCB_MODIFIED;
	node->flags &= ~NNPFS_STALE; /* we might be making it valid */
	if (newsize.LowPart > oldsize.LowPart) {
	    unsigned long size = newsize.LowPart;
	    node->attr.xa_size = size;
	    node->offset = size;
	}
    } else {
	nnpfs_debug(XDEBVNOPS, "nnpfs_fastio_write: no data (%X)!\n", status);
    }
    
    iostatus->Status = status;
    if (NT_SUCCESS(status)) {
	iostatus->Information = length;
	nnpfs_debug (XDEBVNOPS,
		     "nnpfs_fastio_write: wrote %d bytes\n", length);
    } else {
	iostatus->Information = 0;
	nnpfs_debug(XDEBVNOPS,
		    "nnpfs_fastio_write: failed (%X)\n", status);
    }

    return TRUE;
}

void
nnpfs_createsec_acq(FILE_OBJECT *file)
{
    nnpfs_ccb		*ccb;
    struct nnpfs_node	*node;
    
    ASSERT (file);

    ccb = (nnpfs_ccb *) file->FsContext2;
    ASSERT (ccb);

    node = ccb->node;
    ASSERT(node);

    nnpfs_debug(XDEBVNOPS, "nnpfs_createsec_acq(%X)\n", node);

    if (node->fcb.Flags & FSRTL_FLAG_USER_MAPPED_FILE) {
	if (node->flags & NNPFS_FCB_EXECUTE)
	    /* might be exec-mapped, better flush cached data */
	    /* hope for the best */
	    CcFlushCache(file->SectionObjectPointer, NULL, 0, NULL); 

	if (file->WriteAccess) {
	    /* 
	     * we store thread credentials in node to be able to flush
	     * changes in this thread's name when the mmap is closed.
	     */
	
	    ccb->flags |= NNPFS_CCB_MODIFIED;
	    node->flags |= NNPFS_FCB_WRITEMAPPED;
	    if (ccb->cred != NULL)
		node->writemapper = *ccb->cred;
	}
    }

    FsRtlEnterFileSystem();
    ExAcquireResourceExclusiveLite(&node->MainResource, TRUE);
    ExAcquireResourceExclusiveLite(&node->PagingIoResource, TRUE);
    /* FsRtlAcquireFileExclusive(node->backfile); */
    FsRtlExitFileSystem();

    /*
      call backfile->fastioacquire() ?
      
      acquire any nnpfs/node resources?
    */
}

void
nnpfs_createsec_rel(FILE_OBJECT *file)
{
    struct nnpfs_node	*node;
    
    ASSERT (file);

    node = (nnpfs_node *) file->FsContext;
    ASSERT(node);

    nnpfs_debug(XDEBVNOPS, "nnpfs_createsec_rel(%X)\n", node);

    if (node->fcb.Flags & FSRTL_FLAG_USER_MAPPED_FILE)
	nnpfs_debug(XDEBVNOPS,
		    "nnpfs_createsec_rel(%X): MAPPED is set\n", node);

    /* FsRtlReleaseFile(node->backfile); */
    ExReleaseResourceLite(&node->PagingIoResource);
    ExReleaseResourceLite(&node->MainResource);

    /*
      release any nnpfs/node resources?

      call backfile->fastio_release() ?
    */
}

NTSTATUS
nnpfs_modwrite_acq (FILE_OBJECT *file,
		    LARGE_INTEGER *end,
		    ERESOURCE **release_resource,
		    DEVICE_OBJECT *device)
{
    nnpfs_node *node;
    NTSTATUS status = STATUS_SUCCESS;
    ASSERT(file);
    
    node= file->FsContext;
    ASSERT(node);

    nnpfs_debug(XDEBVNOPS, "nnpfs_modwrite_acq(%X) end %x\n",
		node, end->LowPart);

    *release_resource = (ERESOURCE *)4711;

    return status;
}

NTSTATUS
nnpfs_modwrite_rel (FILE_OBJECT *file,
		    ERESOURCE *release_resource,
		    DEVICE_OBJECT *device)
{
    nnpfs_node *node;
    NTSTATUS status = STATUS_SUCCESS;
    ASSERT(file);
    
    node= file->FsContext;
    ASSERT(node);
    ASSERT(release_resource == (ERESOURCE *)4711);

    nnpfs_debug(XDEBVNOPS, "nnpfs_modwrite_rel(%X)\n", node);

    if (TRUE) { /* if (node->writemapper is valid) { */
	nnpfs_debug(XDEBVNOPS,
		    "nnpfs_modwrite_rel(%X): syncing\n", node);
	node->flags &= ~NNPFS_STALE; /* XXX ??? we might be making it valid */
	status = nnpfs_fsync(node, &node->writemapper, NNPFS_WRITE);
    } else {
	nnpfs_debug(XDEBVNOPS,
		    "nnpfs_modwrite_rel(%X): wasn't write mapped!\n", node);
    }
    return status;
}

BOOLEAN
nnpfs_lazywrite_acq(void *context, BOOLEAN waitp)
{
    nnpfs_node *node = context;
    ETHREAD *current_thread = PsGetCurrentThread();

    nnpfs_debug(XDEBVNOPS, "nnpfs_lazywrite_acq(%X) wait %x\n",
		node, waitp);

    if (!ExAcquireResourceSharedLite(&node->PagingIoResource, waitp))
        return FALSE;

    if (node->lazy_writer == NULL)
	node->lazy_writer = current_thread;

    ASSERT(node->lazy_writer == current_thread);

    return TRUE;
}

void
nnpfs_lazywrite_rel(void *context) 
{
    nnpfs_node *node = context;
    nnpfs_debug(XDEBVNOPS, "nnpfs_lazywrite_rel(%X)\n", node);

    ASSERT(node->lazy_writer == PsGetCurrentThread());
    node->lazy_writer = NULL;

    ExReleaseResourceLite(&node->PagingIoResource);
}

BOOLEAN
nnpfs_readahead_acq(void *context, BOOLEAN waitp)
{
    nnpfs_node *node = context;
    nnpfs_debug(XDEBVNOPS, "nnpfs_readahead_acq(%X) wait %x\n",
		node, waitp);

    if (!ExAcquireResourceSharedLite(&node->MainResource, waitp))
        return FALSE;

    ASSERT(IoGetTopLevelIrp() == NULL);
    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);

    return TRUE;
}

void
nnpfs_readahead_rel(void *context) 
{
    nnpfs_node *node = context;
    nnpfs_debug(XDEBVNOPS, "nnpfs_readahead_rel(%X)\n", node);

    ASSERT(IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
    IoSetTopLevelIrp(NULL);

    ExReleaseResourceLite(&node->MainResource);

    return;
}
