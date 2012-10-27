/*
 * Copyright (c) 1999, 2000, 2002-2003 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_misc.c,v 1.9 2003/06/26 20:09:11 tol Exp $ */

#include <nnpfs_locl.h>

/*
 * Allocate a ccb structure for either a zone or non-paged pool.
 * Set approprivate flags.
 */

nnpfs_ccb *
nnpfs_get_ccb (void)
{
    nnpfs_ccb *ccb = NULL;
    BOOLEAN zonep = TRUE;
    
    ExAcquireFastMutex(&NNPFSGlobalData.ZoneAllocationMutex);

    if (!ExIsFullZone(&NNPFSGlobalData.CCBZoneHeader)) {
	ccb = ExAllocateFromZone (&NNPFSGlobalData.CCBZoneHeader);
	ExReleaseFastMutex(&NNPFSGlobalData.ZoneAllocationMutex);
    } else {
	ExReleaseFastMutex(&NNPFSGlobalData.ZoneAllocationMutex);
	ccb = nnpfs_alloc(sizeof(*ccb), 'mgc1');
	zonep = FALSE;
    }

    if (ccb == NULL) /* XXX */
	NNPFSPanic (STATUS_INSUFFICIENT_RESOURCES, sizeof(*ccb), 0);
    
    RtlZeroMemory(ccb, sizeof(*ccb));
    
    if (!zonep)
	NNPFS_SETFLAGS(ccb->flags, NNPFS_CCB_NOT_FROM_ZONE);
    
    return ccb;
}

/*
 * Free ccb structure
 */

void
nnpfs_release_ccb (nnpfs_ccb *ccb)
{
    ASSERT(ccb);

    if (ccb->SearchPattern.Buffer != NULL)
	nnpfs_free(ccb->SearchPattern.Buffer, ccb->SearchPattern.MaximumLength);

    if (! NNPFS_TESTFLAGS(ccb->flags, NNPFS_CCB_NOT_FROM_ZONE)) {
	ExAcquireFastMutex(&NNPFSGlobalData.ZoneAllocationMutex);
	
	ExFreeToZone(&NNPFSGlobalData.CCBZoneHeader, ccb);

	ExReleaseFastMutex(&NNPFSGlobalData.ZoneAllocationMutex);
    } else {
	nnpfs_free(ccb, sizeof(*ccb));
    }
}

/*
 *
 */

struct nnpfs_link *
nnpfs_alloc_link (struct nnpfs_channel *chan, int flags, ULONG tag)
{
    struct nnpfs_link *link = NULL;
    BOOLEAN zonep = TRUE;
    
    ExAcquireFastMutex(&chan->ZoneAllocationMutex);

    if (!ExIsFullZone(&chan->LinkZoneHeader)) {
	link = ExAllocateFromZone (&chan->LinkZoneHeader);
	ExReleaseFastMutex(&chan->ZoneAllocationMutex);
    } else {
	ExReleaseFastMutex(&chan->ZoneAllocationMutex);
	link = nnpfs_alloc(sizeof(*link), tag);
	zonep = FALSE;
    }

    if (link == NULL) /* XXX */
	NNPFSPanic (STATUS_INSUFFICIENT_RESOURCES, sizeof(*link), 0);
    
    RtlZeroMemory(link, sizeof(*link));
    
    NNPFS_SETFLAGS(link->flags, flags);
    if (!zonep)
	NNPFS_SETFLAGS(link->flags, NNPFS_LINK_NOT_FROM_ZONE);
    
    return link;
}

/*
 *
 */

void
nnpfs_free_link (struct nnpfs_channel *chan, struct nnpfs_link *link)
{
    ASSERT(link && chan);

    nnpfs_debug(XDEBMEM, "nnpfs_free_link: %X\n", link);

    if (! NNPFS_TESTFLAGS(link->flags, NNPFS_LINK_NOT_FROM_ZONE)) {
	ExAcquireFastMutex(&chan->ZoneAllocationMutex);
	
	ExFreeToZone(&chan->LinkZoneHeader, link);

	ExReleaseFastMutex(&chan->ZoneAllocationMutex);
    } else {
	nnpfs_free(link, sizeof(*link));
    }
}

/*
 *
 */

void *
nnpfs_alloc (size_t size, ULONG tag)
{
    void *p = ExAllocatePoolWithTag (NonPagedPool, size, tag);
    if (p == NULL)
	nnpfs_debug(XDEBMEM, "nnpfs_alloc: failed for tag %X\n", tag);
    return p;
}

/*
 *
 */

void
nnpfs_free (void *ptr, size_t size)
{
    ExFreePool (ptr);
    nnpfs_debug(XDEBMEM, "nnpfs_free: %X, size %x\n", ptr, size);
}

size_t
strlcpy (char *dst, const char *src, size_t dst_sz)
{
    size_t n;
    char *p;

    for (p = dst, n = 0;
	 n + 1 < dst_sz && *src != '\0';
	 ++p, ++src, ++n)
	*p = *src;
    *p = '\0';
    if (*src == '\0')
	return n;
    else
	return n + strlen (src);
}

/*
 * Retrieve a usable adress from the irp
 */

void *
nnpfs_get_buffer(PIRP irp)
{
    ASSERT(irp);

    if (irp->MdlAddress)
        return MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
    else
        return irp->UserBuffer; /* XXX check */
}
