/*
 * Copyright (c) 2005-2006, Stockholms Universitet
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
 * 3. Neither the name of the university nor the names of its contributors
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

/* $Id: nnpfs_blocks.c,v 1.2 2006/10/24 16:33:25 tol Exp $ */

#include <dummer.h>

/*
 * return true if block is in cache
 */

int
nnpfs_block_have_p(struct nnpfs_cache_handle *handle, uint64_t offset)
{
    uint32_t index = nnpfs_block_index(offset);
    uint32_t maskno = nnpfs_block_masknumber(index);

    assert(nnpfs_offset(offset) == offset);

    if (handle->nmasks == 0)
	return 0;

    if (maskno >= handle->nmasks)
	return 0;

    if (handle->nmasks == 1)
	return (handle->masks.first & nnpfs_block_mask(index));

    return (handle->masks.list[maskno] & nnpfs_block_mask(index));
}

/*
 * mark block at offset as present in cache
 */

void
nnpfs_block_set_have(struct nnpfs_cache_handle *handle, uint64_t offset, int val)
{
    uint32_t index = nnpfs_block_index(offset);
    uint32_t maskno = nnpfs_block_masknumber(index);
    uint32_t mask = nnpfs_block_mask(index);
    uint32_t *slot;

    assert(nnpfs_offset(offset) == offset);

    if (maskno == 0 && handle->nmasks <= 1) {
	handle->nmasks = 1;
	slot = &handle->masks.first;
    } else {
	if (maskno >= handle->nmasks) {
	    int n = maskno + NNPFS_NMASKS - (maskno % NNPFS_NMASKS);
	    int size = n * sizeof(uint32_t);
	    uint32_t *new;
	    uint32_t first;
	    
	    if (handle->nmasks == 1) {
		first = handle->masks.first;
		handle->masks.list = NULL;
	    }
		
	    new = realloc(handle->masks.list, size);
	    assert(new);
	    
	    if (handle->nmasks == 1)
		new[0] = first;
	    
	    memset(&new[handle->nmasks], 0,
		   (n - handle->nmasks) * sizeof(uint32_t));
	    handle->nmasks = n;
	    handle->masks.list = new;
	}
	slot = &handle->masks.list[maskno];
    }
    
    if (val)
	*slot |= mask;
    else
	*slot &= ~mask;
}

static void
nnpfs_block_foreach_int(struct nnpfs_cache_handle *handle,
			nnpfs_block_callback_t fun,
			void *data, 
			uint64_t base_offset,
			int32_t mask)
{
    uint32_t tmp_mask = 1;
    int i;

    if (!mask)
	return;

    for (i = 0; i < 32; i++) {
	if (mask & tmp_mask) {
	    fun(handle, base_offset + i * nnpfs_blocksize, data);
	    mask -= tmp_mask;
	    if (!mask)
		return;
	}

	tmp_mask = tmp_mask << 1;
    }
}

/*
 * call callback for every block present in cache
 */

void
nnpfs_block_foreach(struct nnpfs_cache_handle *handle,
		    nnpfs_block_callback_t fun,
		    void *data)
{
    int i;
    
    if (handle->nmasks == 0)
	return;

    if (handle->nmasks == 1) {
	nnpfs_block_foreach_int(handle, fun, data, 0, handle->masks.first);
	return;
    }

    for (i = 0; i < handle->nmasks; i++)
	nnpfs_block_foreach_int(handle, fun, data, i * 32 * nnpfs_blocksize, handle->masks.list[i]);
}

/*
 * free all handle internal resources 
 */

void
nnpfs_block_free(struct nnpfs_cache_handle *handle)
{
    if (handle->nmasks > 1) {
	free(handle->masks.list);
	handle->masks.list = NULL;
    } else {
	handle->masks.first = 0;
    }

    handle->nmasks = 0;
}

/*
 * return true if we have no data
 */

int
nnpfs_block_empty(struct nnpfs_cache_handle *handle)
{
    int i;

    if (handle->nmasks == 0)
	return 1;

    if (handle->nmasks == 1) {
	if (handle->masks.first == 0)
	    return 1;
	return 0;
    }
    
    for (i = 0; i < handle->nmasks; i++)
	if (handle->masks.list[i] != 0)
	    return 0;

    return 1;
}
