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

/* $Id: blocks.c,v 1.2 2006/10/24 16:32:32 tol Exp $ */

#include <arla_local.h>

/*
 * return pointer to block if it is in cache, else NULL
 */

struct block *
block_get(FCacheEntry *node, uint64_t offset)
{
    struct block *entry = NULL;
    Listitem *item;

    assert(block_offset(offset) == offset);

    for (item = listhead(node->blocks);
	 item;
	 item = listnext(node->blocks, item)) {
	entry = (struct block *)listdata(item);

	if (entry->offset == offset) {
	    fcache_block_lru(entry);
	    return entry;
	}
    }

    return NULL;
}

/*
 * add a block
 *
 * Caller needs to link the block into some lru.
 */

struct block *
block_add(FCacheEntry *node, uint64_t offset)
{
    struct block *new;

#ifdef BLOCKS_PARANOIA
    struct block *old = block_get(node, offset);
    assert(!old);
#endif
    
    assert(block_offset(offset) == offset);

    new = malloc(sizeof(*new));
    assert(new);

    new->offset = offset;
    new->node = node;
    new->flags.kernelp = FALSE;
    new->flags.busy    = FALSE;

    new->lru_le = NULL;
    new->block_le = listaddhead(node->blocks, new);

    return new;
}

/*
 * call callback for every block present in cache
 */

void
block_foreach(FCacheEntry *node,
	      block_callback_t fun,
	      void *data)
{
    struct block *entry;
    Listitem *item, *prev;

    for (item = listtail(node->blocks);
	 item;
	 item = prev) {
	prev = listprev(node->blocks, item);
	entry = (struct block *)listdata(item);
	
	fun(entry, data);
    }
}

/*
 * free all block internal resources
 *
 * Assumes the node is properly locked and that data is taken care of.
 */

void
block_free(struct block *block)
{
    listdel(block->node->blocks, block->block_le);
    free(block);
}

/*
 * Return aggregate status for the node.
 *
 * If we only have busy blocks, return BLOCK_BUSY.   XXX reverse this?
 */

BlockState
block_any(FCacheEntry *node)
{
    struct block *entry;
    Listitem *item, *prev;

    if (listemptyp(node->blocks))
	return BLOCK_NONE;
    
    for (item = listtail(node->blocks);
	 item;
	 item = prev) {
	prev = listprev(node->blocks, item);
	entry = (struct block *)listdata(item);
	
	if (!entry->flags.busy)
	    return BLOCK_GOT;
    }
    
    return BLOCK_BUSY;
}

/*
 * Return TRUE if we have no data. 
 */

Bool
block_emptyp(FCacheEntry *node)
{
    if (listemptyp(node->blocks))
	return TRUE;
    return FALSE;
}

