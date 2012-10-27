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

/* $Id: blocks.h,v 1.2 2006/10/24 16:32:33 tol Exp $ */

#ifndef _BLOCKS_H_
#define _BLOCKS_H_

#include <nnpfs/nnpfs_blocks.h>
#include <fcache.h>

struct block {
    uint64_t offset;
    struct FCacheEntry *node;
    
    Listitem *lru_le;	     /* block lru */
    Listitem *block_le;	     /* node's block list, make it a tree?  */
    
    struct {
	unsigned kernelp : 1;
	unsigned busy : 1;
    } flags;
};
    
typedef enum {
    BLOCK_NONE   = 0x0,
    BLOCK_GOT    = 0x01,
    BLOCK_BUSY   = 0x02
} BlockState;

typedef void (*block_callback_t)(struct block *block, void *data);

/*
 * get block offset of data offset 'off'
 */

static inline uint64_t
block_offset(uint64_t off) {
    return off - (off & (fcache_getblocksize() - 1));
}

/*
 * get next block offset after data offset 'off'
 *
 * This actually gives the same block if it is aligned on a block
 * boundary.  Current users depend on that.
 */

static inline uint64_t
block_next_offset(uint64_t off) {
    return block_offset(off + fcache_getblocksize() - 1);
}

/*
 * get last block offset for file length 'len'
 * Result may not be what is expected for zero.
 */

static inline uint64_t
block_end_offset(uint64_t len) {
    return len ? block_offset(len - 1) : len;
}

struct block *
block_get(FCacheEntry *node, uint64_t offset);

struct block *
block_add(FCacheEntry *node, uint64_t offset);

void
block_foreach(FCacheEntry *node,
	      block_callback_t fun,
	      void *data);

void
block_free(struct block *block);

BlockState
block_any(FCacheEntry *node);

Bool
block_emptyp(FCacheEntry *node);

#endif /* _BLOCKS_H_ */
