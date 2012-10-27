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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

/* $Id: nnpfs_blocks_locl.h,v 1.2 2006/10/24 16:33:44 tol Exp $ */

typedef struct nnpfs_cache_handle {
    /* use bitmasks. not good when one needs one 'handle' per block */
    uint32_t nmasks;
    union {
	uint32_t first; /* nmasks == 1 */
	uint32_t *list; /* nmasks > 1 */
    } masks;
} nnpfs_cache_handle;

#define NNPFS_NMASKS	16


struct nnpfs_node; /* fwd */

typedef void (*nnpfs_block_callback_t)(struct nnpfs_node *node,
				       uint64_t offset,
				       void *data);

#define nnpfs_block_index(offset) (offset >> nnpfs_blocksizebits)
#define nnpfs_block_masknumber(index) (index / 32)
#define nnpfs_block_mask(index) (1UL << (index % 32))


/*
 * get block offset of data offset 'off'
 */

static inline uint64_t
nnpfs_offset(uint64_t off) {
    return off - (off & (nnpfs_blocksize - 1));
}

/*
 * get next block offset after data offset 'off'
 */

static inline uint64_t
nnpfs_next_offset(uint64_t off) {
    return nnpfs_offset(off + nnpfs_blocksize - 1);
}

/*
 * get last block offset for file length 'len'
 * Result may not be what is expected for zero.
 */

static inline uint64_t
nnpfs_end_offset(uint64_t len) {
    return len ? nnpfs_offset(len - 1) : len;
}

int
nnpfs_block_have_p(struct nnpfs_node *node, uint64_t offset);

int
nnpfs_block_setvalid(struct nnpfs_node *node, uint64_t offset);

void
nnpfs_block_setinvalid(struct nnpfs_node *node, uint64_t offset);

void
nnpfs_block_foreach(struct nnpfs_node *node,
		    nnpfs_block_callback_t fun,
		    void *data);

void
nnpfs_block_truncate(struct nnpfs_node *node, uint64_t size);

void
nnpfs_block_free_all(struct nnpfs_node *node);

int
nnpfs_block_empty(struct nnpfs_node *node);

int
nnpfs_block_create(struct nnpfs_node *node, uint64_t offset);

int
nnpfs_block_open(struct nnpfs_node *node, uint64_t offset,
		 int flags, struct file **file);

