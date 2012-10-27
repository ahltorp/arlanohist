/*
 * Copyright (c) 1995 - 2007 Kungliga Tekniska Högskolan
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

#include <config.h>

RCSID("$Id: abuf.c,v 1.4 2007/02/19 09:47:36 tol Exp $") ;

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include <unistd.h>

#include <fs_errors.h>

#include <roken.h>

#include <arla_local.h>

struct abuf_data {
    FCacheEntry *entry;
};

static int
abuf_flush(fbuf *f);

static inline FCacheEntry *
abuf_entry(fbuf *f)
{
    return ((struct abuf_data *)(f)->data)->entry;
}


#ifdef HAVE_MMAP

/*
 * mmap implementation for copy{rx2cache,cache2rx}. It's a little
 * complicated to support reading/writing on non page boundaries, plus
 * the block handling.
 */

#if !defined(MAP_FAILED)
#define MAP_FAILED ((void *)(-1))
#endif


/*
 * use mmap for transfer between rx call and cache files
 */

static int
cachetransfer(struct rx_call *call, FCacheEntry *entry,
	      off_t off, off_t len, Bool rxwritep)
{
    void *buf;
    int rw_len;
    int ret = 0;
    off_t adjust_off, adjust_len;
    size_t mmap_len, block_len;
    size_t size;
    int iosize = getpagesize();
    int fd = 0;

    if (len == 0)
	return ret;

    adjust_off = off % iosize;

    while (len > 0) {
	off_t real_off = off - adjust_off;
	off_t block_off = block_offset(real_off);
	off_t mmap_off = real_off - block_off;

	block_len = fcache_getblocksize() - mmap_off;
	size = len + adjust_off;
	if (size > block_len)
	    size = block_len;

	if (size % iosize)
	    adjust_len = iosize - (size % iosize);
	else 
	    adjust_len = 0;
	mmap_len = size + adjust_len;

	if (fd == 0 || mmap_off == 0) {
	    if (fd != 0)
		if (close(fd))
		    return errno;

	    fd = fcache_open_block(entry, block_off, !rxwritep);
	    if (fd < 0)
		return errno;
	    
	    if (!rxwritep) {
		/*
		 * always truncate to be on the "safe" side.
		 * We assume that we always get a full block or to EOF.
		 */

		ret = ftruncate(fd, mmap_len);
		if (ret)
		    break;
	    }
	}
	
	if (rxwritep)
	    buf = mmap(0, mmap_len, PROT_READ, MAP_PRIVATE, fd, mmap_off);
	else
	    buf = mmap(0, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmap_off);

	if (buf == (void *) MAP_FAILED) {
	    ret = errno;
	    break;
	}

	if (rxwritep)
	    rw_len = rx_Write(call, (char *)buf + adjust_off, size - adjust_off);
	else
	    rw_len = rx_Read(call, (char *)buf + adjust_off, size - adjust_off);

	if (rw_len != mmap_len - adjust_off)
	    ret = conv_to_arla_errno(rx_GetCallError(call));

	len -= rw_len;
	off += rw_len;
	adjust_off = 0;

	if (!rxwritep) {
	    if (msync(buf, mmap_len, MS_ASYNC))
		ret = errno;
	}
	if (munmap(buf, mmap_len))
	    ret = errno;

	if (ret)
	    break;
    }
    
    if (fd != 0)
	close(fd);
    
    return ret;
}
#else /* !HAVE_MMAP */

/*
 * use malloc for transfer between rx call and cache files
 */

static int
cachetransfer(struct rx_call *call, FCacheEntry *entry,
	      off_t off, off_t len, Bool rxwritep)
{
    void *buf;
    int ret = 0;
    size_t io_len, block_len;
    ssize_t nread, nwrite;
    u_long bufsize = 8192;
    int fd = 0;

    if (len == 0)
	return 0;

    buf = malloc(bufsize);
    if (buf == NULL)
	return ENOMEM;

    while (len > 0) {
	uint64_t block_off = block_offset(off);
	off_t buf_off = off - block_off;

	if (block_off == off) {
	    if ((fd != 0 && close(fd) != 0)
 		|| (fd = fcache_open_block(entry, block_off, !rxwritep)) < 0) {
		ret = errno;
		fd = 0;
		arla_debug_assert(0);
		break;
	    }
	}
	
	io_len = min(bufsize, len);
	block_len = fcache_getblocksize() - buf_off;

	if (io_len > block_len)
	    io_len = block_len;
	
	if (rxwritep) {
	    nread = pread(fd, buf, io_len, buf_off);
	    if (nread <= 0) {
		ret = errno;
		arla_debug_assert(0);
		break;
	    }

	    nwrite = rx_Write(call, buf, nread);
	    if (nwrite != nread) {
		ret = conv_to_arla_errno(rx_GetCallError(call));
		break;
	    }
	} else {
	    nread = rx_Read(call, buf, io_len);
	    if (nread != io_len) {
		ret = conv_to_arla_errno(rx_GetCallError(call));
		break;
	    }

	    nwrite = pwrite(fd, buf, nread, buf_off);
	    if (nwrite != nread) {
		ret = errno;
		arla_debug_assert(0);
		break;
	    }
	}
	len -= nread;
	off += nread;

	if (ret)
	    break;
    }
    
    if (fd != 0)
	close(fd);

    free(buf);

    return ret;
}
#endif /* !HAVE_MMAP */

/*
 * Copy from a RX_call to a cache node.
 * The area between offset and len + offset should be present in the cache.
 *
 * Returns 0 or error.
 */

int
copyrx2cache(struct rx_call *call, FCacheEntry *entry, off_t off, off_t len)
{
    return cachetransfer(call, entry, off, len, FALSE);
}

/*
 * Copy `len' bytes from `entry' to `call'.
 * Returns 0 or error.
 */

int
copycache2rx(FCacheEntry *entry, struct rx_call *call, off_t off, off_t len)
{
    return cachetransfer(call, entry, off, len, TRUE);
}

/*
 * actually do the malloc + read thing
 */

static int
abuf_populate(fbuf *f)
{
    uint64_t block_off = 0;
    ssize_t nread;
    off_t off = 0;
    char *buf;
    int fd = 0;
    size_t len = f->len;
    int ret = 0;

    buf = malloc(len);
    if (buf == NULL) {
	int ret = errno;
	arla_warnx(ADEBWARN, "abuf_populate: malloc(%lu) failed",
		   (unsigned long)len);
	arla_debug_assert(0);
	return ret;
    }

    while (len > 0) {
	block_off = block_offset(off);
	off_t r_len = min(len, fcache_getblocksize());

	if ((fd != 0 && close(fd) != 0)
	    || (fd = fcache_open_block(abuf_entry(f),
				       block_off, FALSE)) < 0) {
	    ret = errno;
	    fd = 0;
	    break;
	}
	
	nread = pread(fd, buf + off, r_len, off - block_off);
	if (nread != r_len) {
	    ret = errno;
	    break;
	}

	len -= nread;
	off += nread;
    }

    if (ret)
	free(buf);
    else
	f->buf = buf;

    if (fd)
	close(fd);

    return ret;
}


/*
 * infrastructure for truncate handling
 */

struct truncate_cb_data {
    off_t length;
    uint64_t last_off;
    uint64_t prev_last_off;
};

int
abuf_truncate_block(FCacheEntry *entry, uint64_t offset, uint64_t blocklen)
{
    int ret;
    int fd = fcache_open_block(entry, offset, TRUE);
    if (fd < 0) {
	ret = errno;
	arla_warnx(ADEBWARN, "abuf_truncate_block: "
		   "open failed at offset 0x%" PRIX64 "\n", offset);
	arla_debug_assert(0);
	return ret;
    }

    ret = ftruncate(fd, blocklen);	
    if (ret) {
	ret = errno;
	arla_warnx(ADEBWARN, "abuf_truncate_block: "
		   "truncate failed at offset 0x%" PRIX64 "\n", offset);
	arla_debug_assert(0);
	return ret;
    }

    close(fd);
    return 0;
}

static void
truncate_callback(struct block *block, void *data)
{
    struct truncate_cb_data *cb_data = (struct truncate_cb_data *)data;
    
    if (block->offset >= cb_data->length && block->offset != 0) {
	fcache_throw_block(block);
    } else if (cb_data->last_off == block->offset) {
	(void)abuf_truncate_block(block->node, block->offset,
				  cb_data->length - block->offset);
    } else if (cb_data->prev_last_off == block->offset) {
	uint64_t blocklen = cb_data->length - block->offset;
	uint64_t blocksize = fcache_getblocksize();

	if (blocklen > blocksize)
	    blocklen = blocksize;

	(void)abuf_truncate_block(block->node, block->offset, blocklen);
    } else {
	/* block should be ok */
    }
}

/*
 * truncate the cache data for real, update 'have' flags
 */

static int
abuf_truncate_int(FCacheEntry *entry, off_t length)
{
    struct truncate_cb_data data;

    data.length = length;
    data.last_off = block_offset(length);
    data.prev_last_off =
	block_offset(fcache_get_status_length(&entry->status));

    block_foreach(entry, truncate_callback, &data);
    return 0;
}

/*
 * Change the size of the underlying cache and the fbuf to `new_len'
 * bytes.
 * Returns 0 or error.
 */

static int
abuf_truncate_op(fbuf *f, size_t new_len)
{
    int ret;

    ret = abuf_flush(f);
    if (ret)
	goto fail;

    ret = abuf_truncate_int(abuf_entry(f), new_len);
    if (ret)
	goto fail;

    if (f->buf) {
	void *buf = realloc(f->buf, new_len);
	if (buf == NULL) {
	    ret = ENOMEM;
	    goto fail;
	}
	
	f->buf = buf;
    }

    f->len = new_len;

    return 0;

fail:
    if (f->buf) {
	free(f->buf);
	f->buf = NULL;
    }

    arla_debug_assert(0);

    return ret;
}

/*
 * Change the size of the underlying cache and the fbuf to `new_len'
 * bytes.
 * Returns 0 or error.
 */

int
abuf_truncate(FCacheEntry *entry, size_t new_len)
{
    return abuf_truncate_int(entry, new_len);
}

static void
purge_callback(struct block *block, void *data)
{
    fcache_throw_block(block);
}

/*
 * Throw all data in the node.  This is a special case of truncate
 * that does not leave block zero.
 */

int
abuf_purge(FCacheEntry *entry)
{
    block_foreach(entry, purge_callback, NULL);
    return 0;
}

/*
 * Create a fbuf with (fd, len, flags).
 * Returns 0 or error.
 */

int
abuf_create(fbuf *f, FCacheEntry *entry, size_t len, fbuf_flags flags)
{
    struct abuf_data *data = malloc(sizeof(*data));
    if (data == NULL)
	return ENOMEM;

    data->entry = entry;

    f->data  = data;
    f->len   = len;
    f->buf   = NULL;
    f->flags = flags;

    f->truncate = abuf_truncate_op;

    return abuf_populate(f);
}

/*
 * Write out the data of `f' to the file.
 * Returns 0 or error.
 */

static int
abuf_flush(fbuf *f)
{
    size_t len = f->len;
    uint64_t block_off = 0;
    ssize_t nwrite;
    int fd, ret = 0;

    if (!f->buf)
	return 0;

    if ((f->flags & FBUF_WRITE) != FBUF_WRITE)
	return 0;
    
    while (len > 0 && ret == 0) {
	size_t size = min(len, fcache_getblocksize());

	if ((fd = fcache_open_block(abuf_entry(f),
				    block_off, TRUE)) < 0) {
	    ret = errno;
	    break;
	}
	
	nwrite = write(fd, (char *)f->buf + block_off, size);
	if (nwrite != size) {
	    ret = errno;
	    close(fd);
	    break;
	}

	len -= nwrite;
	block_off += fcache_getblocksize();
	ret = close(fd);
    }

    return ret;
}

/*
 * End using `f'.
 * Returns 0 or error.
 */

int
abuf_end(fbuf *f)
{
    int ret = 0;

    if (f->buf) {
	ret = abuf_flush(f);
	free(f->buf);
	f->buf = NULL;
    }

    free(f->data);

    return ret;
}
