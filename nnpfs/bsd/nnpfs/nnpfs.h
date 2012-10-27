/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs.h,v 1.12 2007/03/28 12:05:46 tol Exp $ */

#ifndef _bsd_nnpfs_h
#define _bsd_nnpfs_h 1

/* maximal number of filesystems on a single device */
#define 	NNNPFS		2 

/*
 * Queues of nnpfs_links hold outbound messages and processes sleeping
 * for replies. The last field is used to return error to sleepers and
 * to keep record of memory to be deallocated when messages have been
 * delivered or dropped.
 */

struct nnpfs_link {
    NNPQUEUE_ENTRY(nnpfs_link)  qentry;
    struct nnpfs_message_header *message;
    u_int error_or_size;	       /* alloc size or
				        * return value after wakeup */
};

#ifdef __APPLE__
/* Tiger doesn't give us struct selinfo, so we invent it. */
struct nnpfs_selinfo {
    u_int32_t datum[31];
    u_int32_t mbz;
};
#endif

#ifdef __APPLE__
typedef lck_mtx_t *nnpfs_mutex_t;
#elif defined(__NetBSD__) || defined(__OpenBSD__)
typedef struct simplelock nnpfs_mutex_t;
#elif defined(__FreeBSD__)
typedef struct mtx nnpfs_mutex_t;
#else
typedef int nnpfs_mutex_t;
#endif

NNPQUEUE_HEAD(nh_link, nnpfs_link);

struct nnpfs {
    /* filesystem */
    int status;
#define NNPFS_MOUNTED	0x1
#define CHANNEL_OPENED	0x2
#define CHANNEL_WAITING 0x4
#define NNPFS_QUOTAWAIT 0x8
#define CHANNEL_CLOSING 0x10
    struct mount *mp;
    struct nnpfs_node *root;
    struct nnpfs_nodelist_head nodehead;
    struct nh_node_list freehead;
    /* char device */
    nnpfs_dev_t dev;
    struct nh_link messageq;	/* Messages not yet read */
    struct nh_link sleepq;	/* Waiting for reply message */
    u_int nsequence;
    uint64_t blocksize;
    int64_t appendquota;
#ifdef __APPLE__
    struct nnpfs_selinfo selinfo;
    struct vfs_attr statfs;
#else
    struct selinfo selinfo;
#endif
    struct nnpfs_message_header *message_buffer;
    d_thread_t *proc;
    /*
     * A mutex to protect proc, selinfo, messageq, sleepq, nodehead,
     * freehead, LIMBO flags in xnodes, ...
     *
     * This is sort of a substitute for GIANT, and we should split it
     * up. The node lists are good candidates for a separate lock.
     */
#if defined(__APPLE__) || defined(__FreeBSD__)
    struct {
	int recurse;
	nnpfs_mutex_t lock;
#if defined(__APPLE__)
	thread_t locker;
#else
	d_thread_t *locker;
#endif
    } lock;
#else
  nnpfs_mutex_t dev_lock;
#endif
    nnpfs_vfs_context ctx;
};

extern struct nnpfs nnpfs_dev[];

#endif /* _nnpfs_h */
