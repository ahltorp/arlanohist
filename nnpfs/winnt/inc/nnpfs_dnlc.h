/*
 * Copyright (c) 1999, 2002 Kungliga Tekniska Högskolan
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

#ifndef _NNPFS_NNPFS_DNLC_H
#define _NNPFS_NNPFS_DNLC_H


#define NNPFS_DNLC_CSIZE 128
#define NNPFS_DNLC_HSIZE NNPFS_DNLC_CSIZE>>3

#define NNPFS_DNLC_USED 0x00000001
#define NNPFS_DNLC_NEGATIVE 0x00000002

typedef struct nnpfs_dnlc_entry {
    XLIST_ENTRY(nnpfs_dnlc_entry) hash_entry;
    XLIST_ENTRY(nnpfs_dnlc_entry) lru_entry;
    unsigned flags;
    struct nnpfs_handle dir;
    struct nnpfs_node *node;
    char namelen;
    char name[NNPFS_MAX_NAME]; /* XXX wasting lotsa memory */
} nnpfs_dnlc_entry;

typedef struct nnpfs_dnlc {
    ERESOURCE  dnlc_lock;
    XLIST_LISTHEAD(nnpfs_dnlc_entry) nc_hash[NNPFS_DNLC_HSIZE];
    XLIST_LISTHEAD(nnpfs_dnlc_entry) nc_lru;
    
    nnpfs_dnlc_entry entries[NNPFS_DNLC_CSIZE];
} nnpfs_dnlc;

void
nnpfs_dnlc_init(nnpfs_dnlc *dnlc);

void
nnpfs_dnlc_shutdown(nnpfs_dnlc *dnlc);

void
nnpfs_dnlc_enter (struct nnpfs_node *p, const char *name, struct nnpfs_node *c);

NTSTATUS
nnpfs_dnlc_lookup (struct nnpfs_node *dir, const char *name,
		 struct nnpfs_node **node);

void
nnpfs_dnlc_uncache (struct nnpfs_node *node);

void
nnpfs_dnlc_drop (struct nnpfs_node *node);

void
nnpfs_dnlc_drop_children (struct nnpfs_node *dir);

#endif
