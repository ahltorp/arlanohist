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

/*
 * Header for credetial cache
 */

/* $Id: cred.h,v 1.41 2007/07/17 15:22:42 map Exp $ */

#ifndef _CRED_H_
#define _CRED_H_

#include <sys/types.h>
#include <time.h>
#include <lock.h>
#include "bool.h"
#include <nnpfs/nnpfs_message.h>

/* The cred-types we support */
#define CRED_NONE     0
#define CRED_KRB4     1
#define CRED_RXGK     3
#define CRED_MAX      CRED_RXGK
#define CRED_ANY      (-1)

struct cred_rxkad {
    struct arla_ClearToken ct;
    size_t ticket_len;
    unsigned char ticket[MAXKRB4TICKETLEN];
};

struct cred_rxgk {
    uint32_t flags;
    uint32_t level;
    uint32_t bytelife;
    uint32_t lifetime;
    uint64_t starttime;
    uint64_t endtime;
    uint32_t enctype;
    uint32_t tokenlen;
    uint32_t keylen;
};

typedef struct {
    nnpfs_pag_t cred;
    uid_t uid;
    int type;
    int securityindex;
    long cell;
    uint32_t hostid;
    time_t expire;
    struct token_rxgk *token_rxgk;
    void *cred_data;
    void (*cred_free_func)(void *);
    struct {
	unsigned killme : 1;
    } flags;
    unsigned refcount;
    union {
	List *list; 
	Listitem *li;
    } pag;
} CredCacheEntry;

/*
 *
 */

void cred_init (unsigned nentries);

CredCacheEntry *
cred_get (long cell, nnpfs_pag_t cred, int type);

void
cred_ref(CredCacheEntry *cred);

int
cred_list_pag(nnpfs_pag_t, int, 
	      int (*func)(CredCacheEntry *, void *),
	      void *);

void
cred_free (CredCacheEntry *ce);

CredCacheEntry *
cred_add (nnpfs_pag_t cred, int type, int securityindex, long cell,
	  time_t expire, void *cred_data, size_t cred_data_sz,
	  uid_t uid);

void
cred_delete (CredCacheEntry *ce);

void
cred_expire (CredCacheEntry *ce);

void cred_status (void);

void cred_remove (nnpfs_pag_t cred);

void cred_foreach (Bool (* func)(CredCacheEntry *e));

#endif /* _CRED_H_ */
