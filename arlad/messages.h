/*
 * Copyright (c) 1995 - 2002, 2004 - 2006 Kungliga Tekniska H�gskolan
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
 *
 */

/* $Id: messages.h,v 1.29 2007/11/05 21:24:01 tol Exp $ */

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

void nnpfs_message_init (void);
int nnpfs_message_receive (int fd, struct nnpfs_message_header *h, u_int size);
void break_callback (FCacheEntry *e);
void install_attr (FCacheEntry *e, int flags);
int install_appendquota(int64_t diff);

long afsfid2inode(const VenusFid *fid);

int
nnpfs_attr2afsstorestatus(struct nnpfs_attr *xa,
			AFSStoreStatus *storestatus);

void
afsstatus2afsstorestatus(AFSFetchStatus *fetchstatus,
			 AFSStoreStatus *storestatus);
nnpfs_rights
afsrights2nnpfsrights(u_long ar, uint32_t FileType, uint32_t UnixModeBits);

void
update_fid(VenusFid oldfid, FCacheEntry *old_entry,
	   VenusFid newfid, FCacheEntry *new_entry);

enum { FCACHE2NNPFSNODE_LENGTH = 1 } ;	/* allow update of filedata */

#define FCACHE2NNPFSNODE_NO_LENGTH	0
#define FCACHE2NNPFSNODE_ALL		(FCACHE2NNPFSNODE_LENGTH)

void
fcacheentry2nnpfsnode (const VenusFid *fid,
		     const VenusFid *statfid, 
		     AFSFetchStatus *status,
		     struct nnpfs_msg_node *node,
                     AccessEntry *ae,
		     int flags);

int
VenusFid_cmp (const VenusFid *fid1, const VenusFid *fid2);


int get_connmode(int32_t *mode);
int set_connmode(int32_t mode, nnpfs_cred *cred);

void
message_init(void);

void
afsstatus2nnpfs_attr (AFSFetchStatus *status,
		      const VenusFid *fid,
		      struct nnpfs_attr *attr,
		      int flags);

#endif /* _MESSAGES_H_ */
