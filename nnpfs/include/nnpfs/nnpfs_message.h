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

/* $Id: nnpfs_message.h,v 1.62 2009/02/24 20:20:55 tol Exp $ */

#ifndef _xmsg_h
#define _xmsg_h

/* bump this for any incompatible changes */

#define NNPFS_VERSION 21

#include <nnpfs/nnpfs_attr.h>

/* Temporary hack? */
#define NNPFS_MAX_MSG_SIZE (1024*64)

typedef uint32_t nnpfs_pag_t;
typedef uint16_t nnpfs_rights;

/*
 * The nnpfs_cred, if pag == 0, use uid 
 */
typedef struct nnpfs_cred {
    uint32_t uid;
    nnpfs_pag_t pag;
} nnpfs_cred;

typedef uint32_t nnpfs_locktype_t;
typedef uint32_t nnpfs_lockid_t;


#define NNPFS_MAXHANDLE (4*4)
#define NNPFS_MAXRIGHTS 8

#define NNPFS_ANONYMOUSID 32766

typedef struct nnpfs_handle {
    uint32_t a, b, c, d;
} nnpfs_handle;

typedef struct nnpfs_block_handle {
    nnpfs_handle node;
    uint64_t offset;
} nnpfs_block_handle;

#define nnpfs_handle_eq(p, q) \
((p)->a == (q)->a && (p)->b == (q)->b && (p)->c == (q)->c && (p)->d == (q)->d)

/*
 * Tokens that apply to nodes, open modes and attributes. Shared
 * reading might be used for exec and exclusive write for remove.
 */
#define NNPFS_OPEN_MASK	0x000f
#define NNPFS_OPEN_NR	0x0001	       /* Normal reading, data might change */
#define NNPFS_OPEN_SR	0x0002	       /* Shared reading, data won't change */
#define NNPFS_OPEN_NW	0x0004	       /* Normal writing, multiple writers */
#define NNPFS_OPEN_EW	0x0008	       /* Exclusive writing (open really) */

#define NNPFS_ATTR_MASK	0x0030
#define NNPFS_ATTR_R	0x0010	       /* Attributes valid */
#define NNPFS_ATTR_W	0x0020	       /* Attributes valid and modifiable */

/*
 * Tokens that apply to node data.
 */
#define NNPFS_DATA_MASK	0x00c0
#define NNPFS_DATA_R	0x0040	       /* Data valid */
#define NNPFS_DATA_W	0x0080	       /* Data valid and modifiable */
#define NNPFS_LOCK_MASK	0x0300
#define NNPFS_LOCK_R	0x0100	       /* Data Shared locks */
#define NNPFS_LOCK_W	0x0200	       /* Data Exclusive locks */

#define NNPFS_ATTR_VALID		NNPFS_ATTR_R
#define NNPFS_DATA_VALID		NNPFS_DATA_W

/* nnpfs_node.flags
 * The lower 16 bit flags are reserved for common nnpfs flags
 * The upper 16 bit flags are reserved for operating system dependent
 * flags.
 */

#define NNPFS_DATA_DIRTY	0x0001
#define NNPFS_ATTR_DIRTY	0x0002
#define NNPFS_AFSDIR		0x0004
#define NNPFS_STALE		0x0008
#define NNPFS_XDELETED		0x0010
#define NNPFS_VMOPEN		0x0020
#define NNPFS_LIMBO		0x0040   /* inactive but not yet ack:ed by daemon */

/*
 * Token match macros, NNPFS_TOKEN_GOT is depricated and
 * NNPFS_TOKEN_GOT_* should be used instead.
 */

/* Are necessary tokens available? */
#define NNPFS_TOKEN_GOT(xn, tok)      ((xn)->tokens & (tok))          /* deprecated */
#define NNPFS_TOKEN_GOT_ANY(xn, tok)  ((xn)->tokens & (tok))          /* at least one must match */
#define NNPFS_TOKEN_GOT_ALL(xn, tok)  (((xn)->tokens & (tok)) == (tok)) /* all tokens must match */
#define NNPFS_TOKEN_SET(xn, tok, mask)	((xn)->tokens |= ((tok) & (mask)))
#define NNPFS_TOKEN_CLEAR(xn, tok, mask)	((xn)->tokens &= ~((tok) & (mask)))

/* definitions for the rights fields */
#define NNPFS_RIGHT_R	0x0001		/* emulated unix read */
#define NNPFS_RIGHT_W	0x0002		/* emulated unix write */
#define NNPFS_RIGHT_X	0x0004		/* emulated unix execute */

#define NNPFS_RIGHT_AR	0x0100		/* read */
#define NNPFS_RIGHT_AL	0x0200		/* list */
#define NNPFS_RIGHT_AI	0x0400		/* insert */
#define NNPFS_RIGHT_AD	0x0800		/* delete */
#define NNPFS_RIGHT_AW	0x1000		/* write */
#define NNPFS_RIGHT_AK	0x2000		/* lock */
#define NNPFS_RIGHT_AA	0x4000		/* admin */

/* Max name length passed in nnpfs messages */

#define NNPFS_MAX_NAME 256
#define NNPFS_MAX_SYMLINK_CONTENT 2048

struct nnpfs_msg_node {
    nnpfs_handle handle;
    uint32_t tokens;
    uint32_t pad1;
    struct nnpfs_attr attr;
    nnpfs_pag_t id[NNPFS_MAXRIGHTS];
    nnpfs_rights rights[NNPFS_MAXRIGHTS];
    nnpfs_rights anonrights;
    uint16_t pad2;
    uint32_t pad3;
};

/*
 * Messages passed through the  nnpfs_dev.
 */
struct nnpfs_message_header {
  uint32_t size;
  uint32_t opcode;
  uint32_t sequence_num;		/* Private */
  uint32_t pad1;
};

/*
 * Used by putdata flag
 */
enum { NNPFS_READ     = 0x01,
       NNPFS_WRITE    = 0x02,
       NNPFS_NONBLOCK = 0x04,
       NNPFS_APPEND   = 0x08,
       NNPFS_FSYNC    = 0x10,
       NNPFS_GC       = 0x20
};

/*
 * Flags for inactivenode
 */
enum { NNPFS_NOREFS = 1, NNPFS_DELETE = 2 };

/*
 * Flags for installattr
 */
enum { NNPFS_PUTATTR_REPLY = 1 };

/*
 * Flags for installdata
 */

enum { NNPFS_ID_INVALID_DNLC = 0x01, NNPFS_ID_AFSDIR = 0x02,
       NNPFS_ID_HANDLE_VALID = 0x04 };

/*
 * Defined message types and their opcodes.
 */
#define NNPFS_MSG_VERSION	0
#define NNPFS_MSG_WAKEUP	1

#define NNPFS_MSG_GETROOT	2
#define NNPFS_MSG_INSTALLROOT	3

#define NNPFS_MSG_GETNODE	4
#define NNPFS_MSG_INSTALLNODE	5

#define NNPFS_MSG_GETATTR	6
#define NNPFS_MSG_INSTALLATTR	7

#define NNPFS_MSG_GETDATA	8
#define NNPFS_MSG_INSTALLDATA	9

#define NNPFS_MSG_INACTIVENODE	10
#define NNPFS_MSG_INVALIDNODE	11
		/* XXX Must handle dropped/revoked tokens better */

#define NNPFS_MSG_OPEN		12

#define NNPFS_MSG_PUTDATA	13
#define NNPFS_MSG_PUTATTR	14

/* Directory manipulating messages. */
#define NNPFS_MSG_CREATE	15
#define NNPFS_MSG_MKDIR		16
#define NNPFS_MSG_LINK		17
#define NNPFS_MSG_SYMLINK	18

#define NNPFS_MSG_REMOVE	19
#define NNPFS_MSG_RMDIR		20

#define NNPFS_MSG_RENAME	21

#define NNPFS_MSG_PIOCTL	22

#define NNPFS_MSG_UPDATEFID	23

#define NNPFS_MSG_ADVLOCK	24

#define NNPFS_MSG_GC		25

#define NNPFS_MSG_DELETE_NODE	26

#define NNPFS_MSG_APPENDDATA	27

#define NNPFS_MSG_DELETEDATA	28

#define NNPFS_MSG_ACCESSES	29

#define NNPFS_MSG_INSTALLQUOTA	30

#define NNPFS_MSG_COUNT		31

/*
 * NNPFS_MESSAGE_VERSION
 *
 * Ask nnpfs about the protocol version it speaks, and inform about
 * the blocksize we use. This was not always like this, so nnpfs must
 * check message version and size before reading.
 */
struct nnpfs_message_version {
  struct nnpfs_message_header header;
  uint32_t version;
  uint32_t pad1;
  uint64_t blocksize;
  int64_t appendquota;
};

/* NNPFS_MESSAGE_WAKEUP */
struct nnpfs_message_wakeup {
  struct nnpfs_message_header header;
  uint32_t sleepers_sequence_num;	/* Where to send wakeup */
  uint32_t error;			/* Return value */
  uint32_t len;				/* data length */
  char msg[1];
};

/* NNPFS_MESSAGE_GETROOT */
struct nnpfs_message_getroot {
  struct nnpfs_message_header header;
  struct nnpfs_cred cred;
  uint64_t pad;				/* keep it larger than wakeup */
};

/* NNPFS_MESSAGE_INSTALLROOT */
struct nnpfs_message_installroot {
  struct nnpfs_message_header header;
  struct nnpfs_msg_node node;
};

/* NNPFS_MESSAGE_GETNODE */
struct nnpfs_message_getnode {
  struct nnpfs_message_header header;
  struct nnpfs_cred cred;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
};

/* NNPFS_MESSAGE_INSTALLNODE */
struct nnpfs_message_installnode {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  struct nnpfs_msg_node node;
};

/* NNPFS_MESSAGE_GETATTR */
struct nnpfs_message_getattr {
  struct nnpfs_message_header header;
  struct nnpfs_cred cred;
  nnpfs_handle handle;
};

/*
 * NNPFS_MESSAGE_INSTALLATTR
 *
 * Install attributes for node.
 * Only handles tokens in NNPFS_ATTR_MASK.
 */
struct nnpfs_message_installattr {
  struct nnpfs_message_header header;
  struct nnpfs_msg_node node;
  uint32_t flag;
  uint32_t pad1;
};

/* NNPFS_MESSAGE_GETDATA */
struct nnpfs_message_getdata {
  struct nnpfs_message_header header;
  struct nnpfs_cred cred;
  nnpfs_handle handle;
  uint32_t tokens;
  uint32_t pad1;
  uint64_t offset;  /* we want the block at this offset */
  uint64_t len;     /* how far in bytes, possibly considered a hint */
};

/*
 * NNPFS_MESSAGE_INSTALLDATA
 *
 * Install a block or node's cache location (w/ NNPFS_NO_OFFSET),
 * along with attributes.  Only handle tokens in NNPFS_DATA_MASK and
 * NNPFS_OPEN_MASK.
 */
struct nnpfs_message_installdata {
  struct nnpfs_message_header header;
  struct nnpfs_msg_node node;
  uint32_t flag;
  uint32_t cache_id;
  uint64_t offset; /* offset for installed block */
};

/* NNPFS_MSG_INACTIVENODE */
struct nnpfs_message_inactivenode {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  uint32_t flag;
  uint32_t pad1;
};

/* NNPFS_MSG_INVALIDNODE */
struct nnpfs_message_invalidnode {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
};

/* NNPFS_MSG_OPEN */
struct nnpfs_message_open {
  struct nnpfs_message_header header;
  struct nnpfs_cred cred;
  nnpfs_handle handle;
  uint32_t tokens;
  uint32_t pad1;
};

/*
 * NNPFS_MSG_PUTDATA
 *
 * If NNPFS_GC flag is set, block has been dropped by kernel.
 */
struct nnpfs_message_putdata {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  struct nnpfs_attr attr;		/* XXX ??? */
  struct nnpfs_cred cred;
  uint32_t flag;
  uint32_t pad1;
  uint64_t offset;
  uint64_t len; /* bytes */
};

/* NNPFS_MSG_PUTATTR */
struct nnpfs_message_putattr {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  struct nnpfs_attr attr;
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_CREATE */
struct nnpfs_message_create {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  struct nnpfs_attr attr;
  uint32_t mode;
  uint32_t pad1;
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_MKDIR */
struct nnpfs_message_mkdir {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  struct nnpfs_attr attr;
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_LINK */
struct nnpfs_message_link {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  nnpfs_handle from_handle;
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_SYMLINK */
struct nnpfs_message_symlink {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  char contents[NNPFS_MAX_SYMLINK_CONTENT];
  struct nnpfs_attr attr;
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_REMOVE */
struct nnpfs_message_remove {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_RMDIR */
struct nnpfs_message_rmdir {
  struct nnpfs_message_header header;
  nnpfs_handle parent_handle;
  char name[NNPFS_MAX_NAME];
  struct nnpfs_cred cred;
};

/* NNPFS_MSG_RENAME */
struct nnpfs_message_rename {
  struct nnpfs_message_header header;
  nnpfs_handle old_parent_handle;
  char old_name[NNPFS_MAX_NAME];
  nnpfs_handle new_parent_handle;
  char new_name[NNPFS_MAX_NAME];
  struct nnpfs_cred cred;
};

#define NNPFS_MSG_MAX_DATASIZE	2048

/* NNPFS_MSG_PIOCTL */
struct nnpfs_message_pioctl {
  struct nnpfs_message_header header;
  uint32_t opcode ;
  uint32_t pad1;
  nnpfs_cred cred;
  uint32_t insize;
  uint32_t outsize;
  char msg[NNPFS_MSG_MAX_DATASIZE];
  nnpfs_handle handle;
};

/* NNPFS_MESSAGE_UPDATEFID */
struct nnpfs_message_updatefid {
  struct nnpfs_message_header header;
  nnpfs_handle old_handle;
  nnpfs_handle new_handle;
};

/* NNPFS_MESSAGE_ADVLOCK */
struct nnpfs_message_advlock {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  struct nnpfs_cred cred;
  nnpfs_locktype_t locktype;
#define NNPFS_WR_LOCK 1 /* Write lock */
#define NNPFS_RD_LOCK 2 /* Read lock */
#define NNPFS_UN_LOCK 3 /* Unlock */
#define NNPFS_BR_LOCK 4 /* Break lock (inform that we don't want the lock) */
  nnpfs_lockid_t lockid;
};

/*
 * NNPFS_MESSAGE_GC
 *
 * Instruct nnpfs to release the indicated blocks if possible.
 * If offset is NNPFS_NO_OFFSET, it's the node we're after.
 */
struct nnpfs_message_gc {
  struct nnpfs_message_header header;
#define NNPFS_GC_MAX_HANDLE 10
  uint32_t len;
  uint32_t pad1;
  nnpfs_block_handle handle[NNPFS_GC_MAX_HANDLE];
};

/* NNPFS_MSG_DELETE_NODE */
struct nnpfs_message_delete_node {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
};

/*
 * NNPFS_MSG_APPENDDATA
 *
 * Block at offset is dirty and exists in nnpfs records.
 * The append quota in nnpfs has been reduced by the block's size and
 * should be replenished using INSTALLQUOTA.
 */
struct nnpfs_message_appenddata {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  uint64_t offset;
};

/*
 * NNPFS_MSG_DELETEDATA
 *
 * block at offset is dropped from nnpfs records
 */
struct nnpfs_message_deletedata {
  struct nnpfs_message_header header;
  nnpfs_handle handle;
  uint64_t offset;
};

/*
 * NNPFS_MSG_ACCESSES
 *
 * Tell daemon that indicated blocks/nodes have been accessed in
 * kernel.
 * If offset is NNPFS_NO_OFFSET, it's the node we're after.
 */
struct nnpfs_message_accesses {
  struct nnpfs_message_header header;
#define NNPFS_ACCESSES_MAX_HANDLE 100
  uint32_t count;
  uint32_t pad1;
  nnpfs_block_handle handle[NNPFS_ACCESSES_MAX_HANDLE];
};

/*
 * NNPFS_MSG_INSTALLQUOTA
 *
 * Tell nnpfs to update its quota/usage.
 */
struct nnpfs_message_installquota {
    struct nnpfs_message_header header;
    int64_t appendbytes;	/* add to append quota */
};

#endif /* _xmsg_h */
