/*
 * Copyright (c) 1995-2007 Kungliga Tekniska Högskolan
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

#include "arla_local.h"
RCSID("$Id: messages.c,v 1.359 2007/11/05 21:24:00 tol Exp $");

#include <nnpfs/nnpfs_message.h>

#include "messages.h"

static int 
nnpfs_message_getroot (int, struct nnpfs_message_getroot*, u_int);

static int 
nnpfs_message_getnode (int, struct nnpfs_message_getnode*, u_int);

static int 
nnpfs_message_getattr (int, struct nnpfs_message_getattr*, u_int);

static int 
nnpfs_message_open (int, struct nnpfs_message_open*, u_int);

static int 
nnpfs_message_getdata (int, struct nnpfs_message_getdata*, u_int);

static int 
nnpfs_message_inactivenode (int,struct nnpfs_message_inactivenode*,u_int);

static int 
nnpfs_message_putdata (int fd, struct nnpfs_message_putdata *h, u_int size);

static int
nnpfs_message_putattr (int fd, struct nnpfs_message_putattr *h, u_int size);

static int
nnpfs_message_create (int fd, struct nnpfs_message_create *h, u_int size);

static int
nnpfs_message_mkdir (int fd, struct nnpfs_message_mkdir *h, u_int size);

static int
nnpfs_message_link (int fd, struct nnpfs_message_link *h, u_int size);

static int
nnpfs_message_symlink (int fd, struct nnpfs_message_symlink *h, u_int size);

static int
nnpfs_message_remove (int fd, struct nnpfs_message_remove *h, u_int size);

static int
nnpfs_message_rmdir (int fd, struct nnpfs_message_rmdir *h, u_int size);

static int
nnpfs_message_rename (int fd, struct nnpfs_message_rename *h, u_int size);

static int
nnpfs_message_pioctl (int fd, struct nnpfs_message_pioctl *h, u_int size) ;

static int 
nnpfs_message_appenddata (int,struct nnpfs_message_appenddata *h, u_int size);

static int 
nnpfs_message_deletedata (int,struct nnpfs_message_deletedata *h, u_int size);

static int 
nnpfs_message_accesses (int,struct nnpfs_message_accesses *h, u_int size);

static int
possibly_have_network(void);

/*
 *
 */

nnpfs_message_function rcvfuncs[] = {
    NULL,						/* version */
    (nnpfs_message_function)nnpfs_message_wakeup,	/* wakeup */
    (nnpfs_message_function)nnpfs_message_getroot,	/* getroot */
    NULL,						/* installroot */
    (nnpfs_message_function)nnpfs_message_getnode, 	/* getnode */
    NULL,						/* installnode */
    (nnpfs_message_function)nnpfs_message_getattr,	/* getattr */
    NULL,						/* installattr */
    (nnpfs_message_function)nnpfs_message_getdata,	/* getdata */
    NULL,						/* installdata */
    (nnpfs_message_function)nnpfs_message_inactivenode,	/* inactivenode */
    NULL,						/* invalidnode */
    (nnpfs_message_function)nnpfs_message_open,		/* open */
    (nnpfs_message_function)nnpfs_message_putdata,      /* put_data */
    (nnpfs_message_function)nnpfs_message_putattr,      /* put attr */
    (nnpfs_message_function)nnpfs_message_create,       /* create */
    (nnpfs_message_function)nnpfs_message_mkdir,	/* mkdir */
    (nnpfs_message_function)nnpfs_message_link,		/* link */
    (nnpfs_message_function)nnpfs_message_symlink,      /* symlink */
    (nnpfs_message_function)nnpfs_message_remove,	/* remove */
    (nnpfs_message_function)nnpfs_message_rmdir,	/* rmdir */
    (nnpfs_message_function)nnpfs_message_rename,	/* rename */
    (nnpfs_message_function)nnpfs_message_pioctl,	/* pioctl */
    NULL,						/* updatefid */
    NULL,						/* advlock */
    NULL,						/* gc nodes */
    NULL,						/* delete node */
    (nnpfs_message_function)nnpfs_message_appenddata,	/* appenddata */
    (nnpfs_message_function)nnpfs_message_deletedata,	/* deletedata */
    (nnpfs_message_function)nnpfs_message_accesses	/* accesses */
};


#if 0
/* number of prefetches currently in progress */
static int num_prefetches = 0;
#endif

/* maximum number of concurrent prefetches */
static int max_prefetches;

/*
 * init.
 */

void
message_init(void)
{
    max_prefetches = kernel_highworkers() - 2; /* XXX should be configurable */
}

/*
 *
 */

long
afsfid2inode (const VenusFid *fid)
{
    return ((fid->fid.Volume & 0x7FFF) << 16 | (fid->fid.Vnode & 0xFFFFFFFF));
}

/*
 * AFSFetchStatus -> nnpfs_attr
 * Setting everything except for length and mode.
 */

void
afsstatus2nnpfs_attr (AFSFetchStatus *status,
		      const VenusFid *fid,
		      struct nnpfs_attr *attr,
		      int flags)
{
    int mode;

    attr->valid = XA_V_NONE;
    switch (status->FileType) {
    case TYPE_FILE :
	mode = S_IFREG;
	XA_SET_TYPE(attr, NNPFS_FILE_REG);
	break;
    case TYPE_DIR :
	mode = S_IFDIR;
	XA_SET_TYPE(attr, NNPFS_FILE_DIR);
	break;
    case TYPE_LINK :
	mode = S_IFLNK;
	XA_SET_TYPE(attr, NNPFS_FILE_LNK);
	break;
    default :
	arla_warnx (ADEBMSG, "afsstatus2nnpfs_attr: default");
	abort ();
    }
    XA_SET_NLINK(attr, status->LinkCount);
    if (flags & FCACHE2NNPFSNODE_LENGTH)
	XA_SET_SIZE(attr, fcache_get_status_length(status));
    XA_SET_UID(attr,status->Owner);
    XA_SET_GID(attr, status->Group);
    XA_SET_ATIME(attr, status->ClientModTime);
    XA_SET_MTIME(attr, status->ClientModTime);
    XA_SET_CTIME(attr, status->ClientModTime);
    XA_SET_FILEID(attr, afsfid2inode(fid));

    /* XXX this is wrong, need to keep track of `our` ae for this req */
    if (fake_stat) {
	nnpfs_rights rights;
	
	rights = afsrights2nnpfsrights(status->CallerAccess,
				       status->FileType,
				       status->UnixModeBits);
	
	if (rights & NNPFS_RIGHT_R)
	    mode |= 0444;
	if (rights & NNPFS_RIGHT_W)
	    mode |= 0222;
	if (rights & NNPFS_RIGHT_X)
	    mode |= 0111;
    } else
	mode |= status->UnixModeBits;

    XA_SET_MODE(attr, mode);
}

/*
 * Transform `access', `FileType' and `UnixModeBits' into rights.
 *
 * There are different transformations for directories and files to be
 * compatible with the Transarc client.
 */

nnpfs_rights
afsrights2nnpfsrights(u_long ar, uint32_t FileType, uint32_t UnixModeBits)
{
    nnpfs_rights ret = 0;

    if (FileType == TYPE_DIR) {
	if (ar & ALIST)
	    ret |= NNPFS_RIGHT_R | NNPFS_RIGHT_X;
	if (ar & (AINSERT | ADELETE))
	    ret |= NNPFS_RIGHT_W;
    } else {
	/*
	 *  If its a file, and the AADMIN bit is set, we are the owner
	 *  of the file. Now we really want to know if we had AINSERT
	 *  the bits on the directory, but since we don't know that
	 *  here, lets just punt and let the fileserver tell us later
	 *  if we guess right. Give read and write to ourself for now.
	 */
	if (FileType == TYPE_FILE && (ar & AADMIN))
	    ret |= NNPFS_RIGHT_R|NNPFS_RIGHT_W;
	/*
	 * Clients can read symlink in directories where they only
	 * have ALIST (l) rights.
	 */
	if (FileType == TYPE_LINK && (ar & ALIST))
	    ret |= NNPFS_RIGHT_R;
	/* 
	 * Match RWX to AREAD+R, AWRITE+W, AREAD+X
	 */
	if ((ar & AREAD) && (UnixModeBits & S_IRUSR))
	    ret |= NNPFS_RIGHT_R;
	if ((ar & AWRITE) && (UnixModeBits & S_IWUSR))
	    ret |= NNPFS_RIGHT_W;
	if ((ar & AREAD) && (UnixModeBits & S_IXUSR))
	    ret |= NNPFS_RIGHT_X;
    }

    if (ar & AREAD)
	ret |= NNPFS_RIGHT_AR;
    if (ar & AWRITE)
	ret |= NNPFS_RIGHT_AW;
    if (ar & ALIST)
	ret |= NNPFS_RIGHT_AL;
    if (ar & AINSERT)
	ret |= NNPFS_RIGHT_AI;
    if (ar & ADELETE)
	ret |= NNPFS_RIGHT_AD;
    if (ar & ALOCK)
	ret |= NNPFS_RIGHT_AK;
    if (ar & AADMIN)
	ret |= NNPFS_RIGHT_AA;

    return ret;
}

void
fcacheentry2nnpfsnode (const VenusFid *fid,
		       const VenusFid *statfid, 
		       AFSFetchStatus *status,
		       struct nnpfs_msg_node *node,
		       AccessEntry *ae,
		       int flags)
{
    int i;

    memcpy (&node->handle, fid, sizeof(*fid));

    afsstatus2nnpfs_attr (status, statfid, &node->attr, flags);

    node->anonrights = afsrights2nnpfsrights(status->AnonymousAccess,
					     status->FileType,
					     status->UnixModeBits);
    for (i = 0; i < NACCESS; i++) {
	node->id[i] = ae[i].cred;
	node->rights[i] = afsrights2nnpfsrights(ae[i].access,
						status->FileType,
						status->UnixModeBits);
    }
}

/*
 * convert `xa' into `storestatus'
 */

int
nnpfs_attr2afsstorestatus(struct nnpfs_attr *xa,
			  AFSStoreStatus *storestatus)
{
    int mask = 0;

    if (XA_VALID_MODE(xa)) {
	storestatus->UnixModeBits = xa->xa_mode;
	mask |= SS_MODEBITS;
    }
    if (XA_VALID_UID(xa)) {
	storestatus->Owner = xa->xa_uid;
	mask |= SS_OWNER;
    }
    if (XA_VALID_GID(xa)) {
	storestatus->Group = xa->xa_gid;
	mask |= SS_GROUP;
    }
    if (XA_VALID_MTIME(xa)) {
	storestatus->ClientModTime = xa->xa_mtime;
	mask |= SS_MODTIME;
    }
    storestatus->Mask = mask;

    /* SS_SegSize */
    storestatus->SegSize = 0;
    return 0;
}

/*
 * Convert an AFSFetchStatus to AFSStoreStatus
 */

void
afsstatus2afsstorestatus(AFSFetchStatus *fetchstatus,
			 AFSStoreStatus *storestatus)
{
    storestatus->UnixModeBits = fetchstatus->UnixModeBits;
    storestatus->Owner = fetchstatus->Owner;
    storestatus->Group = fetchstatus->Group;
    storestatus->ClientModTime = fetchstatus->ClientModTime;
    
    storestatus->Mask = SS_MODEBITS | SS_OWNER | SS_GROUP | SS_MODTIME;

    storestatus->SegSize = 0;
}

/*
 * get new CredCacheEntry, for bad connections.
 */

static void
retry_cred(CredCacheEntry **ce, nnpfs_cred *cred)
{
    int32_t cell = (*ce)->cell;
    
    conn_clearcred(CONN_CS_CRED|CONN_CS_SECIDX, 0, cred->pag, 2);
    cred_expire(*ce);
    cred_free(*ce);
    *ce = cred_get(cell, cred->pag, CRED_ANY);
    assert(*ce);
}

/*
 * Return true iff we should retry the operation.
 * Also replace `ce' with anonymous creds in case it has expired.
 *
 * There must not be passed in any NULL pointers.
 */

static int
try_again (int *ret, CredCacheEntry **ce, nnpfs_cred *cred, const VenusFid *fid)
{
    switch (*ret) {
#ifdef KERBEROS
    case RXKADEXPIRED : 
    case RXKADBADTICKET:
    case RXKADBADKEY:
    case RXKADUNKNOWNKEY:
	retry_cred(ce, cred);
	return TRUE;
    case RXKADSEALEDINCON :
	arla_warnx_with_fid (ADEBWARN, fid,
			     "seal error");
	*ret = EINVAL;
	return FALSE;
#endif	 
    case ARLA_VSALVAGE :
	*ret = EIO;
	return FALSE;
    case ARLA_VNOVNODE :
	*ret = ENOENT;
	return FALSE;
    case ARLA_VMOVED :
    case ARLA_VNOVOL :
	if (fid && !volcache_reliablep (fid->fid.Volume, fid->Cell)) {
	    return TRUE;
	} else {
	    *ret = ENOENT;
	    return FALSE;
	}
    case ARLA_VOFFLINE :
	*ret = ENETDOWN;
	return FALSE;
    case ARLA_VDISKFULL :
	*ret = ENOSPC;
	return FALSE;
    case ARLA_VOVERQUOTA:
#ifdef EDQUOT
	*ret = EDQUOT;
#else
	*ret = ENOSPC;
#endif
	return FALSE;
    case ARLA_VBUSY :
	arla_warnx_with_fid (ADEBWARN, fid,
			     "Waiting for busy volume...");
	IOMGR_Sleep (afs_BusyWaitPeriod);
	return TRUE;
    case ARLA_VRESTARTING:
	arla_warnx_with_fid (ADEBWARN, fid,
			     "Waiting for fileserver to restart...");
	IOMGR_Sleep (afs_BusyWaitPeriod);
	return TRUE;
    case ARLA_VIO :
	*ret = EIO;
	return FALSE;
    default :
	return FALSE;
    }
}

/*
 * try_again() for cross cell operations
 */

static int
try_again_crosscell(int *ret, CredCacheEntry **ce, CredCacheEntry **ce2,
		    nnpfs_cred *cred, const VenusFid *fid)
{
    switch (*ret) {
#ifdef KERBEROS
    case RXKADEXPIRED : 
    case RXKADBADTICKET:
    case RXKADBADKEY:
    case RXKADUNKNOWNKEY: 
	retry_cred(ce, cred);
	retry_cred(ce2, cred);
	return TRUE;
#endif	 
    default:
	return try_again(ret, ce, cred, fid);
    }
}

/*
 * Do some basic setup and paranoia for installattr messages.
 * Note that we grant the node NNPFS_ATTR_R tokens here...
 *
 * XXX more paranoia?
 */

static struct nnpfs_message_header *
make_installattr(struct nnpfs_message_installattr *msg,
		 FCacheEntry *entry,
		 int flags)
{    
    if (!entry->flags.datausedp)
	assert((entry->tokens & NNPFS_DATA_MASK) == 0);
    
    entry->tokens |= NNPFS_ATTR_R;

    fcacheentry2nnpfsnode(&entry->fid, fcache_realfid(entry), 
			  &entry->status, &msg->node,
			  entry->acccache, flags);

    msg->header.opcode = NNPFS_MSG_INSTALLATTR;
    msg->node.tokens = (entry->tokens & NNPFS_ATTR_MASK);
    msg->flag = 0;

    return (struct nnpfs_message_header *)msg;
}

#if 0
/*
 * Do some basic setup and paranoia for installnode messages.
 * Note that we grant the node NNPFS_ATTR_R tokens here...
 *
 * XXX more paranoia?
 */

static struct nnpfs_message_header *
make_installnode(struct nnpfs_message_installnode *msg,
		 FCacheEntry *entry,
		 const VenusFid *parent,
		 const char *name)
{    
    fcacheentry2nnpfsnode(&entry->fid, fcache_realfid(entry), 
			  &entry->status, &msg->node,
			  entry->acccache, FCACHE2NNPFSNODE_ALL);
    
    msg->header.opcode = NNPFS_MSG_INSTALLNODE;
    /* msg->node.tokens = entry->tokens; */
    msg->parent_handle = *parent;
    strlcpy(msg->name, name, sizeof(msg->name));
    
    return (struct nnpfs_message_header *)msg;
}
#endif

/*
 * Do some basic setup and paranoia for installdata messages.
 *
 * This could be extended to do more of the message setup.
 *
 * XXX I'd like some node/block flags handling (kernelp, ...) in here,
 * but maybe they should be taken care of after the actuall install
 * operation has completed successfully.
 */

static struct nnpfs_message_header *
make_installdata(struct nnpfs_message_installdata *msg,
		 FCacheEntry *entry,
		 uint64_t offset,
		 uint32_t flag)
{
    entry->tokens |= NNPFS_ATTR_R|NNPFS_DATA_R;
    msg->node.tokens = (entry->tokens & (NNPFS_DATA_MASK | NNPFS_OPEN_MASK));
    entry->flags.attrusedp = TRUE;
    entry->flags.datausedp = TRUE;
    
    fcacheentry2nnpfsnode(&entry->fid, fcache_realfid(entry), 
			  &entry->status, &msg->node,
			  entry->acccache, FCACHE2NNPFSNODE_ALL);

    msg->offset = offset;
    msg->cache_id = entry->index;
    msg->flag = flag;
    msg->header.opcode = NNPFS_MSG_INSTALLDATA;

    /* XXX we shouldn't do this until operation was successful */
    if (offset != NNPFS_NO_OFFSET)
	fcache_data_setkernelp(entry, offset, TRUE, FALSE);

    return (struct nnpfs_message_header *)msg;
}

/*
 * Fetch data and retry if failing
 */

static int
message_get_data (FCacheEntry **entry,
		  struct nnpfs_cred *cred,
		  CredCacheEntry **ce,
		  uint64_t wanted_length)
{
    int ret;
    do {
	ret = fcache_get_data (entry, ce, 0, wanted_length);
    } while (try_again (&ret, ce, cred, &(*entry)->fid));
    return ret;
}

/*
 *
 */

static int
nnpfs_message_getroot (int fd, struct nnpfs_message_getroot *h, u_int size)
{
    struct nnpfs_message_installroot msg;
    int ret = 0;
    VenusFid root_fid;
    CredCacheEntry *ce;
    FCacheEntry *entry = NULL;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    int32_t cell_id = cell_name2num(cell_getthiscell());

    ce = cred_get (cell_id, h->cred.pag, CRED_ANY);
    assert (ce != NULL);
    do {
	ret = getroot (&root_fid, ce);
    } while (try_again (&ret, &ce, &h->cred, &root_fid));

    if (ret)
	goto out;

    ret = fcache_get(&entry, root_fid, ce);
    if (ret)
	goto out;
	 
    do {
	ret = cm_getattr(entry, ce);
    } while (try_again (&ret, &ce, &h->cred, &root_fid));

    if (ret == 0) {
	fcacheentry2nnpfsnode (&root_fid, fcache_realfid(entry),
			       &entry->status, &msg.node, entry->acccache,
			       FCACHE2NNPFSNODE_ALL);

	entry->tokens |= NNPFS_ATTR_R;
	msg.node.tokens = entry->tokens & ~NNPFS_DATA_MASK;
	msg.header.opcode = NNPFS_MSG_INSTALLROOT;
	h0 = (struct nnpfs_message_header *)&msg;
	h0_len = sizeof(msg);
    }

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					NULL, 0);
    if (entry)
	fcache_release(entry);
    cred_free (ce);

    return 0;
}

static int
nnpfs_message_getnode (int fd, struct nnpfs_message_getnode *h, u_int size)
{
    struct nnpfs_message_installnode msg;
    VenusFid *dirfid = (VenusFid *)&h->parent_handle;
    VenusFid fid;
    VenusFid real_fid;
    AFSFetchStatus status;
    CredCacheEntry *ce;
    FCacheEntry *entry = NULL;
    FCacheEntry *dentry = NULL;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    int ret;

    arla_warnx (ADEBMSG, "getnode (%ld.%lu.%lu.%lu) \"%s\"",
		(long)dirfid->Cell, (unsigned long)dirfid->fid.Volume,
		(unsigned long)dirfid->fid.Vnode,
		(unsigned long)dirfid->fid.Unique, h->name);

    ce = cred_get (dirfid->Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    ret = fcache_get(&dentry, *dirfid, ce);
    if (ret)
	goto out;

    assert_flag(dentry,kernelp);
     
    do {
	ret = cm_lookup (&dentry, h->name, &fid, &ce, TRUE);
	*dirfid = dentry->fid;
    } while (try_again (&ret, &ce, &h->cred, dirfid));

    if (ret)
	goto out;

    fcache_release(dentry);
    dentry = NULL;

    ret = fcache_get(&entry, fid, ce);
    if (ret)
	goto out;

    do {
	ret = cm_getattr(entry, ce);
	status = entry->status;
	real_fid = *fcache_realfid(entry);
    } while (try_again (&ret, &ce, &h->cred, &fid));

    if (ret == 0) {
	fcacheentry2nnpfsnode (&fid, &real_fid, &status, &msg.node,
			       entry->acccache, FCACHE2NNPFSNODE_ALL);

 	entry->tokens |= NNPFS_ATTR_R;
 	msg.node.tokens = entry->tokens;
	msg.parent_handle = h->parent_handle;
	strlcpy (msg.name, h->name, sizeof(msg.name));

	msg.header.opcode = NNPFS_MSG_INSTALLNODE;
	h0 = (struct nnpfs_message_header *)&msg;
	h0_len = sizeof(msg);
    }
 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					NULL, 0);
    if (entry)
	fcache_release(entry);
    if (dentry)
	fcache_release(dentry);
    cred_free (ce);

    return 0;
}

static int
nnpfs_message_getattr (int fd, struct nnpfs_message_getattr *h, u_int size)
{
    struct nnpfs_message_installattr msg;
    VenusFid fid;
    CredCacheEntry *ce;
    FCacheEntry *entry = NULL;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    int ret;

    fid = *(VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "getattr (%ld.%lu.%lu.%lu)",
		(long)fid.Cell, (unsigned long)fid.fid.Volume,
		(unsigned long)fid.fid.Vnode,
		(unsigned long)fid.fid.Unique);
    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    ret = fcache_get(&entry, fid, ce);
    if (ret)
	goto out;

    assert_flag(entry,kernelp);

    do {
	ret = cm_getattr(entry, ce);
    } while (try_again (&ret, &ce, &h->cred, &fid));

    if (ret)
	goto out;
     
    h0 = make_installattr(&msg, entry, FCACHE2NNPFSNODE_ALL);
    h0_len = sizeof(msg);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					NULL, 0);
    if (entry)
	fcache_release(entry);
    cred_free (ce);

    return 0;
}

static int 
nnpfs_message_putattr (int fd, struct nnpfs_message_putattr *h, u_int size)
{
    struct nnpfs_message_installattr msg;
    VenusFid fid;
    AFSStoreStatus status;
    CredCacheEntry *ce;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    int ret;

    FCacheEntry *entry = NULL;

    fid = *(VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "putattr (%ld.%lu.%lu.%lu)",
		(long)fid.Cell, (unsigned long)fid.fid.Volume,
		(unsigned long)fid.fid.Vnode,
		(unsigned long)fid.fid.Unique);
    nnpfs_attr2afsstorestatus(&h->attr, &status);
    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    if (connected_mode != CONNECTED) {
	entry = fcache_find(fid);
	if (!entry) {
	    ret = ENETDOWN;
	    goto out;
	}
    } else {
	ret = fcache_get(&entry, fid, ce);
	if (ret)
	    goto out;
    }

    assert_flag(entry,kernelp);

    if (XA_VALID_SIZE(&h->attr)) {
	/* Bits update may fail on old servers, fixed in openafs-1.2.7 */
	do {
	    ret = cm_ftruncate (entry, h->attr.xa_size, &status, ce);
	} while (try_again (&ret, &ce, &h->cred, &fid));
	if (ret)
	    goto out;
	
	entry->flags.appended = FALSE;
    }

    /* XXX this is redundant on XA_VALID_SIZE(&h->attr), right? */
    if (status.Mask) {
	do {
	    ret = cm_setattr(entry, &status, ce);
	} while (try_again (&ret, &ce, &h->cred, &fid));
    }

    if (ret)
	goto out;

    do {
	ret = cm_getattr(entry, ce);
    } while (try_again (&ret, &ce, &h->cred, &fid));

     
    if (ret)
	goto out;
     
    h0 = make_installattr(&msg, entry, FCACHE2NNPFSNODE_ALL);
    h0_len = sizeof(msg);
    msg.flag = NNPFS_PUTATTR_REPLY;

    if (connected_mode != CONNECTED)
	entry->disco_id = disco_store_status(&fid, &status, entry->disco_id);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num, 
					ret,
					h0, h0_len,
					NULL, 0);
    if (entry)
	fcache_release(entry);
    cred_free (ce);

    return 0;
}

static int 
nnpfs_message_create (int fd, struct nnpfs_message_create *h, u_int size)
{
    VenusFid parent_fid, child_fid;
    AFSStoreStatus store_status;
    CredCacheEntry *ce;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installnode msg2;
    struct nnpfs_message_installdata msg3;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    struct nnpfs_message_header *h2 = NULL;
    size_t h2_len = 0;
    FCacheEntry *dir_entry   = NULL;
    FCacheEntry *child_entry = NULL;

    parent_fid = *(VenusFid *)&h->parent_handle;
    arla_warnx (ADEBMSG, "create (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell,
		(unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique, h->name);

    nnpfs_attr2afsstorestatus(&h->attr, &store_status);
    if (connected_mode != CONNECTED) {
	if (!(store_status.Mask & SS_OWNER)) {
	    store_status.Owner = h->cred.uid;
	    store_status.Mask |= SS_OWNER;
	}
	if (!(store_status.Mask & SS_GROUP)) {
	    store_status.Group = 0;
	    store_status.Mask |= SS_GROUP;
	}
	if (!(store_status.Mask & SS_MODTIME)) {
	    struct timeval now;

	    gettimeofday (&now, NULL);

	    store_status.ClientModTime = now.tv_sec;
	    store_status.Mask |= SS_MODTIME;
	}
    }
    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);

    do {
	ret = cm_create(&dir_entry, h->name, &store_status,
			&child_entry, &ce);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));

    if (ret)
	goto out;

    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    ret = conv_dir(dir_entry, ce, 0);
    if (ret)
	goto out;
     
    /* XXX remove this, we don't want to fetch data from the fileserver 
       ret = message_get_data (&child_entry, &h->cred, &ce, 0); */
    ret = fcache_verify_attr (child_entry, dir_entry, h->name, ce); /* better? */
    if (ret)
	goto out;

    child_fid = child_entry->fid;
     
    assert_flag(dir_entry,kernelp);
    assert_flag(dir_entry,attrusedp);
     
    h0 = make_installdata(&msg1, dir_entry, 0, 0);
    h0_len = sizeof(msg1);
    
    fcacheentry2nnpfsnode (&child_fid, &child_fid,
			   &child_entry->status, &msg2.node, dir_entry->acccache,
			   FCACHE2NNPFSNODE_ALL);
     
    fcache_node_setkernelp(child_entry, TRUE);

    child_entry->tokens |= NNPFS_ATTR_R | NNPFS_DATA_R | NNPFS_DATA_W;
    msg2.node.tokens   = child_entry->tokens & ~(NNPFS_DATA_MASK);
    child_entry->flags.attrusedp = TRUE;
    child_entry->flags.datausedp = TRUE;

    msg2.parent_handle = h->parent_handle;
    strlcpy (msg2.name, h->name, sizeof(msg2.name));
      
    msg2.header.opcode = NNPFS_MSG_INSTALLNODE;
    h1 = (struct nnpfs_message_header *)&msg2;
    h1_len = sizeof(msg2);
     
    /* msg3.node        = msg2.node; */

    h2 = make_installdata(&msg3, child_entry, 0, 0);
    h2_len = sizeof(msg3);

    if (connected_mode != CONNECTED)
	child_entry->disco_id = disco_create_file(&parent_fid, &child_fid,
						  h->name, &store_status);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					h2, h2_len,
					NULL, 0);
    if (dir_entry)
	fcache_release(dir_entry);
    if (child_entry)
	fcache_release(child_entry);
    cred_free (ce);

    return ret;
}

static int 
nnpfs_message_mkdir (int fd, struct nnpfs_message_mkdir *h, u_int size)
{
    VenusFid parent_fid, child_fid;
    AFSStoreStatus store_status;
    AFSFetchStatus fetch_status;
    CredCacheEntry *ce;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installnode msg2;
    struct nnpfs_message_installdata msg3;
    FCacheEntry *dir_entry = NULL;
    FCacheEntry *child_entry = NULL;

    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    struct nnpfs_message_header *h2 = NULL;
    size_t h2_len = 0;

#if 0
    parent_fid = *fid_translate((VenusFid *)&h->parent_handle);
#else
    parent_fid = *(VenusFid *)&h->parent_handle;
#endif
    arla_warnx (ADEBMSG, "mkdir (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell, (unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique, h->name);

    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    nnpfs_attr2afsstorestatus(&h->attr, &store_status);
    if (connected_mode != CONNECTED) {
	if (!(store_status.Mask & SS_OWNER)) {
	    store_status.Owner = h->cred.uid;
	    store_status.Mask |= SS_OWNER;
	}
	if (!(store_status.Mask & SS_MODTIME)) {
	    struct timeval now;

	    gettimeofday (&now, NULL);

	    store_status.ClientModTime = now.tv_sec;
	    store_status.Mask |= SS_MODTIME;
	}
    }

    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;
     
    assert_flag(dir_entry,kernelp);

    do {
	ret = cm_mkdir(&dir_entry, h->name, &store_status,
		       &child_fid, &fetch_status, &ce);
    } while(try_again (&ret, &ce, &h->cred, &dir_entry->fid));

    if (ret)
	goto out;

    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    ret = conv_dir(dir_entry, ce, 0);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);
    assert_flag(dir_entry,attrusedp);
    
    h0 = make_installdata(&msg1, dir_entry, 0, 0);
    h0_len = sizeof(msg1);
     
    ret = fcache_get(&child_entry, child_fid, ce);
    if (ret)
	goto out;
    ret = message_get_data (&child_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    child_fid = child_entry->fid;
     
    ret = conv_dir(child_entry, ce, 0);
    if (ret)
	goto out;

    fcache_node_setkernelp(child_entry, TRUE);
    child_entry->flags.attrusedp = TRUE;
    child_entry->flags.datausedp = TRUE;     
    child_entry->tokens |= NNPFS_ATTR_R;
    msg2.node.tokens = child_entry->tokens & ~(NNPFS_DATA_MASK);
     
    fcacheentry2nnpfsnode (&child_fid, &child_fid,
			   &child_entry->status, &msg2.node,
			   dir_entry->acccache,
			   FCACHE2NNPFSNODE_ALL);
     
    msg2.parent_handle = h->parent_handle;
    strlcpy (msg2.name, h->name, sizeof(msg2.name));
     
    msg2.header.opcode = NNPFS_MSG_INSTALLNODE;
    h1 = (struct nnpfs_message_header *)&msg2;
    h1_len = sizeof(msg2);
     
    /* msg3.node = msg2.node; */

    h2 = make_installdata(&msg3, child_entry, 0, 0);
    h2_len = sizeof(msg3);

    if (connected_mode != CONNECTED)
	child_entry->disco_id = disco_create_dir(&parent_fid, &child_fid, 
						 h->name, &store_status);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					h2, h2_len,
					NULL, 0); 
    if (child_entry) 
	fcache_release(child_entry);
    if (dir_entry)
	fcache_release(dir_entry);
    cred_free (ce);

    return ret;
}

static int 
nnpfs_message_link (int fd, struct nnpfs_message_link *h, u_int size)
{
    VenusFid parent_fid, existing_fid;
    CredCacheEntry *ce;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installnode msg2;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    FCacheEntry *dir_entry = NULL;
    FCacheEntry *child_entry = NULL;

    parent_fid   = *(VenusFid *)&h->parent_handle;
    existing_fid = *(VenusFid *)&h->from_handle;
    arla_warnx (ADEBMSG, "link (%ld.%lu.%lu.%lu) (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell, (unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique,
		(long)existing_fid.Cell,
		(unsigned long)existing_fid.fid.Volume,
		(unsigned long)existing_fid.fid.Vnode,
		(unsigned long)existing_fid.fid.Unique,
		h->name);

    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;

    ret = fcache_get(&child_entry, existing_fid, ce);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);
    assert_flag(child_entry,kernelp);

    do {
	ret = cm_link(&dir_entry, h->name, child_entry, &ce);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));

    if (ret)
	goto out;

    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    ret = conv_dir(dir_entry, ce, 0);
    if (ret == -1)
	goto out;

    assert_flag(dir_entry,kernelp);
    assert_flag(dir_entry,attrusedp);
          
    h0 = make_installdata(&msg1, dir_entry, 0, 0);
    h0_len = sizeof(msg1);
    
    fcacheentry2nnpfsnode(&existing_fid, &existing_fid, /* &child_entry->fid ? */
			  &child_entry->status, &msg2.node,
			  child_entry->acccache,
			  FCACHE2NNPFSNODE_ALL);
    
    child_entry->flags.attrp = TRUE;
    child_entry->tokens |= NNPFS_ATTR_R;

    msg2.node.tokens = child_entry->tokens;
    msg2.parent_handle = h->parent_handle;
    strlcpy (msg2.name, h->name, sizeof(msg2.name));
     
    msg2.header.opcode = NNPFS_MSG_INSTALLNODE;
    h1 = (struct nnpfs_message_header *)&msg2;
    h1_len = sizeof(msg2);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					NULL, 0);
    if (dir_entry)
	fcache_release(dir_entry);
    if (child_entry)
	fcache_release(child_entry);
    cred_free (ce);

    return ret;
}

static int 
nnpfs_message_symlink (int fd, struct nnpfs_message_symlink *h, u_int size)
{
    VenusFid parent_fid, child_fid, real_fid;
    AFSStoreStatus store_status;
    AFSFetchStatus fetch_status;
    CredCacheEntry *ce;
    int saved_ret;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installnode msg2;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    FCacheEntry *dir_entry = NULL;

    parent_fid = *(VenusFid *)&h->parent_handle;
    arla_warnx (ADEBMSG, "symlink (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell, (unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique, h->name);

    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    nnpfs_attr2afsstorestatus(&h->attr, &store_status);

    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);

    do {
	ret = cm_symlink(&dir_entry, h->name, &store_status,
			 &child_fid, &real_fid,
			 &fetch_status,
			 h->contents, &ce);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));
     
    cred_free (ce);
    ce = cred_get (dir_entry->fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    /*
     * Mountpoints can be created even when the target volume doesn't
     * exist, and other things may happen. Always update the directory
     * just to be on the safe side.
     */
    saved_ret = ret;
     
    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    ret = conv_dir(dir_entry, ce, 0);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);
    assert_flag(dir_entry,attrusedp);
    
    h0 = make_installdata(&msg1, dir_entry, 0, 0);
    h0_len = sizeof(msg1);
    
    if (saved_ret) {
	ret = saved_ret;
	goto out;
    }

    fcacheentry2nnpfsnode (&child_fid, &real_fid,
			   &fetch_status, &msg2.node,
			   dir_entry->acccache,
			   FCACHE2NNPFSNODE_ALL);
    
    msg2.node.tokens   = NNPFS_ATTR_R; /* XXX */
    msg2.parent_handle = h->parent_handle;
    strlcpy (msg2.name, h->name, sizeof(msg2.name));
    
    msg2.header.opcode = NNPFS_MSG_INSTALLNODE;
    h1 = (struct nnpfs_message_header *)&msg2;
    h1_len = sizeof(msg2);
    
 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					NULL, 0);
    if (dir_entry)
	fcache_release(dir_entry);
    cred_free (ce);

    return ret;
}

/* 
 * Handle the NNPFS remove message in `h', that is, remove name
 * `h->name' in directory `h->parent' with the creds from `h->cred'.
 */

static int 
nnpfs_message_remove (int fd, struct nnpfs_message_remove *h, u_int size)
{
    VenusFid parent_fid;
    VenusFid fid;
    CredCacheEntry *ce;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installattr msg2;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    FCacheEntry *limbo_entry = NULL;
    FCacheEntry *dir_entry = NULL;
    
    parent_fid = *(VenusFid *)&h->parent_handle;
    arla_warnx (ADEBMSG, "remove (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell, (unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique, h->name);
    
    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);
    
    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;
    
    assert_flag(dir_entry,kernelp);
    
    do {
	ret = cm_lookup (&dir_entry, h->name, &fid, &ce, FALSE);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));
    
    if (ret)
	goto out;

    /*
     * Fetch the linkcount of the to be removed node
     */
    
    ret = fcache_get (&limbo_entry, fid, ce);
    if (ret)
	goto out;
    
    ret = fcache_verify_attr (limbo_entry, dir_entry, h->name, ce);
    if (ret)
	goto out;
    
    /*
     * Do the actual work
     */
    
    do {
	ret = cm_remove(&dir_entry, h->name, &limbo_entry, &ce);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));
    
    if (ret)
	goto out;
    
    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;
    
    if (!dir_entry->flags.extradirp
	|| dir_remove_name (dir_entry, h->name)) {
	ret = conv_dir(dir_entry, ce, 0);
	if (ret)
	    goto out;
    }

    assert(dir_entry->flags.attrusedp);

    h0 = make_installdata(&msg1, dir_entry, 0, NNPFS_ID_INVALID_DNLC);
    h0_len = sizeof(msg1);        
    
    /*
     * Make sure that if the removed node is in the kernel it has the
     * right linkcount since some might hold a reference to it.
     */

    if (limbo_entry->flags.kernelp) {
	/*
	 * Now insert the limbo entry to get right linkcount
	 */
	h1 = make_installattr(&msg2, limbo_entry, FCACHE2NNPFSNODE_ALL);
	h1_len = sizeof(msg2);
    }
    
 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					NULL, 0);
    if (dir_entry)
	fcache_release(dir_entry);
    if (limbo_entry)
	fcache_release (limbo_entry);
    cred_free (ce);

    return ret;
}

static int 
nnpfs_message_rmdir (int fd, struct nnpfs_message_rmdir *h, u_int size)
{
    VenusFid parent_fid, fid;
    CredCacheEntry *ce;
    int ret;
    struct nnpfs_message_installdata msg0;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_installattr msg1;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    FCacheEntry *limbo_entry = NULL;
    FCacheEntry *dir_entry = NULL;

    parent_fid = *(VenusFid *)&h->parent_handle;
    arla_warnx (ADEBMSG, "rmdir (%ld.%lu.%lu.%lu) \"%s\"",
		(long)parent_fid.Cell, (unsigned long)parent_fid.fid.Volume,
		(unsigned long)parent_fid.fid.Vnode,
		(unsigned long)parent_fid.fid.Unique, h->name);

    ce = cred_get (parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    /*
     * Fetch the child-entry fid.
     */

    ret = fcache_get(&dir_entry, parent_fid, ce);
    if (ret)
	goto out;

    assert_flag(dir_entry,kernelp);

    do {
	ret = cm_lookup (&dir_entry, h->name, &fid, &ce, FALSE);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));

    if (ret)
	goto out;

    if (VenusFid_cmp(&dir_entry->fid, &fid) == 0) {
	ret = EINVAL;
	goto out;
    }

    /*
     * Need to get linkcount for silly rename.
     */

    ret = fcache_get (&limbo_entry, fid, ce);
    if (ret)
	goto out;

    ret = fcache_verify_attr (limbo_entry, dir_entry, h->name, ce);
    if (ret)
	goto out;

    /*
     * Do the actual work
     */

    do {
	ret = cm_rmdir(&dir_entry, h->name, &limbo_entry, &ce);
    } while (try_again (&ret, &ce, &h->cred, &dir_entry->fid));

    if (ret)
	goto out;

    ret = message_get_data (&dir_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;

    if (!dir_entry->flags.extradirp
	|| dir_remove_name (dir_entry, h->name)) {
	ret = conv_dir(dir_entry, ce, 0);
	if (ret)
	    goto out;
    }

    h0 = make_installdata(&msg0, dir_entry, 0, NNPFS_ID_INVALID_DNLC);
    h0_len = sizeof(msg0);

    if (limbo_entry->flags.kernelp) {
	h1 = make_installattr(&msg1, limbo_entry, FCACHE2NNPFSNODE_ALL);
	h1_len = sizeof(msg1);
    }
    assert_flag(dir_entry,kernelp);
    assert_flag(dir_entry,attrusedp);

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					NULL, 0);
    if (dir_entry)
	fcache_release(dir_entry);
    if (limbo_entry)
	fcache_release (limbo_entry);

    cred_free (ce);

    return ret;
}

static int 
nnpfs_message_rename (int fd, struct nnpfs_message_rename *h, u_int size)
{
    VenusFid old_parent_fid;
    VenusFid new_parent_fid;
    VenusFid child_fid;
    CredCacheEntry *ce;
    CredCacheEntry *ce2;
    int ret;
    struct nnpfs_message_installdata msg1;
    struct nnpfs_message_installdata msg2;
    struct nnpfs_message_installdata msg3;
    struct nnpfs_message_header *h0 = NULL;
    size_t h0_len = 0;
    struct nnpfs_message_header *h1 = NULL;
    size_t h1_len = 0;
    struct nnpfs_message_header *h2 = NULL;
    size_t h2_len = 0;
    FCacheEntry *old_entry   = NULL;
    FCacheEntry *new_entry   = NULL;
    FCacheEntry *child_entry = NULL;
    int update_child = 0;
    int diff_dir = 0;

    old_parent_fid = *(VenusFid *)&h->old_parent_handle;
    new_parent_fid = *(VenusFid *)&h->new_parent_handle;
    arla_warnx (ADEBMSG,
		"rename (%ld.%lu.%lu.%lu) (%ld.%lu.%lu.%lu) \"%s\" \"%s\"",
		(long)old_parent_fid.Cell,
		(unsigned long)old_parent_fid.fid.Volume,
		(unsigned long)old_parent_fid.fid.Vnode,
		(unsigned long)old_parent_fid.fid.Unique,
		(long)new_parent_fid.Cell,
		(unsigned long)new_parent_fid.fid.Volume,
		(unsigned long)new_parent_fid.fid.Vnode,
		(unsigned long)new_parent_fid.fid.Unique,
		h->old_name,
		h->new_name);

    ce = cred_get (old_parent_fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    if (new_parent_fid.Cell == old_parent_fid.Cell) {
	ce2 = ce;
	cred_ref(ce2);
    } else {
	ce2 = cred_get(new_parent_fid.Cell, h->cred.pag, CRED_ANY);
	assert(ce2);
    }

    diff_dir = VenusFid_cmp (&old_parent_fid, &new_parent_fid);

    ret = fcache_get(&old_entry, old_parent_fid, ce);
    if (ret)
	goto out;

    assert_flag(old_entry,kernelp);
    
    if (diff_dir) {
	ret = fcache_get(&new_entry, new_parent_fid, ce2);
	if (ret)
	    goto out;
    } else {
	new_entry = old_entry;
    }


    assert_flag(new_entry,kernelp);

    do {
	ret = cm_rename(&old_entry, h->old_name,
			&new_entry, h->new_name,
			&child_fid, &update_child, &ce, &ce2);
    } while (try_again_crosscell(&ret, &ce, &ce2, &h->cred, &old_entry->fid));

    if (ret)
	goto out;

    ret = message_get_data (&old_entry, &h->cred, &ce, 0);
    if (ret)
	goto out;
     
    if (!old_entry->flags.extradirp
	|| dir_remove_name (old_entry, h->old_name)) {
	ret = conv_dir(old_entry, ce, 0);
	if (ret)
	    goto out;
    }
     
    assert_flag(old_entry,kernelp);
    assert_flag(old_entry,attrusedp);
     
    h0 = make_installdata(&msg1, old_entry, 0, NNPFS_ID_INVALID_DNLC);
    h0_len = sizeof(msg1);
     
    ret = fcache_get_data (&new_entry, &ce2, 0, 0); /* XXX - fake_mp? */
    if (ret)
	goto out;
     
    ret = conv_dir(new_entry, ce2, 0);
    if (ret)
	goto out;

    assert_flag(new_entry,kernelp);
    assert_flag(new_entry,attrusedp);
     
    h1 = make_installdata(&msg2, new_entry, 0, NNPFS_ID_INVALID_DNLC);
    h1_len = sizeof(msg2);
         
    if (update_child) {
	ret = fcache_get(&child_entry, child_fid, ce2);
	if (ret)
	    goto out;
	ret = message_get_data (&child_entry, &h->cred, &ce2, 0);
	if (ret) {
	    fcache_release(child_entry);
	    goto out;
	}
	child_fid = child_entry->fid;
	 
	ret = conv_dir(child_entry, ce2, 0);
	if (ret)
	    goto out;

	h2 = make_installdata(&msg3, child_entry, 0, NNPFS_ID_INVALID_DNLC);
	h2_len = sizeof(msg3);
    }

 out:
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					h0, h0_len,
					h1, h1_len,
					NULL, 0);
    if (old_entry) fcache_release(old_entry);
    if (new_entry && diff_dir) fcache_release(new_entry);
    if (child_entry) fcache_release(child_entry);
     
    cred_free (ce);
    cred_free(ce2);

    return ret;
}

static int 
nnpfs_message_putdata (int fd, struct nnpfs_message_putdata *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce;
    int ret;
    AFSStoreStatus status;
    FCacheEntry *entry = NULL;
    uint64_t len, end;

    worker_setdebuginfo("message putdata");

    if (h->flag & NNPFS_GC)
	fcache_cleaner_ref();

    fid = *(VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "putdata (%ld.%lu.%lu.%lu)",
		(long)fid.Cell, (unsigned long)fid.fid.Volume,
		(unsigned long)fid.fid.Vnode,
		(unsigned long)fid.fid.Unique);

    nnpfs_attr2afsstorestatus(&h->attr, &status);

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    if (connected_mode != CONNECTED) {
	entry = fcache_find(fid); /* XXX gcp? */
	if (!entry) {
	    ret = ENETDOWN;
	    goto out;
	}
    } else {
	if (h->flag & NNPFS_GC)
	    ret = fcache_get_gc(&entry, fid, ce);
	else
	    ret = fcache_get(&entry, fid, ce);
	if (ret)
	    goto out;
    }

    assert_flag(entry,kernelp);
    assert(XA_VALID_SIZE(&h->attr));
    assert(h->attr.xa_size >= h->offset);

    len = h->attr.xa_size;
    
    if (fcache_get_status_length(&entry->status) < len)
	fcache_set_status_length(&entry->status, len);
    
    end = h->offset + h->len;
    assert(end <= len);
    
#if 0
    worker_setdebuginfo("putdata have");

    /* XXX this is not a good place to be picky about cache usage */
    ret = fcache_set_have(entry, h->offset, end);
    if (ret) {
	arla_warn(ADEBMSG, ret, "nnpfs_message_putdata: set_have");
	goto out;
    }
#endif

    worker_setdebuginfo("putdata write");

    do {
	ret = cm_write(entry, h->flag, h->offset, h->len, &status, ce);
    } while (try_again (&ret, &ce, &h->cred, &fid));
     
    if (ret) {
	arla_warn (ADEBMSG, ret, "nnpfs_message_putdata: cm_write");
	goto out;
    }

    entry->flags.appended = FALSE;

    if (connected_mode != CONNECTED)
	entry->disco_id = disco_store_data(&fid, &status, entry->disco_id);

    if (h->flag & NNPFS_GC) {
	uint64_t blocksize = fcache_getblocksize();
	uint64_t off;
	for (off = h->offset; off < end; off += blocksize)
	    fcache_data_setkernelp(entry, off, FALSE, FALSE);
    } else {
	/* XXX do this on GC too? */

	entry->flags.dirtied = FALSE;
	entry->flags.stale = FALSE;

	/* XXX argh. if this was a partial write we may still have
	 * stale blocks
	 */
    }

 out:
    worker_setdebuginfo("putdata done");

    if (h->flag & NNPFS_GC)
	fcache_cleaner_deref();

    if (ret)
	entry->flags.dirtied = TRUE; /* break_callback(entry); */

    if (entry)
	fcache_release(entry);
    cred_free (ce);
    nnpfs_send_message_wakeup (fd, h->header.sequence_num, ret);
    return 0;
}

static void
prefetch_data(FCacheEntry **e, CredCacheEntry **ce)
{
#if 0 /* XXX no prefetch for now */
    FCacheEntry *entry = *e;
    uint64_t length;
    int ret = 0;

    if (entry->status.FileType != TYPE_FILE)
	return;

    /* always leave a few threads for synchronous work */
    if (num_prefetches >= max_prefetches)
	return;

    num_prefetches++;

    length = fcache_get_status_length(&entry->status);

    if (length > entry->fetched_length) {
	uint64_t offset;

	offset = entry->fetched_length + stats_prefetch(NULL, -1);
	if (offset > length)
	    offset = length;
	arla_warnx (ADEBMSG, "  prefetching to %lu", (unsigned long)offset);
	ret = fcache_get_data (e, ce, 0, offset);
	arla_warnx (ADEBMSG, "  prefetched returned %d", ret);
    }

    num_prefetches--;

#endif
    return;
}

static int
nnpfs_message_open (int fd, struct nnpfs_message_open *h, u_int size)
{
    struct nnpfs_message_installdata msg;
    struct nnpfs_message_header *h0;
    FCacheEntry *entry = NULL;
    CredCacheEntry *ce;
    VenusFid fid;
    int ret;
    
    fid = *(VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "open (%ld.%lu.%lu.%lu)",
		(long)fid.Cell, (unsigned long)fid.fid.Volume,
		(unsigned long)fid.fid.Vnode,
		(unsigned long)fid.fid.Unique);

    worker_setdebuginfo("message open");

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);
    
    worker_setdebuginfo("message open fcache_get");

    ret = fcache_get(&entry, fid, ce);
    if (ret)
	goto out;
    
    assert_flag(entry,kernelp);
    
 tryagain:

    worker_setdebuginfo("message open cm_getattr");
    
    ret = cm_getattr(entry, ce);
    
    if (try_again (&ret, &ce, &h->cred, &fid))
	goto tryagain;
    if (ret)
	goto out;
    
    if (entry->status.FileType == TYPE_DIR) {
	if (h->tokens & NNPFS_DATA_W) {
	    ret = EACCES;
	    goto out;
	}
	
	worker_setdebuginfo("message open fcache_get_data");
	
	ret = fcache_get_data (&entry, &ce, 0,
			       fcache_get_status_length(&entry->status));
	if (try_again (&ret, &ce, &h->cred, &fid))
	    goto tryagain;
	if (ret)
	    goto out;
	fid = entry->fid;
	
	ret = conv_dir(entry, ce, h->tokens);
	if (ret)
	    goto out;
	
	entry->tokens |= h->tokens;
	assert_flag(entry,kernelp);
	 
	h0 = make_installdata(&msg, entry, 0, 0);
    } else {
	worker_setdebuginfo("message open cm_open");
	ret = cm_open (entry, ce, h->tokens);
	if (try_again (&ret, &ce, &h->cred, &fid))
	    goto tryagain;
	if (ret)
	    goto out;
	
	h0 = make_installdata(&msg, entry, NNPFS_NO_OFFSET, 0);
    }
    
    worker_setdebuginfo("message open wakeup");
    
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					&msg, sizeof(msg),
					NULL, 0);
    
    worker_setdebuginfo("message open prefetching");

    prefetch_data(&entry, &ce);

    fcache_release(entry);
    cred_free (ce);
    return ret;

 out:

    if (entry)
	fcache_release(entry);
    cred_free (ce);
    nnpfs_send_message_wakeup_multiple (fd,
					h->header.sequence_num,
					ret,
					NULL, 0);
    return ret;
}

#define NUM_INSTALLDATA 10

static int
send_installdata_range(int fd, FCacheEntry *node,
		       uint64_t offset, uint64_t end,
		       struct nnpfs_message_installdata *proto)
{
    struct nnpfs_message_installdata n_msg[NUM_INSTALLDATA];
    struct nnpfs_message_installdata *msg = &n_msg[0];
    uint64_t blocksize = fcache_getblocksize();
    uint64_t i, n, off;
    Bool kernelp = TRUE;
    int ret = 0;

    if (end <= offset)
	n = 1;
    else
	n = (end - offset - 1) / blocksize + 1;

    if (n > NUM_INSTALLDATA) {
	void *tmp = malloc(n * sizeof(msg[0]));
	if (tmp) {
	    msg = tmp;
	} else {
	    /* oh well, maybe we can add a few at least */
	    n = NUM_INSTALLDATA;
	}
    }

    for (i = 0, off = offset; i < n; i++, off += blocksize) {
	msg[i] = *proto;
	msg[i].offset = off;
    }
    fcache_data_setbusy(node, offset, off, TRUE);
    
    if (node->flags.appended) {
	uint64_t length = fcache_get_status_length(&node->status);
	uint64_t lastoff = off - blocksize;
	if (block_end_offset(length) == lastoff) {
	    ret = abuf_truncate_block(node, lastoff, blocksize);
	    if (ret)
		arla_warn(ADEBWARN, ret,
			  "block truncate failed for (%ld.%lu.%lu.%lu) @%llu",
			  (long)node->fid.Cell,
			  (unsigned long)node->fid.fid.Volume,
			  (unsigned long)node->fid.fid.Vnode,
			  (unsigned long)node->fid.fid.Unique,
			  (unsigned long long)lastoff);
	}
    }
    
    arla_warnx(ADEBMSG, "  sending %llu installdata from %llu to %llu",
	       (unsigned long long)n,
	       (unsigned long long)offset, (unsigned long long)end);

    if (!ret)
	ret = nnpfs_send_message_multiple_list(fd,
					       (struct nnpfs_message_header *)msg,
					       sizeof (msg[0]),
					       n);
    if (msg != &n_msg[0])
	free(msg);

    if (ret)
	kernelp = FALSE;

    for (i = 0, off = offset; i < n; i++, off += blocksize)
	fcache_data_setkernelp(node, off, kernelp, TRUE);

    return ret;
}

static int
nnpfs_message_getdata (int fd, struct nnpfs_message_getdata *h, u_int size)
{
    struct nnpfs_message_installdata msg;
    VenusFid fid;
    CredCacheEntry *ce;
    int ret;
    uint64_t offset, end, length;
    FCacheEntry *entry = NULL;

    worker_setdebuginfo("message getdata");

    fid = *(VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "getdata (%ld.%lu.%lu.%lu)",
		(long)fid.Cell, (unsigned long)fid.fid.Volume,
		(unsigned long)fid.fid.Vnode,
		(unsigned long)fid.fid.Unique);

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    ret = fcache_get(&entry, fid, ce);
    if (ret)
	goto out;

    assert_flag(entry,kernelp);

 tryagain:
    
    worker_setdebuginfo("getdata getattr");

    ret = cm_getattr(entry, ce);
    
    if (try_again (&ret, &ce, &h->cred, &fid))
	goto tryagain;
    if (ret)
	goto out;
    
    length = fcache_get_status_length(&entry->status);
    
    offset = h->offset;
    
    assert(offset % fcache_getblocksize() == 0);
    assert(offset < length || (offset == length && length == 0));
    
    if (entry->status.FileType == TYPE_DIR) {
	end = length;
    } else {
	end = block_next_offset(h->offset + h->len);
	if (end > length)
	    end = length;
    }
    
    /* The first block is always there. */
    if (end == 0) {
	ret = fcache_set_have(entry, end, end);
	if (ret) {
	    arla_warn(ADEBMSG, ret, "nnpfs_message_getdata: set_have");
	    goto out;
	}
    }

    arla_warnx (ADEBMSG, "  requested block at %lu fetching to byte %lu",
		(unsigned long)h->offset, (unsigned long)end);

    worker_setdebuginfo("getdata getdata");

    ret = fcache_get_data(&entry, &ce, offset, end);
    if (try_again (&ret, &ce, &h->cred, &fid))
	goto tryagain;
    if (ret)
	goto out;
     
    worker_setdebuginfo("getdata done");

    if (entry->status.FileType == TYPE_DIR) {
      	ret = conv_dir(entry, ce, h->tokens);
	if (ret)
	    goto out;
#if 0
	msg.flag = NNPFS_ID_INVALID_DNLC;               /* paranoia */
#endif
    }

    if (h->tokens & NNPFS_DATA_W)
	entry->tokens |= NNPFS_DATA_W;
    arla_warnx (ADEBMSG, "  got %lu", (unsigned long)end);

    make_installdata(&msg, entry, NNPFS_NO_OFFSET, 0);
    
    send_installdata_range(fd, entry, offset, end, &msg);
    nnpfs_send_message_wakeup(fd, h->header.sequence_num, ret);

    prefetch_data(&entry, &ce);
     
    fcache_release(entry);
    cred_free (ce);
    return ret;

 out:
    if (entry)
	fcache_release(entry);
    cred_free (ce);
    nnpfs_send_message_wakeup(fd, h->header.sequence_num, ret);

    return ret;
}

/*
 * Send a invalid node to the kernel to invalidate `entry'
 * and record that it's not being used in the kernel.
 */

void
break_callback (FCacheEntry *entry)
{
    struct nnpfs_message_invalidnode msg;
    enum { CALLBACK_BREAK_WARN = 100 };
    static int failed_callbacks_break = 0;
    int ret;

    assert_flag(entry,kernelp);

    /* 
     * Throw away tokens for all directories and unused entries.
     * needs to be same as NNPFS_MSG_INVALIDNODE processing in
     * nnpfs
     */
    if (entry->status.FileType == TYPE_DIR || !entry->flags.datausedp)
	entry->tokens = 0;

    msg.header.opcode = NNPFS_MSG_INVALIDNODE;
    memcpy (&msg.handle, &entry->fid, sizeof(entry->fid));
    ret = nnpfs_message_send (kernel_fd, (struct nnpfs_message_header *)&msg, 
			      sizeof(msg));
    if (ret == EISDIR) {
	/* 
	 * Ignore EISDIR for invalidnode since that means that a
	 * message is on route to arlad to tell it the node is on the
	 * way out from the cache.
	 */
    } else if (ret) {
	arla_warnx (ADEBMSG, "break_callback: (%ld.%lu.%lu.%lu) failed",
		    (long)entry->fid.Cell, 
		    (unsigned long)entry->fid.fid.Volume,
		    (unsigned long)entry->fid.fid.Vnode,
		    (unsigned long)entry->fid.fid.Unique);
	++failed_callbacks_break;
	if (failed_callbacks_break > CALLBACK_BREAK_WARN) {
	    arla_warnx (ADEBWARN, "break_callback: have failed %d times",
			failed_callbacks_break);
	    failed_callbacks_break = 0;
	}
    }
}

/*
 * Send an unsolicited install-attr for the node in `e'
 */

void
install_attr (FCacheEntry *e, int flags)
{
    struct nnpfs_message_installattr msg;
    struct nnpfs_message_header *h;

    memset (&msg, 0, sizeof(msg));
    h = make_installattr(&msg, e, flags);
    
    nnpfs_message_send(kernel_fd, h, sizeof(msg));
}

void
update_fid(VenusFid oldfid, FCacheEntry *old_entry,
	   VenusFid newfid, FCacheEntry *new_entry)
{
    struct nnpfs_message_updatefid msg;

    msg.header.opcode = NNPFS_MSG_UPDATEFID;
    memcpy (&msg.old_handle, &oldfid, sizeof(oldfid));
    memcpy (&msg.new_handle, &newfid, sizeof(newfid));
    nnpfs_message_send (kernel_fd, (struct nnpfs_message_header *)&msg,
			sizeof(msg));
    if (new_entry != NULL) {
	fcache_node_setkernelp(new_entry, TRUE);
	new_entry->flags.attrusedp = TRUE;
    }
    if (old_entry != NULL) {
	fcache_node_setkernelp(old_entry, FALSE);
	old_entry->flags.attrusedp = FALSE;
	old_entry->flags.datausedp = FALSE;
	old_entry->tokens &= ~NNPFS_DATA_MASK;
    }
}

/*
 * Currently kernel never sends inactivenode w/o NNPFS_DELETE set, and
 * we don't handle that case properly.
 */

static int
nnpfs_message_inactivenode (int fd, struct nnpfs_message_inactivenode *h, 
			    u_int size)
{
    FCacheEntry *entry;
    VenusFid *fid;

    if (h->flag & NNPFS_DELETE)
	fcache_cleaner_ref();
    else
	arla_warnx(ADEBWARN, "inactivenode (%ld.%lu.%lu.%lu)"
		   "w/o NNPFS_DELETE!",
		   (long)fid->Cell, (unsigned long)fid->fid.Volume,
		   (unsigned long)fid->fid.Vnode,
		   (unsigned long)fid->fid.Unique);
    
    fid = (VenusFid *)&h->handle;
    arla_warnx (ADEBMSG, "inactivenode (%ld.%lu.%lu.%lu)",
		(long)fid->Cell, (unsigned long)fid->fid.Volume,
		(unsigned long)fid->fid.Vnode,
		(unsigned long)fid->fid.Unique);

    entry = fcache_find(*fid);
    if (!entry) {
	arla_warnx (ADEBWARN, "nnpfs_message_inactivenode: node not found "
		    "(%ld.%lu.%lu.%lu)",
		    (long)fid->Cell, (unsigned long)fid->fid.Volume,
		    (unsigned long)fid->fid.Vnode,
		    (unsigned long)fid->fid.Unique);
	goto out;
    }

    /* non-delete messages may arrive out of order w/ no harm */
    if ((h->flag & NNPFS_DELETE) == 0 && entry->flags.kernelp == 0)
	goto out;
    
    assert_flag(entry,kernelp);

    if (h->flag & NNPFS_DELETE) {
	struct nnpfs_message_delete_node msg;

	fcache_node_setkernelp(entry, FALSE);

	msg.handle = h->handle;
	msg.header.opcode = NNPFS_MSG_DELETE_NODE;
	nnpfs_message_send (kernel_fd,
			    (struct nnpfs_message_header *)&msg,
			    sizeof(msg));
	fcache_unused(entry);
    }

out:
    if (h->flag & NNPFS_DELETE)
	fcache_cleaner_deref();

    if (entry)
	fcache_release(entry);

    return 0;
}

int
install_appendquota(int64_t diff)
{
    struct nnpfs_message_installquota msg;
    int ret;

    msg.header.opcode = NNPFS_MSG_INSTALLQUOTA;
    msg.appendbytes = diff;

    ret = nnpfs_message_send(kernel_fd, &msg.header, sizeof(msg));
    if (ret)
	arla_warnx(ADEBWARN, "install_appendquota returned %d", ret);
    assert(!ret);
    return ret;
}

static void
set_data_kernelp(VenusFid *fid, uint64_t offset, Bool kernelp)
{
    FCacheEntry *entry;
    int ret;

    if (kernelp) {
	worker_setdebuginfo("setkernelp find");
	entry = fcache_find(*fid);
    } else {
	worker_setdebuginfo("unsetkernelp find");
	entry = fcache_find_gcp(*fid, TRUE);
    }

    if (!entry) {
	arla_warnx(ADEBWARN, "set_data_kernelp: node not found "
		   "(%ld.%lu.%lu.%lu)",
		   (long)fid->Cell, (unsigned long)fid->fid.Volume,
		   (unsigned long)fid->fid.Vnode,
		   (unsigned long)fid->fid.Unique);
	return;
    }
    
    /* messages may arrive out of order? */
    if (entry->flags.kernelp) {
	if (kernelp) {
	    Bool exists = fcache_block_exists(entry, offset);
	    if (exists) {
		arla_warnx(ADEBWARN, "set_data_kernelp: append on existing block"
			   "(%ld.%lu.%lu.%lu)@%llu",
			   (long)fid->Cell, (unsigned long)fid->fid.Volume,
			   (unsigned long)fid->fid.Vnode,
			   (unsigned long)fid->fid.Unique,
			   (unsigned long long)offset);
		
		worker_setdebuginfo("setkernelp");
		fcache_data_setkernelp(entry, offset, kernelp, FALSE);
		ret = install_appendquota(fcache_getblocksize());
	    } else {
		ret = fcache_append_block(entry, offset);
		if (ret) {
		    arla_warnx(ADEBWARN, "set_data_kernelp: "
			       "create (%ld.%lu.%lu.%lu)@%llu returned %d",
			       (long)fid->Cell, (unsigned long)fid->fid.Volume,
			       (unsigned long)fid->fid.Vnode,
			       (unsigned long)fid->fid.Unique,
			       (unsigned long long)offset,
			       ret);
		} else {
		    ret = fcache_update_appendquota(entry);
		}
		entry->flags.appended = TRUE;
	    }
	} else {
	    worker_setdebuginfo("setkernelp");
	    fcache_data_setkernelp(entry, offset, kernelp, FALSE);
	}
    } else  {
	arla_warnx(ADEBWARN, "set_data_kernelp: node not in kernel "
		   "(%ld.%lu.%lu.%lu)",
		   (long)fid->Cell, (unsigned long)fid->fid.Volume,
		   (unsigned long)fid->fid.Vnode,
		   (unsigned long)fid->fid.Unique);
    }

    worker_setdebuginfo("release");
    fcache_release(entry);
    return;
}

static int 
nnpfs_message_appenddata(int fd,struct nnpfs_message_appenddata *h, u_int size)
{
    VenusFid *fid = (VenusFid *)&h->handle;

    arla_warnx(ADEBMSG, "nnpfs_message_appenddata (%ld.%lu.%lu.%lu), offset %llu",
	       (long)fid->Cell, (unsigned long)fid->fid.Volume,
	       (unsigned long)fid->fid.Vnode,
	       (unsigned long)fid->fid.Unique,
	       (unsigned long long)h->offset);
    
    set_data_kernelp(fid, h->offset, TRUE);

    return 0;
}

/*
 * Block has been dropped from kernel.
 */

static int 
nnpfs_message_deletedata (int fd,struct nnpfs_message_deletedata *h, u_int size)
{
    VenusFid *fid = (VenusFid *)&h->handle;

    arla_warnx(ADEBMSG, "nnpfs_message_deletedata (%ld.%lu.%lu.%lu), offset %llu",
	       (long)fid->Cell, (unsigned long)fid->fid.Volume,
	       (unsigned long)fid->fid.Vnode,
	       (unsigned long)fid->fid.Unique,
	       (unsigned long long)h->offset);
    
    fcache_cleaner_ref();
    set_data_kernelp(fid, h->offset, FALSE);
    fcache_cleaner_deref();

    return 0;
}

static int 
nnpfs_message_accesses (int fd,struct nnpfs_message_accesses *h, u_int size)
{
    arla_warnx(ADEBWARN, "accesses not implemented");

    return 0;
}


/*
 * Do we have powers for changing stuff?
 */

static Bool
all_powerful_p (const nnpfs_cred *cred)
{
    return cred->uid == 0;
}

/*
 * Flush the contents of a volume
 */

static int
viocflushvolume (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid ;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return EINVAL;

    fid.Cell = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode = 0;
    fid.fid.Unique = 0;

    arla_warnx(ADEBMSG,
	       "flushing volume (%d, %u)",
	       fid.Cell, fid.fid.Volume);

    fcache_purge_volume(fid);
    volcache_invalidate (fid.fid.Volume, fid.Cell);
    return 0 ;
}

/*
 * Get an ACL for a directory
 */

static int
viocgetacl(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    AFSOpaque opaque;
    CredCacheEntry *ce;
    int error;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    fid.Cell = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    do {
	error = getacl (fid, ce, &opaque);
    } while (try_again (&error, &ce, &h->cred, &fid));

    if (error != 0 && error != EACCES)
	error = EINVAL;

    cred_free (ce);
 
    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    opaque.val, opaque.len);
    if (error == 0)
	free (opaque.val);
    return 0;
}

/*
 * Set an ACL for a directory
 */

static int
viocsetacl(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    AFSOpaque opaque;
    CredCacheEntry *ce;
    FCacheEntry *e;
    int error;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    if (h->insize > AFSOPAQUEMAX || h->insize == 0)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    opaque.val = malloc(h->insize);
    if(opaque.val == NULL)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOMEM);

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    opaque.len = h->insize;
    memcpy(opaque.val, h->msg, h->insize);

    do {
	error = setacl (fid, ce, &opaque, &e);
    } while (try_again (&error, &ce, &h->cred, &fid));

    if (error == 0) {
	install_attr (e, FCACHE2NNPFSNODE_ALL);
	fcache_release (e);
    } else if (error != EACCES)
	error = EINVAL;

    cred_free (ce);
    free (opaque.val);
 
    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error, NULL, 0);
    return 0;
}

/*
 * Get volume status
 */

static int
viocgetvolstat(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce;
    AFSFetchVolumeStatus volstat;
    char volumename[AFSNAMEMAX];
    char offlinemsg[AFSOPAQUEMAX];
    char motd[AFSOPAQUEMAX];
    char out[SYSNAMEMAXLEN];
    int32_t outsize = 0;
    int error;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    fid.Cell = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode = 0;
    fid.fid.Unique = 0;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    memset (volumename, 0, AFSNAMEMAX);
    memset (offlinemsg, 0, AFSOPAQUEMAX);
    memset (motd, 0, AFSOPAQUEMAX);
    memset (out, 0, SYSNAMEMAXLEN);

    do {
	error = getvolstat (fid, ce, &volstat,
			    volumename, sizeof(volumename),
			    offlinemsg,
			    motd);
    } while (try_again (&error, &ce, &h->cred, &fid));

    cred_free (ce);

    if (error != 0 && error != EACCES)
	error = EINVAL;

    memcpy (out, (char *) &volstat, sizeof (AFSFetchVolumeStatus));
    outsize = sizeof (AFSFetchVolumeStatus);

    if (volumename[0]) {
	strncpy (out+outsize, volumename, AFSNAMEMAX);
	outsize += strlen (volumename);
    }
    else {
	out[outsize] = 0;
	outsize++;
    }

    if (offlinemsg[0]) {
	strncpy (out+outsize, offlinemsg, AFSOPAQUEMAX);
	outsize += strlen (offlinemsg);
    }
    else {
	out[outsize] = 0;
	outsize++;
    }

    if (motd[0]) {
	strncpy (out+outsize, motd, AFSOPAQUEMAX);
	outsize += strlen (motd);
    }
    else {
	out[outsize] = 0;
	outsize++;
    }

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    out, outsize);
    return 0;
}

/*
 * Set volume status
 */

static int
viocsetvolstat(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce;
    AFSFetchVolumeStatus *involstat;
    AFSStoreVolumeStatus outvolstat;
    char volumename[AFSNAMEMAX];
    char offlinemsg[AFSOPAQUEMAX];
    char motd[AFSOPAQUEMAX];
    int error;
    char *ptr;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return EINVAL;

    fid.Cell = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode = 0;
    fid.fid.Unique = 0;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    involstat = (AFSFetchVolumeStatus *) h->msg;
    outvolstat.Mask = 0x3; /* Store both the next fields */
    outvolstat.MinQuota = involstat->MinQuota;
    outvolstat.MaxQuota = involstat->MaxQuota;

    ptr = h->msg + sizeof (AFSFetchVolumeStatus);

#if 0
    if (*ptr) {
	strncpy (volumename, ptr, AFSNAMEMAX);
	ptr += strlen (ptr);
    }
    else {
	memset (volumename, 0, AFSNAMEMAX);
	ptr++; /* skip 0 character */
    }

    if (*ptr) {
	strncpy (offlinemsg, ptr, AFSOPAQUEMAX);
	ptr += strlen (ptr);
    }
    else {
	memset (offlinemsg, 0, AFSOPAQUEMAX);
	ptr++;
    }

    strncpy (motd, ptr, AFSOPAQUEMAX);
#else
    volumename[0] = '\0';
    offlinemsg[0] = '\0';
    motd[0] = '\0';
#endif

    do {
	error = setvolstat (fid, ce, &outvolstat, volumename,
			    offlinemsg, motd);
    } while (try_again (&error, &ce, &h->cred, &fid));

    if (error != 0 && error != EACCES)
	error = EINVAL;

    cred_free (ce);

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    NULL, 0);
    return 0;
}

/*
 * Get the mount point at (`fid', `filename') using the cred in `ce'
 * and returning the fcache entry in `ret_mp_entry'
 * Return 0 or an error.
 */

static int
get_mount_point (VenusFid fid,
		 const char *filename,
		 CredCacheEntry **ce,
		 FCacheEntry **ret_mp_entry)
{
    FCacheEntry *mp_entry;
    FCacheEntry *dentry;
    VenusFid mp_fid;
    int error;

    if (fid.fid.Volume == 0 && fid.fid.Vnode == 0 && fid.fid.Unique == 0)
	return EINVAL;

    error = fcache_get(&dentry, fid, *ce);
    if (error)
	return error;

    error = fcache_get_data(&dentry, ce, 0, 0);
    if (error) {
	fcache_release(dentry);
	return error;
    }

    error = adir_lookup(dentry, filename, &mp_fid);
    if (error) {
	fcache_release(dentry);
	return error;
    }

    if (VenusFid_cmp(&dentry->fid, &mp_fid) == 0) {
	mp_entry = dentry;
    } else {
	error = fcache_get(&mp_entry, mp_fid, *ce);
	if (error) {
	    fcache_release(dentry);
	    return error;
	}
    }

    error = fcache_verify_attr (mp_entry, dentry, filename, *ce);
    if (mp_entry != dentry)
	fcache_release(dentry);
    if (error) {
	fcache_release(mp_entry);
	return error;
    }

    if ((mp_entry->status.FileType != TYPE_LINK
	 && !mp_entry->flags.fake_mp)
	|| fcache_get_status_length(&mp_entry->status) == 0) { 	/* Is not a mount point */
	fcache_release(mp_entry);
	return EINVAL;
    }
    *ret_mp_entry = mp_entry;
    return 0;
}

/*
 * Read the contents of the mount point in `mp_entry' into `buf',
 * check they look valid and null-terminate.
 * Return 0 or an error
 */

static int
read_mount_point (FCacheEntry **mp_entry, CredCacheEntry **ce,
		  char *buf, int buflen, int *outlen)
{
    int error;
    int len;
    fbuf f;

    error = fcache_get_data (mp_entry, ce, 0, 0);
    if (error)
	return error;

    error = fcache_get_fbuf(*mp_entry, &f, FBUF_READ);
    if (error)
	return error;
    
    len = fbuf_len(&f);
    if (len >= buflen || len <= 0) {
	abuf_end(&f);
	arla_warnx(ADEBWARN, "mountpoint with bad length: %d", len);
	return EIO;
    }
    
    memcpy(buf, fbuf_buf(&f), buflen);
    abuf_end(&f);

    if (buf[0] != '#' && buf[0] != '%') /* Is not a mount point */
	return EINVAL;

    /*
     * To confuse us, the volume is passed up w/o the ending
     * dot. It's not even mentioned in the ``VIOC_AFS_STAT_MT_PT''
     * documentation.
     */

    buf[len - 1] = '\0';
    *outlen = len;

    return 0;
}

/*
 * Get info for a mount point.
 */

static int
vioc_afs_stat_mt_pt(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    int error;
    CredCacheEntry *ce;
    FCacheEntry *e;
    char buf[MAXPATHLEN]; /* AFSNAMEMAX would suffice */
    int len;

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    h->msg[min(h->insize, sizeof(h->msg)-1)] = '\0';

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    error = get_mount_point (fid, h->msg, &ce, &e);
    if (error) {
	cred_free(ce);
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    }

    error = read_mount_point(&e, &ce, buf, sizeof(buf), &len);
    if (error) {
	fcache_release (e);
	cred_free(ce);
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    }

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    buf, len);
    fcache_release (e);
    cred_free (ce);

    return 0;
}

/*
 * Handle the VIOC_AFS_DELETE_MT_PT message in `h' by deleting the
 * mountpoint.  
 */

static int
vioc_afs_delete_mt_pt(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    int error = 0;
    CredCacheEntry *ce;
    struct nnpfs_message_remove remove_msg;
    FCacheEntry *entry;

    h->msg[min(h->insize, sizeof(h->msg)-1)] = '\0';

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    error = get_mount_point (fid, h->msg, &ce, &entry);
    cred_free (ce);
    if (error)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    fcache_release(entry);

    remove_msg.header        = h->header;
    remove_msg.header.size   = sizeof(remove_msg);
    remove_msg.parent_handle = h->handle;
    strlcpy(remove_msg.name, h->msg, sizeof(remove_msg.name));
    remove_msg.cred          = h->cred;

    return nnpfs_message_remove (fd, &remove_msg, sizeof(remove_msg));
}

static int
viocwhereis(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce;
    FCacheEntry *e;
    int error;
    int i, j;
    int32_t addresses[8];
    int bit;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    error = fcache_get(&e, fid, ce);
    if (error) {
	cred_free(ce);
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    }
    error = fcache_verify_attr (e, NULL, NULL, ce);
    if (error) {
	fcache_release(e);
	cred_free(ce);
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    }

    bit = volcache_volid2bit (e->volume, fid.fid.Volume);

    if (bit == -1) {
	fcache_release(e);
	cred_free(ce);
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);
    }

    memset(addresses, 0, sizeof(addresses));
    for (i = 0, j = 0; i < min(e->volume->entry.nServers, MAXNSERVERS); i++) {
	u_long addr = htonl(e->volume->entry.serverNumber[i]);

	if ((e->volume->entry.serverFlags[i] & bit) && addr != 0)
	    addresses[j++] = addr;
    }
    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    addresses, sizeof(long) * j);

    fcache_release(e);
    cred_free (ce);

    return 0;
}

/*
 * Return all db servers for a particular cell.
 */ 

static int
vioc_get_cell(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int i;
    int32_t index;
    const char *cellname;
    int cellname_len;
    int outsize;
    char out[8 * sizeof(int32_t) + MAXPATHLEN]; /* XXX */
    const cell_db_entry *dbservers;
    int num_dbservers;

    index = *((int32_t *) h->msg);
    cellname = cell_num2name(index);
    if (cellname == NULL)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EDOM);
    
    dbservers = cell_dbservers_by_id (index, &num_dbservers);

    if (dbservers == NULL)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EDOM);

    memset(out, 0, sizeof(out));
    cellname_len = min(strlen(cellname), MAXPATHLEN - 1);
    memcpy(out + 8 * sizeof(int32_t), cellname, cellname_len);
    out[8 * sizeof(int32_t) + cellname_len] = '\0';
    outsize = 8 * sizeof(int32_t) + cellname_len + 1;
    for (i = 0; i < min(num_dbservers, 8); ++i) {
	uint32_t addr = dbservers[i].addr.s_addr;
	memcpy (&out[i * sizeof(int32_t)], &addr, sizeof(int32_t));
    }

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
				    out, outsize);

    return 0;
}

/*
 * Return status information about a cell.
 */

static int
vioc_get_cellstatus(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *cellname;
    int32_t cellid;
    uint32_t out = 0;

    cellname = h->msg;
    cellname[h->insize-1]  = '\0';

    cellid = cell_name2num (cellname);
    if (cellid == -1)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOENT);

    if (cellid == 0)
	out |= arla_CELLSTATUS_PRIMARY;
    if (cell_issuid_by_num (cellid))
	out |= arla_CELLSTATUS_SETUID;

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
				    &out, sizeof(out));

    return 0;
}

/*
 * Set status information about a cell.
 */

static int
vioc_set_cellstatus(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int32_t cellid;
    char *cellname;
    uint32_t in = 0;
    int ret;

    if (!all_powerful_p (&h->cred))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EACCES);

    if (h->insize < sizeof (in) + 2) /* terminating NUL and one char */
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    cellname = h->msg + sizeof (in);
    cellname[h->insize-1-sizeof(in)]  = '\0';

    cellid = cell_name2num (cellname);
    if (cellid == -1)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOENT);

    if (in & arla_CELLSTATUS_SETUID) { 
	ret = cell_setsuid_by_num (cellid);
	if (ret)
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,EINVAL);
    }

    nnpfs_send_message_wakeup (fd, h->header.sequence_num, 0);

    return 0;
}

/*
 * Set information about a cell or add a new one.
 */

static int
vioc_new_cell(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    const char *cellname;
    cell_entry *ce;
    int count, i;
    uint32_t *hp;
    cell_db_entry *dbs;

    if (!all_powerful_p (&h->cred))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EPERM);
	    
    if (h->insize < 9)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    hp = (uint32_t *)h->msg;
    for (count = 0; *hp != 0; ++hp)
	++count;

    dbs = malloc (count * sizeof(*dbs));
    if (dbs == NULL)
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOMEM);
	
    memset(dbs, 0, count * sizeof(*dbs));

    hp = (uint32_t *)h->msg;
    for (i = 0; i < count; ++i) {
	dbs[i].name = NULL;
	dbs[i].addr.s_addr = hp[i];
	dbs[i].timeout = 0;
    }

    cellname = h->msg + 8 * sizeof(uint32_t);
    ce = cell_get_by_name (cellname);
    if (ce == NULL) {
	ce = cell_new_dynamic (cellname);

	if (ce == NULL) {
	    free (dbs);
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					      ENOMEM);
	}
    } else {
	free (ce->dbservers);
    }

    ce->ndbservers = count;
    ce->dbservers  = dbs;

    return nnpfs_send_message_wakeup (fd, h->header.sequence_num, 0);
}

#ifdef KERBEROS

/*
 * Return the token for the cell in `ce'
 */

static int
token_for_cell (int fd, struct nnpfs_message_pioctl *h, u_int size,
		CredCacheEntry *ce)
{
    char buf[NNPFS_MSG_MAX_DATASIZE];
    size_t len, cell_len;
    char *p = buf;
    uint32_t tmp;
    struct cred_rxkad *cred = (struct cred_rxkad *)ce->cred_data;
    const char *cell = cell_num2name (ce->cell);

    cell_len = strlen(cell);

    len = 4 + cred->ticket_len + 4 + sizeof(cred->ct) + 4 + cell_len;
    if (len > sizeof(buf))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    tmp = cred->ticket_len;
    memcpy (p, &tmp, sizeof(tmp));
    p += sizeof(tmp);
    memcpy (p, cred->ticket, tmp);
    p += tmp;
    tmp = sizeof(cred->ct);
    memcpy (p, &tmp, sizeof(tmp));
    p += sizeof(tmp);
    memcpy (p, &cred->ct, sizeof(cred->ct));
    p += sizeof(cred->ct);
    tmp = 0;
    memcpy (p, &tmp, sizeof(tmp));
    p += sizeof(tmp);
    strcpy (p, cell);
    p += strlen(cell) + 1;

    len = p - buf;

    cred_free (ce);

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
				    buf, len);
    return 0;
}

struct get_tok {
    int32_t counter;
    int32_t cell;
};

static int
gettok_func(CredCacheEntry *ce, void *ptr)
{
    struct get_tok *gt = ptr;

    if (gt->counter == 0) {
	gt->cell = ce->cell;
	return 1;
    }

    gt->counter--;
    return 0;
}


/*
 * Handle the GETTOK message in `h'
 */

static int
viocgettok (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    CredCacheEntry *ce;
    int32_t cell_id;

    if (h->insize == 0) {
	cell_id = cell_name2num(cell_getthiscell());
    } else if (h->insize == sizeof(uint32_t)) {
	struct get_tok gt;
	int32_t n;

	memcpy (&n, h->msg, sizeof(n));

	if (n < 0) {
	    nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);
	    return 0;
	}

	gt.counter = n;
	gt.cell = -1;

	cred_list_pag(h->cred.pag, CRED_KRB4, gettok_func, &gt);

	if (gt.cell == -1) {
	    nnpfs_send_message_wakeup (fd, h->header.sequence_num, EDOM);
	    return 0;
	}

	cell_id = gt.cell;
    } else {
	nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);
	return 0;
    }

    ce = cred_get (cell_id, h->cred.pag, CRED_KRB4);
    if (ce == NULL) {
	nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOTCONN);
	return 0;
    }

    return token_for_cell (fd, h, size, ce);
}

/*
 * Handle the SETTOK message in `h'
 */

static int
viocsettok (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    struct cred_rxkad cred;
    long cell;
    char realm[256];
    int32_t sizeof_x;
    char *t = h->msg;

    /* someone probed us */
    if (h->insize == 0)
	return EINVAL;
    if (h->insize < 4)
	return EINVAL;

    /* Get ticket_st */
    memcpy(&sizeof_x, t, sizeof(sizeof_x)) ;
    cred.ticket_len = sizeof_x;
    arla_warnx (ADEBMSG, "ticket_st has size %d", sizeof_x);
    t += sizeof(sizeof_x) ;

    /* data used + datalen + cleartoken's length field */
    if ((t - (char *)h->msg) + sizeof_x + 4 > h->insize)
	return EINVAL;
    if (sizeof_x > sizeof(cred.ticket))
	return EINVAL;
    
    memcpy(cred.ticket, t, sizeof_x) ;
    t += sizeof_x ;
    
    /* Get ClearToken */
    memcpy(&sizeof_x, t, sizeof(sizeof_x)) ;
    t += sizeof(sizeof_x) ;
    
    /* data used + datalen + cell's length field */
    if ((t - (char *)h->msg) + sizeof_x + 4 > h->insize)
	return EINVAL;
    
    memcpy(&cred.ct, t, sizeof_x) ;
    t += sizeof_x ;

    /* Get primary cell ? */
    memcpy(&sizeof_x, t, sizeof(sizeof_x)) ;
    t += sizeof(sizeof_x) ;
    
    /* Get Cellname */ 
    strlcpy(realm, t, min(h->insize - (t - (char *)h->msg), sizeof(realm)));
    strlwr(realm);

    cell = cell_name2num(realm);

    if (cell == -1)
	return ENOENT;

    conn_clearcred (CONN_CS_ALL, cell, h->cred.pag, 2);
    fcache_purge_cred(h->cred.pag, cell);
    cred_add (h->cred.pag, CRED_KRB4, 2, cell, cred.ct.EndTimestamp,
	      &cred, sizeof(cred), cred.ct.ViceId);
    return 0;
}

/*
 * Handle the SETTOK message in `h'
 */

static int
viocsettok2 (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *t = h->msg;
    const char *tret;
    int32_t cell;
    pioctl_set_token o;
    size_t s = size;
    int i;

    /* someone probed us */
    if (h->insize == 0)
	return EINVAL;

    tret = ydr_decode_pioctl_set_token(&o, t, &s);
    if (tret == NULL)
	return EINVAL;

    strlwr(o.cell);

    cell = cell_name2num(o.cell);
    if (cell == -1) {
	ydr_free_pioctl_set_token(&o);
	return ENOENT;
    }

    for (i = 0; i < o.tokens.len; i++) {
	token_afs at;

	t = o.tokens.val[i].val;
	tret = ydr_decode_token_afs(&at, t, &s);
	if (tret == NULL)
	    continue;

	switch (at.at_type) {
	case 4: {
	    struct cred_rxgk *cred;
	    size_t credsize;

	    credsize = sizeof(*cred);
	    credsize += at.u.at_gk.gk_token.len;
	    credsize += at.u.at_gk.gk_key.len;
	    
	    cred = ecalloc(1, credsize);
	    cred->flags = at.u.at_gk.gk_flags;
	    cred->level = at.u.at_gk.gk_level;
	    cred->starttime = at.u.at_gk.gk_begintime;
	    cred->endtime = at.u.at_gk.gk_endtime;
	    cred->enctype = at.u.at_gk.gk_enctype;
	    cred->bytelife = at.u.at_gk.gk_bytelife;
	    cred->lifetime = at.u.at_gk.gk_lifetime;
	    cred->tokenlen = at.u.at_gk.gk_token.len;
	    cred->keylen = at.u.at_gk.gk_key.len;
	    memcpy(((unsigned char *)cred) + sizeof(*cred),
		   at.u.at_gk.gk_token.val, at.u.at_gk.gk_token.len);
	    memcpy(((unsigned char *)cred) + sizeof(*cred) + at.u.at_gk.gk_token.len,
		   at.u.at_gk.gk_key.val, at.u.at_gk.gk_key.len);

	    conn_clearcred (CONN_CS_ALL, cell, h->cred.pag, 5);
	    fcache_purge_cred(h->cred.pag, cell);
	    cred_add (h->cred.pag, CRED_RXGK, 5, cell, cred->endtime,
		      cred, credsize, 0);
	    free(cred);
	    
	    break;
	}
	default:
	    ydr_free_token_afs(&at);
	    continue;
	}
	ydr_free_token_afs(&at);
    }
    ydr_free_pioctl_set_token(&o);

    return 0;
}

#endif /* HAVE_KRB5 */

static int
viocunlog (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    nnpfs_pag_t cred = h->cred.pag;

    cred_remove(cred);
    fcache_purge_cred(cred, -1);
    return 0;
}

/*
 * Flush the fid in `h->handle' from the cache.
 */

static int
viocflush (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid ;
    AFSCallBack broken_callback = {0, 0, CBDROPPED};

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return EINVAL;

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    arla_warnx(ADEBMSG,
	       "flushing (%d, %u, %u, %u)",
	       fid.Cell, fid.fid.Volume, fid.fid.Vnode, fid.fid.Unique);

    fcache_stale_entry(fid, broken_callback);
    return 0 ;
}

int
get_connmode(int32_t *mode)
{
    switch(connected_mode) {
    case CONNECTED:
	*mode = arla_CONNMODE_CONN; break;
    case FETCH_ONLY:
	*mode = arla_CONNMODE_FETCH; break;
    case DISCONNECTED:
	*mode = arla_CONNMODE_DISCONN; break;
    default:
	*mode = 0;
	return EINVAL;
    }
    return 0;
}

int
set_connmode(int32_t mode, nnpfs_cred *cred)
{
    switch(mode) {
    case arla_CONNMODE_CONN:
    case arla_CONNMODE_CONN_WITHCALLBACKS:
	if (connected_mode == CONNECTED)
	    return 0;

	disco_closelog();
	
	cmcb_reinit();
	
	if (connected_mode == DISCONNECTED)
	    fcache_discard_attrs();

	if (disco_need_integrate())
	    disco_reintegrate(cred->pag);
	
	if (mode == arla_CONNMODE_CONN_WITHCALLBACKS)
	    fcache_reobtain_callbacks (cred);
	
	connected_mode = CONNECTED;
	break;
    case arla_CONNMODE_FETCH:
	if (connected_mode == CONNECTED)
	    disco_openlog();

	if (connected_mode == DISCONNECTED)
	    fcache_discard_attrs();

	connected_mode = FETCH_ONLY;
	break;
    case arla_CONNMODE_DISCONN:
	if (connected_mode == CONNECTED)
	    disco_openlog();
	
	if (possibly_have_network())
	    fcache_giveup_all_callbacks();

	connected_mode = DISCONNECTED;
	break;
    default:
	return EINVAL;
	break;
    }
    return 0;
}

static int
viocconnect(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *p = h->msg;
    int32_t tmp;
    int32_t ret;
    int error = 0;

    if (h->insize != sizeof(int32_t) ||
	h->outsize != sizeof(int32_t)) {

	ret = -EINVAL;
    } else {
    
	memcpy(&tmp, h->msg, sizeof(tmp));
	p += sizeof(tmp);

	ret = tmp;

	/* check permission */
	switch (tmp) {
	case arla_CONNMODE_PROBE:
	    break;
	default:
	    if (!all_powerful_p(&h->cred))
		return EPERM;
	    break;
	}

	switch(tmp) {
	case arla_CONNMODE_PROBE:
	    error = get_connmode(&ret);
	    break;
	default:
	    error = set_connmode(tmp, &h->cred);
	    break;
	}
    }

    nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, error,
				    &ret, sizeof(ret));
    return 0;
}

static int
getrxkcrypt(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    if (h->outsize == sizeof(uint32_t)) {
	uint32_t n;

#ifdef KERBEROS
	if (conn_rxkad_level == rxkad_crypt)
	    n = 1;
	else
#endif
	    n = 0;

	return nnpfs_send_message_wakeup_data (fd,
					       h->header.sequence_num,
					       0,
					       &n,
					       sizeof(n));
    } else
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);
}

static int
setrxkcrypt(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
#ifdef KERBEROS
    int error = 0;

    if (!all_powerful_p(&h->cred))
	return EPERM;

    if (h->insize == sizeof(uint32_t)) {
	uint32_t n;

	memcpy (&n, h->msg, sizeof(n));

	if (n == 0)
	    conn_rxkad_level = rxkad_auth;
	else if(n == 1)
	    conn_rxkad_level = rxkad_crypt;
	else
	    error = EINVAL;
	if (error == 0)
	    conn_clearcred (CONN_CS_SECIDX, 0, -1, 2);
    } else
	error = EINVAL;
    return error;
#else
    return EOPNOTSUPP;
#endif
}

/*
 * XXX - this function sometimes does a wakeup_data and then an ordinary wakeup is sent in nnpfs_message_pioctl
 */

static int
vioc_fpriostatus (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    struct arla_vioc_fprio *fprio;
    int error = 0;
    VenusFid fid;

    if (h->insize != sizeof(struct arla_vioc_fprio))
	return EINVAL;

    fprio = (struct arla_vioc_fprio *) h->msg;

    fid.Cell = fprio->Cell ;
    fid.fid.Volume = fprio->Volume ;
    fid.fid.Vnode = fprio->Vnode ;
    fid.fid.Unique = fprio->Unique ;

    if (!all_powerful_p(&h->cred))
	return EPERM;

#if 0
    switch(fprio->cmd) {
    case FPRIO_GET: {
	unsigned prio;

	if (h->outsize != sizeof(unsigned)) {
	    error = EINVAL;
	    break;
	}
	
	prio = fprio_get(fid);
	nnpfs_send_message_wakeup_data (fd,
					h->header.sequence_num,
					0,
					&prio,
					sizeof(prio));

	break;
    }
    case FPRIO_SET:
	if (fprio->prio == 0) {
	    fprio_remove(fid);
	    error = 0;
	} else if (fprio->prio < FPRIO_MIN ||
		   fprio->prio > FPRIO_MAX)
	    error = EINVAL;
	else {
	    fprio_set(fid, fprio->prio);
	    error = 0;
	}
	break;
    case FPRIO_GETMAX: 
	if (h->outsize != sizeof(unsigned)) {
	    error = EINVAL;
	    break;
	}

	nnpfs_send_message_wakeup_data (fd,
					h->header.sequence_num,
					0,
					&fprioritylevel,
					sizeof(fprioritylevel));
	error = 0;
	break;
    case FPRIO_SETMAX: 
	if (fprio->prio < FPRIO_MIN ||
	    fprio->prio > FPRIO_MAX)
	    error = EINVAL;
	else {
	    fprioritylevel = fprio->prio;
	    error = 0;
	}
	break;
    default:
	error = EINVAL;
	break;
    }
#endif
    return error;
}

static int
viocgetfid (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
					  &h->handle, sizeof(VenusFid));
}

static int
viocvenuslog (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    if (!all_powerful_p(&h->cred))
	return EPERM;
	    
    conn_status ();
    volcache_status ();
    cred_status ();
    fcache_status ();
    cell_status (stderr);
#if 0
    fprio_status ();
#endif
    rx_PrintStats(stderr);
    worker_printstatus();
    return 0;
}

/*
 * Set or get the sysname
 */

static int
vioc_afs_sysname (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *t = h->msg;
    int32_t parm = *((int32_t *)t);

    if (parm) {
	char t_sysname[SYSNAMEMAXLEN];
	int size;

	if (!all_powerful_p (&h->cred))
	    return nnpfs_send_message_wakeup (fd,
					      h->header.sequence_num,
					      EPERM);
	t += sizeof(int32_t);
	arla_warnx (ADEBMSG, "VIOC_AFS_SYSNAME: setting sysname: %s", t);

	size = min(h->insize, SYSNAMEMAXLEN);

	memcpy(t_sysname, t, size);
	t_sysname[size - 1] = '\0';

	fcache_setdefsysname (t_sysname);

	return nnpfs_send_message_wakeup(fd, h->header.sequence_num, 0);
    } else {
	char *buf;
	const char *sysname = fcache_getdefsysname ();
	size_t sysname_len = strlen (sysname);
	int ret;

	buf = malloc (sysname_len + 4 + 1);
	if (buf == NULL)
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					      ENOMEM);
	/* Return always 1 as we do not support sysname lists.             */
	/* Historically the value of this uint32 has been success/failure. */
	/* OpenAFS' utilities treat this value as the number of elements   */
	/* in a list of returned sysnames. It was never meant to be buflen.*/
	*((uint32_t *)buf) = 1;
	memcpy (buf + 4, sysname, sysname_len);
	buf[sysname_len + 4] = '\0';

	ret = nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					      buf, sysname_len + 5);
	free (buf);
	return ret;
    }
}

static int
viocfilecellname (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *cellname;

    cellname = (char *) cell_num2name(h->handle.a);

    if (cellname) 
	return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
					      cellname, strlen(cellname)+1);
    else 
	return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, EINVAL,
					      NULL, 0);
}

static int
viocgetwscell (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *cellname;

    cellname = (char*) cell_getthiscell();
    return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
					  cellname, strlen(cellname)+1);
}

static int
viocsetcachesize (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t *s = (uint32_t *)h->msg;

    if (!all_powerful_p (&h->cred))
	return EPERM;
	
    if (h->insize >= sizeof(int32_t) * 4) 
	return fcache_reinit(s[0], s[1], s[2], s[3]);
    else
	return fcache_reinit(*s/2, *s, *s*500, *s*1000);
}

/*
 * VIOCCKSERV
 *
 *  in:  flags	- bitmask (1 - dont ping, use cached data, 2 - check fsservers only)
 *       cell	- string (optional)
 *  out: hosts  - uint32_t number of hosts, followed by list of hosts being down.
 */

static int
viocckserv (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int32_t cell = cell_name2num (cell_getthiscell());
    int flags = 0;
    int num_entries;
    uint32_t hosts[arla_CKSERV_MAXSERVERS + 1];
    int msg_size;

    if (h->insize < sizeof(int32_t))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num, EINVAL);

    memset (hosts, 0, sizeof(hosts));

    flags = *(uint32_t *)h->msg;
    flags &= arla_CKSERV_DONTPING|arla_CKSERV_FSONLY;

    if (h->insize > sizeof(int32_t)) {
	h->msg[min(h->insize, sizeof(h->msg)-1)] = '\0';

	cell = cell_name2num (((char *)h->msg) + sizeof(int32_t));
	if (cell == -1)
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num, ENOENT);
    }
    
    num_entries = arla_CKSERV_MAXSERVERS;
    
    conn_downhosts(cell, hosts + 1, &num_entries, flags);
    
    hosts[0] = num_entries;
    msg_size = sizeof(hosts[0]) * (num_entries + 1);
    return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					   hosts, msg_size);
}


/*
 * Return the number of used KBs and reserved KBs
 */

static int
viocgetcacheparms (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t parms[16];
    
    memset(parms, 0, sizeof(parms));
    parms[0] = fcache_highbytes() / 1024;
    parms[1] = fcache_usedbytes() / 1024;
    parms[2] = fcache_highvnodes();
    parms[3] = fcache_usedvnodes();
    parms[4] = fcache_highbytes();
    parms[5] = fcache_usedbytes();
    parms[6] = fcache_lowbytes();
    parms[7] = fcache_lowvnodes();

    h->outsize = sizeof(parms);
    return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
					  parms, sizeof(parms));
}

/*
 * debugging interface to give out statistics of the cache
 */

static int
viocaviator (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t parms[16];
    
    memset(parms, 0, sizeof(parms));
    parms[0] = kernel_highworkers();
    parms[1] = kernel_usedworkers();

    h->outsize = sizeof(parms);
    return nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
					  parms, sizeof(parms));
}

/*
 * Get/set arla debug level
 */

static int
vioc_arladebug (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    if (h->insize != 0) {
	if (h->insize < sizeof(int32_t))
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					      EINVAL);
	if (!all_powerful_p (&h->cred))
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					      EPERM);
	arla_log_set_level_num (*((int32_t *)h->msg));
    }
    if (h->outsize != 0) {
	int32_t debug_level;

	if (h->outsize < sizeof(int32_t))
	    return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					      EINVAL);

	debug_level = arla_log_get_level_num ();
	return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num,
					       0, &debug_level,
					       sizeof(debug_level));
    }
    return nnpfs_send_message_wakeup (fd, h->header.sequence_num, 0);
}

/*
 * GC pags --- there shouldn't be any need to do anything here.
 */

static int
vioc_gcpags (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    return 0;
}

/*
 * Break the callback of the specified fid
 */

static int
vioc_calculate_cache (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t parms[16];
    
    memset(parms, 0, sizeof(parms));
    
    if (!all_powerful_p(&h->cred))
	return EPERM;

    h->outsize = sizeof(parms);

    parms[0] = fcache_calculate_usage();
    parms[1] = fcache_usedbytes();

    arla_warnx (ADEBMISC, 
		"diskusage = %d, usedbytes = %d", 
		parms[0], parms[1]);
    
    return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					   &parms, sizeof(parms));
}

/*
 *
 */

static int
vioc_breakcallback(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int error;
    VenusFid fid;
    FCacheEntry *e;
    CredCacheEntry *ce;

    if (!all_powerful_p(&h->cred))
	return EPERM;

    if (!h->handle.a && !h->handle.b && !h->handle.c && !h->handle.d)
	return EINVAL;

    fid.Cell = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get (fid.Cell, h->cred.pag, CRED_ANY);
    assert (ce != NULL);

    error = fcache_get(&e, fid, ce);
    if (error)
	return error;

    if (!e->flags.kernelp) {
	cred_free (ce);
	return -ENOENT;
    }
	
    break_callback (e);
    
    fcache_release (e);
    cred_free (ce);

    return 0;
}

/*
 * check volume mappings
 */

static int
vioc_ckback(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    volcache_invalidate_all ();
    fcache_invalidate_mp ();
    return 0;
}

/*
 * checks if caller has the rights in h->msg
 */

static int
viocaccess(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce = NULL;
    int ret = 0;
    FCacheEntry *entry = NULL;
    int32_t *rights = (int32_t *) h->msg;

    if (h->insize != sizeof(int32_t)) {
	ret = EINVAL;
	goto out;
    }

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get(fid.Cell, h->cred.pag, CRED_ANY);
    assert(ce != NULL);

    ret = fcache_get (&entry, fid, ce);
    if (ret)
	goto out;

    /* Two reasons for calling read_attr explicitly:
       1. To get our hands on any error code.
       2. To make sure the server is asked, since 
          you don't get callback for change of ACL.

      Still, it is inefficient...

    ret = read_attr(entry, ce);
    if (ret)
	goto out;
    */

    errno = 0;
    ret = cm_checkright(entry, *rights, ce);

 out:
    nnpfs_send_message_wakeup(fd, h->header.sequence_num, ret);
    if (entry)
	fcache_release(entry);
    cred_free (ce);

    return 0;
}

static int
vioc_getvcxstatus2(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    VenusFid fid;
    CredCacheEntry *ce;
    int ret = 0;
    FCacheEntry *entry = NULL;
    struct afs_vcxstat2 stat;

    fid.Cell       = h->handle.a;
    fid.fid.Volume = h->handle.b;
    fid.fid.Vnode  = h->handle.c;
    fid.fid.Unique = h->handle.d;

    ce = cred_get(fid.Cell, h->cred.pag, CRED_ANY);
    assert(ce != NULL);

    ret = fcache_get(&entry, fid, ce);
    if (ret)
	goto out;

    /*         ret = read_attr(entry, ce);
     *
     *     You don't get callback for change of ACL. So you would need
     *     to explicitly ask server to make sure you get correct
     *     access-fields. But it is to inefficient...
     */

    ret = fcache_verify_attr(entry, NULL, NULL, ce);
    if (ret)
	goto out;

    stat.callerAccess = entry->status.CallerAccess;
    stat.cbExpires = entry->callback.ExpirationTime;
    stat.anyAccess = entry->anonaccess;

    if (entry->flags.mountp)
	stat.mvstat = 1;
    else if (entry->flags.vol_root)
	stat.mvstat = 2;
    else
	stat.mvstat = 0;

 out:
    if (ret) {
	nnpfs_send_message_wakeup(fd, h->header.sequence_num, ret);
    } else {
	nnpfs_send_message_wakeup_data(fd, h->header.sequence_num, 0,
				       (char *) &stat, sizeof(stat));
    }
    if (entry)
	fcache_release(entry);
    cred_free (ce);

    return 0;
}

static int
statistics_hostpart(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t host[100];
    uint32_t part[100];
    uint32_t outparms[512];
    int n;
    int outsize;
    int maxslots;
    int i;

    if (h->outsize < sizeof(uint32_t))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);
    
    n = 100;
    collectstats_hostpart(host, part, &n);
    maxslots = (h->outsize / sizeof(uint32_t) - 1) / 2;
    if (n > maxslots)
	n = maxslots;
    
    outsize = (n * 2 + 1) * sizeof(uint32_t);
    
    outparms[0] = n;
    for (i = 0; i < n; i++) {
	outparms[i*2 + 1] = host[i];
	outparms[i*2 + 2] = part[i];
    }
    
    return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					   (char *) &outparms, outsize);
}

static int
statistics_entry(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t *request = (uint32_t *) h->msg;
    uint32_t host;
    uint32_t part;
    uint32_t type;
    uint32_t items_slot;
    uint32_t count[32];
    int64_t items_total[32];
    int64_t total_time[32];
    uint32_t outparms[160];
    int i;
    int j;

    if (h->insize < sizeof(uint32_t) * 5) {
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);
    }

    if (h->outsize < sizeof(uint32_t) * 160) {
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);
    }

    host = request[1];
    part = request[2];
    type = request[3];
    items_slot = request[4];

    collectstats_getentry(host, part, type, items_slot,
			  count, items_total, total_time);

    j = 0;
    for (i = 0; i < 32; i++) {
	outparms[j++] = count[i];
    }
    for (i = 0; i < 32; i++) {
	memcpy(&outparms[j], &items_total[i], 8);
	j+=2;
    }
    for (i = 0; i < 32; i++) {
	memcpy(&outparms[j], &total_time[i], 8);
	j+=2;
    }
    return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					   (char *) &outparms, sizeof(outparms));
}

static int
aioc_statistics(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    uint32_t opcode;

    if (!all_powerful_p (&h->cred))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EPERM);

    if (h->insize < sizeof(opcode))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EPERM);

    memcpy(&opcode, &h->msg, sizeof(opcode));

    switch (opcode) {
    case arla_STATISTICS_OPCODE_LIST:
	return statistics_hostpart(fd, h, size);
    case arla_STATISTICS_OPCODE_GETENTRY:
	return statistics_entry(fd, h, size);
    default:
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);
    }
}


static int
aioc_getcacheparam(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int32_t opcode;
    int64_t val;
    int error = 0;

    if (h->insize < sizeof(opcode) || h->outsize < sizeof(int64_t))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);

    memcpy(&opcode, &h->msg, sizeof(opcode));

    switch(opcode) {
    case arla_GETCACHEPARAMS_OPCODE_HIGHBYTES:
	val = fcache_highbytes();
	break;
    case arla_GETCACHEPARAMS_OPCODE_USEDBYTES:
	val = fcache_usedbytes();
	break;
    case arla_GETCACHEPARAMS_OPCODE_LOWBYTES:
	val = fcache_lowbytes();
	break;
    case arla_GETCACHEPARAMS_OPCODE_HIGHVNODES:
	val = fcache_highvnodes();
	break;
    case arla_GETCACHEPARAMS_OPCODE_USEDVNODES:
	val = fcache_usedvnodes();
	break;
    case arla_GETCACHEPARAMS_OPCODE_LOWVNODES:
	val = fcache_lowvnodes();
	break;
    default:
	error = EINVAL;
	break;
    }

    return nnpfs_send_message_wakeup_data (fd, h->header.sequence_num, 0,
					   (char *) &val, sizeof(val));
}

static int
aioc_setcacheparam(int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    char *p = (char*)&h->msg;
    int32_t opcode;
    int64_t high;
    int64_t low;
    int error = 0;

    if (!all_powerful_p(&h->cred))
	return nnpfs_send_message_wakeup(fd, h->header.sequence_num,
					 EPERM);
    
    if (h->insize < (sizeof(opcode) + sizeof(high) + sizeof(low)))
	return nnpfs_send_message_wakeup (fd, h->header.sequence_num,
					  EINVAL);
    
    memcpy(&opcode, p, sizeof(opcode));
    p += sizeof(opcode);

    memcpy(&high, p, sizeof(high));
    p += sizeof(high);

    memcpy(&low, p, sizeof(low));

    switch(opcode) {
    case arla_SETCACHEPARAMS_OPCODE_BYTES:
	error = fcache_reinit(0, 0, low, high);
	break;
    case arla_SETCACHEPARAMS_OPCODE_VNODES:
	error = fcache_reinit(low, high, 0, 0);
	break;
    default:
	error = EINVAL;
	break;
    }

    return nnpfs_send_message_wakeup(fd, h->header.sequence_num, error);
}


/*
 * Handle a pioctl message in `h'
 */

static int
nnpfs_message_pioctl (int fd, struct nnpfs_message_pioctl *h, u_int size)
{
    int error;

    switch(h->opcode) {
#ifdef KERBEROS
    case ARLA_VIOCSETTOK:
	error = viocsettok (fd, h, size);
	break;
    case ARLA_VIOCSETTOK2:
	error = viocsettok2 (fd, h, size);
	break;
    case ARLA_VIOCGETTOK :
	return viocgettok (fd, h, size);
    case ARLA_VIOCUNPAG:
    case ARLA_VIOCUNLOG:
	error = viocunlog (fd, h, size);
	break;
#endif /* KERBEROS */
    case ARLA_AIOC_CONNECTMODE:
	return viocconnect(fd, h, size);
    case ARLA_VIOCFLUSH:
        error = viocflush(fd, h, size);
	break;
    case ARLA_VIOC_FLUSHVOLUME:
	error = viocflushvolume(fd, h, size);
	break;
    case ARLA_VIOCGETFID:
	return viocgetfid (fd, h, size);
    case ARLA_VIOCGETAL:
	return viocgetacl(fd, h, size);
    case ARLA_VIOCSETAL:
	return viocsetacl(fd, h, size);
    case ARLA_VIOCGETVOLSTAT:
	return viocgetvolstat(fd, h, size);
    case ARLA_VIOCSETVOLSTAT:
	error = viocsetvolstat(fd, h, size);
	break;
    case ARLA_VIOC_AFS_STAT_MT_PT:
	return vioc_afs_stat_mt_pt(fd, h, size);
    case ARLA_VIOC_AFS_DELETE_MT_PT:
	return vioc_afs_delete_mt_pt(fd, h, size);
    case ARLA_VIOCWHEREIS:
	return viocwhereis(fd, h, size);
    case ARLA_VIOCNOP:
	error = EINVAL;
	break;
    case ARLA_VIOCGETCELL:
	return vioc_get_cell(fd, h, size);
    case ARLA_VIOC_GETCELLSTATUS:
	return vioc_get_cellstatus(fd, h, size);
    case ARLA_VIOC_SETCELLSTATUS:
	return vioc_set_cellstatus(fd, h, size);
    case ARLA_VIOCNEWCELL:
	return vioc_new_cell(fd, h, size);
    case ARLA_VIOC_VENUSLOG:
	error = viocvenuslog (fd, h, size);
	break;
    case ARLA_VIOC_AFS_SYSNAME:
	return vioc_afs_sysname (fd, h, size);
    case ARLA_VIOC_FILE_CELL_NAME:
	return viocfilecellname (fd, h, size);
    case ARLA_VIOC_GET_WS_CELL:
	return viocgetwscell (fd, h, size);
    case ARLA_VIOCSETCACHESIZE:
	error = viocsetcachesize (fd, h, size);
	break;
    case ARLA_VIOCCKSERV:
	return viocckserv (fd, h, size);
    case ARLA_VIOCGETCACHEPARAMS:
	return viocgetcacheparms (fd, h, size);
    case ARLA_VIOC_GETRXKCRYPT:
	return getrxkcrypt(fd, h, size);
    case ARLA_VIOC_SETRXKCRYPT:
	error = setrxkcrypt(fd, h, size);
	break;
    case ARLA_VIOC_FPRIOSTATUS:
	error = vioc_fpriostatus(fd, h, size);
	break;
    case ARLA_VIOC_AVIATOR:
	return viocaviator (fd, h, size);
    case ARLA_VIOC_ARLADEBUG:
	return vioc_arladebug (fd, h, size);
    case ARLA_VIOC_GCPAGS:
	error = vioc_gcpags (fd, h, size);
	break;
    case ARLA_VIOC_CALCULATE_CACHE:
	return vioc_calculate_cache (fd, h, size);
    case ARLA_VIOC_BREAKCALLBACK:
	error = vioc_breakcallback (fd, h, size);
	break;
    case ARLA_VIOCACCESS:
        return viocaccess(fd, h, size);
    case ARLA_VIOC_GETVCXSTATUS2:
	return vioc_getvcxstatus2(fd, h, size);
    case ARLA_VIOCCKBACK :
	error = vioc_ckback (fd, h, size);
	break;
    case ARLA_AIOC_STATISTICS:
	return aioc_statistics (fd, h, size);
    case ARLA_AIOC_GETCACHEPARAMS:
	return aioc_getcacheparam(fd, h, size);
    case ARLA_AIOC_SETCACHEPARAMS:
	return aioc_setcacheparam(fd, h, size);
    default:
	arla_warnx (ADEBMSG, "unknown pioctl call %d", h->opcode);
	error = EINVAL ;
    }

    nnpfs_send_message_wakeup (fd, h->header.sequence_num, error);
    
    return 0;
}


/*
 * Return non-zero if there is a possibility that we have a network
 * connectivity. Can't tell the existence of network, just the lack of.
 *
 * Ignore lookback interfaces and known loopback addresses.
 */

static int
possibly_have_network(void)
{
    struct ifaddrs *ifa, *ifa0;
    int found_addr = 0;

    if (getifaddrs(&ifa0) != 0)
	return 1; /* well we don't really have a clue, do we ? */

    for (ifa = ifa0; ifa != NULL && !found_addr; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr == NULL)
	    continue;

#if IFF_LOOPBACK
	if (ifa->ifa_flags & IFF_LOOPBACK)
	    continue;
#endif

	switch (ifa->ifa_addr->sa_family) {
	case AF_INET: {
	    struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
	    if (sin->sin_addr.s_addr == htonl(0x7f000001))
		continue;
	    if (sin->sin_addr.s_addr == htonl(0))
		continue;
	    found_addr = 1;
	    break;
	}
#ifdef RX_SUPPORT_INET6
	case AF_INET6:
	    /* 
	     * XXX avoid link local and local loopback addresses since
	     * those are not allowed in VLDB
	     */
	    found_addr = 1;
	    break;
#endif
	default:
	    break;
	}
    }
    freeifaddrs(ifa0);

    /* if we found an acceptable address, good for us */
    if (found_addr)
	return 1;
    return 0;
}
