/*
 * Copyright (c) 1995-2006 Kungliga Tekniska Högskolan
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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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

#define __NO_VERSION__

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_dev.h>
#include <nnpfs/nnpfs_dirent.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <linux/binfmts.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/writeback.h>
#include <asm/fcntl.h>

#ifdef RCSID
RCSID("$Id: nnpfs_inodeops.c,v 1.226 2010/08/08 20:43:04 tol Exp $");
#endif

static int
nnpfs_fsync_int(struct file *file, u_int flag);

static int
nnpfs_d_revalidate(struct dentry *dentry, struct nameidata *nd);

static int
nnpfs_d_delete(struct dentry *dentry);

static void
nnpfs_d_release(struct dentry *dentry);

static void
nnpfs_d_iput(struct dentry *dentry, struct inode *inode);

/*
 * Return 1 if the `vma' can cause a write to the filesystem, 0 if not.
 */

static int
nnpfs_mightwrite_p (struct vm_area_struct *vma)
{
    if (vma->vm_flags & VM_MAYWRITE && vma->vm_flags & VM_SHARED)
	return 1;
    return 0;
}

/*
 * When we close the mmap:ed memory, flush the data to the fileserver
 */

static void
nnpfs_vma_close (struct vm_area_struct *vma)
{
    int error;
    struct file *file = vma->vm_file;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_vma_close\n"));

    /*
     * I really want to hook the nnpfs_as_writepage, but then everything
     * will be cache:ed in the wrong struct address_space
     */

    if (file->f_mode & FMODE_WRITE && nnpfs_mightwrite_p(vma)) {
	error = nnpfs_fsync_int(file, NNPFS_WRITE);
	if (error) {
	    NNPFSDEB(XDEBVNOPS, ("nnpfs_vma_close: nnpfs_fsync_int returned %d\n",
			       error));
	}
    }
}

static struct vm_operations_struct nnpfs_file_vm_ops = {
    .fault      = filemap_fault,
    .close	= nnpfs_vma_close,
};

struct dentry_operations nnpfs_dentry_operations = {
    .d_revalidate 	= nnpfs_d_revalidate,
    .d_delete	 	= nnpfs_d_delete,
    .d_release	 	= nnpfs_d_release,
    .d_iput		= nnpfs_d_iput,
};

/*
 *
 */

static void
nnpfs_print_path(struct dentry *dentry)
{
    NNPFSDEB(XDEBVNOPS, ("path: %.*s/%.*s\n",
		       (int)dentry->d_parent->d_name.len,
		       dentry->d_parent->d_name.name,
		       (int)dentry->d_name.len,
		       dentry->d_name.name));
}

/*
 *
 */

#if 0
void
nnpfs_print_lock(char *s, struct semaphore *sem)
{
    NNPFSDEB(XDEBLOCK, ("lock: %s sem: %p count: %d\n",
		      s, sem, (int)atomic_read(&sem->count)));
}
#endif

/*
 *
 */

int
nnpfs_d_init (struct dentry *dentry)
{
    struct nnpfs_dentry_data *dentry_data;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_d_init: dentry: %p\n", dentry));
    dentry_data = nnpfs_alloc(sizeof(*dentry_data), NNPFS_MEM_DENTRY);
    if (dentry_data == NULL)
        return -ENOMEM;
    memset(dentry_data, 0, sizeof(*dentry_data));
    dentry->d_op = &nnpfs_dentry_operations;
    dentry_data->xd_flags = 0;
    dentry->d_fsdata = dentry_data;
    return 0;
}

/*
 *
 */

static void
nnpfs_d_release(struct dentry *dentry)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_d_release: dentry: %p\n", dentry));
    nnpfs_free(dentry->d_fsdata, NNPFS_MEM_DENTRY);
    dentry->d_fsdata = NULL;
}

/*
 * iput for our dentries
 */

static void
nnpfs_d_iput(struct dentry *dentry, struct inode *inode)
{
    struct nnpfs_node *node = VNODE_TO_XNODE(inode);
    
    NNPFSDEB(XDEBVNOPS,
	     ("nnpfs_d_iput: dentry %p, inode %p\n", dentry, inode));
    
    if (node->flags & NNPFS_NODE_IPUT) /* XXX locking. never set? */
	nnpfs_irele(inode);
    else
	iput(inode);
}

/*
 * check if we are live
 */

static int
nnpfs_inode_valid(struct inode *inode)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(inode);
    if (nnpfsp->status & NNPFS_ROOTINSTALLED)
	return 0;

    if (inode == nnpfsp->root)
	return nnpfs_fetch_root(inode);

    return -ENODEV;
}

/*
 * nnpfs_lookup now returns a dentry.
 */

static struct dentry *
nnpfs_lookup (struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
    struct nnpfs_message_getnode msg;
    struct nnpfs *nnpfsp;
    struct dentry *new_dentry;
    int error = 0;
    
    struct nnpfs_node *d;
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: %p name: %.*s dir: %p\n",
		       dentry, (int)dentry->d_name.len, dentry->d_name.name,
		       dir));

    if (dentry->d_name.len >= NNPFS_MAX_NAME)
	return ERR_PTR(-ENAMETOOLONG);

    error = nnpfs_inode_valid(dir);
    if (error != 0)
	return ERR_PTR(error);

    nnpfsp = NNPFS_FROM_VNODE(dir);
    d = VNODE_TO_XNODE(dir);

    do {

	msg.header.opcode = NNPFS_MSG_GETNODE;
        
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.cred.pag = nnpfs_get_pag();
	msg.parent_handle = d->handle;
        
	strlcpy(msg.name, dentry->d_name.name, sizeof(msg.name));

	new_dentry = d_lookup(dentry->d_parent, &dentry->d_name);

	if (new_dentry &&
	    (DENTRY_TO_XDENTRY(new_dentry)->xd_flags & NNPFS_XD_ENTRY_VALID))
	    break;
	if (new_dentry)
	    dput(new_dentry);

	NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: sending getnode rpc, dentry: %p\n",
			   dentry));
        error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: getnode rpc done, dentry: %p\n",
			   dentry));
        
        if (error == 0)
            error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    } while (error == 0);

    if (error == -ENOENT) {
        NNPFSDEB(XDEBVNOPS, ("nnpfs_lookup: leaving negative cache\n"));
	
	new_dentry = dentry;
	error = nnpfs_d_init(new_dentry);
	if (error)
	    return ERR_PTR(error);

	d_add(new_dentry, NULL);
	
	DENTRY_TO_XDENTRY(new_dentry)->xd_flags |= 
	    NNPFS_XD_ENTRY_VALID|NNPFS_XD_NAME_VALID;
        return NULL;
    }
    if (error) {
        NNPFSDEB(XDEBVNOPS, ("error %d\n", error));
	return ERR_PTR(error);
    }
    return new_dentry;
}

/*
 *
 */

static int
nnpfs_open_valid(struct inode *vp, u_int tok)
{
  struct nnpfs *nnpfsp;
  struct nnpfs_node *xn;
  int error = 0;

  error = nnpfs_inode_valid(vp);
  if (error)
      return error;

  nnpfsp = NNPFS_FROM_VNODE(vp);
  xn = VNODE_TO_XNODE(vp);
  
  NNPFSDEB(XDEBVFOPS, ("nnpfs_open_valid: tokens 0x%x\n", xn->tokens));

  do {
    if (!NNPFS_TOKEN_GOT(xn, tok))
      {
	struct nnpfs_message_open msg;
	msg.header.opcode = NNPFS_MSG_OPEN;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.cred.pag = nnpfs_get_pag();
	msg.handle = xn->handle;
	msg.tokens = tok;
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	if (error == 0)
            error = NNPFS_MSG_WAKEUP_ERROR(&msg);
      }
    else
      {
	goto done;
      }
  } while (error == 0);

done:
  NNPFSDEB(XDEBVFOPS, ("nnpfs_open_valid: exit tokens 0x%x\n", xn->tokens));
  return error;
}

/*
 *
 */

static int
nnpfs_open(struct inode *i, struct file *f)
{
  int ret;

  NNPFSDEB(XDEBVNOPS, ("nnpfs_open inode: %p f->f_mode: %d aliases:",
		       i, f->f_mode));
  nnpfs_print_aliases(i);

  if (f->f_mode & FMODE_WRITE)
      ret = nnpfs_open_valid(i, NNPFS_OPEN_NW);
  else
      ret = nnpfs_open_valid(i, NNPFS_OPEN_NR);
  
  return ret;
}

/*
 * find first block in given range with validity according to 'validp'
 *
 * returns offset of first such block, or NNPFS_NO_OFFSET if none
 */

static uint64_t
find_first_block(struct nnpfs_node *node, uint64_t offset,
		 uint64_t end, int validp)
{
    loff_t eof = i_size_read(XNODE_TO_VNODE(node));
    uint64_t off;
    
    if (nnpfs_block_empty(node)
	|| offset >= eof)
	return NNPFS_NO_OFFSET;

    /* get some batch search perhaps? */

    BUG_ON(nnpfs_offset(offset) != offset);

    if (end > eof)
	end = eof;
	
    for (off = offset; off < end; off += nnpfs_blocksize) {
	int validity = nnpfs_block_have_p(node, off);
	if (validp) {
	    if (validity)
		return off;
	} else {
	    if (!validity)
		return off;
	}
    }

    return NNPFS_NO_OFFSET;
}

/*
 * store data for entire node
 *
 * We hold i_mutex.
 */

static int
nnpfs_fsync_int(struct file *file, u_int flag)
{
    struct inode *inode = file->f_dentry->d_inode;
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(inode);
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    loff_t len = i_size_read(inode);
    struct nnpfs_message_putdata msg;
    uint64_t off = 0;
    uint64_t end;
    int error;

    error = filemap_write_and_wait(file->f_mapping);
    if (error)
	return error;

    do {	
	/* get first valid block */
	off = find_first_block(xn, off, len, 1);
	if (off >= len || off == NNPFS_NO_OFFSET)
	    break; /* no more blocks installed */
	
	/* find the end of this range of valid blocks */
	end = find_first_block(xn, off + nnpfs_blocksize, len, 0);
	if (end > len)
	    end = len;
	
	nnpfs_inode2attr(XNODE_TO_VNODE(xn), &msg.attr);

	msg.header.opcode = NNPFS_MSG_PUTDATA;
	msg.cred.pag = nnpfs_get_pag();
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.handle = xn->handle;
	msg.flag   = flag;
	msg.offset = off;
	msg.len = end - off;

	xn->pending_writes++; /* XXX lock */

	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);

	/* XXX locking, rpc may fail */
	xn->daemon_length = i_size_read(inode);

	xn->pending_writes--; /* XXX lock */
	BUG_ON(xn->pending_writes < 0);

	off = end;
    } while (!error && end < len);

    if (error)
	xn->flags |= NNPFS_STALE;
    else if (!mapping_writably_mapped(inode->i_mapping))
	xn->flags &= ~NNPFS_DATA_DIRTY; /* XXX race */
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync_int error:%d\n", error));

    return error;
}

/*
 *
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static int
nnpfs_fsync(struct file *file, struct dentry *dentry, int datasync)
#else
static int
nnpfs_fsync(struct file *file, int datasync)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
    struct dentry *dentry = file->f_path.dentry;
#endif
    struct inode *inode = DENTRY_TO_INODE(dentry);
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;

    error = nnpfs_inode_valid(inode);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(inode);
    xn = VNODE_TO_XNODE(inode);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: 0x%p\n", inode));
    NNPFSDEB(XDEBVNOPS, ("nnpfs_fsync: name: %.*s aliases:",
		       (int)dentry->d_name.len, dentry->d_name.name));
    nnpfs_print_aliases(inode);

    if (xn->flags & NNPFS_DATA_DIRTY)
	error = nnpfs_fsync_int(file, NNPFS_WRITE | NNPFS_FSYNC);
    return error;
}

/*
 *
 */

static int
nnpfs_attr_valid(struct inode * vp, u_int tok)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;
    nnpfs_pag_t pag;

    error = nnpfs_inode_valid(vp);
    if (error)
	return error;
    
    nnpfsp = NNPFS_FROM_VNODE(vp);
    xn = VNODE_TO_XNODE(vp);

    pag = nnpfs_get_pag();

    do {
        if (!NNPFS_TOKEN_GOT(xn, tok)) {
            struct nnpfs_message_getattr msg;

            msg.header.opcode = NNPFS_MSG_GETATTR;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
            msg.cred.uid = current->uid;
#else
            msg.cred.uid = current_uid();
#endif
            msg.cred.pag = pag;
            msg.handle = xn->handle;
            error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
            if (error == 0)
		error = NNPFS_MSG_WAKEUP_ERROR(&msg);
        } else {
            goto done;
        }
    } while (error == 0);

done:
    return error;
}

/*
 *
 */

static int
nnpfs_rights_valid(struct inode * vp, nnpfs_pag_t pag)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;
    NNPFSDEB(XDEBVNOPS, ("pag: %d\n", pag));

    error = nnpfs_inode_valid(vp);
    if (error)
	return error;
    
    nnpfsp = NNPFS_FROM_VNODE(vp);
    xn = VNODE_TO_XNODE(vp);

    do {
        if (!nnpfs_has_pag(xn, pag))
        {
            struct nnpfs_message_getattr msg;

            msg.header.opcode = NNPFS_MSG_GETATTR;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
            msg.cred.uid = current->uid;
#else
            msg.cred.uid = current_uid();
#endif
            msg.cred.pag = pag;
            msg.handle = xn->handle;
            error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
            if (error == 0)
		error = NNPFS_MSG_WAKEUP_ERROR(&msg);
        }
        else {
            goto done;
        }
    } while (error == 0);

done:
    return error;
}

/*
 *
 */

static int
check_rights (nnpfs_rights rights, int mode)
{
    int error = 0;

    if (mode & MAY_READ)
	if ((rights & NNPFS_RIGHT_R) == 0)
	    error = -EACCES;
    if (mode & MAY_WRITE)
	if ((rights & NNPFS_RIGHT_W) == 0)
	    error = -EACCES;
    if (mode & MAY_EXEC)
	if ((rights & NNPFS_RIGHT_X) == 0)
	    error = -EACCES;
    return error;
}

/*
 * We don't hold i_mutex.
 */

static int
nnpfs_permission(struct inode *inode, int mode)
{
    int error = 0;
    nnpfs_pag_t pag = nnpfs_get_pag();
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access (%p) mode = 0%o aliases:", inode, mode));
    nnpfs_print_aliases(inode);

    error = nnpfs_attr_valid(inode, NNPFS_ATTR_R);
    if (error == 0) {
	struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
	int i;

	error = check_rights (xn->anonrights, mode);
	
	if (error == 0)
	    goto done;

	NNPFSDEB(XDEBVNOPS, ("nnpfs_access anonaccess failed\n"));

	nnpfs_rights_valid(inode, pag); /* ignore error */
	
	error = -EACCES;
	
	for (i = 0; i < NNPFS_MAXRIGHTS; i++)
	    if (xn->id[i] == pag) {
		error = check_rights (xn->rights[i], mode);
		break;
	    }
    }

done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_access(0%o) = %d\n", mode, error));
    return error;
}

static int
nnpfs_do_getdata(struct nnpfs_node *xn, u_int tok, loff_t offset, loff_t end)
{
    struct nnpfs_message_getdata msg;
    int error;

    msg.header.opcode = NNPFS_MSG_GETDATA;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    msg.cred.uid = current->uid;
#else
    msg.cred.uid = current_uid();
#endif
    msg.cred.pag = nnpfs_get_pag();
    msg.handle = xn->handle;
    msg.tokens = tok;
    msg.offset = offset;
    msg.len = end - offset;

    error = nnpfs_message_rpc(NNPFS_FROM_XNODE(xn), &msg.header, sizeof(msg));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    return error;
}

static void
update_end(struct inode *inode, loff_t *end, int writep)
{
    if (NNPFS_TOKEN_GOT(VNODE_TO_XNODE(inode), NNPFS_ATTR_R)) {
	loff_t size = i_size_read(inode);
	
	if (*end > size && !writep)
	    *end = size;
    }
}

static int
nnpfs_data_valid(struct inode *inode, u_int tok, loff_t want_offset, loff_t want_end)
{
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    int error = 0;
    int writep = ((tok & NNPFS_DATA_W) == NNPFS_DATA_W);
    int did_rpc;
    loff_t offset = nnpfs_offset(want_offset);
    loff_t end, off;

    error = nnpfs_inode_valid(inode);
    if (error != 0)
	return error;

    if (!NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_R))
	printk(KERN_EMERG "NNPFS PANIC WARNING! data_valid w/o tokens!\n");

    if (S_ISDIR(inode->i_mode)) {
	/* hack, entire dir goes in 'first block' */
	offset = 0;
	want_end = 1;
    }

    do {
	did_rpc = 0;
	end = want_end;
	update_end(inode, &end, writep);
		    
	NNPFSDEB(XDEBVNOPS, ("nnpfs_data_valid: want %lld - %lld, "
			     "tokens: want %lx has %lx length: %lld\n",
			     (long long) offset, (long long) end,
			     (long) tok, (long) xn->tokens,
			     (long long)i_size_read(XNODE_TO_VNODE(xn))));
	
	/* use find_first_block() ? */
	off = offset;

	while (off < end) {
	    if (!nnpfs_block_have_p(xn, off)) {
		
		/*
		 * For append beyond what daemon knows, just go ahead.
		 * Offset zero is special in that the block always exists;
		 * we need it "installed" to be safe against gc.
		 */
		
		/* XXX can length be less than end after rpc or schedule? */
		if (off >= xn->daemon_length && off > 0
		    && NNPFS_TOKEN_GOT_ALL(xn, tok|NNPFS_ATTR_R)
		    && (writep || off < nnpfs_end_offset(i_size_read(inode)))) {
		    error = nnpfs_block_create(xn, off);
		    if (error)
			break;

		    update_end(inode, &end, writep);
		    continue;
		}
		
 		did_rpc = 1;
		
		error = nnpfs_do_getdata(xn, tok, off, end);
		if (error)
		    break;

		update_end(inode, &end, writep);
	    }
	    off += nnpfs_blocksize;
	}

	if (error)
	    break;

	if (!NNPFS_TOKEN_GOT_ALL(xn, tok|NNPFS_ATTR_R)) {
	    error = nnpfs_do_getdata(xn, tok, offset, end);
	    did_rpc = 1;
	}
    } while (error == 0 && did_rpc);

	
    return error;
}

/*
 *
 */

int nnpfs_file_mmap(struct file * file, struct vm_area_struct * vma)
{
    int flags, error = 0;
    struct inode *inode = file->f_dentry->d_inode;
    struct address_space *mapping = file->f_mapping;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap inode: %p\n", inode));
    nnpfs_print_path(file->f_dentry);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap aliases:"));
    nnpfs_print_aliases(inode);
    
    BUG_ON(mapping->a_ops != &nnpfs_aops);
    BUG_ON(mapping != inode->i_mapping); /* for check in nnpfs_setsize() */

    if (nnpfs_mightwrite_p(vma))
	flags = NNPFS_DATA_W;
    else
	flags = NNPFS_DATA_R;

    error = nnpfs_data_valid(inode, flags, 0, i_size_read(inode) /* XXX */);
    if (error)
	goto done;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap: data valid\n"));

    if (nnpfs_mightwrite_p(vma))
	/* XXX should be more fine grained */
	VNODE_TO_XNODE(inode)->flags |= NNPFS_DATA_DIRTY;

    file_accessed(file);
    vma->vm_ops = &nnpfs_file_vm_ops;

 done:
    NNPFSDEB(XDEBVNOPS, ("nnpfs_mmap: done %d\n", error));

    return error;
}

/*
 *
 */

static ssize_t
nnpfs_aio_read(struct kiocb *iocb,
	       const struct iovec *iov, unsigned long nr_segs,
	       loff_t pos)
{
    int error = 0;
    struct file *file = iocb->ki_filp;
    ssize_t count = iocb->ki_left;
    struct inode *inode = file->f_dentry->d_inode;
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    
    if (xn != NULL)
	NNPFSDEB(XDEBVNOPS, ("nnpfs_read_file(%p): tokens: 0x%x\n",
			     inode, xn->tokens));

    error = nnpfs_data_valid(inode, NNPFS_DATA_R, pos, pos + count);
    if (error) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_read_file: data not valid %d\n", error));
	return error;
    }
    
    error = generic_file_aio_read(iocb, iov, nr_segs, pos);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_read_file: error = %d\n", error));
    return error;
}

/*
 *
 */

static ssize_t
nnpfs_aio_write(struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs,
		loff_t pos)
{
    int error = 0;
    struct file *file = iocb->ki_filp;
    ssize_t count = iocb->ki_left;
    struct inode *inode = file->f_dentry->d_inode;
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    loff_t realpos = pos;
    
    NNPFSDEB(XDEBVNOPS, ("nnpfs_aio_write(%p): tokens: 0x%x\n",
			 inode, xn->tokens));

    if (file->f_flags & O_APPEND) /* XXX do we have tokens? racy pos? */
      realpos = i_size_read(inode);
    
    error = nnpfs_data_valid(inode, NNPFS_DATA_W, realpos, realpos + count);
    if (error) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_write_file: data not valid %d\n", error));
	return error;
    }

    error = generic_file_aio_write(iocb, iov, nr_segs, pos);
    if (!IS_ERR_VALUE(error))
	xn->flags |= NNPFS_DATA_DIRTY; /* XXX race */

    NNPFSDEB(XDEBVNOPS, ("nnpfs_write_file: error = %d\n", error));
    return error;
}

static int
nnpfs_create(struct inode *dir, struct dentry *dentry,
	     int mode, struct nameidata *nd)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;
    struct nnpfs_message_create msg;

    if (!dir)
	return -ENOENT;

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;
	
    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_create: (%s, %d) dir(%p):",
		       dentry->d_name.name, dentry->d_name.len,
		       dir));
    nnpfs_print_aliases(dir);

    msg.header.opcode = NNPFS_MSG_CREATE;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, dentry->d_name.name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;

    XA_CLEAR(&msg.attr);
    XA_SET_MODE(&msg.attr, mode);
    XA_SET_TYPE(&msg.attr, NNPFS_FILE_REG);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    XA_SET_GID(&msg.attr, current->fsgid);
#else
    XA_SET_GID(&msg.attr, current_fsgid());
#endif
    msg.mode = 0;		/* XXX */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    msg.cred.uid = current->uid;
#else
    msg.cred.uid = current_uid();
#endif
    msg.cred.pag = nnpfs_get_pag();
    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    /* XXX should this really be here with new style dcache insert */
    if (DENTRY_TO_XDENTRY(dentry)->xd_flags == 0) {
	printk(KERN_EMERG "NNPFS Panic: nnpfs_create: dentry not valid\n");
    }

    return error;
    
}

static int
nnpfs_unlink (struct inode * dir, struct dentry *dentry)
{
    struct nnpfs_message_remove msg;
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error;

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;
	
    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);
    
    nnpfs_print_path(dentry);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_remove: dentry: %p aliases:", dentry));
    nnpfs_print_aliases(dentry->d_inode);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_remove: dir: %p aliases:", dir));
    nnpfs_print_aliases(dir);
    
    msg.header.opcode = NNPFS_MSG_REMOVE;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, dentry->d_name.name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    msg.cred.uid = current->uid;
#else
    msg.cred.uid = current_uid();
#endif
    msg.cred.pag = nnpfs_get_pag();
    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    return error;
}

int
nnpfs_rename (struct inode * old_dir, struct dentry *old_dentry,
	     struct inode * new_dir, struct dentry *new_dentry)
{
    struct nnpfs *nnpfsp = NNPFS_FROM_VNODE(old_dir);
    struct nnpfs_message_rename msg;
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename old"));
    nnpfs_print_path(old_dentry);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: dentry: %p aliases:", old_dentry));
    if (old_dentry->d_inode)
	nnpfs_print_aliases(old_dentry->d_inode);
    else
	NNPFSDEB(XDEBVNOPS, ("\n"));
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: dir: %p aliases:", old_dir));
    nnpfs_print_aliases(old_dir);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename new"));
    nnpfs_print_path(new_dentry);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: dentry: %p aliases:", new_dentry));
    if (new_dentry->d_inode)
	nnpfs_print_aliases(new_dentry->d_inode);
    else
	NNPFSDEB(XDEBVNOPS, ("\n"));
    NNPFSDEB(XDEBVNOPS, ("nnpfs_rename: dir: %p aliases:", new_dir));
    nnpfs_print_aliases(new_dir);

    msg.header.opcode = NNPFS_MSG_RENAME;
    msg.old_parent_handle = VNODE_TO_XNODE(old_dir)->handle;
    if (strlcpy(msg.old_name, old_dentry->d_name.name, sizeof(msg.old_name)) >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;

    msg.new_parent_handle = VNODE_TO_XNODE(new_dir)->handle;
    if (strlcpy(msg.new_name, new_dentry->d_name.name, sizeof(msg.new_name)) >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;
	
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    msg.cred.uid = current->uid;
#else
    msg.cred.uid = current_uid();
#endif
    msg.cred.pag = nnpfs_get_pag();
    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    /*
     * linux is "nice" and switches dentry inode, parent, etc for
     * us. Lets try to avoid possibly invalid dcache data.
     */
    if (error == 0)
	DENTRY_TO_XDENTRY(old_dentry)->xd_flags &=
	    ~(NNPFS_XD_ENTRY_VALID|NNPFS_XD_NAME_VALID);

    return error;
}

static int
nnpfs_mkdir(struct inode * dir, struct dentry *dentry, int mode)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_mkdir name:%s\n", dentry->d_name.name));

    if (!dir)
	return -ENOENT;
    if (dentry->d_name.len >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);

    {
	struct nnpfs_message_mkdir msg;

	msg.header.opcode = NNPFS_MSG_MKDIR;
	msg.parent_handle = xn->handle;
	if (strlcpy(msg.name, dentry->d_name.name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	    return -ENAMETOOLONG;

	XA_CLEAR(&msg.attr);
	XA_SET_MODE(&msg.attr, mode);
	XA_SET_TYPE(&msg.attr, NNPFS_FILE_DIR);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	XA_SET_GID(&msg.attr, current->fsgid);
#else
        XA_SET_GID(&msg.attr, current_fsgid());
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.cred.pag = nnpfs_get_pag();
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);

	/* XXX should this really be here */
	if (DENTRY_TO_XDENTRY(dentry)->xd_flags == 0) {
	    printk(KERN_EMERG "NNPFS Panic: nnpfs_mkdir: dentry not valid\n");
	}
    }

    return error;
}

static int
nnpfs_rmdir(struct inode * dir, struct dentry *dentry)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    struct nnpfs_message_rmdir msg;
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_rmdir: (%.*s)\n",
		       (int)dentry->d_name.len,
		       dentry->d_name.name));

    if (dentry->d_name.len >= NNPFS_MAX_NAME)
	return -ENAMETOOLONG;

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);

    msg.header.opcode = NNPFS_MSG_RMDIR;
    msg.parent_handle = xn->handle;
    if (strlcpy(msg.name, dentry->d_name.name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	    return -ENAMETOOLONG;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
    msg.cred.uid = current->uid;
#else
    msg.cred.uid = current_uid();
#endif
    msg.cred.pag = nnpfs_get_pag();
    error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
    if (error == 0)
	error = NNPFS_MSG_WAKEUP_ERROR(&msg);

    if (error == 0)
	d_delete(dentry);

    return error;
}

static int nnpfs_link(struct dentry *old_dentry,
		    struct inode *dir, struct dentry *dentry)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    struct nnpfs_node *from_xn;
    int error = 0;
    const char *name = dentry->d_name.name;
    int len = dentry->d_name.len;
    struct inode *oldinode = DENTRY_TO_INODE(old_dentry);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_link name:%.*s\n", len, name));

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);
    from_xn = VNODE_TO_XNODE(oldinode);

    if (from_xn == NULL)
	return -ENODEV;

    {
	struct nnpfs_message_link msg;

	msg.header.opcode = NNPFS_MSG_LINK;
	msg.parent_handle = xn->handle;
	msg.from_handle = from_xn->handle;
	if (strlcpy(msg.name, name, sizeof(msg.name)) >= NNPFS_MAX_NAME)
	    return -ENAMETOOLONG;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.cred.pag = nnpfs_get_pag();
	error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    }

    return error;
}

static int nnpfs_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;
    const char *name = dentry->d_name.name;
    int len = dentry->d_name.len;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_symlink name:%.*s\n", len, name));

    error = nnpfs_inode_valid(dir);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(dir);
    xn = VNODE_TO_XNODE(dir);

    {
	struct nnpfs_message_symlink *msg = NULL;

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);

	if (msg == NULL)
	  return -ENOMEM;

	msg->header.opcode = NNPFS_MSG_SYMLINK;
	msg->parent_handle = xn->handle;
	if (strlcpy(msg->name, name, sizeof(msg->name)) >= NNPFS_MAX_NAME) {
	  kfree(msg);
	  return -ENAMETOOLONG;
	}
	if (strlcpy(msg->contents, symname, sizeof(msg->contents)) >= NNPFS_MAX_SYMLINK_CONTENT) {
	  kfree(msg);
	  return -ENAMETOOLONG;
	}
	XA_CLEAR(&msg->attr);
	XA_SET_MODE(&msg->attr, 0777);
	XA_SET_TYPE(&msg->attr, NNPFS_FILE_LNK);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	XA_SET_GID(&msg->attr, current->fsgid);
#else
        XA_SET_GID(&msg->attr, current_fsgid());
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg->cred.uid = current->uid;
#else
        msg->cred.uid = current_uid();
#endif
	msg->cred.pag = nnpfs_get_pag();
	error = nnpfs_message_rpc(nnpfsp, &msg->header, sizeof(*msg));
	if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(msg);

	/* XXX should this really be here */
	if (DENTRY_TO_XDENTRY(dentry)->xd_flags == 0) {
	    printk(KERN_EMERG "NNPFS Panic: nnpfs_symlink: dentry not valid\n");
	}
	kfree(msg);
    }

    return error;
}

/*
 * We hold i_mutex.
 */
static int
nnpfs_readdir(struct file * file, void * dirent, filldir_t filldir)
{
    int error;
    loff_t offset, begin_offset;
    struct inode *inode = file->f_dentry->d_inode;
    struct inode *cache_inode;
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    char *buf;
    struct page *page;
    off_t inpage;
    unsigned long page_num;
    struct address_space *mapping;
    struct file *backfile;

    NNPFSDEB(XDEBREADDIR, ("nnpfs_readdir\n"));
    
    error = nnpfs_data_valid(inode, NNPFS_DATA_R, 0, i_size_read(inode));
    if (error)
	return error;

    error = nnpfs_block_open(xn, 0, O_RDONLY ,&backfile);
    if (error) {
	printk("nnpfs_block_open failed: %d\n", -error);
	return error;
    }

    cache_inode = backfile->f_mapping->host;

    while (file->f_pos < i_size_read(cache_inode)) {
	NNPFSDEB(XDEBREADDIR,
	       ("nnpfs_readdir file->f_pos: %d i_size: %d\n",
		(int) file->f_pos, (int) cache_inode->i_size));
	begin_offset = file->f_pos &~ (NNPFS_DIRENT_BLOCKSIZE - 1);
	offset = file->f_pos & (NNPFS_DIRENT_BLOCKSIZE - 1);
	file->f_pos = begin_offset;
	NNPFSDEB(XDEBREADDIR, ("nnpfs_readdir begin_offset: %d offset: %d\n",
			     (int)begin_offset, (int)offset));
	mapping = backfile->f_mapping;
	inpage = file->f_pos & (PAGE_CACHE_SIZE-1);
	page_num = file->f_pos >> PAGE_CACHE_SHIFT;

	NNPFSDEB(XDEBREADDIR,
	       ("nnpfs_readdir inpage: %d page_num: %lu\n",
		(int) inpage,
		page_num));

	page = read_cache_page(mapping, page_num,
			       (filler_t *)mapping->a_ops->readpage,
			       backfile);
	if (IS_ERR(page)) {
	    printk(KERN_EMERG "nnpfs_readdir: read_cache_page failed: %ld\n",
		   PTR_ERR(page));
	    error = PTR_ERR(page);
	    break;
	}
	wait_on_page_locked(page);
	if (!PageUptodate(page)) {
	    printk(KERN_EMERG "nnpfs_readdir: page not uptodate\n");
	    page_cache_release (page);
	    error = -EIO;
	    break;
	}
	buf = (char *)kmap (page);
	buf += inpage;

	while (offset < NNPFS_DIRENT_BLOCKSIZE) {
	    struct nnpfs_dirent *xdirent = (struct nnpfs_dirent *) (buf + offset);
	    int filldir_error;

	    NNPFSDEB(XDEBREADDIR,
		   ("nnpfs_readdir offset: %d namlen: %d offset2: %d\n",
		    (int) offset,
		    (int) xdirent->d_namlen,
		    (int) (offset+begin_offset)));

	    if (xdirent->d_fileno != 0
		&& (filldir_error = filldir (dirent,
				     xdirent->d_name,
				     xdirent->d_namlen,
				     offset + begin_offset,
				     xdirent->d_fileno,
				     DT_UNKNOWN)) < 0) {
		NNPFSDEB(XDEBREADDIR,
			 ("nnpfs_readdir filldir: %d\n", filldir_error));
		break;
	    }
	    offset += xdirent->d_reclen;

	    if (xdirent->d_reclen == 0) {
		printk(KERN_EMERG "NNPFS Panic: "
		       "empty dirent at %lld in nnpfs_readdir, pos %d size %d\n",
		       (long long)offset, (int)file->f_pos,
		       (int)cache_inode->i_size);
		NNPFSDEB(XDEBVNOPS, ("inode: %p aliases:", inode));
		nnpfs_print_aliases(inode);

		NNPFSDEB(XDEBVNOPS, ("cache_inode: %p aliases:", cache_inode));
		nnpfs_print_aliases(cache_inode);

		error = -EIO;
		break;
	    }
	}
	kunmap (page);
	page_cache_release (page);

	if (offset > NNPFS_DIRENT_BLOCKSIZE)
	    offset = NNPFS_DIRENT_BLOCKSIZE;

	file->f_pos = begin_offset + offset;

	if (error || offset < NNPFS_DIRENT_BLOCKSIZE)
	    break;
    }
    
    filp_close(backfile, NULL);
    return error;
}
   
/*
 * We don't hold i_mutex.
 */

static int
nnpfs_readlink (struct dentry *dentry, char *buffer, int buflen)
{
    int error = 0;
    struct inode *inode = DENTRY_TO_INODE(dentry);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_readlink\n"));
    
    error = nnpfs_data_valid(inode, NNPFS_DATA_R, 0, i_size_read(inode));
    if (error == 0)
	error = generic_readlink(dentry, buffer, buflen);

    return error;
}

/*
 * We don't hold i_mutex.
 */

static void *
nnpfs_follow_link (struct dentry *dentry,
		 struct nameidata *nd)
{
    int error = 0;
    struct inode *inode = DENTRY_TO_INODE(dentry);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_follow_link\n"));
    
    error = nnpfs_data_valid(inode, NNPFS_DATA_R, 0, i_size_read(inode));
    if (error)
       return ERR_PTR(error);

    return page_follow_link_light(dentry, nd);
}

/*
 * fetch the attributes of `dentry' and store them in `attr'.
 *
 * We don't hold i_mutex.
 */

static int
nnpfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
    struct inode *inode = DENTRY_TO_INODE(dentry);
    int error;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_getattr\n"));

    error = nnpfs_attr_valid(inode, NNPFS_ATTR_R);
    if (!error)
	generic_fillattr(inode, stat);
	    
    return error;
}

/*
 * set the attributes of `dentry' to `attr'
 */

int
nnpfs_setattr (struct dentry *dentry, struct iattr *attr)
{
    struct inode *inode = DENTRY_TO_INODE(dentry);
    struct nnpfs_node *xn;
    struct nnpfs *nnpfsp;
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_setattr\n"));

    error = nnpfs_inode_valid(inode);
    if (error)
	return error;

    xn = VNODE_TO_XNODE(inode);
    nnpfsp = NNPFS_FROM_VNODE(inode);


    if (NNPFS_TOKEN_GOT(xn, NNPFS_ATTR_W)) {
        /* Update attributes and mark them dirty. */
        VNODE_TO_XNODE(inode)->flags |= NNPFS_ATTR_DIRTY;
	return -EINVAL;                /* XXX not yet implemented */
    } else {
        struct nnpfs_message_putattr msg;

        msg.header.opcode = NNPFS_MSG_PUTATTR;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	msg.cred.uid = current->uid;
#else
        msg.cred.uid = current_uid();
#endif
	msg.cred.pag = nnpfs_get_pag();
        msg.handle = xn->handle;
        nnpfs_iattr2attr(xn, attr, &msg.attr);

        error = nnpfs_message_rpc(nnpfsp, &msg.header, sizeof(msg));
        if (error == 0)
	    error = NNPFS_MSG_WAKEUP_ERROR(&msg);
    }
    
    return error;
}

/*
 * Called when the last reference to an open file is closed.
 */

static int
nnpfs_release_file (struct inode *inode, struct file *file)
{
    struct nnpfs *nnpfsp;
    struct nnpfs_node *xn;
    int error = 0;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_release_file\n"));

    error = nnpfs_inode_valid(inode);
    if (error)
	return error;

    nnpfsp = NNPFS_FROM_VNODE(inode);
    xn = VNODE_TO_XNODE(inode);

    NNPFSDEB(XDEBVNOPS,
	   ("nnpfs_release_file inode->i_count: %d inode: %p aliases:",
	    nnpfs_icount(inode), inode));
    nnpfs_print_aliases(inode);
    
    /* i_state & (I_DIRTY_DATASYNC | I_DIRTY_PAGES) */
    if (file->f_mode & FMODE_WRITE && xn->flags & NNPFS_DATA_DIRTY)
	error = nnpfs_fsync_int(file, NNPFS_WRITE);
    
    if (error)
	NNPFSDEB(XDEBVNOPS, ("nnpfs_release_file error: %d\n",error));

    return error;
}

/*
 *
 */

static int
nnpfs_flush(struct file *file, fl_owner_t id)
{
    NNPFSDEB(XDEBVNOPS, ("nnpfs_flush\n"));

    if (file && file->f_dentry && file->f_dentry->d_inode)
	return nnpfs_release_file(file->f_dentry->d_inode, file);
    else
	return 0;
}

/*
 * Return 1 if `dentry' is still valid, otherwise 0.
 */

static int
nnpfs_d_revalidate(struct dentry *dentry, struct nameidata *nd) 
{
    struct inode *inode = DENTRY_TO_INODE(dentry);
    NNPFSDEB(XDEBVNOPS, ("nnpfs_d_revalidate %p \"%.*s\" (inode %p)\n",
		       dentry,
		       (int)dentry->d_name.len,
		       dentry->d_name.name,
		       inode));

    /* If it's the root it's going to be valid. */
    if (IS_ROOT(dentry))
	return 1;

    if ((DENTRY_TO_XDENTRY(dentry)->xd_flags & NNPFS_XD_ENTRY_VALID) == 0) {
	if (nnpfs_dcount(dentry) == 1) /* We are the only one */
	    d_drop(dentry);
	return 0;
    }

    if (DENTRY_TO_XDENTRY(dentry)->xd_flags & NNPFS_XD_NAME_VALID)
	return 1;

    if (inode) {
	int error;

	nnpfs_print_aliases(inode);

	error = nnpfs_attr_valid(inode, NNPFS_ATTR_R);
	if (error) {
	    NNPFSDEB(XDEBVNOPS, ("invalid\n"));
	    return 0;
	} else {
	    NNPFSDEB(XDEBVNOPS, ("valid\n"));
	    return 1;
	}
    } else {
	/*
	 * Negative entries are always valid,
	 * they are cleared in nnpfs_message_invalidnode
	 */
        NNPFSDEB(XDEBVNOPS, ("nnpfs_d_revalidate: negative entry\n"));
	return 1;
    }
    printk(KERN_EMERG "NNPFS Panic: a case in nnpfs_d_revalidate has not "
	   "been taken care of\n");
    return 0;
}

static
int
nnpfs_d_delete(struct dentry *dentry)
{
    struct inode *inode;
    struct nnpfs_node *xn;

    NNPFSDEB(XDEBVNOPS, ("nnpfs_d_delete: dentry %p(%.*s): "
		       "all references dropped\n",
		       dentry,
		       (int)dentry->d_name.len,
		       dentry->d_name.name));

    inode = dentry->d_inode;
    if (inode) {
	xn = VNODE_TO_XNODE(inode);

	if ((xn->flags & NNPFS_STALE) != 0 && nnpfs_icount(inode) == 1)	{
	    NNPFSDEB(XDEBVNOPS, ("nnpfs_d_delete: stale\n"));
	    /* this will cause a iput where d_delete is non void */
	    return 1;
	}
    }
    return 0;
}

static ssize_t
nnpfs_splice_read(struct file *file, loff_t *ppos,
		  struct pipe_inode_info *pipe, size_t count,
		  unsigned int flags)
{
    int error = 0;
    struct inode *inode = file->f_dentry->d_inode;
    struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
    
    if (xn != NULL)
	NNPFSDEB(XDEBVNOPS, ("nnpfs_sendfile: tokens: 0x%x\n", xn->tokens));

    error = nnpfs_data_valid(inode, NNPFS_DATA_R, *ppos, *ppos + count);
    if (error) {
	NNPFSDEB(XDEBVNOPS, ("nnpfs_sendfile: data not valid %d\n", error));
	return error;
    }
    error = file->f_op->splice_read(file, ppos, pipe, count, flags);

    NNPFSDEB(XDEBVNOPS, ("nnpfs_sendfile: error = %d\n", error));
    return error;
}

/*
 *
 *
 */

static struct file *
nnpfs_open_backing(struct page *page, int flag, loff_t *local_offset)
{
	struct inode *inode = page->mapping->host;
	struct nnpfs_node *xn = VNODE_TO_XNODE(inode);
	loff_t global_offset = page_offset(page);
	loff_t offset = nnpfs_offset(global_offset);
	struct file *file;
	int error;
	int tokens = NNPFS_DATA_R;
	
	if ((flag & O_ACCMODE) != O_RDONLY)
	    tokens = NNPFS_DATA_W;

	error = nnpfs_data_valid(inode, tokens, offset,
				 global_offset + PAGE_CACHE_SIZE);
	if (error) {
	    printk("nnpfs_open_backing valid(%d.%d.%d.%d @0x%llx) -> %d"
		   "tokens 0x%x\n",
		   xn->handle.a, xn->handle.b,
		   xn->handle.c, xn->handle.d,
		   (unsigned long long)offset, -error, xn->tokens);
	    return ERR_PTR(error);
	}

	    
	error = nnpfs_block_open(xn, offset, flag, &file);
	if (error) {
	    printk("nnpfs_open_backing open(%d.%d.%d.%d @0x%llx) -> %d\n",
		   xn->handle.a, xn->handle.b,
		   xn->handle.c, xn->handle.d,
		   (unsigned long long)offset, -error);
	    return ERR_PTR(error);
	}

	if (local_offset)
	    *local_offset = global_offset - offset;

	return file;
}

/*
 * Return page index in backing file for given (front)page.
 */
static unsigned long
nnpfs_get_backindex(struct page *page)
{
    struct inode *inode = page->mapping->host;
    unsigned bits = nnpfs_blocksizebits - PAGE_CACHE_SHIFT;

    if (S_ISDIR(inode->i_mode))
	/* hack, entire dir goes in 'first block' */
	return page->index;

    return page->index % (1 << bits);
}

/*
 * copy contents of our page to page in backfile
 */
static int
nnpfs_write_backpage(struct page *page, struct file *backfile)
{
	struct address_space *mapping = backfile->f_mapping;
	unsigned len = PAGE_CACHE_SIZE;
	struct page *backpage;
	void *fsdata;
	unsigned long offset;

	int error;
	
	do {
		error = pagecache_write_begin(backfile, mapping, 0, len,
					      AOP_FLAG_UNINTERRUPTIBLE,
					      &backpage, &fsdata);
		if (!error) {
			copy_highpage(backpage, page);
			flush_dcache_page(backpage);
			error = pagecache_write_end(backfile, mapping, 0, len,
					len, backpage, fsdata);
			if (error > 0)
				error = 0;
		}
		if (error == AOP_TRUNCATED_PAGE) {
			continue;
		}
	} while (0);

	offset = page_offset(backpage);

	if (error)
		printk("nnpfs_write_backpage: EIO\n");
#ifdef NNPFS_SAFE_SYNC
	else
		(void)sync_page_range(mapping->host, mapping, offset, len);
#endif
	
	return error;
}

/*
 * fill our page from backfile
 */
static int
nnpfs_read_backpage(struct page *page, struct file *backfile)
{
	struct address_space *mapping = backfile->f_mapping;
	unsigned long n = nnpfs_get_backindex(page);
	struct page *backpage;
	unsigned long offset;

	backpage = read_mapping_page(mapping, n, backfile);
	if (!IS_ERR(backpage)) {
		wait_on_page_locked(backpage);

		if (PageUptodate(backpage) && !PageError(backpage)) {
			offset = page_offset(backpage);
			copy_highpage(page, backpage);
			page_cache_release(backpage);
#ifdef NNPFS_SAFE_SYNC
			(void)invalidate_inode_pages2_range(mapping,
							    offset,
							    offset);
#endif
#if 0
			{
			    char *addr;
			    kmap(page);
			    addr = page_address(page);
			    NNPFSDEB(XDEBVNOPS, ("nnpfs_read_backpage: %x%x%x%x\n",
						 addr[0], addr[1], addr[2], addr[3]));
			    kunmap(page);
			}
#endif

			flush_dcache_page(page);
			return 0;
		}

		page_cache_release(backpage);
	}

	printk("nnpfs_get_backpage: EIO\n");
	return -EIO;
}

/*
 * Fill our page from backing file's page cache.
 */
static int
nnpfs_readpage_int(struct page *page, struct file *backfile)
{
	int error;

	if (PageUptodate(page)) {
		NNPFSDEB(XDEBVNOPS, ("nnpfs_readpage_int: uptodate\n"));
		return 0;
	}
	error = nnpfs_read_backpage(page, backfile);
	if (error)
		SetPageError(page);
	else
		SetPageUptodate(page);

	return error;
}

static int
nnpfs_readpage(struct file *file, struct page *page)
{
	struct file *backfile;
	int error;

	NNPFSDEB(XDEBVNOPS, ("nnpfs_readpage(%p): page 0x%llx\n",
			     file->f_mapping->host,
			     (unsigned long long)page_offset(page)));

	backfile = nnpfs_open_backing(page, O_RDONLY, NULL);
	if (IS_ERR(backfile)) {
		printk("nnpfs_readpage: bad backfile\n");
		error = PTR_ERR(backfile);
	} else {
		error = nnpfs_readpage_int(page, backfile);
		filp_close(backfile, NULL);
	}

	unlock_page(page);

	return error;
}

static int
nnpfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int error;
	struct file *backfile;

	page_cache_get(page);
        if (!PageUptodate(page))
		printk("nnpfs_writepage: page not up to date\n");

	backfile = nnpfs_open_backing(page, O_WRONLY, NULL);
	if (IS_ERR(backfile)) {
		error = PTR_ERR(backfile);
	} else {
		error = nnpfs_write_backpage(page, backfile);

		filp_close(backfile, NULL);
	}

	SetPageUptodate(page); /* check for error and Clearuptodate? */
	unlock_page(page);
	page_cache_release(page);	

	if (error)
		printk("nnpfs_writepage: return %d\n", error);

	return error;
}

/* from, to are within page */
static int
nnpfs_prepare_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
	struct file *backfile;
	struct inode *inode;
	loff_t modsize, offset;
	int ret = 0;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	NNPFSDEB(XDEBVNOPS, ("nnpfs_prepare_write(%p): page 0x%llx, %u-%u\n",
			     file->f_mapping->host, 
			     (unsigned long long)page_offset(page), from, to));

	/* todo:
	 * if we don't cover the entire page, read in the rest from backfile.
	 * if we extend backfile, truncate it.
	 * if we're writing to a hole, do what?
	 *
	 * maybe we should just always preread. what else do we need to cover?
	 */

	backfile = nnpfs_open_backing(page, O_RDWR, &offset);
	if (IS_ERR(backfile)) {
		return PTR_ERR(backfile);
	}

	inode = backfile->f_mapping->host;
	modsize = (offset + to) & (nnpfs_blocksize - 1);
	if (modsize == 0)
		modsize = nnpfs_blocksize;

	if (modsize > i_size_read(inode)) {
		int error;
		error = vmtruncate(inode, modsize);
		if (error) {
			printk("nnpfs_prepare_write: truncate(%llu) -> %d\n",
			       modsize, -error);
			BUG(); /* XXX not correct */
		}
	}

	if (to - from < PAGE_CACHE_SIZE)
	    ret = nnpfs_readpage_int(page, backfile);
	else
	    SetPageUptodate(page);

	filp_close(backfile, NULL);

#if 0
	if (!ret) {
	    char *addr;
	    kmap(page);
	    addr = page_address(page);
	    NNPFSDEB(XDEBVNOPS, ("nnpfs_prepare_write(%p): %x%x%x%x\n",
				 file->f_mapping->host, 
				 addr[0], addr[1], addr[2], addr[3]));
	    kunmap(page);
	}
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)

static int
nnpfs_write_begin(struct file *file, struct address_space *mapping, loff_t pos,
unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
	struct page *page;
	pgoff_t index;
	unsigned from;

	index = pos >> PAGE_CACHE_SHIFT;
	from = pos & (PAGE_CACHE_SIZE - 1);

#ifdef AOP_FLAG_NOFS
	page = grab_cache_page_write_begin(mapping, index, flags);
#else
	page = __grab_cache_page(mapping, index);
#endif
	if (page == NULL)
		return -ENOMEM;

	*pagep = page;

	return nnpfs_prepare_write(file, page, from, from + len);
}

#endif

static int
nnpfs_commit_write(struct file *file, struct page *page,
		   unsigned from, unsigned to)
{
    struct inode *inode = page->mapping->host;
    loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

    if (pos > inode->i_size) {
	i_size_write(inode, pos);

	spin_lock(&inode->i_lock);
	inode->i_blocks = (pos + I_BLOCKS_UNIT - 1) >> I_BLOCKS_BITS;
	spin_unlock(&inode->i_lock);
    }
    set_page_dirty(page);

#if 0
    {
	char *addr;
	kmap(page);
	addr = page_address(page);
	NNPFSDEB(XDEBVNOPS, ("nnpfs_commit_write(%p): %x%x%x%x\n",
			     file->f_mapping->host, 
			     addr[0], addr[1], addr[2], addr[3]));
	kunmap(page);
    }
#endif
    
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)

static int
nnpfs_write_end(struct file *file, struct address_space *mapping, loff_t pos,
		unsigned len, unsigned copied, struct page *page, void *fsdata)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);

	/* zero the stale part of the page if we did a short copy */
	if (copied < len) {
		void *kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + from + copied, 0, len - copied);
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
	}

	nnpfs_commit_write(file, page, from, from + copied);

	unlock_page(page);
	page_cache_release(page);

	return copied;
}

#endif

const
struct address_space_operations nnpfs_aops = {
	.readpage = nnpfs_readpage,
	.writepage = nnpfs_writepage,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	.prepare_write = nnpfs_prepare_write,
	.commit_write = nnpfs_commit_write,
#else
	.write_begin = nnpfs_write_begin,
	.write_end = nnpfs_write_end,
#endif
};

/*
 * File operations
 */

struct file_operations nnpfs_file_operations = {
    .aio_read	= nnpfs_aio_read,
    .aio_write	= nnpfs_aio_write,
    .mmap	= nnpfs_file_mmap,
    .open	= nnpfs_open,
    .flush	= nnpfs_flush,
    .release	= nnpfs_release_file,
    .fsync	= nnpfs_fsync,
    .splice_read = nnpfs_splice_read,
};

struct file_operations nnpfs_dead_operations = {
};

struct file_operations nnpfs_dir_operations = {
    .readdir	= nnpfs_readdir,
    .flush	= nnpfs_flush,
};

struct file_operations nnpfs_link_operations = {
    .flush = nnpfs_flush,
};

/*
 * Inode operations
 */

struct inode_operations nnpfs_file_inode_operations = {
    .permission		= nnpfs_permission,
    .setattr		= nnpfs_setattr,
    .getattr		= nnpfs_getattr,
};

struct inode_operations nnpfs_dir_inode_operations = {
    .create		= nnpfs_create,
    .lookup		= nnpfs_lookup,
    .link		= nnpfs_link,
    .unlink 		= nnpfs_unlink,
    .symlink 		= nnpfs_symlink,
    .mkdir		= nnpfs_mkdir,
    .rmdir 		= nnpfs_rmdir,
    .rename 		= nnpfs_rename,
    .permission 	= nnpfs_permission,
    .setattr 		= nnpfs_setattr,
    .getattr 		= nnpfs_getattr,
};

struct inode_operations nnpfs_dead_inode_operations = {
};

struct inode_operations nnpfs_link_inode_operations = {
    .readlink 		= nnpfs_readlink,
    .follow_link 	= nnpfs_follow_link,
    .put_link 		= page_put_link,
};
