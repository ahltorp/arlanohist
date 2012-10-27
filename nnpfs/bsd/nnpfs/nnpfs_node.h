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

/* 	$Id: nnpfs_node.h,v 1.48 2010/06/16 19:58:53 tol Exp $	 */

#ifndef _nnpfs_xnode_h
#define _nnpfs_xnode_h

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_KERNEL_LF_ADVLOCK
#include <sys/lockf.h>
#endif

#include <nnpfs/nnpfs_attr.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_queue.h>

extern uint64_t nnpfs_blocksize;
extern uint32_t nnpfs_blocksizebits;

#include <nnpfs/nnpfs_blocks.h>
#include <nnpfs/nnpfs_blocks_locl.h>

struct nnpfs;

#ifdef __APPLE__
typedef struct lock__bsd__ nnpfs_vnode_lock;
struct vattr;
struct nameidata;
struct vop_generic_args;
#else
typedef struct lock nnpfs_vnode_lock;
#endif

#ifdef __APPLE__
#define nnpfs_vrele(vp) vnode_rele(vp)
#define nnpfs_vrecycle(vp, foo, bar) vnode_recycle(vp)
#define nnpfs_vput(vp) vnode_put(vp)
#define nnpfs_vref(vp) vnode_ref(vp)
#define nnpfs_vletgo(vn) nnpfs_vput(vn)

#define nnpfs_vfs_vattr vnode_attr

#define nnpfs_vattr_get_size(va) ((va)->va_data_size)
#define nnpfs_vattr_get_ctime_sec(va) ((va)->va_create_time.tv_sec)
#define nnpfs_vattr_get_atime_sec(va) ((va)->va_access_time.tv_sec)
#define nnpfs_vattr_get_mtime_sec(va) ((va)->va_modify_time.tv_sec)
#define nnpfs_vattr_get_mtime_nsec(va) ((va)->va_modify_time.tv_nsec)

#define nnpfs_vattr_set(va, n, val) VATTR_RETURN(va, n, val)

#define nnpfs_vattr_set_size(va, val) do { \
    VATTR_RETURN(va, va_total_size, val); \
    VATTR_RETURN(va, va_data_size, val); \
    } while (0)
#define nnpfs_vattr_set_bytes(va, val) do { \
    VATTR_RETURN(va, va_total_alloc, val); \
    VATTR_RETURN(va, va_data_alloc, val); \
    } while (0)
#define nnpfs_vattr_set_time(va, n, sec, nsec) do {	\
	struct timespec tmp_time;			\
	tmp_time.tv_sec = (sec);			\
	tmp_time.tv_nsec = (nsec);		\
	nnpfs_vattr_set(va, n, tmp_time);		\
    } while (0)
#define nnpfs_vattr_set_ctime(va, sec, nsec)		\
    nnpfs_vattr_set_time(va, va_create_time, sec, nsec)
#define nnpfs_vattr_set_atime(va, sec, nsec)		\
    nnpfs_vattr_set_time(va, va_access_time, sec, nsec)
#define nnpfs_vattr_set_mtime(va, sec, nsec)		\
    nnpfs_vattr_set_time(va, va_modify_time, sec, nsec)

#define nnpfs_vattr_size_isactive(va) VATTR_IS_ACTIVE(va, va_data_size)
#define nnpfs_vattr_mtime_isactive(va) VATTR_IS_ACTIVE(va, va_modify_time)

#define nnpfs_vnode_isdir(vp) vnode_isdir(vp)
#define nnpfs_vnode_islnk(vp) vnode_islnk(vp)
#define nnpfs_vnode_ischr(vp) vnode_ischr(vp)
#define nnpfs_vnode_isreg(vp) vnode_isreg(vp)
#define nnpfs_vnode_mount(vp) vnode_mount(vp)
#define nnpfs_vnode_isinuse(vp, cnt) vnode_isinuse(vp, cnt)

#else

#if (defined(__FreeBSD__) && __FreeBSD_version >= 600000) || (defined(__OpenBSD__) && OpenBSD >= 200805)
#define nnpfs_vrecycle(vp, foo, bar) vrecycle(vp, bar)
#else
#define nnpfs_vrecycle(vp, foo, bar) vrecycle(vp, foo, bar)
#endif

#define nnpfs_vrele(vp) vrele(vp)
#define nnpfs_vput(vp) vput(vp)
#if (defined(__OpenBSD__) && OpenBSD >= 201005)
#define nnpfs_vref(vp) vref(vp)
#else
#define nnpfs_vref(vp) VREF(vp)
#endif
#define nnpfs_vletgo(vn) nnpfs_vrele(vn)

#define nnpfs_vfs_vattr vattr

#define nnpfs_vattr_get_size(va) ((va)->va_size)
#define nnpfs_vattr_get_ctime_sec(va) ((va)->va_ctime.tv_sec)
#define nnpfs_vattr_get_atime_sec(va) ((va)->va_atime.tv_sec)
#define nnpfs_vattr_get_mtime_sec(va) ((va)->va_mtime.tv_sec)
#define nnpfs_vattr_get_mtime_nsec(va) ((va)->va_mtime.tv_nsec)

#define nnpfs_vattr_set(va, n, val) ((va)-> n = (val))

#define nnpfs_vattr_set_size(va, val) ((va)->va_size = (val))
#define nnpfs_vattr_set_bytes(va, val) ((va)->va_bytes = (val))
#define nnpfs_vattr_set_ctime(va, sec, nsec) do {	\
	(va)->va_ctime.tv_sec = (sec);			\
	(va)->va_ctime.tv_nsec = (nsec);		\
    } while (0)
#define nnpfs_vattr_set_atime(va, sec, nsec) do {	\
	(va)->va_atime.tv_sec = (sec);			\
	(va)->va_atime.tv_nsec = (nsec);		\
    } while (0)
#define nnpfs_vattr_set_mtime(va, sec, nsec) do {	\
	(va)->va_mtime.tv_sec = (sec);			\
	(va)->va_mtime.tv_nsec = (nsec);		\
    } while (0)

#define nnpfs_vattr_size_isactive(va) ((va)->va_size != (va_size_t)VNOVAL)
#define nnpfs_vattr_mtime_isactive(va) ((va)->va_mtime.tv_sec != (time_t)VNOVAL)

#define nnpfs_vnode_isdir(vp) ((vp)->v_type == VDIR)
#define nnpfs_vnode_islnk(vp) ((vp)->v_type == VLNK)
#define nnpfs_vnode_ischr(vp) ((vp)->v_type == VCHR)
#define nnpfs_vnode_isreg(vp) ((vp)->v_type == VREG)
#define nnpfs_vnode_mount(vp) ((vp)->v_mount)
#define nnpfs_vnode_isinuse(vp, cnt) ((vp)->v_usecount > (cnt))

#endif

#ifdef __APPLE__

typedef vfs_context_t nnpfs_vfs_context;
#define nnpfs_vfs_context_proc(c) vfs_context_proc(c)
#define nnpfs_vfs_context_ucred(c) vfs_context_ucred(c)
#define nnpfs_vfs_context_create(nnpfs) \
    do { nnpfs->ctx = vfs_context_create(NULL); } while(0)
#define nnpfs_vfs_context_rele(ctx) vfs_context_rele(ctx)

#else

typedef struct nnpfs_vfscontext {
    d_thread_t *proc;
    nnpfs_kernel_cred cred;
} nnpfs_vfs_context;

#define nnpfs_vfs_context_init(ctx, p, creds) do {	\
	(ctx).proc = (p);			\
	(ctx).cred = (creds);			\
    } while (0)

#define nnpfs_vfs_context_proc(c) ((c).proc)
#define nnpfs_vfs_context_ucred(c) ((c).cred)

#define nnpfs_vfs_context_create(nnpfs)	\
    nnpfs_vfs_context_init(nnpfs->ctx, nnpfs_curproc(), nnpfs_proc_to_cred(nnpfs_curproc()));
#define nnpfs_vfs_context_rele(ctx) do { } while(0)

#endif

struct nnpfs_node {
#if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 105280000
    struct genfs_node gnode;
#endif
    struct vnode *vn;
    uint32_t index;
    struct nnpfs_cache_handle data;
    struct vnode *cache_vn;
    struct nnpfs_vfs_vattr attr;
    uint64_t daemon_length;
#ifdef __APPLE__
    int writers;
#endif
    int pending_writes;
    int async_error;
    u_int flags;
    u_int tokens;
    nnpfs_handle handle;
    nnpfs_pag_t id[NNPFS_MAXRIGHTS];
    nnpfs_rights rights[NNPFS_MAXRIGHTS];
    nnpfs_rights anonrights;

#ifndef __FreeBSD__
#if (defined(HAVE_KERNEL_LOCKMGR) || defined(HAVE_KERNEL_DEBUGLOCKMGR)) && !defined(__APPLE__)
    nnpfs_vnode_lock lock;
#else
    int vnlocks;
#endif
#endif /* !__FreeBSD__ */

#ifdef HAVE_KERNEL_LF_ADVLOCK
#ifdef __DragonFly__
    struct   lockf lockf;
#else
    struct   lockf *lockf;
#endif
#endif
    nnpfs_cred rd_cred;
    nnpfs_cred wr_cred;
    NNPQUEUE_ENTRY(nnpfs_node) nn_hash;
    NNPQUEUE_ENTRY(nnpfs_node) nn_free;
};

#define XN_HASHSIZE	101

NNPQUEUE_HEAD(nh_node_list, nnpfs_node);

struct nnpfs_nodelist_head {
    struct nh_node_list	nh_nodelist[XN_HASHSIZE];
};

void	nnpfs_init_head(struct nnpfs_nodelist_head *);
void	nnpfs_node_purge(struct nnpfs_nodelist_head *,
			 void (*func)(struct nnpfs_node *));
int	nnpfs_node_find(struct nnpfs *nnpfsp, nnpfs_handle *handlep,
			struct nnpfs_node **node);

void	nnpfs_remove_node(struct nnpfs_nodelist_head *, struct nnpfs_node *);
void	nnpfs_insert(struct nnpfs_nodelist_head *, struct nnpfs_node *);
int	nnpfs_update_handle(struct nnpfs *, nnpfs_handle *, nnpfs_handle *);

struct nnpfs;

int nnpfs_getnewvnode(struct nnpfs *,
		      struct vnode **,
		      struct nnpfs_handle *, 
		      struct nnpfs_msg_node *,
		      d_thread_t *, int);


#define XNODE_TO_VNODE(xp) ((xp)->vn)
#ifdef __APPLE__
#define VNODE_TO_XNODE(vp) ((struct nnpfs_node *) vnode_fsnode(vp))
#else
#define VNODE_TO_XNODE(vp) ((struct nnpfs_node *) (vp)->v_data)
#endif

#if defined(__APPLE__)
#define nnpfs_do_vget(vp, lockflag, proc) vnode_get(vp)
#elif defined(__DragonFly__)
#define nnpfs_do_vget(vp, lockflag, proc) vget((vp), NULL, (lockflag), (proc))
#elif defined(HAVE_ONE_ARGUMENT_VGET)
#define nnpfs_do_vget(vp, lockflag, proc) vget((vp))
#elif defined(HAVE_TWO_ARGUMENT_VGET)
#define nnpfs_do_vget(vp, lockflag, proc) vget((vp), (lockflag))
#elif defined(HAVE_THREE_ARGUMENT_VGET)
#define nnpfs_do_vget(vp, lockflag, proc) vget((vp), (lockflag), (proc))
#else
#error what kind of vget
#endif


#ifndef HAVE_VOP_T
#if defined(__FreeBSD_version) && __FreeBSD_version > 600006
typedef struct vop_vector vop_t;
#else
typedef int vop_t (void *);
#endif
#endif

#ifdef LK_INTERLOCK
#define HAVE_LK_INTERLOCK
#else
#define LK_INTERLOCK 0
#endif

#ifdef LK_RETRY
#define HAVE_LK_RETRY
#else
#define LK_RETRY 0
#endif

/*
 * This is compat code for older vfs that have a 
 * vget that only take a integer (really boolean) argument
 * that the the returned vnode will be returned locked
 */

#ifdef LK_EXCLUSIVE
#define HAVE_LK_EXCLUSIVE 1
#else
#define LK_EXCLUSIVE 1
#endif

#ifdef LK_SHARED
#define HAVE_LK_SHARED 1
#else
#define LK_SHARED 1
#endif

void nnpfs_setcred(nnpfs_cred *ncred, nnpfs_kernel_cred ucred);

#endif				       /* _nnpfs_xnode_h */
