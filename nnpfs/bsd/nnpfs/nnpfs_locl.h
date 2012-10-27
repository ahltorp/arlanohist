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

/* $Id: nnpfs_locl.h,v 1.116 2008/02/26 21:59:17 tol Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef RCSID
#define RCSID(x)
#endif

typedef struct componentname nnpfs_componentname;

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#ifdef HAVE_SYS_MODULE_H
#include <sys/module.h>
#endif
#include <sys/systm.h>
#include <sys/fcntl.h>
#ifdef HAVE_SYS_SYSPROTO_H
#include <sys/sysproto.h>
#endif
#include <sys/conf.h>
#include <sys/mount.h>
#ifdef HAVE_SYS_EXEC_H
#include <sys/exec.h>
#endif
#ifdef HAVE_SYS_SYSENT_H
#include <sys/sysent.h>
#endif
#ifdef HAVE_SYS_LKM_H
#include <sys/lkm.h>
#endif
#ifdef HAVE_SYS_LOCK_H
#include <sys/lock.h>
#endif
#ifdef HAVE_SYS_MUTEX_H
#include <sys/mutex.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <sys/vnode.h>
#ifdef __APPLE__
#include <sys/vnode_if.h>
#endif
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/ucred.h>
#include <sys/select.h>
#include <sys/uio.h>
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#ifdef HAVE_SYS_POOL_H
#include <sys/pool.h>
#endif
#ifdef HAVE_SYS_SIGNALVAR_H
#include <sys/signalvar.h>
#endif
#ifdef HAVE_SYS_STDINT_H
#include <sys/stdint.h>
#endif
#ifdef HAVE_SYS_INTTYPES_H
#include <sys/inttypes.h>
#endif
#include <sys/syscall.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#ifdef HAVE_SYS_SA_H
#include <sys/sa.h>
#endif
#ifdef HAVE_SYS_SYSCALLARGS_H
#include <sys/syscallargs.h>
#endif
#ifdef HAVE_SYS_ATTR_H
#include <sys/attr.h>
#endif
#if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 399001900 /* 3.99.19 */

#define HAVE_SYS_KAUTH_H
#endif
#ifdef HAVE_SYS_KAUTH_H
#include <sys/kauth.h>
#endif
#ifdef HAVE_SYS_PRIV_H
#include <sys/priv.h>
#endif

#ifdef HAVE_MISCFS_GENFS_GENFS_H
#include <miscfs/genfs/genfs.h>
#endif
#ifdef HAVE_MISCFS_SYNCFS_SYNCFS_H
#include <miscfs/syncfs/syncfs.h>
#endif
#ifndef HAVE_KERNEL_UVM_ONLY
#ifdef HAVE_VM_VM_H
#include <vm/vm.h>
#endif
#ifdef HAVE_VM_VM_EXTERN_H
#include <vm/vm_extern.h>
#endif
#ifdef HAVE_VM_VM_ZONE_H
#include <vm/vm_zone.h>
#endif
#ifdef HAVE_VM_VM_OBJECT_H
#include <vm/vm_object.h>
#endif
#endif
#ifdef HAVE_UVM_UVM_EXTERN_H
#include <uvm/uvm_extern.h>
#endif
#ifdef HAVE_VM_UMA_H
#include <vm/uma.h>
#endif

#ifdef __APPLE__
#undef MACH_ASSERT
#define MACH_ASSERT 1
#include <kern/assert.h>

#include <machine/machine_routines.h>
#include <mach/machine/vm_types.h>
#include <sys/ubc.h>
#include <sys/kauth.h>
#endif

#ifdef __FreeBSD__
#include <sys/bio.h>
#include <sys/buf.h>
#endif

#if defined(__FreeBSD__)
#define nnpfs_assert(x) \
do { if(!(x)) panic("nnpfs_assert(" #x ") failed"); } while(0);
#else
#define nnpfs_assert(x) assert(x)
#endif

#if 0
#define nnpfs_debug_assert(x) nnpfs_assert(x)
#else
#define nnpfs_debug_assert(x) do { } while(0)
#endif

#ifdef __APPLE__

/* exported but not documented nor in headers */
int ubc_isinuse(struct vnode *vp, int busycount);

#define nnpfs_vop_read(t, uio, ioflag, ctx, error) \
	(error) = VNOP_READ((t), (uio), (ioflag), (ctx))
#define nnpfs_vop_write(t, uio, ioflag, ctx, error) \
	(error) = VNOP_WRITE((t), (uio), (ioflag), (ctx))
#define nnpfs_lookup_access(dvp, ctx, proc, error)	\
	(error) = vnode_authorize((dvp), NULL, KAUTH_VNODE_EXECUTE, (ctx))

#define nnpfs_tsleep(chan, pri, msg)	\
	msleep((chan), NULL, (pri), (msg), NULL)
#define nnpfs_msleep(chan, mtx, pri, msg)		\
	msleep((chan), (mtx), (pri), (msg), NULL)

#else /* !__APPLE__ */

#define nnpfs_vop_read(t, uio, ioflag, cred, error) \
	(error) = VOP_READ((t), (uio), (ioflag), (cred))
#define nnpfs_vop_write(t, uio, ioflag, cred, error) \
	(error) = VOP_WRITE((t), (uio), (ioflag), (cred))
#define nnpfs_lookup_access(dvp, ctx, proc, error) \
	(error) = VOP_ACCESS((dvp), VEXEC, nnpfs_vfs_context_ucred(ctx), (proc))

#if defined(__OpenBSD__) && !defined(DIAGNOSTIC)
#define nnpfs_vprint(msg, vp)   do { } while(0)
#else
#define nnpfs_vprint(msg, vp)   vprint(msg, vp)
#endif

#define nnpfs_tsleep(chan, pri, msg)	\
	tsleep((chan), (pri), (msg), 0)

#if defined(__FreeBSD__)
#define nnpfs_msleep(chan, mtx, pri, msg)		\
	msleep((chan), (mtx), (pri), (msg), 0)
#elif defined(__NetBSD__)
#define nnpfs_msleep(chan, mtx, pri, msg)		\
	ltsleep((chan), (pri), (msg), 0, (mtx)) /* XXX */
#else
#define nnpfs_msleep(chan, mtx, pri, msg)		\
	tsleep((chan), (pri), (msg), 0) /* XXX */
#endif

#endif /* !__APPLE__ */


#ifdef __APPLE__
#define nnpfs_vop_getattr(t, attr, ctx, error) \
	(error) = vnode_getattr(t, attr, ctx)
#elif defined(__DragonFly__)
#define nnpfs_vop_getattr(t, attr, ctx, error) \
    (error) = VOP_GETATTR((t), (attr), nnpfs_vfs_context_proc(ctx))
#elif defined(__NetBSD__) && __NetBSD_Version__ > 399001900 /* NetBSD 3.99.19 */
#define nnpfs_vop_getattr(t, attr, ctx, error) \
	(error) = VOP_GETATTR((t), (attr), nnpfs_vfs_context_ucred(ctx), \
			      nnpfs_vfs_context_proc(ctx))
#else
#define nnpfs_vop_getattr(t, attr, ctx, error) \
    (error) = VOP_GETATTR((t), (attr), nnpfs_vfs_context_ucred(ctx), nnpfs_vfs_context_proc(ctx))
#endif

#ifndef __APPLE__
#define VATTR_INIT(va) VATTR_NULL(va)
#define nnpfs_set_va_size(va,size) ((va)->va_size = (size))
#define nnpfs_vnode_setattr(vp, va, ctx) VOP_SETATTR(vp, va, nnpfs_vfs_context_ucred(ctx), nnpfs_vfs_context_proc(ctx))
#else
#define nnpfs_set_va_size(va,size) VATTR_SET(va,va_data_size,size)
#define nnpfs_vnode_setattr(vp, va, ctx) vnode_setattr(vp, va, ctx)
#endif

typedef u_quad_t va_size_t;


#if defined(__FreeBSD_version) || defined(__DragonFly__)
#if __FreeBSD_version < 600006
# error This version is unsupported
#endif
#define HAVE_FREEBSD_THREAD
typedef d_thread_t syscall_d_thread_t;
#define syscall_thread_to_thread(x) (x)
#else /* !__FreeBSD_version || __DragonFly__ */

#if defined(__NetBSD__) && __NetBSD_Version__ >= 399001400 /* NetBSD 3.99.14 */
typedef struct lwp syscall_d_thread_t;
#define syscall_thread_to_thread(x) ((x))

#elif defined(__NetBSD__)
typedef struct lwp syscall_d_thread_t;
#define syscall_thread_to_thread(x) ((x)->l_proc)

#else
typedef struct proc syscall_d_thread_t;
#define syscall_thread_to_thread(x) (x)
#endif

#if __NetBSD_Version__ >= 399001400 /* NetBSD 3.99.14 */
typedef struct lwp d_thread_t;
#else /* __NetBSD_Version__ >= 399001400 */
typedef struct proc d_thread_t;
#endif /* __NetBSD_Version__ >= 399001400 */
#endif /* !__FreeBSD_version || __DragonFly__ */

#ifdef VV_ROOT
#define NNPFS_MAKE_VROOT(v) ((v)->v_vflag |= VV_ROOT) /* FreeBSD 5 */
#else
#define NNPFS_MAKE_VROOT(v) ((v)->v_flag |= VROOT)
#endif

#if defined(__NetBSD__) && __NetBSD_Version__ >= 105280000
#include <miscfs/genfs/genfs.h>
#include <miscfs/genfs/genfs_node.h>

struct genfs_ops nnpfs_genfsops;
#endif

#if defined(__NetBSD__) && __NetBSD_Version__ >= 399001900 /* NetBSD 3.99.19 */
typedef struct kauth_cred *nnpfs_kernel_cred;
#define nnpfs_cred_get_uid(cred) kauth_cred_getuid(cred)
#else
typedef struct ucred *nnpfs_kernel_cred;
#define nnpfs_cred_get_uid(cred) ((cred)->cr_uid)
#endif

#if defined(HAVE_FREEBSD_THREAD)
#ifdef __DragonFly__
#define nnpfs_uio_to_proc(uiop) ((uiop)->uio_td == NULL ? curthread : (uiop)->uio_td)
#define nnpfs_cnp_to_proc(cnp) ((cnp)->cn_td)
#else
#define nnpfs_uio_to_proc(uiop) ((uiop)->uio_td)
#define nnpfs_cnp_to_proc(cnp) ((cnp)->cn_thread)
#endif
#define nnpfs_proc_to_cred(td) ((td)->td_proc->p_ucred)
#define nnpfs_proc_to_euid(td) ((td)->td_proc->p_ucred->cr_uid)
#elif defined(__APPLE__)
#define nnpfs_uio_to_proc(uiop) XXX
#define nnpfs_cnp_to_proc(cnp) ((cnp)->cn_proc)
#define nnpfs_proc_to_cred(p) proc_ucred(p)
#define nnpfs_proc_to_euid(p) XXX
#elif defined(__NetBSD__) && __NetBSD_Version__ >= 399001400 /* 3.99.14 */
#define nnpfs_uio_to_proc(uiop) ((uiop)->uio_lwp)
#define nnpfs_cnp_to_proc(cnp) ((cnp)->cn_lwp)
#define nnpfs_proc_to_cred(p) ((p)->l_proc->p_cred)
#define nnpfs_proc_to_euid(p) ((p)->l_proc->p_ucred->cr_uid)
#else
#define nnpfs_uio_to_proc(uiop) ((uiop)->uio_procp)
#define nnpfs_cnp_to_proc(cnp) ((cnp)->cn_proc)
#define nnpfs_proc_to_cred(p) ((p)->p_ucred)
#define nnpfs_proc_to_euid(p) ((p)->p_ucred->cr_uid)
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version >= 500043
extern const char *VT_AFS;
#endif

#ifdef __APPLE__
extern int nnpfs_typenum;

#define nnpfs_uio_resid(uiop) uio_resid(uiop)
#define nnpfs_uio_setresid(uiop, val) uio_setresid((uiop), (val))
#define nnpfs_uio_offset(uiop) uio_offset(uiop)
#define nnpfs_uio_setoffset(uiop, val) uio_setoffset((uiop), (val))
#else
#define nnpfs_uio_resid(uiop) ((uiop)->uio_resid)
#define nnpfs_uio_setresid(uiop, val) ((uiop)->uio_resid = (val))
#define nnpfs_uio_offset(uiop) ((uiop)->uio_offset)
#define nnpfs_uio_setoffset(uiop,  val) ((uiop)->uio_offset = (val))
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
typedef void * nnpfs_malloc_type;
#elif defined(__NetBSD__) && __NetBSD_Version__ >= 106140000 /* 1.6N */
typedef struct malloc_type * nnpfs_malloc_type;
#else
typedef int nnpfs_malloc_type;
#endif

/* openbsd 3.5 uses a pool for name component string, but doesn't
 * provide a PNBUF_PUT macro */
#if defined(OpenBSD) && OpenBSD >= 200405 && !defined(PNBUF_PUT)
#define PNBUF_PUT(_n) pool_put(&namei_pool, _n)
#endif

#ifdef __APPLE__
#include <sys/vm.h>
#define nnpfs_curproc() (current_proc())
#else
#if defined(HAVE_FREEBSD_THREAD)
#define nnpfs_curproc() (curthread)
#else
#if __NetBSD_Version__ >= 399001400 /* 3.99.14 */
#define nnpfs_curproc() (curlwp)
#else
#define nnpfs_curproc() (curproc)
#endif
#endif
#endif

void	nnpfs_pushdirty(struct vnode *vp);


#if defined(HAVE_UINTPTR_T) /* c99 enviroment */
#define nnpfs_uintptr_t		uintptr_t
#else
#if defined(_LP64) || defined(alpha) || defined(__alpha__) || defined(__sparc64__) || defined(__sparcv9__)
#define nnpfs_uintptr_t		unsigned long long
#else /* !LP64 */
#define nnpfs_uintptr_t		unsigned long
#endif /* LP64 */
#endif

/*
 * XXX
 */

#ifndef SCARG
#if defined(__FreeBSD_version) && __FreeBSD_version >  500042
#define SCARG(a, b) ((a)->b)
#define syscallarg(x)   x
#else
#define SCARG(a, b) ((a)->b.datum)
#define syscallarg(x)   union { x datum; register_t pad; }
#endif /* __FreeBSD_version */
#endif /* SCARG */

#ifndef syscallarg
#define syscallarg(x)   x
#endif

#ifndef HAVE_REGISTER_T
typedef int register_t;
#endif

/* malloc(9) waits by default, freebsd post 5.0 choose to remove the flag */
#ifndef M_WAITOK
#define M_WAITOK 0
#endif

#if defined(HAVE_DEF_STRUCT_SETGROUPS_ARGS)
#define nnpfs_setgroups_args setgroups_args
#elif defined(HAVE_DEF_STRUCT_SYS_SETGROUPS_ARGS)
#define nnpfs_setgroups_args sys_setgroups_args
#elif defined(__APPLE__)
struct nnpfs_setgroups_args{
        syscallarg(u_int)   gidsetsize;
        syscallarg(gid_t)   *gidset;
};
#else
#error what is your setgroups named ?
#endif


#ifdef HAVE_KERNEL_VFS_GETVFS
#define nnpfs_vfs_getvfs vfs_getvfs
#else
#define nnpfs_vfs_getvfs getvfs
#endif

#ifdef HAVE_FOUR_ARGUMENT_VFS_OBJECT_CREATE
#define nnpfs_vfs_object_create(vp,proc,ucred) vfs_object_create(vp,proc,ucred,TRUE)
#elif defined(__DragonFly__)
#define nnpfs_vfs_object_create(vp,proc,ucred) vfs_object_create(vp,proc)
#else
#define nnpfs_vfs_object_create(vp,proc,ucred) vfs_object_create(vp,proc,ucred)
#endif

#if  defined(UVM) || (defined(__NetBSD__) && __NetBSD_Version__ >= 105280000)
#define nnpfs_set_vp_size(vp, sz) uvm_vnp_setsize(vp, sz)
#elif HAVE_KERNEL_VNODE_PAGER_SETSIZE
#define nnpfs_set_vp_size(vp, sz) vnode_pager_setsize(vp, sz)
#elif defined(__APPLE__)
#define nnpfs_set_vp_size(vp, sz) ubc_setsize(vp, sz)
#else
#define nnpfs_set_vp_size(vp, sz)
#endif

#ifdef __APPLE__
#define nnpfs_statvfs struct vfs_attr
#elif defined(__NetBSD_Version__) && __NetBSD_Version__ > 299000900 /* really statvfs */
#define nnpfs_statvfs struct statvfs
#else
#define nnpfs_statvfs struct statfs
#endif

/* namei flag */
#ifdef LOCKLEAF
#define NNPFS_LOCKLEAF LOCKLEAF
#else
#define NNPFS_LOCKLEAF 0
#endif

#ifdef MPSAFE
#define NNPFS_MPSAFE MPSAFE
#else
#define NNPFS_MPSAFE 0
#endif

#if defined(HAVE_SYS_MUTEX_H) && !defined(OpenBSD)
#define nnpfs_interlock_lock(interlock) mtx_lock(interlock);
#define nnpfs_interlock_unlock(interlock) mtx_unlock(interlock);
#else
#define nnpfs_interlock_lock(interlock) simple_lock(interlock);
#define nnpfs_interlock_unlock(interlock) simple_unlock(interlock);
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 502116
#define nnpfs_dev_t	struct cdev *
#else
#define nnpfs_dev_t	dev_t 
#endif

#ifndef VN_KNOTE
#define VN_KNOTE(vp,v) do { } while(0)
#endif

#define nnpfs_major(dev) major(dev)
#define nnpfs_minor(dev) minor(dev)

#if defined(__FreeBSD__) && __FreeBSD_version >= 503001
#define NNPFS_VN_KNOTE(a,b) VN_KNOTE_UNLOCKED(a,b)
#else
#define NNPFS_VN_KNOTE(a,b) VN_KNOTE(a,b)
#endif


#ifdef NEED_VGONEL_PROTO
void    vgonel (struct vnode *vp, d_thread_t *p);
#endif

#ifdef NEED_ISSIGNAL_PROTO
int	issignal (d_thread_t *);
#endif

#ifdef NEED_STRNCMP_PROTO
int	strncmp (const char *, const char *, size_t);
#endif

#ifdef NEED_VN_WRITECHK_PROTO
int	vn_writechk (struct vnode *);
#endif

#include <nnpfs/nnpfs_node.h>
#include <nnpfs/nnpfs_syscalls.h>

#ifdef __DragonFly__

#define VREF(vp) vref((vp))

/* DragonFly doesn't use sleep priorities */
#define PZERO  0
#define PVFS   0

/* Backward compatability defines */
#define CREATE NAMEI_CREATE
#define LOOKUP NAMEI_LOOKUP
#define RENAME NAMEI_RENAME

#define FOLLOW     CNP_FOLLOW
#define HASBUF     CNP_HASBUF
#define ISDOTDOT   CNP_ISDOTDOT
#define ISLASTCN   CNP_ISLASTCN
#define LOCKLEAF   CNP_LOCKLEAF
#define LOCKPARENT CNP_LOCKPARENT
#define MAKEENTRY  CNP_MAKEENTRY
#define SAVENAME   CNP_SAVENAME
#define SAVESTART  CNP_SAVESTART

#endif /* __DragonFly__ */

#if defined(__NetBSD__) && __NetBSD_Version__ >= 299001100
#define KERNEL_VAR_VNOPS_CONST const
#else
#define KERNEL_VAR_VNOPS_CONST
#endif

#define NNPFS_MSG_WAKEUP_ERROR(m) \
	(((struct nnpfs_message_wakeup *)(void *)m)->error)

/* 
 *  The VOP table
 *
 *    What VOPs do we have today ? 
 */

#define  NNPFS_VOP_DEF(n)			\
	struct vop_##n##_args;			\
	int nnpfs_##n(struct vop_##n##_args *)

#include "nnpfs/nnpfs_vopdefs.h"
