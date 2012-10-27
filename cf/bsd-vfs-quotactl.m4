dnl
dnl $Id: bsd-vfs-quotactl.m4,v 1.1 2008/02/26 22:01:31 tol Exp $
dnl

dnl
dnl Find out if VFS_QUOTACTL accepts a void * or a caddr_t argument.
dnl

AC_DEFUN([AC_BSD_FUNC_VFS_QUOTACTL], [
AC_CACHE_CHECK(if VFS_QUOTACTL takes caddr_t argument, ac_cv_func_vfs_quotactl_caddr,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/mount.h>

vfs_quotactl_t foo_quotactl;

int
foo_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t arg,
    struct thread *td)
{

	return (0);
}
],[],
ac_cv_func_vfs_quotactl_caddr=yes,
ac_cv_func_vfs_quotactl_caddr=no))
if test "$ac_cv_func_vfs_quotactl_caddr" = yes; then
	AC_DEFINE(HAVE_VFS_QUOTACTL_CADDR, 1,
	[define if VFS_QUOTACTL takes a caddr_t argument])
fi
])
