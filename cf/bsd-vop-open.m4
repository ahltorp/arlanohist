dnl
dnl $Id: bsd-vop-open.m4,v 1.1 2008/02/26 22:01:32 tol Exp $
dnl

dnl
dnl Find out if VOP_OPEN takes a struct file or an integer final argument on
dnl FreeBSD.
dnl

AC_DEFUN([AC_BSD_FUNC_VOP_OPEN], [
AC_CACHE_CHECK(if VOP_OPEN takes a struct file final argument, ac_cv_func_vop_open_file_arg,
save_CFLAGS2="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_OPEN(NULL, 0, NULL, NULL, (struct file *)NULL)],
ac_cv_func_vop_open_file_arg=yes,
ac_cv_func_vop_open_file_arg=no))
if test "$ac_cv_func_vop_open_file_arg" = yes; then
	AC_DEFINE(HAVE_FINAL_ARG_FILE_VOP_OPEN, 1,
	[define if VOP_OPEN takes a file final argument])
fi
CFLAGS="$save_CFLAGS2"
])
