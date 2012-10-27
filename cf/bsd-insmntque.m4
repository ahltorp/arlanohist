dnl
dnl $Id: bsd-insmntque.m4,v 1.1 2008/02/26 22:01:30 tol Exp $
dnl

dnl
dnl Find out if kernel has insmntque
dnl

AC_DEFUN([AC_BSD_FUNC_INSMNTQUE], [
AC_CACHE_CHECK(if kernel has insmntque, ac_cv_func_insmntque,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[insmntque(0, 0)],
ac_cv_func_insmntque=yes,
ac_cv_func_insmntque=no))
if test "$ac_cv_func_insmntque" = yes; then
	AC_DEFINE_UNQUOTED(HAVE_KERNEL_INSMNTQUE, 1,
	[define if kernel has insmntque])
fi
])
