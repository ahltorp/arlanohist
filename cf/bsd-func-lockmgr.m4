dnl
dnl $Id: bsd-func-lockmgr.m4,v 1.4 2004/02/12 16:28:15 lha Exp $
dnl

AC_DEFUN([AC_BSD_FUNC_LOCKMGR], [
AC_CACHE_CHECK(if lockmgr takes four arguments,
ac_cv_func_lockmgr_four_args,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/lock.h>
], [lockmgr(NULL, 0, NULL, NULL)],
ac_cv_func_lockmgr_four_args=yes,
ac_cv_func_lockmgr_four_args=no))
if test "$ac_cv_func_lockmgr_four_args" = yes; then
	AC_DEFINE(HAVE_FOUR_ARGUMENT_LOCKMGR, 1,
	[define if lockmgr takes four arguments])
fi
])
