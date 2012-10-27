dnl
dnl $Id: bsd-vop-unlock.m4,v 1.1 2008/02/26 22:01:33 tol Exp $
dnl

dnl
dnl Find out if VOP_UNLOCK takes one, two, or three arguments
dnl

AC_DEFUN([AC_BSD_FUNC_VOP_UNLOCK], [
AC_CACHE_CHECK(if VOP_UNLOCK takes one argument, ac_cv_func_vop_unlock_one_arg,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_UNLOCK(0)],
ac_cv_func_vop_unlock_one_arg=yes,
ac_cv_func_vop_unlock_one_arg=no))
if test "$ac_cv_func_vop_unlock_one_arg" = yes; then
	AC_DEFINE_UNQUOTED(HAVE_ONE_ARGUMENT_VOP_UNLOCK, 1,
	[define if VOP_UNLOCK takes one argument])
fi

AC_CACHE_CHECK(if VOP_UNLOCK takes two arguments, ac_cv_func_vop_unlock_two_args,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_UNLOCK(0, 0)],
ac_cv_func_vop_unlock_two_args=yes,
ac_cv_func_vop_unlock_two_args=no))
if test "$ac_cv_func_vop_unlock_two_args" = yes; then
	AC_DEFINE(HAVE_TWO_ARGUMENT_VOP_UNLOCK, 1,
	[define if VOP_UNLOCK takes two arguments])
fi

AC_CACHE_CHECK(if VOP_UNLOCK takes three arguments, ac_cv_func_vop_unlock_three_args,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_UNLOCK(0, 0, 0)],
ac_cv_func_vop_unlock_three_args=yes,
ac_cv_func_vop_unlock_three_args=no))
if test "$ac_cv_func_vop_unlock_three_args" = yes; then
	AC_DEFINE(HAVE_THREE_ARGUMENT_VOP_UNLOCK, 1,
	[define if VOP_UNLOCK takes three arguments])
fi
])
