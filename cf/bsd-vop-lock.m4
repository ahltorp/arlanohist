dnl
dnl $Id: bsd-vop-lock.m4,v 1.4 2004/02/12 16:28:15 lha Exp $
dnl

dnl
dnl Find out if VOP_LOCK takes one, two, or three arguments
dnl

AC_DEFUN([AC_BSD_FUNC_VOP_LOCK], [
AC_CACHE_CHECK(if VOP_LOCK takes one argument, ac_cv_func_vop_lock_one_arg,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_LOCK(0)],
ac_cv_func_vop_lock_one_arg=yes,
ac_cv_func_vop_lock_one_arg=no))
if test "$ac_cv_func_vop_lock_one_arg" = yes; then
	AC_DEFINE_UNQUOTED(HAVE_ONE_ARGUMENT_VOP_LOCK, 1,
	[define if VOP_LOCK takes one argument])
fi

AC_CACHE_CHECK(if VOP_LOCK takes two arguments, ac_cv_func_vop_lock_two_args,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_LOCK(0, 0)],
ac_cv_func_vop_lock_two_args=yes,
ac_cv_func_vop_lock_two_args=no))
if test "$ac_cv_func_vop_lock_two_args" = yes; then
	AC_DEFINE(HAVE_TWO_ARGUMENT_VOP_LOCK, 1,
	[define if VOP_LOCK takes two arguments])
fi

AC_CACHE_CHECK(if VOP_LOCK takes three arguments, ac_cv_func_vop_lock_three_args,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[VOP_LOCK(0, 0, 0)],
ac_cv_func_vop_lock_three_args=yes,
ac_cv_func_vop_lock_three_args=no))
if test "$ac_cv_func_vop_lock_three_args" = yes; then
	AC_DEFINE(HAVE_THREE_ARGUMENT_VOP_LOCK, 1,
	[define if VOP_LOCK takes three arguments])
fi
])
