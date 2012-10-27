dnl
dnl $Id: bsd-vnode-create-vobject.m4,v 1.1 2008/02/26 22:01:32 tol Exp $
dnl

dnl
dnl Find out if vnode_create_vobject() takes one argument or two on BSD; if
dnl two then we need to use vnode_create_vobject_off() instead.
dnl

AC_DEFUN([AC_BSD_FUNC_VNODE_CREATE_VOBJECT], [
AC_CACHE_CHECK(if vnode_create_vobject takes three arguments, ac_cv_func_vnode_create_vobject,
AC_TRY_COMPILE_KERNEL([
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
],[vnode_create_vobject(0, 0, 0)],
ac_cv_func_vnode_create_vobject_three_args=yes,
ac_cv_func_vnode_create_vobject_three_args=no))
if test "$ac_cv_func_vnode_create_vobject_three_args" = yes; then
	AC_DEFINE(HAVE_THREE_ARGUMENT_VNODE_CREATE_VOBJ, 1,
	[define if vnode_create_vobject takes three arguments])
fi
])
