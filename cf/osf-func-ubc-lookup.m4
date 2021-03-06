dnl
dnl $Id: osf-func-ubc-lookup.m4,v 1.3 2004/02/12 16:28:18 lha Exp $
dnl

AC_DEFUN([AC_OSF_FUNC_UBC_LOOKUP], [
AC_CACHE_CHECK(if ubc_lookup takes six arguments,
ac_cv_func_ubc_lookup_six_args,
AC_TRY_COMPILE_KERNEL([
#if defined(__osf__) && defined(__GNUC__)
#define asm __foo_asm
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <vm/vm_ubc.h>
], [ubc_lookup(NULL, 0, 0, 0, NULL, NULL)],
ac_cv_func_ubc_lookup_six_args=yes,
ac_cv_func_ubc_lookup_six_args=no))
if test "$ac_cv_func_ubc_lookup_six_args" = yes; then
	AC_DEFINE(HAVE_SIX_ARGUMENT_UBC_LOOKUP, 1,
	[define if ubc_lookup takes six arguments])
fi
])
