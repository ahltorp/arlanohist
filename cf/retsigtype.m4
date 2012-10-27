dnl
dnl $Id: retsigtype.m4,v 1.4 2004/02/12 16:28:18 lha Exp $
dnl
dnl Figure out return type of signal handlers, and define SIGRETURN macro
dnl that can be used to return from one
dnl
AC_DEFUN([rk_RETSIGTYPE],[
AC_TYPE_SIGNAL
if test "$ac_cv_type_signal" = "void" ; then
	AC_DEFINE(VOID_RETSIGTYPE, 1, [Define if signal handlers return void.])
fi
AC_SUBST(VOID_RETSIGTYPE)
AH_BOTTOM([#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif])
])