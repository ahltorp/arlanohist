dnl
dnl $Id: check-kerberos2.m4,v 1.2 2004/02/12 16:28:16 lha Exp $
dnl
dnl Check if the dog is alive
dnl

AC_DEFUN([AC_CHECK_KERBEROS2],[

AC_ARG_WITH(krb4,
[  --with-krb4=dir         use kerberos 4 in dir],
[],[with_krb4=yes])

AC_ARG_WITH(krb4-lib,
[  --with-krb4-lib=dir     use kerberos 4 libraries in dir],
[if test "$withval" = "yes" -o "$withval" = "no"; then
  AC_MSG_ERROR([No argument for --with-krb4-lib])
fi])

AC_ARG_WITH(krb4-include,
[  --with-krb4-include=dir use kerberos 4 headers in dir],
[if test "$withval" = "yes" -o "$withval" = "no"; then
  AC_MSG_ERROR([No argument for --with-krb4-include])
fi])


dnl
dnl Check for kerberos4
dnl

if test X"$with_krb4" != "Xno" -a X"$with_krb4" != "Xyes" ; then
   if test X"$with_krb4_lib" = "X"; then
      with_krb4_lib="$with_krb4/lib"
   fi
   if test X"$with_krb4_include" = "X"; then
      with_krb4_include="$with_krb4/include"
   fi
fi

AC_MSG_CHECKING(probing for kerberos 4)
AC_CACHE_VAL(ac_cv_found_krb4,[
if test "X$with_krb4" = "Xyes"; then
  for krblibs in "" /usr/heimdal /usr/athena /usr/kerberos /usr/local; do
    AC_CHECK_KRB4_2($krblibs, $with_krb4_lib, $with_krb4_include)
  done
elif test "X$with_krb4" != "Xno" -a "X$with_krb4" != "Xyes"; then
  AC_CHECK_KRB4_2($with_krb4, $with_krb4_lib, $with_krb4_include)
fi])

if test $ac_cv_found_krb4 != no; then
  AC_MSG_RESULT(yes)

  KRB4_INC_DIR=$ac_cv_krb4_where_inc
  KRB4_LIB_DIR=$ac_cv_krb4_where_lib
  KRB4_INC_FLAGS=
  if test "X$KRB4_INC_DIR" != "X" ; then
    KRB4_INC_FLAGS="-I${KRB4_INC_DIR}"
  fi
  KRB4_LIB_LIBS="$ac_cv_krb4_extralib"
  if test "X$KRB4_LIB_DIR" != "X" ; then
    KRB4_LIB_DIR="-L${KRB4_LIB_DIR}"
  fi
  KRB4_LIB_FLAGS="$KRB4_LIB_DIR $KRB4_LIB_LIBS"

else
  AC_MSG_RESULT(no)
fi

AC_SUBST(KRB4_LIB_DIR)
AC_SUBST(KRB4_INC_DIR)
AC_SUBST(KRB4_INC_FLAGS)
AC_SUBST(KRB4_LIB_LIBS)
AC_SUBST(KRB4_LIB_FLAGS)

])


dnl base, lib, inc
AC_DEFUN([AC_CHECK_KRB4_2],[
  AC_MSG_RESULT(started)
  if test -n "$2"; then
     klib=$2
  else
     klib=$1/lib;
  fi
  AC_MSG_CHECKING(for Kerberos 4 libs in $klib)
  AC_KRB4_LIB_WHERE1($klib)

  if test "$ac_cv_found_krb4_lib" != "no" ; then

     AC_MSG_RESULT([found, looking for include files])

     if test X$3 != "X"; then
       AC_MSG_CHECKING(for Kerberos 4 headers in $3)
       AC_KRB4_INC_WHERE1($3)
       if test "$ac_cv_found_krb4_inc" = "yes"; then
         AC_MSG_RESULT(found)
       else
         AC_MSG_RESULT(not found)
       fi
     else
       for j in "" kerberos "kerberosIV"; do
         if test -n "$1"; then
	   if test -n "$j"; then
	     d="$1/$j"
  	   else
	     d="$1"
	   fi
         else
	   if test -n "$j"; then
	     d="/usr/include/$j"
	   fi
         fi
         AC_MSG_CHECKING(for Kerberos 4 headers in $d)
	 AC_KRB4_INC_WHERE1($d)
         if test "$ac_cv_found_krb4_inc" = "yes"; then
	   AC_MSG_RESULT(found)
	   break 3
         else
	   AC_MSG_RESULT(not found)
         fi
       done
     fi

     if test "$ac_cv_found_krb4_inc" = "yes"; then
       ac_cv_krb4_where_inc=$d
       ac_cv_found_krb4=yes

       AC_DEFINE(KERBEROS, 1, [define if you have kerberos])
       AC_DEFINE(HAVE_KRB4, 1, [define if you have kerberos 4])

     else
       ac_cv_found_krb4=no
       ac_cv_found_krb4_lib=no
     fi
       AC_MSG_CHECKING(will use Kerberos 4)
  else
    :
  fi
])
