dnl
dnl $Id: kernel.m4,v 1.2 2004/02/12 16:28:17 lha Exp $
dnl

dnl 
dnl Check for where the kernel is stored
dnl

AC_DEFUN([AC_KERNEL],
[
dnl XXX XXX XXX *** this test sucks *** XXX XXX XXX
if test "$ac_kernel_ld" = ""; then
if test "$ac_cv_sys_elf_object_format" = yes; then
ac_kernel_ld='${LD-ld} -o conftest $LDFLAGS -R $KERNEL conftest.o -e _foo 1>&AC_FD_CC'
else
ac_kernel_ld='${LD-ld} -o conftest $LDFLAGS -A $KERNEL conftest.o -e _foo 1>&AC_FD_CC'
fi
fi
])
