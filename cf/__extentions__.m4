dnl $Id: __extentions__.m4,v 1.1 2002/04/27 16:48:51 lha Exp $
dnl
dnl Define __EXTENSIONS__
dnl

AC_DEFUN([AC__EXTENSIONS__],[
AH_VERBATIM([__EXTENSIONS__],[
/*
 * Defining this enables us to get the definition of `sigset_t' and
 * other importatnt definitions on Solaris.
 */

#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif
])
])
