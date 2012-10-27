#!/bin/sh
#
#	$Id: mingwin.sh,v 1.1 2002/04/09 12:46:49 lha Exp $
#
#	A warper around configure for the mingw environment.
#	Enables the user to at least get thru running configure
#	and compileing libroken.
#
#	It also serves as documentaion of what is lacking the
#	current implementation (like in roken, and c/o)
#
#

progname=`basename $0`
srcdir=`dirname $0`/..

toolchain=/usr/pkg/cross/i386-mingw32/bin

while true
do
  case $1 in
  --mingw-arla-srcdir)
    if [ X$2 = X ] ; then
       echo $progname: missing argument to --srcdir
       exit 1;
    fi
    srcdir=$2
    shift 2
   ;;
  --mingw-toolchain)
    if [ X$2 = X ] ; then
       echo $progname: missing argument to --srcdir
       exit 1;
    fi
    toolchain=$2
    shift 2
   ;;
  *) break;;
  esac
done

echo $srcdir

if [ ! -f $srcdir/arlad/arla.c ]; then
    echo Missing arla srcdir as first argument
    exit 1
fi

if [ ! -f $toolchain/gcc ]; then
    echo Missing mingw toolchain
    exit 1
fi

PATH="$toolchain:$PATH"
export PATH

ARGS="$ARGS --enable-littleendian"
ARGS="$ARGS --without-x"
ARGS="$ARGS --disable-mmap"
ARGS="$ARGS --without-krb5"
ARGS="$ARGS --without-krb4"

env \
    ac_cv_htonl_works=yes \
    ac_cv_var_h_errno=yes \
    ac_cv_func_localtime_r=yes \
    ac_cv_func_getusershell=yes \
    ac_cv_func_vsyslog=yes \
$srcdir/configure $ARGS $* i386-unknown-mingw32

touch include/bits.o
touch include/bits

cat > include/atypes.h <<EOF
#ifndef __ATYPES_H
#define __ATYPES_H 1

#include <stdint.h>

typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;

#endif

EOF

