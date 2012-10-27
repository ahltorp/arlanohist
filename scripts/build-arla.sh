#!/bin/sh
# $Id: build-arla.sh,v 1.2 2002/06/03 17:00:48 lha Exp $
#
# This script will build a release of arla /usr/obj/arla-$VERSION
#

ppath=`dirname $0`
test -f ${ppath}/test-config && . ${ppath}/test-config


if [ X$ADIR = X ]; then
    ADIR=/nfsafs/e.kth.se/home/staff/lha/src/cvs/arla-0.35
fi

export VERSION ADIR

if [ ! -d /nfsafs/stacken.kth.se ] ;then
	mount -t nfs -o soft afs.pdc.kth.se:/afs /nfsafs
fi
if [ ! -d /nfsafs/stacken.kth.se ] ;then
	mount -F nfs afs.pdc.kth.se:/afs /nfsafs
fi
if [ ! -d /nfsafs/stacken.kth.se ] ;then
	echo Oppps, no /nfsafs
	exit 1
fi

MAKE=make

eval `grep '^VERSION=' $ADIR/configure.in`

if [ X$VERSION = X ]; then
    echo "Failed to find version of arla"
    exit 1
fi

OBJDIR=/usr/obj/arla-$VERSION

os=`$ADIR/config.guess`
case "$os" in
  *-*-*netbsd*)
	CONFIG_ARGS="--with-roken=/usr --with-roken-include=/usr/include/krb5"
	;;
esac

echo Objdir is $OBJDIR

rm -rf $OBJDIR
mkdir -p $OBJDIR
cd $OBJDIR

echo "Building arla echo $VERSION test script" > log 2>&1
echo "Platform: `uname -a`" >> log 2>&1
echo "Gnuname: $os" >> log 2>&1
date >> log 2>&1
echo Objdir is $OBJDIR >> log 2>&1 

echo "Configure"
echo $CONFIG_ENV $ADIR/configure $CONFIG_ARGS >> log
env $CONFIG_ENV $ADIR/configure $CONFIG_ARGS >> log 2>&1
e=$?
if [ $e != 0 ] ; then
    echo "Configure failed with: $e" >> log
    echo "Configure failed with: $e"
    exit $e
fi

echo "Make"
$MAKE >> log 2>&1
e=$?
if [ $e != 0 ] ; then
    echo "Make failed with: $e" >> log
    echo "Make failed with: $e"
    exit $e
fi

echo "Cleaning target dir"
rm -rf /usr/arla

echo "Install"
$MAKE install >> log 2>&1
e=$?
if [ $e != 0 ] ; then
    echo "Install failed with: $e" >> log
    echo "Install failed with: $e"
    exit $e
fi

echo Done
date >> log 2>&1 
echo Done >> log 2>&1
