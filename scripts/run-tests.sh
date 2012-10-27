#!/bin/sh
#
# $Id: run-tests.sh,v 1.2 2002/06/03 16:59:18 lha Exp $
#
# This script will:
# - cd to the build directory and run the regression suite ther
# - build a summery of the test results
#

ppath=`dirname $0`

while test $# != 0; do
  case $1
  -no-start-arla)  startarla=no ;;
  -no-run-tests)  runtests=no ;;
  esac
  shift;
done

test -f ${ppath}/test-config && . ${ppath}/test-config

if [ X$ADIR = X ]; then
    ADIR=/nfsafs/e.kth.se/home/staff/lha/src/cvs/arla-0.35
fi

USER="-user nobody"

eval `grep '^VERSION=' $ADIR/configure.in`
if [ X$VERSION = X ]; then
    echo "Failed to find version of arla"
    exit 1
fi

WORKDIR=/afs/e.kth.se/home/staff/lha/TEST

export VERSION ADIR WORKDIR

OBJDIR=/usr/obj/arla-$VERSION

if [ ! -d $OBJDIR -o ! -d $OBJDIR/tests ] ; then
    echo "Failed to find \$OBJDIR or \$OBJDIR/tests"
    exit 1
fi

cd $OBJDIR/tests

if [ ! -d /afs/stacken.kth.se ] ; then
    echo "/afs already exists, refusing to start"
    exit 1
fi

if [ X$startarla != Xno ]; then
    echo "Starting arla"
    /usr/arla/sbin/startarla

    sleep 10

else
   echo "Not starting arla"
fi

if [ ! -d /afs/stacken.kth.se ] ; then
    echo "/afs does not exists, refusing to run tests"
    exit 1
fi

if [ X$runtests != Xno ] ; then


    echo WORKDIR is $WORKDIR
    echo WORKDIR is $WORKDIR >> rlog

    echo "Running fast tests"
    echo "Running fast tests" >> rlog
    date >> rlog
    ./run-tests $USER -all -fast >> rlog-fast 2>&1
    echo "Running slow tests"
    echo "Running slow tests" >> rlog
    date >> rlog
    ./run-tests $USER -all >> rlog-slow 2>&1

    date >> rlog
fi

echo Creating report

cat > rlog-report <<EOF

. Test report for arla-$VERSION

EOF

uname -a | sed 's/^/        /' >> rlog-report

echo "	Summery created:" >> rlog-report
TZ=UTC date | sed 's/^/        /' >> rlog-report

cat >> rlog-report <<EOF

. Result times

EOF

cat rlog | sed 's/^/        /' >> rlog-report

cat >> rlog-report <<EOF

. Fast tests - summery

EOF

${ppath}/extract-result.sh rlog-fast >> rlog-report

cat >> rlog-report <<EOF

. Fast tests - summery

EOF

${ppath}/extract-result.sh rlog-slow >> rlog-report 2>&1

cat >> rlog-report <<EOF

. Report log

EOF
sed 's/^/        /' < rlog >> rlog-report
cat >> rlog-report <<EOF

. Complete tests below

+ Fast tests

EOF
sed 's/^/        /' < rlog-fast >> rlog-report
cat >> rlog-report <<EOF

+ Slow tests

EOF
sed 's/^/        /' < rlog-slow >> rlog-report

exit 0
