#!/bin/sh
#
# $Id: extract-result.sh,v 1.1 2002/02/25 02:18:04 lha Exp $
#

if grep 'All test(s) were succesful' $1 > /dev/null; then
    
    echo "	All test(s) were succesful"

else

	T=`grep 'Failed test(s) were:' $1 | sed 's/[^:]*: *//'`

	echo "	Failed test(s) were:"
	echo
	for a in $T ; do
	    echo "	$a"
	done
fi

