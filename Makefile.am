# $Id: Makefile.am,v 1.6 2007/11/05 21:20:41 tol Exp $

include $(top_srcdir)/Makefile.am.common

if RXKAD
rxkad = rxkad
endif

SUBDIRS		= \
		include \
		lib \
		util \
		ydr \
		lwp \
		rxdef \
		lib/ko \
		rx \
		rxgk \
		lib/bufdir \
		$(rxkad) \
		nnpfs \
		appl/lib \
		arlad \
		conf \
		appl \
		tests \
		doc \
		tools

ACLOCAL_AMFLAGS = -I cf

EXTRA_DIST = Makefile.am.common
