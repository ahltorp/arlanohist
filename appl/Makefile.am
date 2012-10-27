# $Id: Makefile.am,v 1.7 2006/10/24 16:32:21 tol Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS=lib

if X11
SUBDIRS+=amon
endif

if RXKAD
SUBDIRS+=fs afsutils
endif

SUBDIRS+=afstool pts udebug perf vos bos

if MACOSX
SUBDIRS+=mac
endif
