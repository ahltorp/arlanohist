# $Id: Makefile.am,v 1.3 2006/11/13 17:28:46 tol Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = dummer

dummer_SOURCES = dummer.c nnpfs_node.c nnpfs_message.c nnpfs_blocks.c

dummer_CPPFLAGS = \
	-I$(srcdir)/../../include \
	-I$(srcdir)/../../util \
	-I$(srcdir)/../include \
	-I.

dummer_LDADD = \
	../../util/libarlautil.la \
	$(LIBS)
