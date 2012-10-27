# $Id: Makefile.am,v 1.7 2005/03/15 21:49:56 lha Exp $

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libarlalib.la

INCLUDES += \
	-I.					\
	-I$(srcdir)				\
	-I../../include				\
	-I$(srcdir)/../../include		\
	-I../.. -I$(srcdir)/../..		\
	-I../../rxdef				\
	-I$(srcdir)/../../arlad			\
	-I$(srcdir)/../../nnpfs/include		\
	$(INC_roken)				\
	$(KRB5_INC_FLAGS)

libarlalib_la_SOURCES = arlalib.c fs_lib.c ka-procs.c tokens.c
libarlalib_la_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\"

libarlalib_la_LIBADD = \
	../../rxdef/librxdefclient.la \
	../../rxdef/libkaclient.la \
	../../lib/ko/libko.la \
	../../util/libarlautil.la \
	../../rx/librx.la \
	../../lib/vers/libvers.la \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(LIB_sl) \
	$(LIB_roken)
