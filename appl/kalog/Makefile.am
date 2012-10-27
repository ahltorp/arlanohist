# $Id: Makefile.am,v 1.2 2005/03/15 21:47:02 lha Exp $

include $(top_srcdir)/Makefile.am.common

INCLUDES += \
	-I$(srcdir)/../.. \
	-I$(srcdir)/../../include \
	-I$(srcdir)/../lib \
	-I../../include \
	-I../../rxdef \
	-I. \
	-I$(srcdir)/../../arlad \
	$(INC_roken)

bin_PROGRAMS = kalog

man_MANS = kalog.1

kalog_SOURCES = kalog.c

LDADD = \
	../lib/libarlalib.la \
	../../rxdef/libkaclient.la \
	../../rxdef/librxdefclient.la \
	../../rx/librx.la \
	-L../../lwp -llwp @PLWP_LIB_FLAGS@ \
	../../lib/vers/libvers.la \
	../../lib/ko/libko.la \
	../../util/libarlautil.la \
	$(LIB_roken) \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(RXKAD_LIBS) $(LIBS)
