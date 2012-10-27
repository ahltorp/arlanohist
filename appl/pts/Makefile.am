# $Id: Makefile.am,v 1.6 2005/03/15 21:47:20 lha Exp $

include $(top_srcdir)/Makefile.am.common

INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(srcdir)/../lib \
	-I../../rxdef \
	-I$(srcdir)/../.. \
	$(KRB5_INC_FLAGS)

bin_PROGRAMS = pts

man_MANS = pts.1

pts_SOURCES = pts.c

LDADD = ../lib/libarlalib.la \
	../../rxdef/librxdefclient.la \
	../../lib/ko/libko.la \
	../../util/libarlautil.la \
	../../rx/librx.la \
	-L../../lwp -llwp $(PLWP_LIB_FLAGS) \
	../../lib/vers/libvers.la \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(LIB_sl) \
	$(LIB_roken)
