# $Id: Makefile.am,v 1.6 2005/08/25 08:45:22 lha Exp $

include $(top_srcdir)/Makefile.am.common

INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(srcdir)/../lib \
	-I../../rxdef \
	-I$(srcdir)/../.. \
	$(KRB5_INC_FLAGS)

bin_PROGRAMS = tokens unlog

man_MANS = tokens.1 unlog.1

tokens_SOURCES = tokens.c
unlog_SOURCES = unlog.c

LDADD = ../lib/libarlalib.la \
	../../rxdef/librxdefclient.la \
	../../lib/ko/libko.la \
	../../util/libarlautil.la \
	../../rx/librx.la \
	../../lwp/liblwp.a \
	../../lib/vers/libvers.la \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(LIB_sl) \
	$(LIB_roken)
