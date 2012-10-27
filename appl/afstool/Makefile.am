# $Id: Makefile.am,v 1.12 2005/03/15 21:47:48 lha Exp $

include $(top_srcdir)/Makefile.am.common

INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(srcdir)/../lib \
	-I../../rxdef \
	-I$(srcdir)/../.. \
	$(KRB5_INC_FLAGS)

bin_PROGRAMS = afstool

man_MANS = afstool.1

afstool_SOURCES = \
	afstool.c \
	at_mini_cm.c \
	at_fileserver.c \
	at_fs_flush_cps.c \
	at_fs_getcap.c \
	at_fs_gettime.c \
	at_cachemgr.c \
	at_cm_whoareyou.c \
	at_cm_localcell.c \
	at_ubik.c \
	at_u_debug.c

LDADD = ../lib/libarlalib.la \
	../../rxdef/librxdefclient.la \
	../../rxdef/librxcbclient.la \
	../../rxdef/librxcbserver.la \
	../../lib/ko/libko.la \
	../../util/libarlautil.la \
	../../rx/librx.la \
	-L../../lwp -llwp $(PLWP_LIB_FLAGS) \
	../../lib/vers/libvers.la \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(LIB_sl) \
	$(LIB_roken)
