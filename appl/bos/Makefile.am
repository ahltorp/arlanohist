# $Id: Makefile.am,v 1.3 2005/03/15 21:46:27 lha Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = bos

bos_SOURCES = \
	bos.c \
	bos_status.c \
	bos_adduser.c \
	bos_getrestart.c \
	bos_listhosts.c \
	bos_listusers.c \
	bos_stop.c \
	bos_start.c \
	bos_addhost.c \
	bos_removehost.c \
	bos_restart.c

bos_CPPFLAGS = \
	$(KRB5_INC_FLAGS) \
	$(KAFS_CPPFLAGS) \
	-I$(srcdir)/../.. \
	-I$(srcdir)/../../include \
	-I$(srcdir)/../lib \
	-I../../include \
	$(INC_sl) \
	-I../../rxdef \
	-I. \
	$(KERNEL_INCLUDE) \
	-I$(srcdir)/../../nnpfs/include \
	-I$(srcdir)/../../arlad \
	-I$(srcdir)/../../rxkad \
	$(INC_roken)

bos_LDADD = \
	../lib/libarlalib.la \
	../../rxdef/librxdefclient.la \
	../../rx/librx.la \
	-L../../lwp -llwp $(PLWP_LIB_FLAGS) \
	../../lib/vers/libvers.la \
	../../lib/ko/libko.la ../../util/libarlautil.la \
	$(LIB_sl) \
	$(READLINE_lib) \
	$(LIB_roken) \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(RXKAD_LIBS) @LIBS@
