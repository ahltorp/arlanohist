# $Id: Makefile.am,v 1.6 2006/03/15 09:11:49 tol Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = amon

amon_SOURCES = amon.c

amon_CPPFLAGS = \
		$(DEFINES) $(CFLAGS) \
		-I$(srcdir)/../lib \
		-I$(srcdir)/../.. \
		-I$(srcdir)/../../include \
		-I../../include \
		-I../../rxdef \
		$(KERNEL_INCLUDE) \
		-I$(srcdir)/../../nnpfs/include \
		-I$(srcdir)/../../arlad \
		-I$(srcdir)/../../rxkad \
		$(KRB5_INC_FLAGS) $(KAFS_CPPFLAGS) \
		$(X_CFLAGS) $(PLWP_INC_FLAGS) $(INC_roken)


amon_LDADD = \
		../lib/libarlalib.la \
		../../rxdef/librxdefclient.la \
		../../rxdef/libkaclient.la \
		../../rx/librx.la \
		-L../../lwp -llwp @PLWP_LIB_FLAGS@ \
		../../lib/vers/libvers.la \
		../../lib/ko/libko.la \
		../../util/libarlautil.la \
		$(LIB_roken) \
		$(RXKAD_LIBS) \
		$(KAFS_LIBS) \
		$(RXKAD_LIBS) \
		$(LIB_roken) $(LIBS) \
		$(X_LIBS)  \
		-lXaw -lXt -lXmu -lXext $(X_PRE_LIBS) -lX11 $(X_EXTRA_LIBS)
