# $Id: Makefile.am,v 1.5 2008/02/21 20:42:53 tol Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = fs

fs_SOURCES = \
	fs.c \
	fs_flushvol.c \
	fs_lsm.c \
	fs_setquota.c \
	fs_arladebug.c \
	fs_getcache.c \
	fs_mkm.c \
	fs_statistics.c \
	fs_checkservers.c \
	fs_getcellstat.c \
	fs_newcell.c \
	fs_strerror.c \
	fs_connect.c \
	fs_getfid.c \
	fs_quota.c \
	fs_whereis.c \
	fs_copyacl.c \
	fs_getprio.c \
	fs_rmm.c \
	fs_whichcell.c \
	fs_diskfree.c \
	fs_la.c \
	fs_setacl.c \
	fs_wscell.c \
	fs_examine.c \
	fs_listcell.c \
	fs_setcache.c \
	fs_nnpfsdebug.c \
	fs_flush.c \
	fs_listquota.c \
	fs_setcrypt.c \
	fs_getcalleraccess.c \
	arladebu.c


arladebu.c: $(srcdir)/../../arlad/arladebu.c
	test -f arladebu.c || $(LN_S) $(srcdir)/../../arlad/arladebu.c arladebu.c


fs_CPPFLAGS = \
	-I$(srcdir)/../../include \
	$(KRB5_INC_FLAGS) \
	$(KAFS_CPPFLAGS) \
	-I$(srcdir)/../.. \
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

fs_LDADD = \
	-L../lib -larlalib \
	../../rxdef/librxdefclient.la \
	-L../../rx -lrx \
	-L../../lwp -llwp $(PLWP_LIB_FLAGS) \
	../../lib/vers/libvers.la \
	../../lib/ko/libko.la ../../util/libarlautil.la \
	$(LIB_sl) \
	$(READLINE_lib) \
	$(LIB_roken) \
	$(RXKAD_LIBS) \
	$(KAFS_LIBS) \
	$(RXKAD_LIBS) @LIBS@

man_MANS = fs.1
