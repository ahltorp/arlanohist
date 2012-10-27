# $Id: Makefile.am,v 1.4 2006/03/15 15:53:02 tol Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS = Arla_Configuration arlacmm mafslog

noinst_SCRIPTS = make-mac-package.sh

CLEANFILES = make-mac-package.sh

EXTRA_DIST = make-mac-package.sh.in

make-mac-package.sh: make-mac-package.sh.in
	sed -e "s!%VERSION%!$(VERSION)!" $(srcdir)/make-mac-package.sh.in | \
	sed -e "s!%prefix%!$(prefix)!" | \
	sed -e "s!%srcdir%!$(srcdir)!" > $@
	chmod +x $@
