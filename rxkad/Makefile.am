#
# $Id: Makefile.am,v 1.8 2007/01/16 11:57:00 tol Exp $
#

include $(top_srcdir)/Makefile.am.common

noinst_LTLIBRARIES = librxkad.la

INCLUDES += -I. 			\
	-I$(srcdir)			\
	-I../include			\
	-I$(srcdir)/../include		\
	-I.. -I$(srcdir)/..		\
	$(INC_roken) 			\
	$(KRB5_INC_FLAGS)

#disable server side for now to get rid of des.h dependency
# -- milko's not in working condition anyway
# KRB4_COMPAT_SOURCES = 			\
# 	decomp_ticket.c			\
# 	lifetime.c			\
# 	rw.c
KRB4_COMPAT_SOURCES =

#RXK_SERV_SOURCES = rxk_serv.c
RXK_SERV_SOURCES = 

librxkad_la_SOURCES =			\
	rxk_locl.c			\
	rxk_clnt.c			\
	rxk_crpt.c			\
	osi_alloc.c			\
	rxk_info.c			\
	$(RXK_SERV_SOURCES)		\
	$(KRB4_COMPAT_SOURCES)


LDADD = \
	$(KRB5_LIB_FLAGS)


rxincludedir = $(includedir)/rxkad
rxinclude_HEADERS = rxkad.h
