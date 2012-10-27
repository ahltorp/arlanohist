#
# $Id: Makefile.am,v 1.5 2004/02/04 12:06:31 lha Exp $
#

include $(top_srcdir)/Makefile.am.common

YFLAGS = -d

INCLUDES += \
	-I$(srcdir) \
	 -I$(srcdir)/../util \
	-I../include \
	-I$(srcdir)/../include \
	-I. \
	$(INC_roken)

bin_PROGRAMS = ydr

ydr_CFLAGS = -DCPP="\"$(CPP) $(CPPFLAGS) $(YDR_CPPFLAGS)\""

ydr_SOURCES = \
	parse.y \
	lex.l \
	lex.h \
	main.c \
	symbol.c \
	types.c \
	types.h \
	output.c \
	output.h \
	sym.h

LDADD = \
	../util/libarlautil.la 	\
	$(LIB_roken)			\
	$(LIBS)

CLEANFILES = lex.c parse.c parse.h
