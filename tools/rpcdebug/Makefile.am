## Process this file with automake to produce Makefile.in

CC=$(CC_FOR_BUILD)
LIBTOOL = @LIBTOOL@ --tag=CC

EXTRA_DIST= neat_idea.c

noinst_PROGRAMS = rpcdebug
rpcdebug_SOURCES = rpcdebug.c
rpcdebug_CFLAGS=$(CFLAGS_FOR_BUILD)
rpcdebug_CPPFLAGS=$(CPPFLAGS_FOR_BUILD) -I$(top_srcdir)/support/include
rpcdebug_LDFLAGS=$(LDFLAGS_FOR_BUILD)

MAINTAINERCLEANFILES = Makefile.in
