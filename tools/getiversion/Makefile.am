## Process this file with automake to produce Makefile.in

CC=$(CC_FOR_BUILD)
LIBTOOL = @LIBTOOL@ --tag=CC

noinst_PROGRAMS = getiversion
getiversion_SOURCES = getiversion.c
getiversion_CFLAGS=$(CFLAGS_FOR_BUILD)
getiversion_CPPFLAGS=$(CPPFLAGS_FOR_BUILD) -I$(top_srcdir)/support/include
getiversion_LDFLAGS=$(LDFLAGS_FOR_BUILD)

MAINTAINERCLEANFILES = Makefile.in
