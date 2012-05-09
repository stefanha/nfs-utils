## Process this file with automake to produce Makefile.in

man8_MANS	= nfsdcld.man
EXTRA_DIST	= $(man8_MANS)

AM_CFLAGS	+= -D_LARGEFILE64_SOURCE
sbin_PROGRAMS	= nfsdcld

nfsdcld_SOURCES = nfsdcld.c sqlite.c

nfsdcld_LDADD = ../../support/nfs/libnfs.a $(LIBEVENT) $(LIBSQLITE) $(LIBCAP)

MAINTAINERCLEANFILES = Makefile.in

