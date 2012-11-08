## Process this file with automake to produce Makefile.in

man8_MANS	= nfsdcld.man nfsdcltrack.man
EXTRA_DIST	= $(man8_MANS)

AM_CFLAGS	+= -D_LARGEFILE64_SOURCE
sbin_PROGRAMS	= nfsdcld nfsdcltrack

nfsdcld_SOURCES = nfsdcld.c sqlite.c
nfsdcld_LDADD = ../../support/nfs/libnfs.a $(LIBEVENT) $(LIBSQLITE) $(LIBCAP)

nfsdcltrack_SOURCES = nfsdcltrack.c sqlite.c
nfsdcltrack_LDADD = ../../support/nfs/libnfs.a $(LIBSQLITE) $(LIBCAP)

MAINTAINERCLEANFILES = Makefile.in

