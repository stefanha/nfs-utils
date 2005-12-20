## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libnfs.a
libnfs_a_SOURCES = exports.c rmtab.c xio.c rpcmisc.c rpcdispatch.c \
		   xlog.c xmalloc.c wildmat.c nfssvc.c nfsclient.c \
		   nfsexport.c getfh.c nfsctl.c lockdsvc.c \
		   svc_socket.c cacheio.c closeall.c

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = \
	clients.c \
	keytab.c \
	ypupdate_xdr.c
