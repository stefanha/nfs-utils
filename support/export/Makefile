#
# libexport.a
# Miscellaneous utility functions related to exporting and mounting
# of NFS volumes.
#

LIBNAME	= libexport.a
SRCS	= $(RPCSRCS) client.c export.c hostname.c nfsctl.c rmtab.c \
	  xtab.c
OBJS	= $(SRCS:.c=.o)

RPCSRCS	= mount_clnt.c mount_xdr.c
RPCHDRS	= mount.h

include $(TOP)rules.mk

$(RPCHDRS) $(RPCSRCS): mount.x
	$(RM) $(RPCHDRS) $(RPCSRCS)
	$(RPCGEN) -h -o mount.h $<
	$(RPCGEN) -l -o mount_clnt.c $<
	$(RPCGEN) -c -o mount_xdr.c $<

clean distclean::
	$(RM) $(RPCHDRS) $(RPCSRCS)

install::
	@:

predep:: $(RPCHDRS) $(RPCSRCS)
	$(LN_S) ../export/mount.h ../include/mount.h
