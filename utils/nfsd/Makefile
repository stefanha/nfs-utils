#
# Makefile for knfsd
#

PROGRAM	= nfsd
PREFIX	= rpc.
OBJS	= nfsd.o
DEPLIBS = $(TOP)support/lib/libfs.a
LIBS	= -lnfs
MAN8	= nfsd

include $(TOP)rules.mk

# 
# all::	nfsd
# 	@echo "Done."
# 
# nfsd:	$(OBJS)
# 	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lnfs
# 
# clean distclean::
# 	rm -f *.o
# 
# distclean::
# 	rm -f nfsd .depend
# 
# install::
# 	install -o root -g root -m 755 nfsd /usr/sbin/rpc.$knfsd
# 
# dep::
# 	$(CC) $(CFLAGS) -M $(OBJS:.o=.c) > .depend
# 
# ifeq (.depend,$(wildcard .depend))
# include .depend
# endif
