#
# Makefile for rpc.mountd
#

PROGRAM	= mountd
PREFIX	= rpc.
OBJS	= mountd.o mount_dispatch.o auth.o rmtab.o
LIBDEPS	= $(TOP)support/lib/libexport.a $(TOP)/support/lib/libnfs.a
LIBS	= -lexport -lnfs
MAN8	= mountd

include $(TOP)rules.mk
