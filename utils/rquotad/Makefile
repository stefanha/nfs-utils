#
# Makefile for rpc.mountd
#

PROGRAM	= rquotad
PREFIX	= rpc.
OBJS	= rquota_server.o rquota_svc.o rquota_xdr.o quotactl.o hasquota.o
DEPLIBS	= 
MAN8	= rquotad

LIBS	+= -lnfs $(LIBBSD)

include $(TOP)rules.mk
