#
# Makefile for rpc.rquotad
#

PROGRAM	= rquotad
PREFIX	= rpc.
OBJS	= rquota_server.o rquota_svc.o rquota_xdr.o quotactl.o hasquota.o
DEPLIBS	= 
MAN8	= rquotad

LIBS	+= -lnfs -lmisc $(LIBBSD) $(LIBWRAP) $(LIBNSL)

include $(TOP)rules.mk
