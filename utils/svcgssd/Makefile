#
# Makefile for rpc.gssd
#

PROGRAM	= svcgssd
PREFIX	= rpc.
OBJS	= svcgssd.o svcgssd_main_loop.o svcgssd_proc.o err_util.o gss_util.o \
	  gss_oids.o context.o context_heimdal.o cacheio.o svcgssd_mech2file.o
LIBDEPS	= $(TOP)support/lib/librpc.a $(TOP)support/lib/libgssapi.a
LIBS	= -Wl,-rpath=$(KRBDIR)/lib -lrpc -lgssapi -ldl $(KRBLIB) -lnfsidmap
MAN8	= svcgssd

predep ::
	- ln ../gssd/err_util.c
	- ln ../gssd/gss_util.c
	- ln ../gssd/gss_oids.c
	- ln ../gssd/context.c
	- ln ../gssd/context_heimdal.c

include $(TOP)rules.mk

CFLAGS += -I../gssd -DKRB5_VERSION=$(KRB5_VERSION) \
	-I$(TOP)support/rpc/include/ -I$(KRBDIR)/include
