#
# Makefile for rpc.gssd
#

PROGRAM	= gssd
PREFIX	= rpc.
OBJS	= gssd.o gssd_main_loop.o gssd_proc.o err_util.o gss_util.o \
	  gss_oids.o context.o context_heimdal.o krb5_util.o
LIBDEPS	= $(TOP)support/lib/librpc.a $(TOP)support/lib/libgssapi.a
LIBS	= -Wl,-rpath=$(KRBDIR)/lib -lrpc -lgssapi -ldl $(KRBLIB)
MAN8	= gssd

include $(TOP)rules.mk

CFLAGS += -DKRB5_VERSION=$(KRB5_VERSION) -I$(TOP)support/rpc/include/ \
 	-I$(KRBDIR)/include
