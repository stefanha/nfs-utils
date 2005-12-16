#
# Makefile for rpc.gssd
#

TOP	= ../../
PROGRAM	= svcgssd
PREFIX	= rpc.
OBJS	= svcgssd.o svcgssd_main_loop.o svcgssd_proc.o err_util.o gss_util.o \
	  gss_oids.o context.o context_heimdal.o cacheio.o svcgssd_mech2file.o
LIBS	= -Wl,-rpath=$(KRBDIR)/lib -lrpcsecgss -lgssapi -ldl $(KRBLIB) -lnfsidmap -lnfs
MAN8	= svcgssd

LINKED	= err_util.c gss_util.c gss_oids.c context.c context_heimdal.c

predep :: $(LINKED)

$(LINKED) :
	ln -s ../gssd/$@ .

distclean ::
	for f in $(LINKED); do \
	    if [ -L "$$f" ]; then \
		echo "rm -f $$f"; \
		rm -f "$$f"; \
	    fi; \
	done

include $(TOP)rules.mk

CFLAGS += -I../gssd -DKRB5_VERSION=$(KRB5_VERSION) \
	-I$(TOP)support/rpc/include/ -I$(KRBDIR)/include
