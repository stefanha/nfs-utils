# Copyright (C) 1995-1999 Jeffrey A. Uphoff
# Adapted for linux-nfs build tree by Olaf Kirch, 1996.
#
# NSM for Linux.

# Uncomment for embedded client-side simulation functions.
#SIMUL	= -DSIMULATIONS

# Undefined is normal, defined provides debug logging.
#DEBUG	= -DDEBUG

##################################################################
#	no user-serviceable parts below this line
##################################################################
PROGRAM	= statd
PREFIX	= rpc.
OBJS	= $(SRCS:.c=.o)
CCOPTS	= $(DEBUG) $(SIMUL)
LIBS	= -lexport -lnfs -lmisc $(LIBWRAP) $(LIBNSL)

SRCS	= $(RPCSRCS) $(SIMSRCS) \
	  callback.c notlist.c log.c misc.c monitor.c notify.c simu.c \
	  stat.c statd.c state.c svc_run.c rmtcall.c
HDRS	= $(RPCHDRS) $(SIMHDRS)

RPCSRCS	= sm_inter_clnt.c sm_inter_svc.c sm_inter_xdr.c
RPCHDRS	= sm_inter.h

ifdef SIMUL
SIMSRCS	= sim_sm_inter_clnt.c sim_sm_inter_svc.c
SIMHDRS	= sim_sm_inter.h
SRCS   += simulate.c
endif

MAN8	= statd

include $(TOP)rules.mk

AFLAGS	+= -Wno-unused

$(RPCHDRS) $(RPCSRCS):	sm_inter.x
	$(RM) $(RPCHDRS) $(RPCSRCS)
	$(RPCGEN) -h -o sm_inter.h $<
	$(RPCGEN) -l -o sm_inter_clnt.c $<
	$(RPCGEN) -m -o sm_inter_svc.c $<
	$(RPCGEN) -c -o sm_inter_xdr.c $<

$(SIMHDRS) $(SIMSRCS):	sim_sm_inter.x
	$(RM) $(SIMHDRS) $(SIMSRCS)
	$(RPCGEN) -h -o sim_sm_inter.h $<
	$(RPCGEN) -l -o sim_sm_inter_clnt.c $<
	$(RPCGEN) -m -o sim_sm_inter_svc.c $<

clean::
	$(RM) $(PROGRAM)

distclean::
	$(RM) $(RPCHDRS) $(RPCSRCS) $(SIMHDRS) $(SIMSRCS)

predep:: $(RPCHDRS) $(RPCSRCS)
