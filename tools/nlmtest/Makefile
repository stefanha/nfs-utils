#
# nlmtest	Exercise some NLM calls to test the lockd server.
#

TOP	= ../../
TOOL	= nlmtest
SRCS	= $(RPCSRCS) nlmtest.c
OBJS	= $(SRCS:.c=.o)

RPCSRCS	= nlm_prot_clnt.c nlm_prot_xdr.c
RPCHDRS	= nlm_prot.h

#LIBS	= -lnfs

include $(TOP)rules.mk

install::
	@:

$(RPCHDRS) $(RPCSRCS): nlm_prot.x
	$(RM) $(RPCHDRS) $(RPCSRCS)
	$(RPCGEN) -h -o nlm_prot.h $<
	$(RPCGEN) -l -o nlm_prot_clnt.c $<
	$(RPCGEN) -c -o nlm_prot_xdr.c $<

clean distclean::
	$(RM) $(RPCHDRS) $(RPCSRCS)
