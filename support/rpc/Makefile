#
# librpc.a
# rpc library with rpcsec_gss
#

LIBNAME	= librpc.a
SRCS	= auth_gss.c authgss_prot.c svc.c svc_run.c svc_auth.c \
	  svc_auth_none.c svc_auth_unix.c svc_auth_gss.c \
	  svc_raw.c svc_simple.c svc_tcp.c svc_udp.c \
	  rpc_commondata.c
OBJS	= $(SRCS:.c=.o)

include $(TOP)rules.mk

CFLAGS += -I$(TOP)support/rpc/include -DDEBUG

install::
	@:
