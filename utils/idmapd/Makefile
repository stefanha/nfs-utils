#
# Makefile for rpc.idmapd
#

PROGRAM	= idmapd
PREFIX	= rpc.
OBJS	= atomicio.o cfg.o idmapd.o setproctitle.o strlcat.o strlcpy.o
LIBS	= -levent -lnfsidmap
MAN8	= idmapd
MAN5	= idmapd.conf

include $(TOP)rules.mk
