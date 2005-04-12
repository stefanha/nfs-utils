#
# Makefile for nhfsstone
#

SCRIPTS	= nhfsrun nhfsnums nhfsgraph

TOP	= ../../
PROGRAM	= nhfsstone
OBJS	= nhfsstone.o
MAN8	= nhfsstone $(SCRIPTS)

include $(TOP)rules.mk

install::
	for s in $(SCRIPTS); do \
	    $(INSTALLSCRIPT) $$s $(SBINDIR)/$(PREFIX)$k$$s; \
	done
