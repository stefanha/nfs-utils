#
# Makefile for nhfsstone
#

SCRIPTS	= nhfsrun nhfsnums nhfsgraph

PROGRAM	= nhfsstone
OBJS	= nhfsstone.o
MAN8	= nhfsstone $(SCRIPTS)

include $(TOP)rules.mk

install::
	for s in $(SCRIPTS); do \
	    $(INSTALLBIN) $(PROGRAM) $(SBINDIR)/$(PREFIX)$k$$s; \
	done
