#
# Makefile for linux-nfs/support
#

TOP	 = ../../

include $(TOP)rules.mk

all install::	mount.h
	@:

distclean::
	$(RM) mount.h config.h

mount.h:
	$(LN_S) ../export/mount.h .

# .EXPORT_ALL_VARIABLES:
