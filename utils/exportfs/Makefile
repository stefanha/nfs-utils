#
# dummy Makefile
#

PROGRAM	= exportfs
OBJS	= exportfs.o
LIBDEPS	= $(TOP)support/lib/libexport.a $(TOP)/support/lib/libnfs.a
LIBS	= -lexport -lnfs -lmisc
MAN8	= exportfs
MAN5	= exports
MAN7	= nfsd

include $(TOP)rules.mk

