## Process this file with automake to produce Makefile.in

man8_MANS	= nhfsstone.man nhfsrun.man nhfsnums.man nhfsgraph.man
EXTRA_DIST	= $(man8_MANS) DISCLAIMER README.linux

dist_sbin_SCRIPTS = nhfsrun nhfsnums nhfsgraph

sbin_PROGRAMS	= nhfsstone
nhfsstone_SOURCES = nhfsstone.c
nhfsstone_LDADD = ../../support/export/libexport.a \
	  	  ../../support/nfs/libnfs.a \
		  ../../support/misc/libmisc.a

MAINTAINERCLEANFILES = Makefile.in
