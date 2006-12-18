## Process this file with automake to produce Makefile.in

OPTDIRS =

if CONFIG_RQUOTAD
OPTDIRS += rquotad
endif

if CONFIG_NFSV4
OPTDIRS += idmapd
endif

if CONFIG_GSS
OPTDIRS += gssd
endif

if CONFIG_MOUNT
OPTDIRS += mount
endif

SUBDIRS = \
	exportfs \
	lockd \
	mountd \
	nfsd \
	nfsstat \
	showmount \
	statd \
	$(OPTDIRS)

MAINTAINERCLEANFILES = Makefile.in
