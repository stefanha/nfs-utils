## Process this file with automake to produce Makefile.in

OPTDIRS =

if CONFIG_RQUOTAD
OPTDIRS += rquotad
endif

if CONFIG_NFSV4
OPTDIRS += idmapd
endif

if CONFIG_GSS
OPTDIRS += gssd svcgssd
endif

SUBDIRS = \
	exportfs \
	lockd \
	mountd \
	nfsd \
	nfsstat \
	nhfsstone \
	showmount \
	statd \
	$(OPTDIRS)

MAINTAINERCLEANFILES = Makefile.in
