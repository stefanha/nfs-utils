## Process this file with automake to produce Makefile.in

LINKSRCS = \
	err_util.c \
	gss_util.c \
	gss_oids.c \
	context.c \
	context_heimdal.c

man8_MANS	= svcgssd.man

RPCPREFIX	= rpc.
KPREFIX		= @kprefix@
sbin_PROGRAMS	= svcgssd

EXTRA_DIST = $(man8_MANS)

svcgssd_SOURCES = \
	cacheio.c \
	svcgssd.c \
	svcgssd_main_loop.c \
	svcgssd_mech2file.c \
	svcgssd_proc.c \
	$(LINKSRCS) \
	cacheio.h \
	svcgssd.h

svcgssd_LDADD = \
	../../support/nfs/libnfs.a \
	-lrpcsecgss -lgssapi -lnfsidmap \
	-ldl $(KRBLIBS)

svcgssd_LDFLAGS = -Wl,-rpath=$(KRBDIR)/lib

svcgssd_CPPFLAGS = -I$(top_srcdir)/support/rpc/include \
		   $(AM_CPPFLAGS) $(CPPFLAGS) \
		   -I$(top_srcdir)/utils/gssd

svcgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) \
		 $(KRBCFLAGS)

BUILT_SOURCES = $(LINKSRCS)

MAINTAINERCLEANFILES = Makefile.in

CLEANFILES = $(LINKSRCS)

LINKDIR = $(top_srcdir)/utils/gssd

$(LINKSRCS): %:
	ln -sf $(LINKDIR)/$@ $@

#######################################################################
# The following allows the current practice of having
# daemons renamed during the install to include RPCPREFIX
# and the KPREFIX
# This could all be done much easier with program_transform_name
# ( program_transform_name = s/^/$(RPCPREFIX)$(KPREFIX)/ )
# but that also renames the man pages, which the current
# practice does not do.
#######################################################################
install-exec-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PROGRAMS); do \
	    mv -f $$p$(EXEEXT) $(RPCPREFIX)$(KPREFIX)$$p$(EXEEXT) ;\
	  done)
uninstall-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PROGRAMS); do \
	    rm -f $(RPCPREFIX)$(KPREFIX)$$p$(EXEEXT) ;\
	  done)


# XXX This makes some assumptions about what automake does.
# XXX But there is no install-man-hook or install-man-local.
install-man: install-man8 install-man-links
uninstall-man: uninstall-man8 uninstall-man-links

install-man-links:
	(cd $(DESTDIR)$(man8dir) && \
	  for m in $(man8_MANS) $(dist_man8_MANS) $(nodist_man8_MANS); do \
	    inst=`echo $$m | sed -e 's/man$$/8/'`; \
	    rm -f $(RPCPREFIX)$$inst ; \
	    $(LN_S) $$inst $(RPCPREFIX)$$inst ; \
	  done)

uninstall-man-links:
	(cd $(DESTDIR)$(man8dir) && \
	  for m in $(man8_MANS) $(dist_man8_MANS) $(nodist_man8_MANS); do \
	    inst=`echo $$m | sed -e 's/man$$/8/'`; \
	    rm -f $(RPCPREFIX)$$inst ; \
	  done)

