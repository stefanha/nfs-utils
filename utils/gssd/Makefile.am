## Process this file with automake to produce Makefile.in

man8_MANS	= gssd.man svcgssd.man

RPCPREFIX	= rpc.
KPREFIX		= @kprefix@
sbin_PREFIXED	= gssd svcgssd
sbin_PROGRAMS	= $(sbin_PREFIXED) gss_clnt_send_err
sbin_SCRIPTS	= gss_destroy_creds

EXTRA_DIST = \
	gss_destroy_creds \
	$(man8_MANS)

COMMON_SRCS = \
	context.c \
	context_mit.c \
	context_heimdal.c \
	context_spkm3.c \
	gss_util.c \
	gss_oids.c \
	err_util.c \
	\
	context.h \
	err_util.h \
	gss_oids.h \
	gss_util.h

gssd_SOURCES = \
	$(COMMON_SRCS) \
	gssd.c \
	gssd_main_loop.c \
	gssd_proc.c \
	krb5_util.c \
	\
	gssd.h \
	krb5_util.h \
	write_bytes.h

gssd_LDADD = $(RPCSECGSS_LIBS) $(KRBLIBS)
gssd_LDFLAGS = -Wl,-rpath=$(KRBDIR)/lib

gssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) \
	      $(RPCSECGSS_CFLAGS) $(KRBCFLAGS)

svcgssd_SOURCES = \
	$(COMMON_SRCS) \
	cacheio.c \
	svcgssd.c \
	svcgssd_main_loop.c \
	svcgssd_mech2file.c \
	svcgssd_proc.c \
	\
	cacheio.h \
	svcgssd.h

svcgssd_LDADD = \
	../../support/nfs/libnfs.a \
	$(RPCSECGSS_LIBS) -lnfsidmap \
	$(KRBLIBS)

svcgssd_LDFLAGS = -Wl,-rpath=$(KRBDIR)/lib

svcgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) \
		 $(RPCSECGSS_CFLAGS) $(KRBCFLAGS)

gss_clnt_send_err_SOURCES = gss_clnt_send_err.c

MAINTAINERCLEANFILES = Makefile.in

#######################################################################
# The following allows the current practice of having
# daemons renamed during the install to include RPCPREFIX
# and the KPREFIX
# This could all be done much easier with program_transform_name
# ( program_transform_name = s/^/$(RPCPREFIX)$(KPREFIX)/ )
# but that also renames the man pages, which the current
# practice does not do.
install-exec-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PREFIXED); do \
	    mv -f $$p$(EXEEXT) $(RPCPREFIX)$(KPREFIX)$$p$(EXEEXT) ;\
	  done)
uninstall-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PREFIXED); do \
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

