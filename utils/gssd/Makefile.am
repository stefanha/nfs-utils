## Process this file with automake to produce Makefile.in

man8_MANS	= gssd.man

RPCPREFIX	= rpc.
KPREFIX		= @kprefix@
sbin_PROGRAMS	= gssd

EXTRA_DIST = \
	$(man8_MANS) \
	gss_clnt_send_err.c \
	gss_destroy_creds

gssd_SOURCES = \
	context.c \
	context_heimdal.c \
	err_util.c \
	gss_oids.c \
	gss_util.c \
	gssd.c \
	gssd_main_loop.c \
	gssd_proc.c \
	krb5_util.c \
	\
	context.h \
	err_util.h \
	gss_oids.h \
	gss_util.h \
	gssd.h \
	krb5_util.h \
	write_bytes.h

gssd_LDADD = -lrpcsecgss -lgssapi -ldl $(KRBLIBS)
gssd_LDFLAGS = -Wl,-rpath=$(KRBDIR)/lib

gssd_CPPFLAGS = -I$(top_srcdir)/support/rpc/include \
	      $(AM_CPPFLAGS) $(CPPFLAGS)
		
gssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) \
	      $(KRBCFLAGS)

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

