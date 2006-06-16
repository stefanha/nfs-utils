## Process this file with automake to produce Makefile.in

man8_MANS	= mount.nfs.man umount.nfs.man

RPCGEN	= $(top_builddir)/tools/rpcgen/rpcgen

GENFILES_CLNT	= nfsmount_clnt.c
GENFILES_XDR	= nfsmount_xdr.c
GENFILES_H	= nfsmount.h

GENFILES	= $(GENFILES_CLNT) $(GENFILES_XDR) $(GENFILES_H)

sbin_PROGRAMS	= mount.nfs
EXTRA_DIST = nfsmount.x $(man8_MANS)
mount_nfs_SOURCES = mount.c nfsmount.c nfs4mount.c nfsumount.c \
		  nfsmount_xdr.c mount_constants.h nfs4_mount.h nfsmount.h \
		  nfs_mount4.h

BUILT_SOURCES = $(GENFILES)
mount_nfs_LDADD = ../../support/nfs/libnfs.a


$(RPCGEN):
	make -C ../../tools/rpcgen all

$(GENFILES_CLNT): %_clnt.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -l -o $@ $<

$(GENFILES_SVC): %_svc.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -m -o $@ $<

$(GENFILES_XDR): %_xdr.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -c -o $@ $<

$(GENFILES_H): %.h: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -h -o $@ $<


MAINTAINERCLEANFILES = Makefile.in

CLEANFILES = $(GENFILES)

install-exec-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  ln -sf $(sbin_PROGRAMS) mount.nfs4 && \
	  ln -sf $(sbin_PROGRAMS) umount.nfs && \
	  ln -sf $(sbin_PROGRAMS) umount.nfs4)
uninstall-hook:
	(cd $(DESTDIR)$(sbindir) && \
	    rm -f mount.nfs4 umount.nfs umount.nfs4)


install-man-links:
	(cd $(DESTDIR)$(man8dir) && \
	  for m in $(man8_MANS) $(dist_man8_MANS) $(nodist_man8_MANS); do \
	    inst=`echo $$m | sed -e 's/man$$/8/'`; \
	    rm -f $$inst ; \
	  done)

uninstall-man-links:
	(cd $(DESTDIR)$(man8dir) && \
	  for m in $(man8_MANS) $(dist_man8_MANS) $(nodist_man8_MANS); do \
	    inst=`echo $$m | sed -e 's/man$$/8/'`; \
	    rm -f $$inst ; \
	  done)

