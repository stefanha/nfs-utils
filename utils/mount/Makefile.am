## Process this file with automake to produce Makefile.in

man8_MANS	= mount.nfs.man umount.nfs.man

sbin_PROGRAMS	= mount.nfs
EXTRA_DIST = nfsmount.x $(man8_MANS)
mount_nfs_SOURCES = mount.c nfsmount.c nfs4mount.c nfsumount.c \
		  mount_constants.h nfs4_mount.h nfs_mount4.h

mount_nfs_LDADD = ../../support/nfs/libnfs.a \
		  ../../support/export/libexport.a

MAINTAINERCLEANFILES = Makefile.in

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

