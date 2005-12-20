## Process this file with automake to produce Makefile.in

SUBDIRS = tools support utils linux-nfs

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = \
	autogen.sh \
	\
	debian/changelog \
	debian/control \
	debian/copyright \
	debian/etc.exports \
	debian/idmapd.conf \
	debian/nfs-common.conffiles \
	debian/nfs-common.default \
	debian/nfs-common.dirs \
	debian/nfs-common.files \
	debian/nfs-common.init \
	debian/nfs-common.install \
	debian/nfs-common.postinst \
	debian/nfs-common.postrm \
	debian/nfs-common.prerm \
	debian/nfs-kernel-server.NEWS \
	debian/nfs-kernel-server.conffiles \
	debian/nfs-kernel-server.default \
	debian/nfs-kernel-server.dirs \
	debian/nfs-kernel-server.init \
	debian/nfs-kernel-server.postinst \
	debian/nfs-kernel-server.postrm \
	debian/nfs-kernel-server.prerm \
	debian/nhfsstone.dirs \
	debian/nhfsstone.files \
	debian/nhfsstone.postinst \
	debian/nhfsstone.prerm \
	debian/rules \
	\
	aclocal/nfs-utils.m4 \
	aclocal/kerberos5.m4 \
	aclocal/tcp-wrappers.m4

install-data-hook:
	if [ ! -d $(statedir) ]; then mkdir -p $(statedir); fi
	touch $(statedir)/xtab; chmod 644 $(statedir)/xtab
	touch $(statedir)/etab; chmod 644 $(statedir)/etab
	touch $(statedir)/rmtab; chmod 644 $(statedir)/rmtab
	mkdir -p $(statedir)/sm $(statedir)/sm.bak
	touch $(statedir)/state
	chmod go-rwx $(statedir)/sm $(statedir)/sm.bak $(statedir)/state
	chown $(statduser) $(statedir)/sm $(statedir)/sm.bak $(statedir)/state
