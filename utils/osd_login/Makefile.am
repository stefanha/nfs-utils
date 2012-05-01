## Process this file with automake to produce Makefile.in

OSD_LOGIN_FILES= osd_login

EXTRA_DIST= $(OSD_LOGIN_FILES)

all-local: $(OSD_LOGIN_FILES)

install-data-hook:
	$(INSTALL) --mode 755 osd_login $(DESTDIR)/sbin/osd_login

MAINTAINERCLEANFILES = Makefile.in
