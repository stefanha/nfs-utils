#
# linux-nfs/Makefile
#

SUBDIRS	= tools support utils
TOP	= 

all:: config.mk utils/statd/.depend
install:: all

include $(TOP)rules.mk


config.mk:
	./configure

utils/statd/.depend:
	$(MAKE) $(MFLAGS) dep

distclean clean::
	rm -f postscript/*.ps
	rm -f LOG make.log

distclean::
	rm -fr bin
	rm -f config.cache config.log config.mk config.status

install:: installman
	if [ ! -d $(STATEDIR) ]; then mkdir -p $(STATEDIR); fi
	touch $(STATEDIR)/xtab; chmod 644 $(STATEDIR)/xtab
	touch $(STATEDIR)/etab; chmod 644 $(STATEDIR)/etab
	touch $(STATEDIR)/rmtab; chmod 644 $(STATEDIR)/rmtab
	mkdir -p $(STATEDIR)/sm $(STATEDIR)/sm.bak
	touch $(STATEDIR)/state
	chmod go-rwx $(STATEDIR)/sm $(STATEDIR)/sm.bak $(STATEDIR)/state
	chown $(STATDUSER) $(STATEDIR)/sm $(STATEDIR)/sm.bak $(STATEDIR)/state
