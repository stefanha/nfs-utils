
include	$(TOP)rules.mk

LIBS	= libnfs.a libexport.a libmisc.a

all install::	$(LIBS)
	@:

clean distclean::
	rm -f $(LIBS)

lib%.a:
	ln -sf ../$*/$@ .
