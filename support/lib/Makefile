
include	$(TOP)rules.mk

LIBS	= libnfs.a libexport.a libmisc.a librpc.a libgssapi.a

all install::	$(LIBS)
	@:

clean distclean::
	rm -f $(LIBS)

lib%.a:
	ln -sf ../$*/$@ .
