
include	$(TOP)rules.mk

LIBS	= libnfs.a libexport.a

all install::	$(LIBS)
	@:

clean distclean::
	rm -f $(LIBS)

lib%.a:
	ln -sf ../$*/$@ .
