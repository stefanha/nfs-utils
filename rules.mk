#
# General make rules
#
.DEFAULT:	all
.PHONY:		$(ALLTARGETS)

include $(TOP)config.mk

##################################################################
# Subdirectory handling
##################################################################
ifneq ($(SUBDIRS),)
$(ALLTARGETS)::
	@set -e; for d in $(SUBDIRS); do \
		echo "Making $@ in $$d"; \
		$(MAKE) --no-print-directory TOP=../$(TOP) -C $$d $@; \
	done
endif

##################################################################
# Building an RPC daemon
##################################################################
ifneq ($(PROGRAM),)
TARGET	= $(PROGRAM)

$(PROGRAM): $(OBJS) $(LIBDEPS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:: $(PROGRAM)
	-$(MKDIR) $(SBINDIR)
	$(INSTALLBIN) $(PROGRAM) $(SBINDIR)/$(PREFIX)$k$(PROGRAM)
endif

##################################################################
# Building a tool
##################################################################
ifneq ($(TOOL),)
TARGET	= $(TOOL)

$(TOOL): $(OBJS) $(LIBDEPS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
endif

##################################################################
# Building a library
##################################################################
ifneq ($(LIBNAME),)
TARGET	= $(LIBNAME)

$(LIBNAME): $(OBJS)
	$(AR) cr $@ $^
	$(RANLIB) $@
endif

##################################################################
# Generic target rules
##################################################################
ifneq ($(TARGET),)
all:: $(TARGET)
	@echo "Building $(TARGET) done."

install:: $(TARGET)

distclean::
	rm -f $(TARGET)
endif

##################################################################
# Cleaning rules
##################################################################
clean distclean::
	rm -f *.o *~ \#* a.out core

distclean::
	rm -f LOG X Y Z x y z .depend

##################################################################
# Manpage installation
# Isn't GNU make a wonderful thing?
##################################################################
ifneq ($(MAN1)$(MAN5)$(MAN8)$(MAN9),)
MANINIT	= ext=$(MAN$sEXT); dir=$(MAN$sDIR); pgs="$(MAN$s)";
MANLOOP = $(MANINIT) for man in $$pgs; do eval $$cmd; done
MDCMD	= $(MKDIR) \$$dir
MICMD	= $(RM) \$$dir/\$$man.\$$ext; \
	  echo $(INSTALLMAN) \$$man.man \$$dir/\$$man.\$$ext; \
	  $(INSTALLMAN) \$$man.man \$$dir/\$$man.\$$ext
LNCMD	= $(RM) \$$dir/$(PREFIX)\$$man.\$$ext; \
	  echo $(LN_S) \$$man.\$$ext \$$dir/$(PREFIX)\$$man.\$$ext; \
	  $(LN_S) \$$man.\$$ext \$$dir/$(PREFIX)\$$man.\$$ext
PSCMD	= echo \"$(MAN2PS) \$$man.man > $(TOP)postscript/\$$man.ps\"; \
	  $(MAN2PS) \$$man.man > $(TOP)postscript/\$$man.ps

installman::
	@$(foreach s, 1 5 8 9, cmd="$(MDCMD)" $(MANLOOP);)
	@$(foreach s, 1 5 8 9, cmd="$(MICMD)" $(MANLOOP);)
ifneq ($(PREFIX),)
	@$(foreach s, 1 5 8 9, cmd="$(LNCMD)" $(MANLOOP);)
endif

postscript::
	@$(foreach s, 1 5 8 9, cmd="$(PSCMD)" $(MANLOOP);)
else
postscript installman::
	@: No manpages...
endif

##################################################################
# Indenting
##################################################################
ifneq ($(SRCS),)
indent:
	$(INDENT) $(SRCS)
endif
	
##################################################################
# Handling of dependencies
##################################################################
ifneq ($(OBJS),)
depend dep::
	$(CC) $(CFLAGS) -M $(OBJS:.o=.c) > .depend
endif

ifeq (.depend,$(wildcard .depend))
include .depend
endif
