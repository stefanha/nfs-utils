#
# gss context destruction tool
#

PROGRAM	= gss_clnt_send_err
OBJS	= gss_clnt_send_err.o

include $(TOP)rules.mk

gss_clnt_send_err.o: ../gssd/gss_clnt_send_err.c
	$(CC) -c $(CFLAGS) $(?:.o=.c)

install::
	$(INSTALLBIN) ../gssd/gss_destroy_creds $(SBINDIR)/$(PREFIX)$kgss_destroy_creds
