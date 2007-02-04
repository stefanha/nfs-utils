/*
  gssd.c

  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  Copyright (c) 2002 Andy Adamson <andros@UMICH.EDU>.
  Copyright (c) 2002 Marius Aamodt Eriksen <marius@UMICH.EDU>.
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "config.h"

#include <sys/param.h>
#include <sys/socket.h>
#include <rpc/rpc.h>

#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "krb5_util.h"

char pipefsdir[PATH_MAX] = GSSD_PIPEFS_DIR;
char keytabfile[PATH_MAX] = GSSD_DEFAULT_KEYTAB_FILE;
char ccachedir[PATH_MAX] = GSSD_DEFAULT_CRED_DIR;
int  use_memcache = 0;

void
sig_die(int signal)
{
	/* destroy krb5 machine creds */
	gssd_destroy_krb5_machine_creds();
	printerr(1, "exiting on signal %d\n", signal);
	exit(1);
}

void
sig_hup(int signal)
{
	/* don't exit on SIGHUP */
	printerr(1, "Received SIGHUP... Ignoring.\n");
	return;
}

static void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-f] [-v] [-r] [-p pipefsdir] [-k keytab] [-d ccachedir]\n",
		progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fg = 0;
	int verbosity = 0;
	int rpc_verbosity = 0;
	int opt;
	extern char *optarg;
	char *progname;

	while ((opt = getopt(argc, argv, "fvrmMp:k:d:")) != -1) {
		switch (opt) {
			case 'f':
				fg = 1;
				break;
			case 'm':
				/* Accept but ignore this. Now the default. */
				break;
			case 'M':
				use_memcache = 1;
				break;
			case 'v':
				verbosity++;
				break;
			case 'r':
				rpc_verbosity++;
				break;
			case 'p':
				strncpy(pipefsdir, optarg, sizeof(pipefsdir));
				if (pipefsdir[sizeof(pipefsdir)-1] != '\0')
					errx(1, "pipefs path name too long");
				break;
			case 'k':
				strncpy(keytabfile, optarg, sizeof(keytabfile));
				if (keytabfile[sizeof(keytabfile)-1] != '\0')
					errx(1, "keytab path name too long");
				break;
			case 'd':
				strncpy(ccachedir, optarg, sizeof(ccachedir));
				if (ccachedir[sizeof(ccachedir)-1] != '\0')
					errx(1, "ccachedir path name too long");
				break;
			default:
				usage(argv[0]);
				break;
		}
	}
	strncat(pipefsdir + strlen(pipefsdir), "/" GSSD_SERVICE_NAME,
		sizeof(pipefsdir)-strlen(pipefsdir));
	if (pipefsdir[sizeof(pipefsdir)-1] != '\0')
		errx(1, "pipefs path name too long");

	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	initerr(progname, verbosity, fg);
#ifdef HAVE_AUTHGSS_SET_DEBUG_LEVEL
	authgss_set_debug_level(rpc_verbosity);
#else
        if (rpc_verbosity > 0)
		printerr(0, "Warning: rpcsec_gss library does not "
			    "support setting debug level\n");
#endif

	if (gssd_check_mechs() != 0)
		errx(1, "Problem with gssapi library");

	if (!fg && daemon(0, 0) < 0)
		errx(1, "fork");

	signal(SIGINT, sig_die);
	signal(SIGTERM, sig_die);
	signal(SIGHUP, sig_hup);

	/* Process keytab file and get machine credentials */
	gssd_refresh_krb5_machine_creds();

	gssd_run();
	printerr(0, "gssd_run returned!\n");
	abort();
}
