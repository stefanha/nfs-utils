/*
  gssd.c

  Copyright (c) 2000, 2004 The Regents of the University of Michigan.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif	/* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <rpc/rpc.h>
#include <netinet/in.h>

#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <memory.h>
#include <fcntl.h>
#include <dirent.h>

#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "krb5_util.h"
#include "nfslib.h"

static char *pipefs_dir = GSSD_PIPEFS_DIR;
char *keytabfile = GSSD_DEFAULT_KEYTAB_FILE;
char **ccachesearch;
int  use_memcache = 0;
int  root_uses_machine_creds = 1;
unsigned int  context_timeout = 0;
unsigned int  rpc_timeout = 5;
char *preferred_realm = NULL;
extern struct pollfd *pollarray;
extern unsigned long pollsize;

#define POLL_MILLISECS	500

static volatile int dir_changed = 1;

static void dir_notify_handler(__attribute__((unused))int sig)
{
	dir_changed = 1;
}

static void
scan_poll_results(int ret)
{
	int			i;
	struct clnt_info	*clp;

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next)
	{
		i = clp->gssd_poll_index;
		if (i >= 0 && pollarray[i].revents) {
			if (pollarray[i].revents & POLLHUP) {
				clp->gssd_close_me = 1;
				dir_changed = 1;
			}
			if (pollarray[i].revents & POLLIN)
				handle_gssd_upcall(clp);
			pollarray[clp->gssd_poll_index].revents = 0;
			ret--;
			if (!ret)
				break;
		}
		i = clp->krb5_poll_index;
		if (i >= 0 && pollarray[i].revents) {
			if (pollarray[i].revents & POLLHUP) {
				clp->krb5_close_me = 1;
				dir_changed = 1;
			}
			if (pollarray[i].revents & POLLIN)
				handle_krb5_upcall(clp);
			pollarray[clp->krb5_poll_index].revents = 0;
			ret--;
			if (!ret)
				break;
		}
	}
}

static int
topdirs_add_entry(int pfd, const char *name)
{
	struct topdirs_info *tdi;

	tdi = malloc(sizeof(*tdi) + strlen(pipefs_dir) + strlen(name) + 2);
	if (!tdi) {
		printerr(0, "ERROR: Couldn't allocate struct topdirs_info\n");
		return -1;
	}

	sprintf(tdi->dirname, "%s/%s", pipefs_dir, name);

	tdi->fd = openat(pfd, name, O_RDONLY);
	if (tdi->fd < 0) {
		printerr(0, "ERROR: failed to open %s: %s\n",
			 tdi->dirname, strerror(errno));
		free(tdi);
		return -1;
	}

	fcntl(tdi->fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(tdi->fd, F_NOTIFY, DN_CREATE|DN_DELETE|DN_MODIFY|DN_MULTISHOT);

	TAILQ_INSERT_HEAD(&topdirs_list, tdi, list);
	return 0;
}

static void
topdirs_init_list(void)
{
	DIR *pipedir;
	struct dirent *dent;

	TAILQ_INIT(&topdirs_list);

	pipedir = opendir(".");
	if (!pipedir) {
		printerr(0, "ERROR: could not open rpc_pipefs directory: '%s'\n",
			 strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ((dent = readdir(pipedir))) {
		if (dent->d_type != DT_DIR)
			continue;

		if (dent->d_name[0] == '.')
			continue;

		if (topdirs_add_entry(dirfd(pipedir), dent->d_name))
			exit(EXIT_FAILURE);
	}

	if (TAILQ_EMPTY(&topdirs_list)) {
		printerr(0, "ERROR: the rpc_pipefs directory is empty!\n");
		exit(EXIT_FAILURE);
	}

	closedir(pipedir);
}

#ifdef HAVE_PPOLL
static void gssd_poll(struct pollfd *fds, unsigned long nfds)
{
	sigset_t emptyset;
	int ret;

	sigemptyset(&emptyset);
	ret = ppoll(fds, nfds, NULL, &emptyset);
	if (ret < 0) {
		if (errno != EINTR)
			printerr(0, "WARNING: error return from poll\n");
	} else if (ret == 0) {
		printerr(0, "WARNING: unexpected timeout\n");
	} else {
		scan_poll_results(ret);
	}
}
#else	/* !HAVE_PPOLL */
static void gssd_poll(struct pollfd *fds, unsigned long nfds)
{
	int ret;

	/* race condition here: dir_changed could be set before we
	 * enter the poll, and we'd never notice if it weren't for the
	 * timeout. */
	ret = poll(fds, nfds, POLL_MILLISECS);
	if (ret < 0) {
		if (errno != EINTR)
			printerr(0, "WARNING: error return from poll\n");
	} else if (ret == 0) {
		/* timeout */
	} else { /* ret > 0 */
		scan_poll_results(ret);
	}
}
#endif	/* !HAVE_PPOLL */

static void
gssd_run(void)
{
	struct sigaction	dn_act = {
		.sa_handler = dir_notify_handler
	};
	sigset_t		set;

	sigemptyset(&dn_act.sa_mask);
	sigaction(DNOTIFY_SIGNAL, &dn_act, NULL);

	/* just in case the signal is blocked... */
	sigemptyset(&set);
	sigaddset(&set, DNOTIFY_SIGNAL);
	sigprocmask(SIG_UNBLOCK, &set, NULL);

	topdirs_init_list();
	init_client_list();

	printerr(1, "beginning poll\n");
	while (1) {
		while (dir_changed) {
			dir_changed = 0;
			if (update_client_list()) {
				/* Error msg is already printed */
				exit(1);
			}

			daemon_ready();
		}
		gssd_poll(pollarray, pollsize);
	}
}

static void
sig_die(int signal)
{
	/* destroy krb5 machine creds */
	if (root_uses_machine_creds)
		gssd_destroy_krb5_machine_creds();
	printerr(1, "exiting on signal %d\n", signal);
	exit(0);
}

static void
sig_hup(int signal)
{
	/* don't exit on SIGHUP */
	printerr(1, "Received SIGHUP(%d)... Ignoring.\n", signal);
	return;
}

static void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-f] [-l] [-M] [-n] [-v] [-r] [-p pipefsdir] [-k keytab] [-d ccachedir] [-t timeout] [-R preferred realm] [-D]\n",
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
	int i;
	extern char *optarg;
	char *progname;
	char *ccachedir = NULL;

	while ((opt = getopt(argc, argv, "DfvrlmnMp:k:d:t:T:R:")) != -1) {
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
			case 'n':
				root_uses_machine_creds = 0;
				break;
			case 'v':
				verbosity++;
				break;
			case 'r':
				rpc_verbosity++;
				break;
			case 'p':
				pipefs_dir = optarg;
				break;
			case 'k':
				keytabfile = optarg;
				break;
			case 'd':
				ccachedir = optarg;
				break;
			case 't':
				context_timeout = atoi(optarg);
				break;
			case 'T':
				rpc_timeout = atoi(optarg);
				break;
			case 'R':
				preferred_realm = strdup(optarg);
				break;
			case 'l':
#ifdef HAVE_SET_ALLOWABLE_ENCTYPES
				limit_to_legacy_enctypes = 1;
#else 
				errx(1, "Encryption type limits not supported by Kerberos libraries.");
#endif
				break;
			case 'D':
				avoid_dns = 0;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	/*
	 * Some krb5 routines try to scrape info out of files in the user's
	 * home directory. This can easily deadlock when that homedir is on a
	 * kerberized NFS mount. By setting $HOME unconditionally to "/", we
	 * prevent this behavior in routines that use $HOME in preference to
	 * the results of getpw*.
	 */
	if (setenv("HOME", "/", 1)) {
		printerr(1, "Unable to set $HOME: %s\n", strerror(errno));
		exit(1);
	}

	if (ccachedir) {
		char *ccachedir_copy;
		char *ptr;

		for (ptr = ccachedir, i = 2; *ptr; ptr++)
			if (*ptr == ':')
				i++;

		ccachesearch = malloc(i * sizeof(char *));
	       	ccachedir_copy = strdup(ccachedir);
		if (!ccachedir_copy || !ccachesearch) {
			printerr(0, "malloc failure\n");
			exit(EXIT_FAILURE);
		}

		i = 0;
		ccachesearch[i++] = strtok(ccachedir, ":");
		while(ccachesearch[i - 1])
			ccachesearch[i++] = strtok(NULL, ":");

	} else {
		ccachesearch = malloc(3 * sizeof(char *));
		if (!ccachesearch) {
			printerr(0, "malloc failure\n");
			exit(EXIT_FAILURE);
		}

		ccachesearch[0] = GSSD_DEFAULT_CRED_DIR;
		ccachesearch[1] = GSSD_USER_CRED_DIR;
		ccachesearch[2] = NULL;
	}

	if (preferred_realm == NULL)
		gssd_k5_get_default_realm(&preferred_realm);

	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	initerr(progname, verbosity, fg);
#ifdef HAVE_AUTHGSS_SET_DEBUG_LEVEL
	if (verbosity && rpc_verbosity == 0)
		rpc_verbosity = verbosity;
	authgss_set_debug_level(rpc_verbosity);
#else
        if (rpc_verbosity > 0)
		printerr(0, "Warning: rpcsec_gss library does not "
			    "support setting debug level\n");
#endif

	if (gssd_check_mechs() != 0)
		errx(1, "Problem with gssapi library");

	daemon_init(fg);

	if (chdir(pipefs_dir)) {
		printerr(1, "ERROR: chdir(%s) failed: %s\n", pipefs_dir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, sig_die);
	signal(SIGTERM, sig_die);
	signal(SIGHUP, sig_hup);

	gssd_run();
	printerr(0, "gssd_run returned!\n");
	abort();
}

