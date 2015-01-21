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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/poll.h>
#include <rpc/rpc.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#include <netdb.h>
#include <event.h>

#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "krb5_util.h"
#include "nfslib.h"

static char *pipefs_path = GSSD_PIPEFS_DIR;
static DIR *pipefs_dir;
static int pipefs_fd;

char *keytabfile = GSSD_DEFAULT_KEYTAB_FILE;
char **ccachesearch;
int  use_memcache = 0;
int  root_uses_machine_creds = 1;
unsigned int  context_timeout = 0;
unsigned int  rpc_timeout = 5;
char *preferred_realm = NULL;

TAILQ_HEAD(topdir_list_head, topdir) topdir_list;

struct topdir {
	TAILQ_ENTRY(topdir) list;
	TAILQ_HEAD(clnt_list_head, clnt_info) clnt_list;
	int fd;
	char *name;
	char dirname[];
};

/*
 * topdir_list:
 *	linked list of struct topdir with basic data about a topdir.
 *
 * clnt_list:
 *      linked list of struct clnt_info with basic data about a clntXXX dir,
 *      one per topdir.
 *
 * Directory structure: created by the kernel
 *      {rpc_pipefs}/{topdir}/clntXX      : one per rpc_clnt struct in the kernel
 *      {rpc_pipefs}/{topdir}/clntXX/krb5 : read uid for which kernel wants
 *					    a context, write the resulting context
 *      {rpc_pipefs}/{topdir}/clntXX/info : stores info such as server name
 *      {rpc_pipefs}/{topdir}/clntXX/gssd : pipe for all gss mechanisms using
 *					    a text-based string of parameters
 *
 * Algorithm:
 *      Poll all {rpc_pipefs}/{topdir}/clntXX/YYYY files.  When data is ready,
 *      read and process; performs rpcsec_gss context initialization protocol to
 *      get a cred for that user.  Writes result to corresponding krb5 file
 *      in a form the kernel code will understand.
 *      In addition, we make sure we are notified whenever anything is
 *      created or destroyed in {rpc_pipefs} or in any of the clntXX directories,
 *      and rescan the whole {rpc_pipefs} when this happens.
 */

/* Avoid DNS reverse lookups on server names */
static int avoid_dns = 1;

/*
 * convert a presentation address string to a sockaddr_storage struct. Returns
 * true on success or false on failure.
 *
 * Note that we do not populate the sin6_scope_id field here for IPv6 addrs.
 * gssd nececessarily relies on hostname resolution and DNS AAAA records
 * do not generally contain scope-id's. This means that GSSAPI auth really
 * can't work with IPv6 link-local addresses.
 *
 * We *could* consider changing this if we did something like adopt the
 * Microsoft "standard" of using the ipv6-literal.net domainname, but it's
 * not really feasible at present.
 */
static int
addrstr_to_sockaddr(struct sockaddr *sa, const char *node, const char *port)
{
	int rc;
	struct addrinfo *res;
	struct addrinfo hints = { .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV };

#ifndef IPV6_SUPPORTED
	hints.ai_family = AF_INET;
#endif /* IPV6_SUPPORTED */

	rc = getaddrinfo(node, port, &hints, &res);
	if (rc) {
		printerr(0, "ERROR: unable to convert %s|%s to sockaddr: %s\n",
			 node, port, rc == EAI_SYSTEM ? strerror(errno) :
						gai_strerror(rc));
		return 0;
	}

#ifdef IPV6_SUPPORTED
	/*
	 * getnameinfo ignores the scopeid. If the address turns out to have
	 * a non-zero scopeid, we can't use it -- the resolved host might be
	 * completely different from the one intended.
	 */
	if (res->ai_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)res->ai_addr;
		if (sin6->sin6_scope_id) {
			printerr(0, "ERROR: address %s has non-zero "
				    "sin6_scope_id!\n", node);
			freeaddrinfo(res);
			return 0;
		}
	}
#endif /* IPV6_SUPPORTED */

	memcpy(sa, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 1;
}

/*
 * convert a sockaddr to a hostname
 */
static char *
get_servername(const char *name, const struct sockaddr *sa, const char *addr)
{
	socklen_t		addrlen;
	int			err;
	char			*hostname;
	char			hbuf[NI_MAXHOST];
	unsigned char		buf[sizeof(struct in6_addr)];

	if (avoid_dns) {
		/*
		 * Determine if this is a server name, or an IP address.
		 * If it is an IP address, do the DNS lookup otherwise
		 * skip the DNS lookup.
		 */
		int is_fqdn = 1;
		if (strchr(name, '.') == NULL)
			is_fqdn = 0; /* local name */
		else if (inet_pton(AF_INET, name, buf) == 1)
			is_fqdn = 0; /* IPv4 address */
		else if (inet_pton(AF_INET6, name, buf) == 1)
			is_fqdn = 0; /* IPv6 addrss */

		if (is_fqdn) {
			return strdup(name);
		}
		/* Sorry, cannot avoid dns after all */
	}

	switch (sa->sa_family) {
	case AF_INET:
		addrlen = sizeof(struct sockaddr_in);
		break;
#ifdef IPV6_SUPPORTED
	case AF_INET6:
		addrlen = sizeof(struct sockaddr_in6);
		break;
#endif /* IPV6_SUPPORTED */
	default:
		printerr(0, "ERROR: unrecognized addr family %d\n",
			 sa->sa_family);
		return NULL;
	}

	err = getnameinfo(sa, addrlen, hbuf, sizeof(hbuf), NULL, 0,
			  NI_NAMEREQD);
	if (err) {
		printerr(0, "ERROR: unable to resolve %s to hostname: %s\n",
			 addr, err == EAI_SYSTEM ? strerror(errno) :
						   gai_strerror(err));
		return NULL;
	}

	hostname = strdup(hbuf);

	return hostname;
}

/* XXX buffer problems: */
static int
read_service_info(char *info_file_name, char **servicename, char **servername,
		  int *prog, int *vers, char **protocol,
		  struct sockaddr *addr) {
#define INFOBUFLEN 256
	char		buf[INFOBUFLEN + 1];
	static char	server[128];
	int		nbytes;
	static char	service[128];
	static char	address[128];
	char		program[16];
	char		version[16];
	char		protoname[16];
	char		port[128];
	char		*p;
	int		fd = -1;
	int		numfields;

	*servicename = *servername = *protocol = NULL;

	if ((fd = open(info_file_name, O_RDONLY)) == -1) {
		printerr(0, "ERROR: can't open %s: %s\n", info_file_name,
			 strerror(errno));
		goto fail;
	}
	if ((nbytes = read(fd, buf, INFOBUFLEN)) == -1)
		goto fail;
	close(fd);
	fd = -1;
	buf[nbytes] = '\0';

	numfields = sscanf(buf,"RPC server: %127s\n"
		   "service: %127s %15s version %15s\n"
		   "address: %127s\n"
		   "protocol: %15s\n",
		   server,
		   service, program, version,
		   address,
		   protoname);

	if (numfields == 5) {
		strcpy(protoname, "tcp");
	} else if (numfields != 6) {
		goto fail;
	}

	port[0] = '\0';
	if ((p = strstr(buf, "port")) != NULL)
		sscanf(p, "port: %127s\n", port);

	/* get program, and version numbers */
	*prog = atoi(program + 1); /* skip open paren */
	*vers = atoi(version);

	if (!addrstr_to_sockaddr(addr, address, port))
		goto fail;

	*servername = get_servername(server, addr, address);
	if (*servername == NULL)
		goto fail;

	nbytes = snprintf(buf, INFOBUFLEN, "%s@%s", service, *servername);
	if (nbytes > INFOBUFLEN)
		goto fail;

	if (!(*servicename = calloc(strlen(buf) + 1, 1)))
		goto fail;
	memcpy(*servicename, buf, strlen(buf));

	if (!(*protocol = strdup(protoname)))
		goto fail;
	return 0;
fail:
	printerr(0, "ERROR: failed to read service info\n");
	if (fd != -1) close(fd);
	free(*servername);
	free(*servicename);
	free(*protocol);
	*servicename = *servername = *protocol = NULL;
	return -1;
}

static void
destroy_client(struct clnt_info *clp)
{
	if (clp->krb5_fd >= 0) {
		close(clp->krb5_fd);
		event_del(&clp->krb5_ev);
	}

	if (clp->gssd_fd >= 0) {
		close(clp->gssd_fd);
		event_del(&clp->gssd_ev);
	}

	if (clp->dir_fd >= 0)
		close(clp->dir_fd);

	free(clp->relpath);
	free(clp->servicename);
	free(clp->servername);
	free(clp->protocol);
	free(clp);
}

static struct clnt_info *
insert_new_clnt(struct topdir *tdi)
{
	struct clnt_info *clp;

	clp = calloc(1, sizeof(struct clnt_info));
	if (!clp) {
		printerr(0, "ERROR: can't malloc clnt_info: %s\n",
			 strerror(errno));
		return NULL;
	}

	clp->krb5_fd = -1;
	clp->gssd_fd = -1;
	clp->dir_fd = -1;

	TAILQ_INSERT_HEAD(&tdi->clnt_list, clp, list);
	return clp;
}

static void gssd_scan(void);

static void
gssd_clnt_gssd_cb(int UNUSED(fd), short which, void *data)
{
	struct clnt_info *clp = data;

	if (which != EV_READ) {
		printerr(2, "Closing 'gssd' pipe %s\n", clp->relpath);
		close(clp->gssd_fd);
		clp->gssd_fd = -1;
		event_del(&clp->gssd_ev);
		gssd_scan();
		return;
	}

	handle_gssd_upcall(clp);
}

static void
gssd_clnt_krb5_cb(int UNUSED(fd), short which, void *data)
{
	struct clnt_info *clp = data;

	if (which != EV_READ) {
		printerr(2, "Closing 'krb5' pipe %s\n", clp->relpath);
		close(clp->krb5_fd);
		clp->krb5_fd = -1;
		event_del(&clp->krb5_ev);
		gssd_scan();
		return;
	}

	handle_krb5_upcall(clp);
}

static int
process_clnt_dir_files(struct clnt_info * clp)
{
	char name[strlen(clp->relpath) + strlen("/krb5") + 1];
	char gname[strlen(clp->relpath) + strlen("/gssd") + 1];
	bool gssd_was_closed;
	bool krb5_was_closed;

	gssd_was_closed = clp->gssd_fd < 0 ? true : false;
	krb5_was_closed = clp->krb5_fd < 0 ? true : false;

	sprintf(gname, "%s/gssd", clp->relpath);
	sprintf(name, "%s/krb5", clp->relpath);

	if (clp->gssd_fd == -1)
		clp->gssd_fd = openat(pipefs_fd, gname, O_RDWR);

	if (clp->gssd_fd == -1) {
		if (clp->krb5_fd == -1)
			clp->krb5_fd = openat(pipefs_fd, name, O_RDWR);

		/* If we opened a gss-specific pipe, let's try opening
		 * the new upcall pipe again. If we succeed, close
		 * gss-specific pipe(s).
		 */
		if (clp->krb5_fd != -1) {
			clp->gssd_fd = openat(pipefs_fd, gname, O_RDWR);
			if (clp->gssd_fd != -1) {
				close(clp->krb5_fd);
				clp->krb5_fd = -1;
			}
		}
	}

	if (gssd_was_closed && clp->gssd_fd >= 0) {
		event_set(&clp->gssd_ev, clp->gssd_fd, EV_READ | EV_PERSIST,
			  gssd_clnt_gssd_cb, clp);
		event_add(&clp->gssd_ev, NULL);
	}

	if (krb5_was_closed && clp->krb5_fd >= 0) {
		event_set(&clp->krb5_ev, clp->krb5_fd, EV_READ | EV_PERSIST,
			  gssd_clnt_krb5_cb, clp);
		event_add(&clp->krb5_ev, NULL);
	}

	if ((clp->krb5_fd == -1) && (clp->gssd_fd == -1))
		/* not fatal, files might appear later */
		return 0;

	if (clp->prog == 0) {
		char info_file_name[strlen(clp->relpath) + strlen("/info") + 1];

		sprintf(info_file_name, "%s/info", clp->relpath);
		read_service_info(info_file_name, &clp->servicename,
				  &clp->servername, &clp->prog, &clp->vers,
				  &clp->protocol, (struct sockaddr *) &clp->addr);
	}

	clp->scanned = true;
	return 0;
}

static void
process_clnt_dir(struct topdir *tdi, const char *name)
{
	struct clnt_info *clp;

	clp = insert_new_clnt(tdi);
	if (!clp)
		goto out;

	clp->relpath = malloc(strlen(tdi->name) + strlen("/") + strlen(name) + 1);
	if (!clp->relpath)
		goto out;

	sprintf(clp->relpath, "%s/%s", tdi->name, name);
	clp->name = clp->relpath + strlen(tdi->name) + 1;

	if ((clp->dir_fd = open(clp->relpath, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			printerr(0, "ERROR: can't open %s: %s\n",
				 clp->relpath, strerror(errno));
		goto out;
	}

	fcntl(clp->dir_fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(clp->dir_fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_MULTISHOT);

	if (process_clnt_dir_files(clp))
		goto out;

	return;

out:
	if (clp) {
		TAILQ_REMOVE(&tdi->clnt_list, clp, list);
		destroy_client(clp);
	}
}

static struct topdir *
gssd_get_topdir(const char *name)
{
	struct topdir *tdi;

	TAILQ_FOREACH(tdi, &topdir_list, list)
		if (!strcmp(tdi->name, name))
			return tdi;

	tdi = malloc(sizeof(*tdi) + strlen(pipefs_path) + strlen(name) + 2);
	if (!tdi) {
		printerr(0, "ERROR: Couldn't allocate struct topdir\n");
		return NULL;
	}

	sprintf(tdi->dirname, "%s/%s", pipefs_path, name);
	tdi->name = tdi->dirname + strlen(pipefs_path) + 1;
	TAILQ_INIT(&tdi->clnt_list);

	tdi->fd = openat(pipefs_fd, name, O_RDONLY);
	if (tdi->fd < 0) {
		printerr(0, "ERROR: failed to open %s: %s\n",
			 tdi->dirname, strerror(errno));
		free(tdi);
		return NULL;
	}

	fcntl(tdi->fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(tdi->fd, F_NOTIFY, DN_CREATE|DN_DELETE|DN_MODIFY|DN_MULTISHOT);

	TAILQ_INSERT_HEAD(&topdir_list, tdi, list);
	return tdi;
}

static void
gssd_scan_topdir(const char *name)
{
	struct topdir *tdi;
	int dfd;
	DIR *dir;
	struct clnt_info *clp;
	struct dirent *d;

	tdi = gssd_get_topdir(name);
	if (!tdi)
		return;

	dfd = openat(pipefs_fd, tdi->name, O_RDONLY);
	if (dfd < 0) {
		printerr(0, "ERROR: can't openat %s: %s\n",
			 tdi->dirname, strerror(errno));
		return;
	}

	dir = fdopendir(dfd);
	if (!dir) {
		printerr(0, "ERROR: can't fdopendir %s: %s\n",
			 tdi->dirname, strerror(errno));
		return;
	}

	TAILQ_FOREACH(clp, &tdi->clnt_list, list)
		clp->scanned = false;

	while ((d = readdir(dir))) {
		if (d->d_type != DT_DIR)
			continue;

		if (strncmp(d->d_name, "clnt", strlen("clnt")))
			continue;

		TAILQ_FOREACH(clp, &tdi->clnt_list, list)
			if (!strcmp(clp->name, d->d_name))
				break;

		if (clp)
			process_clnt_dir_files(clp);
		else
			process_clnt_dir(tdi, d->d_name);
	}

	closedir(dir);

	TAILQ_FOREACH(clp, &tdi->clnt_list, list) {
		void *saveprev;

		if (clp->scanned)
			continue;

		printerr(2, "destroying client %s\n", clp->relpath);
		saveprev = clp->list.tqe_prev;
		TAILQ_REMOVE(&tdi->clnt_list, clp, list);
		destroy_client(clp);
		clp = saveprev;
	}
}

static void
gssd_scan(void)
{
	struct dirent *d;

	rewinddir(pipefs_dir);

	while ((d = readdir(pipefs_dir))) {
		if (d->d_type != DT_DIR)
			continue;

		if (d->d_name[0] == '.')
			continue;

		gssd_scan_topdir(d->d_name);
	}

	if (TAILQ_EMPTY(&topdir_list)) {
		printerr(0, "ERROR: the rpc_pipefs directory is empty!\n");
		exit(EXIT_FAILURE);
	}
}

static void
gssd_scan_cb(int UNUSED(ifd), short UNUSED(which), void *UNUSED(data))
{
	gssd_scan();
}


static void
gssd_atexit(void)
{
	if (root_uses_machine_creds)
		gssd_destroy_krb5_machine_creds();
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
	struct event sighup_ev;
	struct event sigdnotify_ev;

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
				pipefs_path = optarg;
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

	event_init();

	pipefs_dir = opendir(pipefs_path);
	if (!pipefs_dir) {
		printerr(1, "ERROR: opendir(%s) failed: %s\n", pipefs_path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	pipefs_fd = dirfd(pipefs_dir);
	if (fchdir(pipefs_fd)) {
		printerr(1, "ERROR: fchdir(%s) failed: %s\n", pipefs_path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (atexit(gssd_atexit)) {
		printerr(1, "ERROR: atexit failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	signal_set(&sighup_ev, SIGHUP, gssd_scan_cb, NULL);
	signal_add(&sighup_ev, NULL);
	signal_set(&sigdnotify_ev, DNOTIFY_SIGNAL, gssd_scan_cb, NULL);
	signal_add(&sigdnotify_ev, NULL);

	TAILQ_INIT(&topdir_list);
	gssd_scan();
	daemon_ready();

	event_dispatch();

	printerr(1, "ERROR: event_dispatch() returned!\n");
	return EXIT_FAILURE;
}

