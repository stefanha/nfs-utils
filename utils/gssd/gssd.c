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

#define POLL_MILLISECS	500

TAILQ_HEAD(clnt_list_head, clnt_info) clnt_list;

TAILQ_HEAD(topdirs_list_head, topdirs_info) topdirs_list;

struct topdirs_info {
	TAILQ_ENTRY(topdirs_info)	list;
	int				fd;
	char				dirname[];
};

static volatile int dir_changed = 1;

static void dir_notify_handler(__attribute__((unused))int sig)
{
	dir_changed = 1;
}


/*
 * pollarray:
 *      array of struct pollfd suitable to pass to poll. initialized to
 *      zero - a zero struct is ignored by poll() because the events mask is 0.
 *
 * clnt_list:
 *      linked list of struct clnt_info which associates a clntXXX directory
 *	with an index into pollarray[], and other basic data about that client.
 *
 * Directory structure: created by the kernel
 *      {rpc_pipefs}/{dir}/clntXX         : one per rpc_clnt struct in the kernel
 *      {rpc_pipefs}/{dir}/clntXX/krb5    : read uid for which kernel wants
 *					    a context, write the resulting context
 *      {rpc_pipefs}/{dir}/clntXX/info    : stores info such as server name
 *      {rpc_pipefs}/{dir}/clntXX/gssd    : pipe for all gss mechanisms using
 *					    a text-based string of parameters
 *
 * Algorithm:
 *      Poll all {rpc_pipefs}/{dir}/clntXX/YYYY files.  When data is ready,
 *      read and process; performs rpcsec_gss context initialization protocol to
 *      get a cred for that user.  Writes result to corresponding krb5 file
 *      in a form the kernel code will understand.
 *      In addition, we make sure we are notified whenever anything is
 *      created or destroyed in {rpc_pipefs} or in any of the clntXX directories,
 *      and rescan the whole {rpc_pipefs} when this happens.
 */

static struct pollfd * pollarray;

static unsigned long pollsize;  /* the size of pollaray (in pollfd's) */

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
	if (clp->krb5_poll_index != -1)
		memset(&pollarray[clp->krb5_poll_index], 0,
					sizeof(struct pollfd));
	if (clp->gssd_poll_index != -1)
		memset(&pollarray[clp->gssd_poll_index], 0,
					sizeof(struct pollfd));
	if (clp->dir_fd != -1) close(clp->dir_fd);
	if (clp->krb5_fd != -1) close(clp->krb5_fd);
	if (clp->gssd_fd != -1) close(clp->gssd_fd);
	free(clp->dirname);
	free(clp->pdir);
	free(clp->servicename);
	free(clp->servername);
	free(clp->protocol);
	free(clp);
}

static struct clnt_info *
insert_new_clnt(void)
{
	struct clnt_info	*clp = NULL;

	if (!(clp = (struct clnt_info *)calloc(1,sizeof(struct clnt_info)))) {
		printerr(0, "ERROR: can't malloc clnt_info: %s\n",
			 strerror(errno));
		goto out;
	}
	clp->krb5_poll_index = -1;
	clp->gssd_poll_index = -1;
	clp->krb5_fd = -1;
	clp->gssd_fd = -1;
	clp->dir_fd = -1;

	TAILQ_INSERT_HEAD(&clnt_list, clp, list);
out:
	return clp;
}

static int
process_clnt_dir_files(struct clnt_info * clp)
{
	char	name[PATH_MAX];
	char	gname[PATH_MAX];
	char	info_file_name[PATH_MAX];

	if (clp->gssd_close_me) {
		printerr(2, "Closing 'gssd' pipe for %s\n", clp->dirname);
		close(clp->gssd_fd);
		memset(&pollarray[clp->gssd_poll_index], 0,
			sizeof(struct pollfd));
		clp->gssd_fd = -1;
		clp->gssd_poll_index = -1;
		clp->gssd_close_me = 0;
	}
	if (clp->krb5_close_me) {
		printerr(2, "Closing 'krb5' pipe for %s\n", clp->dirname);
		close(clp->krb5_fd);
		memset(&pollarray[clp->krb5_poll_index], 0,
			sizeof(struct pollfd));
		clp->krb5_fd = -1;
		clp->krb5_poll_index = -1;
		clp->krb5_close_me = 0;
	}

	if (clp->gssd_fd == -1) {
		snprintf(gname, sizeof(gname), "%s/gssd", clp->dirname);
		clp->gssd_fd = open(gname, O_RDWR);
	}
	if (clp->gssd_fd == -1) {
		if (clp->krb5_fd == -1) {
			snprintf(name, sizeof(name), "%s/krb5", clp->dirname);
			clp->krb5_fd = open(name, O_RDWR);
		}

		/* If we opened a gss-specific pipe, let's try opening
		 * the new upcall pipe again. If we succeed, close
		 * gss-specific pipe(s).
		 */
		if (clp->krb5_fd != -1) {
			clp->gssd_fd = open(gname, O_RDWR);
			if (clp->gssd_fd != -1) {
				if (clp->krb5_fd != -1)
					close(clp->krb5_fd);
				clp->krb5_fd = -1;
			}
		}
	}

	if ((clp->krb5_fd == -1) && (clp->gssd_fd == -1))
		return -1;
	snprintf(info_file_name, sizeof(info_file_name), "%s/info",
			clp->dirname);
	if (clp->prog == 0)
		read_service_info(info_file_name, &clp->servicename,
				  &clp->servername, &clp->prog, &clp->vers,
				  &clp->protocol, (struct sockaddr *) &clp->addr);
	return 0;
}

static int
get_poll_index(int *ind)
{
	unsigned int i;

	*ind = -1;
	for (i=0; i<pollsize; i++) {
		if (pollarray[i].events == 0) {
			*ind = i;
			break;
		}
	}
	if (*ind == -1) {
		printerr(0, "ERROR: No pollarray slots open\n");
		return -1;
	}
	return 0;
}


static int
insert_clnt_poll(struct clnt_info *clp)
{
	if ((clp->gssd_fd != -1) && (clp->gssd_poll_index == -1)) {
		if (get_poll_index(&clp->gssd_poll_index)) {
			printerr(0, "ERROR: Too many gssd clients\n");
			return -1;
		}
		pollarray[clp->gssd_poll_index].fd = clp->gssd_fd;
		pollarray[clp->gssd_poll_index].events |= POLLIN;
	}

	if ((clp->krb5_fd != -1) && (clp->krb5_poll_index == -1)) {
		if (get_poll_index(&clp->krb5_poll_index)) {
			printerr(0, "ERROR: Too many krb5 clients\n");
			return -1;
		}
		pollarray[clp->krb5_poll_index].fd = clp->krb5_fd;
		pollarray[clp->krb5_poll_index].events |= POLLIN;
	}

	return 0;
}

static void
process_clnt_dir(char *dir, char *pdir)
{
	struct clnt_info *	clp;

	if (!(clp = insert_new_clnt()))
		goto fail_destroy_client;

	if (!(clp->pdir = strdup(pdir)))
		goto fail_destroy_client;

	/* An extra for the '/', and an extra for the null */
	if (!(clp->dirname = calloc(strlen(dir) + strlen(pdir) + 2, 1))) {
		goto fail_destroy_client;
	}
	sprintf(clp->dirname, "%s/%s", pdir, dir);
	if ((clp->dir_fd = open(clp->dirname, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			printerr(0, "ERROR: can't open %s: %s\n",
				 clp->dirname, strerror(errno));
		goto fail_destroy_client;
	}
	fcntl(clp->dir_fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(clp->dir_fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_MULTISHOT);

	if (process_clnt_dir_files(clp))
		goto fail_keep_client;

	if (insert_clnt_poll(clp))
		goto fail_destroy_client;

	return;

fail_destroy_client:
	if (clp) {
		TAILQ_REMOVE(&clnt_list, clp, list);
		destroy_client(clp);
	}
fail_keep_client:
	/* We couldn't find some subdirectories, but we keep the client
	 * around in case we get a notification on the directory when the
	 * subdirectories are created. */
	return;
}

/*
 * This is run after a DNOTIFY signal, and should clear up any
 * directories that are no longer around, and re-scan any existing
 * directories, since the DNOTIFY could have been in there.
 */
static void
update_old_clients(struct dirent **namelist, int size, char *pdir)
{
	struct clnt_info *clp;
	void *saveprev;
	int i, stillhere;
	char fname[PATH_MAX];

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next) {
		/* only compare entries in the global list that are from the
		 * same pipefs parent directory as "pdir"
		 */
		if (strcmp(clp->pdir, pdir) != 0) continue;

		stillhere = 0;
		for (i=0; i < size; i++) {
			snprintf(fname, sizeof(fname), "%s/%s",
				 pdir, namelist[i]->d_name);
			if (strcmp(clp->dirname, fname) == 0) {
				stillhere = 1;
				break;
			}
		}
		if (!stillhere) {
			printerr(2, "destroying client %s\n", clp->dirname);
			saveprev = clp->list.tqe_prev;
			TAILQ_REMOVE(&clnt_list, clp, list);
			destroy_client(clp);
			clp = saveprev;
		}
	}
	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next) {
		if (!process_clnt_dir_files(clp))
			insert_clnt_poll(clp);
	}
}

/* Search for a client by directory name, return 1 if found, 0 otherwise */
static int
find_client(char *dirname, char *pdir)
{
	struct clnt_info	*clp;
	char fname[PATH_MAX];

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next) {
		snprintf(fname, sizeof(fname), "%s/%s", pdir, dirname);
		if (strcmp(clp->dirname, fname) == 0)
			return 1;
	}
	return 0;
}

static int
process_pipedir(char *pipe_name)
{
	struct dirent **namelist;
	int i, j;

	if (chdir(pipe_name) < 0) {
		printerr(0, "ERROR: can't chdir to %s: %s\n",
			 pipe_name, strerror(errno));
		return -1;
	}

	j = scandir(pipe_name, &namelist, NULL, alphasort);
	if (j < 0) {
		printerr(0, "ERROR: can't scandir %s: %s\n",
			 pipe_name, strerror(errno));
		return -1;
	}

	update_old_clients(namelist, j, pipe_name);
	for (i=0; i < j; i++) {
		if (!strncmp(namelist[i]->d_name, "clnt", 4)
		    && !find_client(namelist[i]->d_name, pipe_name))
			process_clnt_dir(namelist[i]->d_name, pipe_name);
		free(namelist[i]);
	}

	free(namelist);

	return 0;
}

/* Used to read (and re-read) list of clients, set up poll array. */
static int
update_client_list(void)
{
	int retval = -1;
	struct topdirs_info *tdi;

	TAILQ_FOREACH(tdi, &topdirs_list, list) {
		retval = process_pipedir(tdi->dirname);
		if (retval)
			printerr(1, "WARNING: error processing %s\n",
				 tdi->dirname);

	}
	return retval;
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


#define FD_ALLOC_BLOCK		256
static void
init_client_list(void)
{
	struct rlimit rlim;

	TAILQ_INIT(&clnt_list);

	/* Eventually plan to grow/shrink poll array: */
	if (!getrlimit(RLIMIT_NOFILE, &rlim) && rlim.rlim_cur != RLIM_INFINITY)
		pollsize = rlim.rlim_cur;
	else
		pollsize = FD_ALLOC_BLOCK;

	pollarray = calloc(pollsize, sizeof(struct pollfd));
	if (!pollarray) {
		printerr(1, "ERROR: calloc failed\n");
		exit(EXIT_FAILURE);
	}
}

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

