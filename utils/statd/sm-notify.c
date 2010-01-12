/*
 * Send NSM notify calls to all hosts listed in /var/lib/sm
 *
 * Copyright (C) 2004-2006 Olaf Kirch <okir@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <errno.h>
#include <grp.h>

#include "xlog.h"
#include "nsm.h"
#include "nfsrpc.h"

#define NSM_PROG	100024
#define NSM_PROGRAM	100024
#define NSM_VERSION	1
#define NSM_TIMEOUT	2
#define NSM_NOTIFY	6
#define NSM_MAX_TIMEOUT	120	/* don't make this too big */
#define MAXMSGSIZE	256

struct nsm_host {
	struct nsm_host *	next;
	char *			name;
	struct sockaddr_storage	addr;
	struct addrinfo		*ai;
	time_t			last_used;
	time_t			send_next;
	unsigned int		timeout;
	unsigned int		retries;
	unsigned int		xid;
};

static char		nsm_hostname[256];
static int		nsm_state;
static int		opt_debug = 0;
static _Bool		opt_update_state = true;
static unsigned int	opt_max_retry = 15 * 60;
static char *		opt_srcaddr = 0;
static uint16_t		opt_srcport = 0;

static void		notify(void);
static int		notify_host(int, struct nsm_host *);
static void		recv_reply(int);
static void		insert_host(struct nsm_host *);
static struct nsm_host *find_host(uint32_t);
static int		record_pid(void);

static struct nsm_host *	hosts = NULL;

static struct addrinfo *smn_lookup(const char *name)
{
	struct addrinfo	*ai, hint = {
#if HAVE_DECL_AI_ADDRCONFIG
		.ai_flags	= AI_ADDRCONFIG,
#endif	/* HAVE_DECL_AI_ADDRCONFIG */
		.ai_family	= AF_INET,
		.ai_protocol	= IPPROTO_UDP,
	};
	int error;

	error = getaddrinfo(name, NULL, &hint, &ai);
	if (error) {
		xlog(D_GENERAL, "getaddrinfo(3): %s", gai_strerror(error));
		return NULL;
	}

	return ai;
}

__attribute_malloc__
static struct nsm_host *
smn_alloc_host(const char *hostname, const time_t timestamp)
{
	struct nsm_host	*host;

	host = calloc(1, sizeof(*host));
	if (host == NULL)
		goto out_nomem;

	host->name = strdup(hostname);
	if (host->name == NULL) {
		free(host);
		goto out_nomem;
	}

	host->last_used = timestamp;
	host->timeout = NSM_TIMEOUT;
	host->retries = 100;		/* force address retry */

	return host;

out_nomem:
	xlog_warn("Unable to allocate memory");
	return NULL;
}

static void smn_forget_host(struct nsm_host *host)
{
	xlog(D_CALL, "Removing %s from notify list", host->name);

	nsm_delete_notified_host(host->name);

	free(host->name);
	if (host->ai)
		freeaddrinfo(host->ai);

	free(host);
}

static unsigned int
smn_get_host(const char *hostname,
		__attribute__ ((unused)) const struct sockaddr *sap,
		__attribute__ ((unused)) const struct mon *m,
		const time_t timestamp)
{
	struct nsm_host	*host;

	host = smn_alloc_host(hostname, timestamp);
	if (host == NULL)
		return 0;

	insert_host(host);
	xlog(D_GENERAL, "Added host %s to notify list", hostname);
	return 1;
}

int
main(int argc, char **argv)
{
	int	c;
	int	force = 0;
	char *	progname;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];

	while ((c = getopt(argc, argv, "dm:np:v:P:f")) != -1) {
		switch (c) {
		case 'f':
			force = 1;
			break;
		case 'd':
			opt_debug++;
			break;
		case 'm':
			opt_max_retry = atoi(optarg) * 60;
			break;
		case 'n':
			opt_update_state = false;
			break;
		case 'p':
			opt_srcport = atoi(optarg);
			break;
		case 'v':
			opt_srcaddr = optarg;
			break;
		case 'P':
			if (!nsm_setup_pathnames(argv[0], optarg))
				exit(1);
			break;

		default:
			goto usage;
		}
	}

	if (optind < argc) {
usage:		fprintf(stderr,
			"Usage: %s -notify [-dfq] [-m max-retry-minutes] [-p srcport]\n"
			"            [-P /path/to/state/directory] [-v my_host_name]\n",
			progname);
		exit(1);
	}

	xlog_syslog(1);
	if (opt_debug) {
		xlog_stderr(1);
		xlog_config(D_ALL, 1);
	} else
		xlog_stderr(0);

	xlog_open(progname);
	xlog(L_NOTICE, "Version " VERSION " starting");

	if (nsm_is_default_parentdir()) {
		if (record_pid() == 0 && force == 0 && opt_update_state) {
			/* already run, don't try again */
			xlog(L_NOTICE, "Already notifying clients; Exiting!");
			exit(0);
		}
	}

	if (opt_srcaddr) {
		strncpy(nsm_hostname, opt_srcaddr, sizeof(nsm_hostname)-1);
	} else
	if (gethostname(nsm_hostname, sizeof(nsm_hostname)) < 0) {
		xlog(L_ERROR, "Failed to obtain name of local host: %m");
		exit(1);
	}

	(void)nsm_retire_monitored_hosts();
	if (nsm_load_notify_list(smn_get_host) == 0) {
		xlog(D_GENERAL, "No hosts to notify; exiting");
		return 0;
	}

	nsm_state = nsm_get_state(opt_update_state);
	if (nsm_state == 0)
		exit(1);
	nsm_update_kernel_state(nsm_state);

	if (!opt_debug) {
		xlog(L_NOTICE, "Backgrounding to notify hosts...\n");

		if (daemon(0, 0) < 0) {
			xlog(L_ERROR, "unable to background: %m");
			exit(1);
		}

		close(0);
		close(1);
		close(2);
	}

	notify();

	if (hosts) {
		struct nsm_host	*hp;

		while ((hp = hosts) != 0) {
			hosts = hp->next;
			xlog(L_NOTICE, "Unable to notify %s, giving up",
				hp->name);
		}
		exit(1);
	}

	exit(0);
}

/*
 * Notify hosts
 */
static void
notify(void)
{
	struct sockaddr_storage address;
	struct sockaddr *local_addr = (struct sockaddr *)&address;
	time_t	failtime = 0;
	int	sock = -1;
	int retry_cnt = 0;

 retry:
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		xlog(L_ERROR, "Failed to create RPC socket: %m");
		exit(1);
	}
	fcntl(sock, F_SETFL, O_NONBLOCK);

	memset(&address, 0, sizeof(address));
	local_addr->sa_family = AF_INET;	/* Default to IPv4 */

	/* Bind source IP if provided on command line */
	if (opt_srcaddr) {
		struct addrinfo *ai = smn_lookup(opt_srcaddr);
		if (!ai) {
			xlog(L_ERROR,
				"Not a valid hostname or address: \"%s\"",
				opt_srcaddr);
			exit(1);
		}

		/* We know it's IPv4 at this point */
		memcpy(local_addr, ai->ai_addr, ai->ai_addrlen);

		freeaddrinfo(ai);
	}

	/* Use source port if provided on the command line,
	 * otherwise use bindresvport */
	if (opt_srcport) {
		nfs_set_port(local_addr, opt_srcport);
		if (bind(sock, local_addr, sizeof(struct sockaddr_in)) < 0) {
			xlog(L_ERROR, "Failed to bind RPC socket: %m");
			exit(1);
		}
	} else {
		struct servent *se;
		struct sockaddr_in *sin = (struct sockaddr_in *)local_addr;
		(void) bindresvport(sock, sin);
		/* try to avoid known ports */
		se = getservbyport(sin->sin_port, "udp");
		if (se && retry_cnt < 100) {
			retry_cnt++;
			close(sock);
			goto retry;
		}
	}

	if (opt_max_retry)
		failtime = time(NULL) + opt_max_retry;

	if (!nsm_drop_privileges(-1))
		exit(1);

	while (hosts) {
		struct pollfd	pfd;
		time_t		now = time(NULL);
		unsigned int	sent = 0;
		struct nsm_host	*hp;
		long		wait;

		if (failtime && now >= failtime)
			break;

		while (hosts && ((wait = hosts->send_next - now) <= 0)) {
			/* Never send more than 10 packets at once */
			if (sent++ >= 10)
				break;

			/* Remove queue head */
			hp = hosts;
			hosts = hp->next;

			if (notify_host(sock, hp))
				continue;

			/* Set the timeout for this call, using an
			   exponential timeout strategy */
			wait = hp->timeout;
			if ((hp->timeout <<= 1) > NSM_MAX_TIMEOUT)
				hp->timeout = NSM_MAX_TIMEOUT;
			hp->send_next = now + wait;
			hp->retries++;

			insert_host(hp);
		}
		if (hosts == NULL)
			return;

		xlog(D_GENERAL, "Host %s due in %ld seconds",
				hosts->name, wait);

		pfd.fd = sock;
		pfd.events = POLLIN;

		wait *= 1000;
		if (wait < 100)
			wait = 100;
		if (poll(&pfd, 1, wait) != 1)
			continue;

		recv_reply(sock);
	}
}

/*
 * Send notification to a single host
 */
static int
notify_host(int sock, struct nsm_host *host)
{
	struct sockaddr_storage address;
	struct sockaddr *dest = (struct sockaddr *)&address;
	socklen_t destlen = sizeof(address);
	static unsigned int	xid = 0;
	uint32_t		msgbuf[MAXMSGSIZE], *p;
	unsigned int		len;

	if (!xid)
		xid = getpid() + time(NULL);
	if (!host->xid)
		host->xid = xid++;

	if (host->ai == NULL) {
		host->ai = smn_lookup(host->name);
		if (host->ai == NULL) {
			xlog_warn("DNS resolution of %s failed; "
				"retrying later", host->name);
			return 0;
		}
	}

	memset(msgbuf, 0, sizeof(msgbuf));
	p = msgbuf;
	*p++ = htonl(host->xid);
	*p++ = 0;
	*p++ = htonl(2);

	/* If we retransmitted 4 times, reset the port to force
	 * a new portmap lookup (in case statd was restarted).
	 * We also rotate through multiple IP addresses at this
	 * point.
	 */
	if (host->retries >= 4) {
		/* don't rotate if there is only one addrinfo */
		if (host->ai->ai_next == NULL)
			memcpy(&host->addr, host->ai->ai_addr,
						host->ai->ai_addrlen);
		else {
			struct addrinfo *first = host->ai;
			struct addrinfo **next = &host->ai;

			/* remove the first entry from the list */
			host->ai = first->ai_next;
			first->ai_next = NULL;
			/* find the end of the list */
			next = &first->ai_next;
			while ( *next )
				next = & (*next)->ai_next;
			/* put first entry at end */
			*next = first;
			memcpy(&host->addr, first->ai_addr,
						first->ai_addrlen);
		}

		nfs_set_port((struct sockaddr *)&host->addr, 0);
		host->retries = 0;
	}

	memcpy(dest, &host->addr, destlen);
	if (nfs_get_port(dest) == 0) {
		/* Build a PMAP packet */
		xlog(D_GENERAL, "Sending portmap query to %s", host->name);

		nfs_set_port(dest, 111);
		*p++ = htonl(100000);
		*p++ = htonl(2);
		*p++ = htonl(3);

		/* Auth and verf */
		*p++ = 0; *p++ = 0;
		*p++ = 0; *p++ = 0;

		*p++ = htonl(NSM_PROGRAM);
		*p++ = htonl(NSM_VERSION);
		*p++ = htonl(IPPROTO_UDP);
		*p++ = 0;
	} else {
		/* Build an SM_NOTIFY packet */
		xlog(D_GENERAL, "Sending SM_NOTIFY to %s", host->name);

		*p++ = htonl(NSM_PROGRAM);
		*p++ = htonl(NSM_VERSION);
		*p++ = htonl(NSM_NOTIFY);

		/* Auth and verf */
		*p++ = 0; *p++ = 0;
		*p++ = 0; *p++ = 0;

		/* state change */
		len = strlen(nsm_hostname);
		*p++ = htonl(len);
		memcpy(p, nsm_hostname, len);
		p += (len + 3) >> 2;
		*p++ = htonl(nsm_state);
	}
	len = (p - msgbuf) << 2;

	if (sendto(sock, msgbuf, len, 0, dest, destlen) < 0)
		xlog_warn("Sending Reboot Notification to "
			"'%s' failed: errno %d (%m)", host->name, errno);
	
	return 0;
}

/*
 * Receive reply from remote host
 */
static void
recv_reply(int sock)
{
	struct nsm_host	*hp;
	struct sockaddr *sap;
	uint32_t	msgbuf[MAXMSGSIZE], *p, *end;
	uint32_t	xid;
	int		res;

	res = recv(sock, msgbuf, sizeof(msgbuf), 0);
	if (res < 0)
		return;

	xlog(D_GENERAL, "Received packet...");

	p = msgbuf;
	end = p + (res >> 2);

	xid = ntohl(*p++);
	if (*p++ != htonl(1)	/* must be REPLY */
	 || *p++ != htonl(0)	/* must be ACCEPTED */
	 || *p++ != htonl(0)	/* must be NULL verifier */
	 || *p++ != htonl(0)
	 || *p++ != htonl(0))	/* must be SUCCESS */
		return;

	/* Before we look at the data, find the host struct for
	   this reply */
	if ((hp = find_host(xid)) == NULL)
		return;
	sap = (struct sockaddr *)&hp->addr;

	if (nfs_get_port(sap) == 0) {
		/* This was a portmap request */
		unsigned int	port;

		port = ntohl(*p++);
		if (p > end)
			goto fail;

		hp->send_next = time(NULL);
		if (port == 0) {
			/* No binding for statd. Delay the next
			 * portmap query for max timeout */
			xlog(D_GENERAL, "No statd on %s", hp->name);
			hp->timeout = NSM_MAX_TIMEOUT;
			hp->send_next += NSM_MAX_TIMEOUT;
		} else {
			nfs_set_port(sap, port);
			if (hp->timeout >= NSM_MAX_TIMEOUT / 4)
				hp->timeout = NSM_MAX_TIMEOUT / 4;
		}
		hp->xid = 0;
	} else {
		/* Successful NOTIFY call. Server returns void,
		 * so nothing we need to do here (except
		 * check that we didn't read past the end of the
		 * packet)
		 */
		if (p <= end) {
			xlog(D_GENERAL, "Host %s notified successfully",
					hp->name);
			smn_forget_host(hp);
			return;
		}
	}

fail:	/* Re-insert the host */
	insert_host(hp);
}

/*
 * Insert host into sorted list
 */
static void
insert_host(struct nsm_host *host)
{
	struct nsm_host	**where, *p;

	where = &hosts;
	while ((p = *where) != 0) {
		/* Sort in ascending order of timeout */
		if (host->send_next < p->send_next)
			break;
		/* If we have the same timeout, put the
		 * most recently used host first.
		 * This makes sure that "recent" hosts
		 * get notified first.
		 */
		if (host->send_next == p->send_next
		 && host->last_used > p->last_used)
			break;
		where = &p->next;
	}

	host->next = *where;
	*where = host;
}

/*
 * Find host given the XID
 */
static struct nsm_host *
find_host(uint32_t xid)
{
	struct nsm_host	**where, *p;

	where = &hosts;
	while ((p = *where) != 0) {
		if (p->xid == xid) {
			*where = p->next;
			return p;
		}
		where = &p->next;
	}
	return NULL;
}

/*
 * Record pid in /var/run/sm-notify.pid
 * This file should remain until a reboot, even if the
 * program exits.
 * If file already exists, fail.
 */
static int record_pid(void)
{
	char pid[20];
	ssize_t len;
	int fd;

	(void)snprintf(pid, sizeof(pid), "%d\n", (int)getpid());
	fd = open("/var/run/sm-notify.pid", O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (fd < 0)
		return 0;

	len = write(fd, pid, strlen(pid));
	if ((len < 0) || ((size_t)len != strlen(pid))) {
		xlog_warn("Writing to pid file failed: errno %d (%m)",
				errno);
	}

	(void)close(fd);
	return 1;
}
