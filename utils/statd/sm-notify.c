/*
 * Send NSM notify calls to all hosts listed in /var/lib/sm
 *
 * Copyright (C) 2004-2006 Olaf Kirch <okir@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

#ifndef BASEDIR
# ifdef NFS_STATEDIR
#  define BASEDIR		NFS_STATEDIR
# else
#  define BASEDIR		"/var/lib/nfs"
# endif
#endif

#define DEFAULT_SM_STATE_PATH	BASEDIR "/state"
#define	DEFAULT_SM_DIR_PATH	BASEDIR "/sm"
#define	DEFAULT_SM_BAK_PATH	DEFAULT_SM_DIR_PATH ".bak"

char *_SM_BASE_PATH = BASEDIR;
char *_SM_STATE_PATH = DEFAULT_SM_STATE_PATH;
char *_SM_DIR_PATH = DEFAULT_SM_DIR_PATH;
char *_SM_BAK_PATH = DEFAULT_SM_BAK_PATH;

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
	char *			path;
	struct sockaddr_storage	addr;
	struct addrinfo		*ai;
	time_t			last_used;
	time_t			send_next;
	unsigned int		timeout;
	unsigned int		retries;
	unsigned int		xid;
};

static char		nsm_hostname[256];
static uint32_t		nsm_state;
static int		opt_debug = 0;
static int		opt_update_state = 1;
static unsigned int	opt_max_retry = 15 * 60;
static char *		opt_srcaddr = 0;
static uint16_t		opt_srcport = 0;

static unsigned int	nsm_get_state(int);
static void		notify(void);
static int		notify_host(int, struct nsm_host *);
static void		recv_reply(int);
static void		backup_hosts(const char *, const char *);
static void		get_hosts(const char *);
static void		insert_host(struct nsm_host *);
static struct nsm_host *find_host(uint32_t);
static int		record_pid(void);
static void		drop_privs(void);
static void		set_kernel_nsm_state(int state);

static struct nsm_host *	hosts = NULL;

/*
 * Address handling utilities
 */

static unsigned short smn_get_port(const struct sockaddr *sap)
{
	switch (sap->sa_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)sap)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)sap)->sin6_port);
	}
	return 0;
}

static void smn_set_port(struct sockaddr *sap, const unsigned short port)
{
	switch (sap->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)sap)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)sap)->sin6_port = htons(port);
		break;
	}
}

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

static void smn_forget_host(struct nsm_host *host)
{
	unlink(host->path);
	free(host->path);
	free(host->name);
	if (host->ai)
		freeaddrinfo(host->ai);

	free(host);
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
			opt_update_state = 0;
			break;
		case 'p':
			opt_srcport = atoi(optarg);
			break;
		case 'v':
			opt_srcaddr = optarg;
			break;
		case 'P':
			_SM_BASE_PATH = strdup(optarg);
			_SM_STATE_PATH = malloc(strlen(optarg)+1+sizeof("state"));
			_SM_DIR_PATH = malloc(strlen(optarg)+1+sizeof("sm"));
			_SM_BAK_PATH = malloc(strlen(optarg)+1+sizeof("sm.bak"));
			if (_SM_BASE_PATH == NULL ||
			    _SM_STATE_PATH == NULL ||
			    _SM_DIR_PATH == NULL ||
			    _SM_BAK_PATH == NULL) {
				fprintf(stderr, "unable to allocate memory");
				exit(1);
			}
			strcat(strcpy(_SM_STATE_PATH, _SM_BASE_PATH), "/state");
			strcat(strcpy(_SM_DIR_PATH, _SM_BASE_PATH), "/sm");
			strcat(strcpy(_SM_BAK_PATH, _SM_BASE_PATH), "/sm.bak");
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

	if (strcmp(_SM_BASE_PATH, BASEDIR) == 0) {
		if (record_pid() == 0 && force == 0 && opt_update_state == 1) {
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

	backup_hosts(_SM_DIR_PATH, _SM_BAK_PATH);
	get_hosts(_SM_BAK_PATH);

	/* If there are not hosts to notify, just exit */
	if (!hosts) {
		xlog(D_GENERAL, "No hosts to notify; exiting");
		return 0;
	}

	/* Get and update the NSM state. This will call sync() */
	nsm_state = nsm_get_state(opt_update_state);
	set_kernel_nsm_state(nsm_state);

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
		smn_set_port(local_addr, opt_srcport);
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

	drop_privs();

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

		smn_set_port((struct sockaddr *)&host->addr, 0);
		host->retries = 0;
	}

	memcpy(dest, &host->addr, destlen);
	if (smn_get_port(dest) == 0) {
		/* Build a PMAP packet */
		xlog(D_GENERAL, "Sending portmap query to %s", host->name);

		smn_set_port(dest, 111);
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

	if (smn_get_port(sap) == 0) {
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
			smn_set_port(sap, port);
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
 * Back up all hosts from the sm directory to sm.bak
 */
static void
backup_hosts(const char *dirname, const char *bakname)
{
	struct dirent	*de;
	DIR		*dir;

	if (!(dir = opendir(dirname))) {
		xlog_warn("Failed to open %s: %m", dirname);
		return;
	}

	while ((de = readdir(dir)) != NULL) {
		char	src[1024], dst[1024];

		if (de->d_name[0] == '.')
			continue;

		snprintf(src, sizeof(src), "%s/%s", dirname, de->d_name);
		snprintf(dst, sizeof(dst), "%s/%s", bakname, de->d_name);
		if (rename(src, dst) < 0)
			xlog_warn("Failed to rename %s -> %s: %m", src, dst);
	}
	closedir(dir);
}

/*
 * Get all entries from sm.bak and convert them to host entries
 */
static void
get_hosts(const char *dirname)
{
	struct nsm_host	*host;
	struct dirent	*de;
	DIR		*dir;

	if (!(dir = opendir(dirname))) {
		xlog_warn("Failed to open %s: %m", dirname);
		return;
	}

	host = NULL;
	while ((de = readdir(dir)) != NULL) {
		struct stat	stb;
		char		path[1024];

		if (de->d_name[0] == '.')
			continue;
		if (host == NULL)
			host = calloc(1, sizeof(*host));
		if (host == NULL) {
			xlog_warn("Unable to allocate memory");
			return;
		}

		snprintf(path, sizeof(path), "%s/%s", dirname, de->d_name);
		if (stat(path, &stb) < 0)
			continue;

		host->last_used = stb.st_mtime;
		host->timeout = NSM_TIMEOUT;
		host->path = strdup(path);
		host->name = strdup(de->d_name);
		host->retries = 100; /* force address retry */

		insert_host(host);
		host = NULL;
	}
	closedir(dir);

	if (host)
		free(host);
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
 * Retrieve the current NSM state
 */
static unsigned int
nsm_get_state(int update)
{
	char		newfile[PATH_MAX];
	int		fd, state;

	if ((fd = open(_SM_STATE_PATH, O_RDONLY)) < 0) {
		xlog_warn("%s: %m", _SM_STATE_PATH);
		xlog_warn("Creating %s, set initial state 1",
			_SM_STATE_PATH);
		state = 1;
		update = 1;
	} else {
		if (read(fd, &state, sizeof(state)) != sizeof(state)) {
			xlog_warn("%s: bad file size, setting state = 1",
				_SM_STATE_PATH);
			state = 1;
			update = 1;
		} else {
			if (!(state & 1))
				state += 1;
		}
		close(fd);
	}

	if (update) {
		state += 2;
		snprintf(newfile, sizeof(newfile),
				"%s.new", _SM_STATE_PATH);
		if ((fd = open(newfile, O_CREAT|O_WRONLY, 0644)) < 0) {
			xlog(L_ERROR, "Cannot create %s: %m", newfile);
			exit(1);
		}
		if (write(fd, &state, sizeof(state)) != sizeof(state)) {
			xlog(L_ERROR,
				"Failed to write state to %s", newfile);
			exit(1);
		}
		close(fd);
		if (rename(newfile, _SM_STATE_PATH) < 0) {
			xlog(L_ERROR,
				"Cannot create %s: %m", _SM_STATE_PATH);
			exit(1);
		}
		sync();
	}

	return state;
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
	int fd;

	snprintf(pid, 20, "%d\n", getpid());
	fd = open("/var/run/sm-notify.pid", O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (fd < 0)
		return 0;
	if (write(fd, pid, strlen(pid)) != strlen(pid))  {
		xlog_warn("Writing to pid file failed: errno %d (%m)",
				errno);
	}
	close(fd);
	return 1;
}

/* Drop privileges to match owner of state-directory
 * (in case a reply triggers some unknown bug).
 */
static void drop_privs(void)
{
	struct stat st;

	if (stat(_SM_DIR_PATH, &st) == -1 &&
	    stat(_SM_BASE_PATH, &st) == -1) {
		st.st_uid = 0;
		st.st_gid = 0;
	}

	if (st.st_uid == 0) {
		xlog_warn("Running as 'root'.  "
			"chown %s to choose different user", _SM_DIR_PATH);
		return;
	}

	setgroups(0, NULL);
	if (setgid(st.st_gid) == -1
	    || setuid(st.st_uid) == -1) {
		xlog(L_ERROR, "Fail to drop privileges");
		exit(1);
	}
}

static void set_kernel_nsm_state(int state)
{
	int fd;
	const char *file = "/proc/sys/fs/nfs/nsm_local_state";

	fd = open(file ,O_WRONLY);
	if (fd >= 0) {
		char buf[20];
		snprintf(buf, sizeof(buf), "%d", state);
		if (write(fd, buf, strlen(buf)) != strlen(buf)) {
			xlog_warn("Writing to '%s' failed: errno %d (%m)",
				file, errno);
		}
		close(fd);
	}
}
