/*
 * utils/mountd/mountd.c
 *
 * Authenticate mount requests and retrieve file handle.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include "xmalloc.h"
#include "misc.h"
#include "mountd.h"
#include "rpcmisc.h"

static void		usage(const char *, int exitcode);
static exports		get_exportlist(void);
static struct nfs_fh_len *get_rootfh(struct svc_req *, dirpath *, int *, int v3);

static struct option longopts[] =
{
	{ "foreground", 0, 0, 'F' },
	{ "debug", 1, 0, 'd' },
	{ "help", 0, 0, 'h' },
	{ "exports-file", 1, 0, 'f' },
	{ "nfs-version", 1, 0, 'V' },
	{ "no-nfs-version", 1, 0, 'N' },
	{ "version", 0, 0, 'v' },
	{ "port", 1, 0, 'p' },
	{ NULL, 0, 0, 0 }
};

static int nfs_version = -1;

/*
 * Signal handler.
 */
static void 
killer (int sig)
{
  if (nfs_version & 0x1)
    pmap_unset (MOUNTPROG, MOUNTVERS);
  if (nfs_version & (0x1 << 1))
    pmap_unset (MOUNTPROG, MOUNTVERS_POSIX);
  if (nfs_version & (0x1 << 2))
    pmap_unset (MOUNTPROG, MOUNTVERS_NFSV3);
  xlog (L_FATAL, "Caught signal %d, un-registering and exiting.", sig);
}

bool_t
mount_null_1_svc(struct svc_req *rqstp, void *argp, void *resp)
{
	return 1;
}

bool_t
mount_mnt_1_svc(struct svc_req *rqstp, dirpath *path, fhstatus *res)
{
	struct nfs_fh_len *fh;

	xlog(D_CALL, "MNT1(%s) called", *path);
	if ((fh = get_rootfh(rqstp, path, &res->fhs_status, 0)) != NULL)
		memcpy(&res->fhstatus_u.fhs_fhandle, fh->fh_handle, 32);
	return 1;
}

bool_t
mount_dump_1_svc(struct svc_req *rqstp, void *argp, mountlist *res)
{
	struct sockaddr_in *addr =
		(struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	xlog(L_NOTICE, "dump request from %s",
		inet_ntoa(addr->sin_addr));

	*res = mountlist_list();
	return 1;
}

bool_t
mount_umnt_1_svc(struct svc_req *rqstp, dirpath *argp, void *resp)
{
	struct sockaddr_in *sin
		= (struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	nfs_export	*exp;
	char		*p = *argp;
	char		rpath[MAXPATHLEN+1];

	if (*p == '\0')
		p = "/";

	if (realpath(p, rpath) != NULL) {
		rpath[sizeof (rpath) - 1] = '\0';
		p = rpath;
	}

	if (!(exp = auth_authenticate("unmount", sin, p))) {
		return 1;
	}
	mountlist_del(exp, p);
	export_reset (exp);
	return 1;
}

bool_t
mount_umntall_1_svc(struct svc_req *rqstp, void *argp, void *resp)
{
	/* Reload /etc/xtab if necessary */
	auth_reload();

	mountlist_del_all((struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt));
	return 1;
}

bool_t
mount_export_1_svc(struct svc_req *rqstp, void *argp, exports *resp)
{
	struct sockaddr_in *addr =
		(struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	xlog(L_NOTICE, "export request from %s",
		inet_ntoa(addr->sin_addr));
	*resp = get_exportlist();
	return 1;
}

bool_t
mount_exportall_1_svc(struct svc_req *rqstp, void *argp, exports *resp)
{
	struct sockaddr_in *addr =
		(struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	xlog(L_NOTICE, "exportall request from %s",
		inet_ntoa(addr->sin_addr));
	*resp = get_exportlist();
	return 1;
}

/*
 * MNTv2 pathconf procedure
 *
 * The protocol doesn't include a status field, so Sun apparently considers
 * it good practice to let anyone snoop on your system, even if it's
 * pretty harmless data such as pathconf. We don't.
 *
 * Besides, many of the pathconf values don't make much sense on NFS volumes.
 * FIFOs and tty device files represent devices on the *client*, so there's
 * no point in getting the server's buffer sizes etc.
 */
bool_t
mount_pathconf_2_svc(struct svc_req *rqstp, dirpath *path, ppathcnf *res)
{
	struct sockaddr_in *sin
		= (struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	struct stat	stb;
	nfs_export	*exp;
	char		rpath[MAXPATHLEN+1];
	char		*p = *path;

	memset(res, 0, sizeof(*res));

	if (*p == '\0')
		p = "/";

	/* Reload /etc/xtab if necessary */
	auth_reload();

	/* Resolve symlinks */
	if (realpath(p, rpath) != NULL) {
		rpath[sizeof (rpath) - 1] = '\0';
		p = rpath;
	}

	/* Now authenticate the intruder... */
	if (!(exp = auth_authenticate("mount", sin, p))) {
		return 1;
	} else if (stat(p, &stb) < 0) {
		xlog(L_WARNING, "can't stat exported dir %s: %s",
				p, strerror(errno));
		export_reset (exp);
		return 1;
	}

	res->pc_link_max  = pathconf(p, _PC_LINK_MAX);
	res->pc_max_canon = pathconf(p, _PC_MAX_CANON);
	res->pc_max_input = pathconf(p, _PC_MAX_INPUT);
	res->pc_name_max  = pathconf(p, _PC_NAME_MAX);
	res->pc_path_max  = pathconf(p, _PC_PATH_MAX);
	res->pc_pipe_buf  = pathconf(p, _PC_PIPE_BUF);
	res->pc_vdisable  = pathconf(p, _PC_VDISABLE);

	/* Can't figure out what to do with pc_mask */
	res->pc_mask[0]   = 0;
	res->pc_mask[1]   = 0;

	export_reset (exp);

	return 1;
}

/*
 * NFSv3 MOUNT procedure
 */
bool_t
mount_mnt_3_svc(struct svc_req *rqstp, dirpath *path, mountres3 *res)
{
	static int	flavors[] = { AUTH_NULL, AUTH_UNIX };
	struct nfs_fh_len *fh;

	xlog(D_CALL, "MNT3(%s) called", *path);
	if ((fh = get_rootfh(rqstp, path, (int *) &res->fhs_status, 1)) != NULL) {
		struct mountres3_ok	*ok = &res->mountres3_u.mountinfo;

		ok->fhandle.fhandle3_len = fh->fh_size;
		ok->fhandle.fhandle3_val = fh->fh_handle;
		ok->auth_flavors.auth_flavors_len = 2;
		ok->auth_flavors.auth_flavors_val = flavors;
	}
	return 1;
}

static struct nfs_fh_len *
get_rootfh(struct svc_req *rqstp, dirpath *path, int *error, int v3)
{
	struct sockaddr_in *sin =
		(struct sockaddr_in *) svc_getcaller(rqstp->rq_xprt);
	struct stat	stb;
	nfs_export	*exp;
	char		rpath[MAXPATHLEN+1];
	char		*p = *path;

	if (*p == '\0')
		p = "/";

	/* Reload /var/lib/nfs/etab if necessary */
	auth_reload();

	/* Resolve symlinks */
	if (realpath(p, rpath) != NULL) {
		rpath[sizeof (rpath) - 1] = '\0';
		p = rpath;
	}

	/* Now authenticate the intruder... */
	if (!(exp = auth_authenticate("mount", sin, p))) {
		*error = NFSERR_ACCES;
	} else if (stat(p, &stb) < 0) {
		xlog(L_WARNING, "can't stat exported dir %s: %s",
				p, strerror(errno));
		if (errno == ENOENT)
			*error = NFSERR_NOENT;
		else
			*error = NFSERR_ACCES;
	} else if (!S_ISDIR(stb.st_mode) && !S_ISREG(stb.st_mode)) {
		xlog(L_WARNING, "%s is not a directory or regular file", p);
		*error = NFSERR_NOTDIR;
	} else {
		struct nfs_fh_len  *fh;

		if (!exp->m_exported)
			export_export(exp);
		if (!exp->m_xtabent)
			xtab_append(exp);

		if (v3)
			fh = getfh_size ((struct sockaddr *) sin, p, 64);
		if (!v3 || (fh == NULL && errno == EINVAL)) {
			/* We first try the new nfs syscall. */
			fh = getfh ((struct sockaddr *) sin, p);
			if (fh == NULL && errno == EINVAL)
				/* Let's try the old one. */
				fh = getfh_old ((struct sockaddr *) sin,
						stb.st_dev, stb.st_ino);
		}
		if (fh != NULL) {
			mountlist_add(exp, p);
			*error = NFS_OK;
			export_reset (exp);
			return fh;
		}
		xlog(L_WARNING, "getfh failed: %s", strerror(errno));
		*error = NFSERR_ACCES;
	}
	export_reset (exp);
	return NULL;
}

static exports
get_exportlist(void)
{
	static exports		elist = NULL;
	struct exportnode	*e, *ne;
	struct groupnode	*g, *ng, *c, **cp;
	nfs_export		*exp;
	int			i;

	if (!auth_reload() && elist)
		return elist;

	for (e = elist; e != NULL; e = ne) {
		ne = e->ex_next;
		for (g = e->ex_groups; g != NULL; g = ng) {
			ng = g->gr_next;
			xfree(g->gr_name);
			xfree(g);
		}
		xfree(e->ex_dir);
		xfree(e);
	}
	elist = NULL;

	for (i = 0; i < MCL_MAXTYPES; i++) {
		for (exp = exportlist[i]; exp; exp = exp->m_next) {
			for (e = elist; e != NULL; e = e->ex_next) {
				if (!strcmp(exp->m_export.m_path, e->ex_dir))
					break;
			}
			if (!e) {
				e = (struct exportnode *) xmalloc(sizeof(*e));
				e->ex_next = elist;
				e->ex_groups = NULL;
				e->ex_dir = xstrdup(exp->m_export.m_path);
				elist = e;
			}

			/* We need to check if we should remove
			   previous ones. */
			if (i == MCL_ANONYMOUS && e->ex_groups) {
				for (g = e->ex_groups; g; g = ng) {
					ng = g->gr_next;
					xfree(g->gr_name);
					xfree(g);
				}
				e->ex_groups = NULL;
				continue;
			}

			if (i != MCL_FQDN && e->ex_groups) {
			  struct hostent 	*hp;

			  cp = &e->ex_groups;
			  while ((c = *cp) != NULL) {
			    if (client_gettype (c->gr_name) == MCL_FQDN
			        && (hp = gethostbyname(c->gr_name))) {
			      hp = hostent_dup (hp);
			      if (client_check(exp->m_client, hp)) {
				*cp = c->gr_next;
				xfree(c->gr_name);
				xfree(c);
				xfree (hp);
				if ((c = *cp) == NULL)
				  break;
			      }
			      else
				xfree (hp);
			    }
			    cp = &(c->gr_next);
			  }
			}

			if (exp->m_export.e_hostname [0] != '\0') {
				for (g = e->ex_groups; g; g = g->gr_next)
					if (strcmp (exp->m_export.e_hostname,
						    g->gr_name) == 0)
						break;
				if (g)
					continue;
				g = (struct groupnode *) xmalloc(sizeof(*g));
				g->gr_name = xstrdup(exp->m_export.e_hostname);
				g->gr_next = e->ex_groups;
				e->ex_groups = g;
			}
		}
	}

	return elist;
}

int
main(int argc, char **argv)
{
	char	*export_file = _PATH_EXPORTS;
	int	foreground = 0;
	int	port = 0;
	int	c;
	struct sigaction sa;

	/* Parse the command line options and arguments. */
	opterr = 0;
	while ((c = getopt_long(argc, argv, "Fd:f:p:P:hN:V:v", longopts, NULL)) != EOF)
		switch (c) {
		case 'F':
			foreground = 1;
			break;
		case 'd':
			xlog_sconfig(optarg, 1);
			break;
		case 'f':
			export_file = optarg;
			break;
		case 'h':
			usage(argv [0], 0);
			break;
		case 'P':	/* XXX for nfs-server compatibility */
		case 'p':
			port = atoi(optarg);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "%s: bad port number: %s\n",
					argv [0], optarg);
				usage(argv [0], 1);
			}
			break;
		case 'N':
			nfs_version &= ~(1 << (atoi (optarg) - 1));
			break;
		case 'V':
			nfs_version |= 1 << (atoi (optarg) - 1);
			break;
		case 'v':
			printf("kmountd %s\n", VERSION);
			exit(0);
		case 0:
			break;
		case '?':
		default:
			usage(argv [0], 1);
		}

	/* No more arguments allowed. */
	if (optind != argc || !(nfs_version & 0x7))
		usage(argv [0], 1);

	/* Initialize logging. */
/*	xlog_open("mountd"); */

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (nfs_version & 0x1)
		rpc_init("mountd", MOUNTPROG, MOUNTVERS,
			 mount_dispatch, port, 0);
	if (nfs_version & (0x1 << 1))
		rpc_init("mountd", MOUNTPROG, MOUNTVERS_POSIX,
			 mount_dispatch, port, 0);
	if (nfs_version & (0x1 << 2))
		rpc_init("mountd", MOUNTPROG, MOUNTVERS_NFSV3,
			 mount_dispatch, port, 0);

	sa.sa_handler = killer;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	auth_init(export_file);

	if (!foreground) {
		/* We first fork off a child. */
		if ((c = fork()) > 0)
			exit(0);
		if (c < 0) {
			xlog(L_FATAL, "mountd: cannot fork: %s\n",
						strerror(errno));
		}
		/* Now we remove ourselves from the foreground.
		   Redirect stdin/stdout/stderr first. */
		{
			int fd = open("/dev/null", O_RDWR);
			(void) dup2(fd, 0);
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			if (fd > 2) (void) close(fd);
		}
		setsid();
		xlog_background();
	}

	svc_run();

	xlog(L_ERROR, "Ack! Gack! svc_run returned!\n");
	exit(1);
}

static void
usage(const char *prog, int n)
{
	fprintf(stderr,
"Usage: %s [-Fhnv] [-d kind] [-f exports-file] [-V version]\n"
"	[-N version] [--debug kind] [-p|--port port] [--help] [--version]\n"
"	[--exports-file=file] [--nfs-version version]\n"
"	[--no-nfs-version version]\n", prog);
	exit(n);
}
