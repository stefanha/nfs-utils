/*
 * showmount.c -- show mount information for an NFS server
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <fcntl.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <mount.h>
#include <unistd.h>

#define TIMEOUT_UDP	3
#define TIMEOUT_TCP	10
#define TOTAL_TIMEOUT	20

static char *	version = "showmount for " VERSION;
static char *	program_name;
static int	headers = 1;
static int	hflag = 0;
static int	aflag = 0;
static int	dflag = 0;
static int	eflag = 0;

static struct option longopts[] =
{
	{ "all", 0, 0, 'a' },
	{ "directories", 0, 0, 'd' },
	{ "exports", 0, 0, 'e' },
	{ "no-headers", 0, &headers, 0 },
	{ "version", 0, 0, 'v' },
	{ "help", 0, 0, 'h' },
	{ NULL, 0, 0, 0 }
};

#define MAXHOSTLEN 256

static int dump_cmp(const void *pv, const void *qv)
{
	const char **p = (const char **)pv;
	const char **q = (const char **)qv;
	return strcmp(*p, *q);
}

static void usage(FILE *fp, int n)
{
	fprintf(fp, "Usage: %s [-adehv]\n", program_name);
	fprintf(fp, "       [--all] [--directories] [--exports]\n");
	fprintf(fp, "       [--no-headers] [--help] [--version] [host]\n");
	exit(n);
}

/*
 *  Perform a non-blocking connect on the socket fd.
 *
 *  tout contains the timeout.  It will be modified to contain the time
 *  remaining (i.e. time provided - time elasped).
 */
static int connect_nb(int fd, struct sockaddr_in *addr, struct timeval *tout)
{
	int flags, ret;
	socklen_t len;
	fd_set rset;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		return -1;

	/*
	 * From here on subsequent sys calls could change errno so
	 * we set ret = -errno to capture it in case we decide to
	 * use it later.
	 */
	len = sizeof(struct sockaddr);
	ret = connect(fd, (struct sockaddr *)addr, len);
	if (ret < 0 && errno != EINPROGRESS) {
		ret = -errno;
		goto done;
	}

	if (ret == 0)
		goto done;

	/* now wait */
	FD_ZERO(&rset);
	FD_SET(fd, &rset);

	ret = select(fd + 1, NULL, &rset, NULL, tout);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		else
			ret = -errno;
		goto done;
	}

	if (FD_ISSET(fd, &rset)) {
		int status;

		len = sizeof(ret);
		status = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);
		if (status < 0) {
			ret = -errno;
			goto done;
		}

		/* Oops - something wrong with connect */
		if (ret)
			ret = -ret;
	}

done:
	fcntl(fd, F_SETFL, flags);
	return ret;
}

static unsigned short getport(struct sockaddr_in *addr,
			 unsigned long prog, unsigned long vers, int prot)
{
	CLIENT *client;
	enum clnt_stat status;
	struct pmap parms;
	int ret, sock;
	struct sockaddr_in laddr, saddr;
	struct timeval tout = {0, 0};
	socklen_t len;
	unsigned int send_sz = 0;
	unsigned int recv_sz = 0;
	unsigned short port;

	memset(&laddr, 0, sizeof(laddr));
	memset(&saddr, 0, sizeof(saddr));
	memset(&parms, 0, sizeof(parms));

	memcpy(&saddr, addr, sizeof(saddr));
	saddr.sin_port = htons(PMAPPORT);

	if (prot == IPPROTO_TCP) {
		sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			return 0;
		}

		tout.tv_sec = TIMEOUT_TCP;

		ret = connect_nb(sock, &saddr, &tout);
		if (ret == -1) {
			close(sock);
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			return 0;
		}
		client = clnttcp_create(&saddr,
					PMAPPROG, PMAPVERS, &sock,
					0, 0);
	} else {
		/*
		 * bind to any unused port.  If we left this up to the rpc
		 * layer, it would bind to a reserved port, which has been shown
		 * to exhaust the reserved port range in some situations.
		 */
		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == -1) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			return 0;
		}

		laddr.sin_family = AF_INET;
		laddr.sin_port = 0;
		laddr.sin_addr.s_addr = htonl(INADDR_ANY);

		tout.tv_sec = TIMEOUT_UDP;

		send_sz = RPCSMALLMSGSIZE;
		recv_sz = RPCSMALLMSGSIZE;

		len = sizeof(struct sockaddr_in);
		if (bind(sock, (struct sockaddr *)&laddr, len) < 0) {
			close(sock);
			sock = RPC_ANYSOCK;
			/* FALLTHROUGH */
		}
		client = clntudp_bufcreate(&saddr, PMAPPROG, PMAPVERS,
					   tout, &sock, send_sz, recv_sz);
	}

	if (!client) {
		close(sock);
		rpc_createerr.cf_stat = RPC_RPCBFAILURE;
		return 0;
	}

	clnt_control(client, CLSET_FD_CLOSE, NULL);

	parms.pm_prog = prog;
	parms.pm_vers = vers;
	parms.pm_prot = prot;

	status = clnt_call(client, PMAPPROC_GETPORT,
			   (xdrproc_t) xdr_pmap, (caddr_t) &parms,
			   (xdrproc_t) xdr_u_short, (caddr_t) &port,
			   tout);

	if (status != RPC_SUCCESS) {
		clnt_geterr(client, &rpc_createerr.cf_error);
		rpc_createerr.cf_stat = status;
		clnt_destroy(client);
		return 0;
	} else if (port == 0) {
		rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}

	clnt_destroy(client);

	return htons(port);
}

int main(int argc, char **argv)
{
	char hostname_buf[MAXHOSTLEN];
	char *hostname;
	enum clnt_stat clnt_stat;
	struct hostent *hp;
	struct sockaddr_in server_addr;
	int ret, msock;
	struct timeval total_timeout;
	struct timeval pertry_timeout;
	int c;
	CLIENT *mclient;
	groups grouplist;
	exports exportlist, exl;
	mountlist dumplist;
	mountlist list;
	int i;
	int n;
	int maxlen;
	char **dumpv;

	program_name = argv[0];
	while ((c = getopt_long(argc, argv, "adehv", longopts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			aflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'e':
			eflag = 1;
			break;
		case 'h':
			usage(stdout, 0);
			break;
		case 'v':
			printf("%s\n", version);
			exit(0);
		case 0:
			break;
		case '?':
		default:
			usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	switch (aflag + dflag + eflag) {
	case 0:
		hflag = 1;
		break;
	case 1:
		break;
	default:
		fprintf(stderr, "%s: only one of -a, -d or -e is allowed\n",
			program_name);
		exit(1);
		break;
	}

	switch (argc) {
	case 0:
		if (gethostname(hostname_buf, MAXHOSTLEN) < 0) {
			perror("getting hostname");
			exit(1);
		}
		hostname = hostname_buf;
		break;
	case 1:
		hostname = argv[0];
		break;
	default:
		fprintf(stderr, "%s: only one hostname is allowed\n",
			program_name);
		exit(1);
		break;
	}

	if (inet_aton(hostname, &server_addr.sin_addr)) {
		server_addr.sin_family = AF_INET;
	}
	else {
		if ((hp = gethostbyname(hostname)) == NULL) {
			fprintf(stderr, "%s: can't get address for %s\n",
				program_name, hostname);
			exit(1);
		}
		server_addr.sin_family = AF_INET;
		memcpy(&server_addr.sin_addr, hp->h_addr, hp->h_length);
	}

	/* create mount deamon client */

	mclient = NULL;
	msock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (msock != -1) {
		server_addr.sin_port = getport(&server_addr,
					 MOUNTPROG, MOUNTVERS, IPPROTO_TCP);
		if (server_addr.sin_port) {
			ret = connect_nb(msock, &server_addr, 0);
			if (ret != -1)
				mclient = clnttcp_create(&server_addr,
						MOUNTPROG, MOUNTVERS, &msock,
						0, 0);
			else
				close(msock);
		} else
			close(msock);
	}

	if (!mclient) {
		server_addr.sin_port = getport(&server_addr,
					 MOUNTPROG, MOUNTVERS, IPPROTO_UDP);
		if (!server_addr.sin_port) {
			clnt_pcreateerror("showmount");
			exit(1);
		}
		msock = RPC_ANYSOCK;
		pertry_timeout.tv_sec = TIMEOUT_UDP;
		pertry_timeout.tv_usec = 0;
		if ((mclient = clntudp_create(&server_addr,
		    MOUNTPROG, MOUNTVERS, pertry_timeout, &msock)) == NULL) {
			clnt_pcreateerror("mount clntudp_create");
			exit(1);
		}
	}
	mclient->cl_auth = authunix_create_default();
	total_timeout.tv_sec = TOTAL_TIMEOUT;
	total_timeout.tv_usec = 0;

	if (eflag) {
		memset(&exportlist, '\0', sizeof(exportlist));

		clnt_stat = clnt_call(mclient, MOUNTPROC_EXPORT,
			(xdrproc_t) xdr_void, NULL,
			(xdrproc_t) xdr_exports, (caddr_t) &exportlist,
			total_timeout);
		if (clnt_stat != RPC_SUCCESS) {
			clnt_perror(mclient, "rpc mount export");
			exit(1);
		}
		if (headers)
			printf("Export list for %s:\n", hostname);
		maxlen = 0;
		for (exl = exportlist; exl; exl = exl->ex_next) {
			if ((n = strlen(exl->ex_dir)) > maxlen)
				maxlen = n;
		}
		while (exportlist) {
			printf("%-*s ", maxlen, exportlist->ex_dir);
			grouplist = exportlist->ex_groups;
			if (grouplist)
				while (grouplist) {
					printf("%s%s", grouplist->gr_name,
						grouplist->gr_next ? "," : "");
					grouplist = grouplist->gr_next;
				}
			else
				printf("(everyone)");
			printf("\n");
			exportlist = exportlist->ex_next;
		}
		exit(0);
	}

	memset(&dumplist, '\0', sizeof(dumplist));
	clnt_stat = clnt_call(mclient, MOUNTPROC_DUMP,
		(xdrproc_t) xdr_void, NULL,
		(xdrproc_t) xdr_mountlist, (caddr_t) &dumplist,
		total_timeout);
	if (clnt_stat != RPC_SUCCESS) {
		clnt_perror(mclient, "rpc mount dump");
		exit(1);
	}

	n = 0;
	for (list = dumplist; list; list = list->ml_next)
		n++;
	dumpv = (char **) calloc(n, sizeof (char *));
	if (n && !dumpv) {
		fprintf(stderr, "%s: out of memory\n", program_name);
		exit(1);
	}
	i = 0;

	if (hflag) {
		if (headers)
			printf("Hosts on %s:\n", hostname);
		while (dumplist) {
			dumpv[i++] = dumplist->ml_hostname;
			dumplist = dumplist->ml_next;
		}
	}
	else if (aflag) {
		if (headers)
			printf("All mount points on %s:\n", hostname);
		while (dumplist) {
			char *t;

			t=malloc(strlen(dumplist->ml_hostname)+strlen(dumplist->ml_directory)+2);
			if (!t)
			{
				fprintf(stderr, "%s: out of memory\n", program_name);
				exit(1);
			}
			sprintf(t, "%s:%s", dumplist->ml_hostname, dumplist->ml_directory);
			dumpv[i++] = t;
			dumplist = dumplist->ml_next;
		}
	}
	else if (dflag) {
		if (headers)
			printf("Directories on %s:\n", hostname);
		while (dumplist) {
			dumpv[i++] = dumplist->ml_directory;
			dumplist = dumplist->ml_next;
		}
	}

	qsort(dumpv, n, sizeof (char *), dump_cmp);
	
	for (i = 0; i < n; i++) {
		if (i == 0 || strcmp(dumpv[i], dumpv[i - 1]) != 0)
			printf("%s\n", dumpv[i]);
	}
	exit(0);
}

