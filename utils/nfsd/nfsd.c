/*
 * nfsd
 *
 * This is the user level part of nfsd. This is very primitive, because
 * all the work is now done in the kernel module.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nfslib.h"
#include "nfssvc.h"
#include "xlog.h"

static void	usage(const char *);

static struct option longopts[] =
{
	{ "host", 1, 0, 'H' },
	{ "help", 0, 0, 'h' },
	{ "no-nfs-version", 1, 0, 'N' },
	{ "no-tcp", 0, 0, 'T' },
	{ "no-udp", 0, 0, 'U' },
	{ "port", 1, 0, 'P' },
	{ "port", 1, 0, 'p' },
	{ "debug", 0, 0, 'd' },
	{ "syslog", 0, 0, 's' },
	{ NULL, 0, 0, 0 }
};
unsigned int protobits = NFSCTL_ALLBITS;
unsigned int versbits = NFSCTL_ALLBITS;
int minorvers4 = NFSD_MAXMINORVERS4;		/* nfsv4 minor version */

int
main(int argc, char **argv)
{
	int	count = 1, c, error, portnum = 0, fd, found_one;
	char *p, *progname, *port;
	char *haddr = NULL;
	int	socket_up = 0;

	progname = strdup(basename(argv[0]));
	if (!progname) {
		fprintf(stderr, "%s: unable to allocate memory.\n", argv[0]);
		exit(1);
	}

	port = strdup("nfs");
	if (!port) {
		fprintf(stderr, "%s: unable to allocate memory.\n", progname);
		exit(1);
	}

	xlog_syslog(0);
	xlog_stderr(1);

	while ((c = getopt_long(argc, argv, "dH:hN:p:P:sTU", longopts, NULL)) != EOF) {
		switch(c) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'H':
			/*
			 * for now, this only handles one -H option. Use the
			 * last one specified.
			 */
			free(haddr);
			haddr = strdup(optarg);
			if (!haddr) {
				fprintf(stderr, "%s: unable to allocate "
					"memory.\n", progname);
				exit(1);
			}
			break;
		case 'P':	/* XXX for nfs-server compatibility */
		case 'p':
			/* only the last -p option has any effect */
			portnum = atoi(optarg);
			if (portnum <= 0 || portnum > 65535) {
				fprintf(stderr, "%s: bad port number: %s\n",
					progname, optarg);
				usage(progname);
			}
			free(port);
			port = strdup(optarg);
			if (!port) {
				fprintf(stderr, "%s: unable to allocate "
						"memory.\n", progname);
				exit(1);
			}
			break;
		case 'N':
			switch((c = strtol(optarg, &p, 0))) {
			case 4:
				if (*p == '.') {
					minorvers4 = -atoi(p + 1);
					break;
				}
			case 3:
			case 2:
				NFSCTL_VERUNSET(versbits, c);
				break;
			default:
				fprintf(stderr, "%s: Unsupported version\n", optarg);
				exit(1);
			}
			break;
		case 's':
			xlog_syslog(1);
			xlog_stderr(0);
			break;
		case 'T':
			NFSCTL_TCPUNSET(protobits);
			break;
		case 'U':
			NFSCTL_UDPUNSET(protobits);
			break;
		default:
			fprintf(stderr, "Invalid argument: '%c'\n", c);
		case 'h':
			usage(progname);
		}
	}

	xlog_open(progname);

	/*
	 * Do some sanity checking, if the ctlbits are set
	 */
	if (!NFSCTL_UDPISSET(protobits) && !NFSCTL_TCPISSET(protobits)) {
		xlog(L_ERROR, "invalid protocol specified");
		exit(1);
	}
	found_one = 0;
	for (c = NFSD_MINVERS; c <= NFSD_MAXVERS; c++) {
		if (NFSCTL_VERISSET(versbits, c))
			found_one = 1;
	}
	if (!found_one) {
		xlog(L_ERROR, "no version specified");
		exit(1);
	}			

	if (NFSCTL_VERISSET(versbits, 4) && !NFSCTL_TCPISSET(protobits)) {
		xlog(L_ERROR, "version 4 requires the TCP protocol");
		exit(1);
	}
	if (haddr == NULL) {
		struct in_addr in = {INADDR_ANY}; 
		haddr = strdup(inet_ntoa(in));
	}

	if (chdir(NFS_STATEDIR)) {
		xlog(L_ERROR, "chdir(%s) failed: %m", NFS_STATEDIR);
		exit(1);
	}

	if (optind < argc) {
		if ((count = atoi(argv[optind])) < 0) {
			/* insane # of servers */
			xlog(L_ERROR, "invalid server count (%d), using 1",
				      count);
			count = 1;
		}
	}

	/* can only change number of threads if nfsd is already up */
	if (nfssvc_inuse()) {
		socket_up = 1;
		goto set_threads;
	}

	/*
	 * must set versions before the fd's so that the right versions get
	 * registered with rpcbind. Note that on older kernels w/o the right
	 * interfaces, these are a no-op.
	 */
	nfssvc_setvers(versbits, minorvers4);

	error = nfssvc_set_sockets(AF_INET, protobits, haddr, port);
	if (!error)
		socket_up = 1;

set_threads:
	/* don't start any threads if unable to hand off any sockets */
	if (!socket_up) {
		xlog(L_ERROR, "unable to set any sockets for nfsd");
		goto out;
	}
	error = 0;

	/*
	 * KLUDGE ALERT:
	 * Some kernels let nfsd kernel threads inherit open files
	 * from the program that spawns them (i.e. us).  So close
	 * everything before spawning kernel threads.  --Chip
	 */
	fd = open("/dev/null", O_RDWR);
	if (fd == -1)
		xlog(L_ERROR, "Unable to open /dev/null: %m");
	else {
		/* switch xlog output to syslog since stderr is being closed */
		xlog_syslog(1);
		xlog_stderr(0);
		(void) dup2(fd, 0);
		(void) dup2(fd, 1);
		(void) dup2(fd, 2);
	}
	closeall(3);

	if ((error = nfssvc_threads(portnum, count)) < 0)
		xlog(L_ERROR, "error starting threads: errno %d (%m)", errno);
out:
	free(port);
	free(haddr);
	free(progname);
	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "Usage:\n"
		"%s [-d|--debug] [-H hostname] [-p|-P|--port port] [-N|--no-nfs-version version ] [-s|--syslog] [-T|--no-tcp] [-U|--no-udp] nrservs\n", 
		prog);
	exit(2);
}
