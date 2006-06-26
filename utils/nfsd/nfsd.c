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
#include <syslog.h>
#include <netdb.h>
#include "nfslib.h"

static void	usage(const char *);

static struct option longopts[] =
{
	{ "help", 0, 0, 'h' },
	{ "no-nfs-version", 1, 0, 'N' },
	{ NULL, 0, 0, 0 }
};
unsigned int versbits = NFSCTL_ALLBITS;

int
main(int argc, char **argv)
{
	int	count = 1, c, error, port, fd, found_one;
	struct servent *ent;

	ent = getservbyname ("nfs", "udp");
	if (ent != NULL)
		port = ntohs (ent->s_port);
	else
		port = 2049;

	while ((c = getopt_long(argc, argv, "hN:p:P:", longopts, NULL)) != EOF) {
		switch(c) {
		case 'P':	/* XXX for nfs-server compatibility */
		case 'p':
			port = atoi(optarg);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "%s: bad port number: %s\n",
					argv[0], optarg);
				usage(argv [0]);
			}
			break;
		case 'N':
			switch((c = atoi(optarg))) {
			case 2:
			case 3:
			case 4:
				NFSCTL_VERUNSET(versbits, c);
				break;
			default:
				fprintf(stderr, "%c: Unsupported version\n", c);
				exit(1);
			}
			break;
		default:
			fprintf(stderr, "Invalid argument: '%c'\n", c);
		case 'h':
			usage(argv[0]);
		}
	}
	/*
	 * Do some sanity checking, if the ctlbits are set
	 */
	found_one = 0;
	for (c = NFSD_MINVERS; c <= NFSD_MAXVERS; c++) {
		if (NFSCTL_VERISSET(versbits, c))
			found_one = 1;
	}
	if (!found_one) {
		fprintf(stderr, "no version specified\n");
		exit(1);
	}			

	if (chdir(NFS_STATEDIR)) {
		fprintf(stderr, "%s: chdir(%s) failed: %s\n",
			argv [0], NFS_STATEDIR, strerror(errno));
		exit(1);
	}

	if (optind < argc) {
		if ((count = atoi(argv[optind])) < 0) {
			/* insane # of servers */
			fprintf(stderr,
				"%s: invalid server count (%d), using 1\n",
				argv[0], count);
			count = 1;
		}
	}
	/* KLUDGE ALERT:
	   Some kernels let nfsd kernel threads inherit open files
	   from the program that spawns them (i.e. us).  So close
	   everything before spawning kernel threads.  --Chip */
	fd = open("/dev/null", O_RDWR);
	if (fd == -1)
		perror("/dev/null");
	else {
		(void) dup2(fd, 0);
		(void) dup2(fd, 1);
		(void) dup2(fd, 2);
	}
	closeall(3);

	openlog("nfsd", LOG_PID, LOG_DAEMON);
	if ((error = nfssvc(port, count, versbits)) < 0) {
		int e = errno;
		syslog(LOG_ERR, "nfssvc: %s", strerror(e));
		closelog();
	}

	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "Usage:\n"
		"%s [-p|-P|--port port] [-N|--no-nfs-version version ] nrservs\n", 
		prog);
	exit(2);
}
