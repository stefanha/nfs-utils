/*
 * nfsd
 *
 * This is the user level part of nfsd. This is very primitive, because
 * all the work is now done in the kernel module.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <syslog.h>
#include "nfslib.h"

static void	usage(const char *);

int
main(int argc, char **argv)
{
	int	count = 1, c, error, port, fd;

	port = 2049;

	/* FIXME: Check for nfs in /etc/services */

	while ((c = getopt(argc, argv, "hp:P:")) != EOF) {
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
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
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
	fd = sysconf(_SC_OPEN_MAX);
	while (--fd > 2)
		(void) close(fd);

	if ((error = nfssvc(port, count)) < 0) {
		int e = errno;
		openlog("nfsd", LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "nfssvc: %s", strerror(e));
		closelog();
	}

	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "usage:\n"
			"%s nrservs\n", prog);
	exit(2);
}
