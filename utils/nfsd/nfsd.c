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
#include <getopt.h>
#include "nfslib.h"

static void	usage(const char *);

int
main(int argc, char **argv)
{
	int	count = 1, c, error, port;

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

	if (optind < argc) {
		if ((count = atoi(argv[optind])) < 0) {
			/* insane # of servers */
			fprintf(stderr,
				"%s: invalid server count (%d), using 1\n",
				argv[0], count);
			count = 1;
		}
	}

	if ((error = nfssvc(port, count)) < 0)
		perror("nfssvc");

	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "usage:\n"
			"%s nrservs\n", prog);
	exit(2);
}
