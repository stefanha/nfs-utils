/*
 * lockd
 *
 * This is the user level part of lockd. This is very primitive, because
 * all the work is now done in the kernel module.
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "nfslib.h"

static void	usage(const char *);

int
main(int argc, char **argv)
{
	int error;

	if (argc > 1)
		usage (argv [0]);

	if (chdir(NFS_STATEDIR)) {
		fprintf(stderr, "%s: chdir(%s) failed: %s\n",
			argv [0], NFS_STATEDIR, strerror(errno));
		exit(1);
	}

	if ((error = lockdsvc()) < 0) {
		if (errno == EINVAL)
			/* Ignore EINVAL since kernel may start
			   lockd automatically. */
			error = 0;
		else
			perror("lockdsvc");
	}

	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "usage:\n%s\n", prog);
	exit(2);
}
