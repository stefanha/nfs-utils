/*
 * lockd
 *
 * This is the user level part of lockd. This is very primitive, because
 * all the work is now done in the kernel module.
 *
 */

#include "config.h"

#include <stdio.h>
#include "nfslib.h"

static void	usage(const char *);

int
main(int argc, char **argv)
{
	int error;

	if (argc > 1)
		usage (argv [0]);

	if ((error = lockdsvc()) < 0)
		perror("lockdsvc");

	return (error != 0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "usage:\n%s\n", prog);
	exit(2);
}
