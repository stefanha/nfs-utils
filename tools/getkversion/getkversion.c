/*
 * Get version number of the kernel this was compiled for.
 * This is NOT the same as calling uname(), because we may be
 * running on a different kernel.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/version.h>
#include <stdio.h>

int
main(void)	/* This is for Dan Popp ;) */
{
	printf("%s\n", UTS_RELEASE);
	return 0;
}
