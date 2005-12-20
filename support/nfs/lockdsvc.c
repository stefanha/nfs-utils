/*
 * support/nfs/nfssvc.c
 *
 * Run an NFS daemon.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <nfslib.h>

int
lockdsvc()
{
	struct nfsctl_arg	arg;

	arg.ca_version = NFSCTL_VERSION;
	return nfsctl(LOCKDCTL_SVC, &arg, NULL);
}
