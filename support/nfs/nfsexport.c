/*
 * support/nfs/export.c
 *
 * Add or delete an NFS export in knfsd.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <string.h>
#include "nfslib.h"

int
nfsexport(struct nfsctl_export *exp)
{
	struct nfsctl_arg	arg;

	arg.ca_version = NFSCTL_VERSION;
	memcpy(&arg.ca_export, exp, sizeof(arg.ca_export));
	return nfsctl(NFSCTL_EXPORT, &arg, NULL);
}

int
nfsunexport(struct nfsctl_export *exp)
{
	struct nfsctl_arg	arg;

	arg.ca_version = NFSCTL_VERSION;
	memcpy(&arg.ca_export, exp, sizeof(arg.ca_export));
	return nfsctl(NFSCTL_UNEXPORT, &arg, NULL);
}
