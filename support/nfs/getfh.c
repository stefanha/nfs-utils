/*
 * support/nfs/getfh.c
 *
 * Get the FH for a given client and directory. This function takes
 * the NFS protocol version number as an additional argument.
 *
 * This function has nothing in common with the SunOS getfh function,
 * which is a front-end to the RPC mount call.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "nfslib.h"

struct knfs_fh *
getfh_old (struct sockaddr *addr, dev_t dev, ino_t ino)
{
	static union nfsctl_res	res;
	struct nfsctl_arg	arg;

	arg.ca_version = NFSCTL_VERSION;
	arg.ca_getfh.gf_version = 2;	/* obsolete */
	arg.ca_getfh.gf_dev = dev;
	arg.ca_getfh.gf_ino = ino;
	memcpy(&arg.ca_getfh.gf_addr, addr, sizeof(struct sockaddr_in));

	if (nfsctl(NFSCTL_GETFH, &arg, &res) < 0)
		return NULL;

	return &res.cr_getfh;
}

struct knfs_fh *
getfh(struct sockaddr *addr, const char *path)
{
        static union nfsctl_res res;
        struct nfsctl_arg       arg;

        arg.ca_version = NFSCTL_VERSION;
        arg.ca_getfd.gd_version = 2;    /* obsolete */
        strncpy(arg.ca_getfd.gd_path, path,
		sizeof(arg.ca_getfd.gd_path) - 1);
	arg.ca_getfd.gd_path[sizeof (arg.ca_getfd.gd_path) - 1] = '\0';
        memcpy(&arg.ca_getfd.gd_addr, addr, sizeof(struct sockaddr_in));

        if (nfsctl(NFSCTL_GETFD, &arg, &res) < 0)
                return NULL;

        return &res.cr_getfh;
}
