/*
 * support/nfs/nfssvc.c
 *
 * Run an NFS daemon.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <unistd.h>
#include <fcntl.h>

#include "nfslib.h"

int
nfssvc(int port, int nrservs)
{
	struct nfsctl_arg	arg;
	int fd;

	fd = open("/proc/fs/nfsd/threads", O_WRONLY);
	if (fd < 0)
		fd = open("/proc/fs/nfs/threads", O_WRONLY);
	if (fd >= 0) {
		/* 2.5+ kernel with nfsd filesystem mounted.
		 * Just write the number in.
		 * Cannot handle port number yet, but does anyone care?
		 */
		char buf[20];
		int n;
		snprintf(buf, 20,"%d\n", nrservs);
		n = write(fd, buf, strlen(buf));
		close(fd);
		if (n != strlen(buf))
			return -1;
		else
			return 0;
	}

	arg.ca_version = NFSCTL_VERSION;
	arg.ca_svc.svc_nthreads = nrservs;
	arg.ca_svc.svc_port = port;
	return nfsctl(NFSCTL_SVC, &arg, NULL);
}
