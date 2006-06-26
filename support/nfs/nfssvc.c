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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include "nfslib.h"

static void
nfssvc_versbits(unsigned int ctlbits)
{
	int fd, n, off;
	char buf[BUFSIZ], *ptr;

	ptr = buf;
	off = 0;
	fd = open("/proc/fs/nfsd/versions", O_WRONLY);
	if (fd < 0)
		return;

	for (n = NFSD_MINVERS; n <= NFSD_MAXVERS; n++) {
		if (NFSCTL_VERISSET(ctlbits, n))
		    off += snprintf(ptr+off, BUFSIZ - off, "+%d ", n);
		else
		    off += snprintf(ptr+off, BUFSIZ - off, "-%d ", n);
	}
	snprintf(ptr+off, BUFSIZ - off, "\n");
	if (write(fd, buf, strlen(buf)) != strlen(buf)) {
		syslog(LOG_ERR, "nfssvc: Setting version failed: errno %d (%s)", 
			errno, strerror(errno));
	}
	close(fd);

	return;
}
int
nfssvc(int port, int nrservs, unsigned int versbits)
{
	struct nfsctl_arg	arg;
	int fd;

	nfssvc_versbits(versbits);

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
