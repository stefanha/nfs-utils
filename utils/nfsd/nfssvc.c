/*
 * utils/nfsd/nfssvc.c
 *
 * Run an NFS daemon.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "nfslib.h"
#include "xlog.h"

#define NFSD_PORTS_FILE     "/proc/fs/nfsd/portlist"
#define NFSD_VERS_FILE    "/proc/fs/nfsd/versions"
#define NFSD_THREAD_FILE  "/proc/fs/nfsd/threads"

/*
 * declaring a common static scratch buffer here keeps us from having to
 * continually thrash the stack. The value of 128 bytes here is really just a
 * SWAG and can be increased if necessary. It ought to be enough for the
 * routines below however.
 */
char buf[128];

/*
 * Are there already sockets configured? If not, then it is safe to try to
 * open some and pass them through.
 *
 * Note: If the user explicitly asked for 'udp', then we should probably check
 * if that is open, and should open it if not. However we don't yet. All
 * sockets have to be opened when the first daemon is started.
 */
int
nfssvc_inuse(void)
{
	int fd, n;

	fd = open(NFSD_PORTS_FILE, O_RDONLY);

	/* problem opening file, assume that nothing is configured */
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf));
	close(fd);

	xlog(D_GENERAL, "knfsd is currently %s", (n > 0) ? "up" : "down");

	return (n > 0);
}

static void
nfssvc_setfds(int port, unsigned int ctlbits, char *haddr)
{
	int fd, on=1;
	int udpfd = -1, tcpfd = -1;
	struct sockaddr_in sin;

	if (nfssvc_inuse())
		return;

	fd = open(NFSD_PORTS_FILE, O_WRONLY);
	if (fd < 0)
		return;
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(port);
	sin.sin_addr.s_addr =  inet_addr(haddr);

	if (NFSCTL_UDPISSET(ctlbits)) {
		udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (udpfd < 0) {
			xlog(L_ERROR, "unable to create UDP socket: "
				"errno %d (%m)", errno);
			exit(1);
		}
		if (bind(udpfd, (struct  sockaddr  *)&sin, sizeof(sin)) < 0){
			xlog(L_ERROR, "unable to bind UDP socket: "
				"errno %d (%m)", errno);
			exit(1);
		}
	}

	if (NFSCTL_TCPISSET(ctlbits)) {
		tcpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (tcpfd < 0) {
			xlog(L_ERROR, "unable to create TCP socket: "
				"errno %d (%m)", errno);
			exit(1);
		}
		if (setsockopt(tcpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			xlog(L_ERROR, "unable to set SO_REUSEADDR: "
				"errno %d (%m)", errno);
			exit(1);
		}
		if (bind(tcpfd, (struct  sockaddr  *)&sin, sizeof(sin)) < 0){
			xlog(L_ERROR, "unable to bind TCP socket: "
				"errno %d (%m)", errno);
			exit(1);
		}
		if (listen(tcpfd, 64) < 0){
			xlog(L_ERROR, "unable to create listening socket: "
				"errno %d (%m)", errno);
			exit(1);
		}
	}
	if (udpfd >= 0) {
		snprintf(buf, sizeof(buf), "%d\n", udpfd); 
		if (write(fd, buf, strlen(buf)) != strlen(buf)) {
			xlog(L_ERROR, 
			       "writing fds to kernel failed: errno %d (%m)", 
			       errno);
		}
		close(fd);
		fd = -1;
	}
	if (tcpfd >= 0) {
		if (fd < 0)
			fd = open(NFSD_PORTS_FILE, O_WRONLY);
		snprintf(buf, sizeof(buf), "%d\n", tcpfd); 
		if (write(fd, buf, strlen(buf)) != strlen(buf)) {
			xlog(L_ERROR, 
			       "writing fds to kernel failed: errno %d (%m)", 
			       errno);
		}
	}
	close(fd);

	return;
}
static void
nfssvc_versbits(unsigned int ctlbits, int minorvers4)
{
	int fd, n, off;
	char *ptr;

	ptr = buf;
	off = 0;
	fd = open(NFSD_VERS_FILE, O_WRONLY);
	if (fd < 0)
		return;

	for (n = NFSD_MINVERS; n <= NFSD_MAXVERS; n++) {
		if (NFSCTL_VERISSET(ctlbits, n))
		    off += snprintf(ptr+off, sizeof(buf) - off, "+%d ", n);
		else
		    off += snprintf(ptr+off, sizeof(buf) - off, "-%d ", n);
	}
	n = minorvers4 >= 0 ? minorvers4 : -minorvers4;
	if (n >= NFSD_MINMINORVERS4 && n <= NFSD_MAXMINORVERS4)
		    off += snprintf(ptr+off, sizeof(buf) - off, "%c4.%d",
				    minorvers4 > 0 ? '+' : '-',
				    n);
	xlog(D_GENERAL, "Writing version string to kernel: %s", buf);
	snprintf(ptr+off, sizeof(buf) - off, "\n");
	if (write(fd, buf, strlen(buf)) != strlen(buf))
		xlog(L_ERROR, "Setting version failed: errno %d (%m)", errno);

	close(fd);

	return;
}
int
nfssvc(int port, int nrservs, unsigned int versbits, int minorvers4,
	unsigned protobits, char *haddr)
{
	struct nfsctl_arg	arg;
	int fd;

	/* Note: must set versions before fds so that
	 * the ports get registered with portmap against correct
	 * versions
	 */
	nfssvc_versbits(versbits, minorvers4);
	nfssvc_setfds(port, protobits, haddr);

	fd = open(NFSD_THREAD_FILE, O_WRONLY);
	if (fd < 0)
		fd = open("/proc/fs/nfs/threads", O_WRONLY);
	if (fd >= 0) {
		/* 2.5+ kernel with nfsd filesystem mounted.
		 * Just write the number in.
		 * Cannot handle port number yet, but does anyone care?
		 */
		int n;
		snprintf(buf, sizeof(buf), "%d\n", nrservs);
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
