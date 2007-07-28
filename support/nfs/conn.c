/*
 * conn.c -- NFS client mount / umount connection code support functions
 *
 * 2006-06-06 Amit Gud <agud@redhat.com>
 * - Moved code snippets to nfs-utils/support/nfs from util-linux/mount/nfsmount.c
 *
 */

#include "config.h"
#include <errno.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conn.h"

#if SIZEOF_SOCKLEN_T - 0 == 0
#define socklen_t int
#endif

extern int verbose;

/*
 * Create a socket that is locally bound to a 
 * reserve or non-reserve port. For any failures,
 * RPC_ANYSOCK is returned which will cause 
 * the RPC code to create the socket instead. 
 */
int get_socket(struct sockaddr_in *saddr, u_int p_prot, int resvp, int conn)
{
	int so, cc, type;
	struct sockaddr_in laddr;
	socklen_t namelen = sizeof(laddr);

	type = (p_prot == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM);
	if ((so = socket (AF_INET, type, p_prot)) < 0) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		if (verbose) {
			fprintf(stderr, 
				"mount: Unable to create %s socket: errno %d (%s)\n",
				p_prot == IPPROTO_UDP ? "UDP" : "TCP", 
				errno, strerror(errno));
		}
		return RPC_ANYSOCK;
	}
	laddr.sin_family = AF_INET;
	laddr.sin_port = 0;
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (resvp) {
		if (bindresvport(so, &laddr) < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			if (verbose) {
				fprintf(stderr, 
					"mount: Unable to bindresvport %s socket: errno %d (%s)\n",
					p_prot == IPPROTO_UDP ? "UDP" : "TCP", 
					errno, strerror(errno));
			}
			close(so);
			return RPC_ANYSOCK;
		}
	} else {
		cc = bind(so, (struct sockaddr *)&laddr, namelen);
		if (cc < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			if (verbose) {
				fprintf(stderr, 
					"mount: Unable to bind to %s socket: errno %d (%s)\n",
					p_prot == IPPROTO_UDP ? "UDP" : "TCP", 
					errno, strerror(errno));
			}
			close(so);
			return RPC_ANYSOCK;
		}
	}
	if (type == SOCK_STREAM || (conn && type == SOCK_DGRAM)) {
		cc = connect(so, (struct sockaddr *)saddr, namelen);
		if (cc < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			if (verbose) {
				fprintf(stderr, 
					"mount: Unable to connect to %s:%d, errno %d (%s)\n",
					inet_ntoa(saddr->sin_addr), ntohs(saddr->sin_port),
					errno, strerror(errno));
			}
			close(so);
			return RPC_ANYSOCK;
		}
	}
	return so;
}
