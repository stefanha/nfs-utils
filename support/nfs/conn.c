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

/* Map an NFS version into the corresponding Mountd version */
u_long nfsvers_to_mnt(const u_long vers)
{
	static const u_long nfs_to_mnt[] = { 0, 0, 1, 3 };
	if (vers <= 3)
		return nfs_to_mnt[vers];
	return 0;
}

/* Map a Mountd version into the corresponding NFS version */
u_long mntvers_to_nfs(const u_long vers)
{
	static const u_long mnt_to_nfs[] = { 0, 2, 2, 3 };
	if (vers <= 3)
		return mnt_to_nfs[vers];
	return 0;
}

/*
 * Create a socket that is locally bound to a 
 * reserve or non-reserve port. For any failures,
 * RPC_ANYSOCK is returned which will cause 
 * the RPC code to create the socket instead. 
 */
int get_socket(struct sockaddr_in *saddr, u_int p_prot, int resvp)
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
	if (type == SOCK_STREAM || type == SOCK_DGRAM) {
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

/*
 * Sigh... getport() doesn't actually check the version number.
 * In order to make sure that the server actually supports the service
 * we're requesting, we open and RPC client, and fire off a NULL
 * RPC call.
 */
int
clnt_ping(struct sockaddr_in *saddr, const u_long prog, const u_long vers,
	  const u_int prot, struct sockaddr_in *caddr)
{
	CLIENT *clnt=NULL;
	int sock, stat;
	static char clnt_res;

	rpc_createerr.cf_stat = stat = errno = 0;
	sock = get_socket(saddr, prot, FALSE);
	if (sock == RPC_ANYSOCK && errno == ETIMEDOUT) {
		/*
		 * TCP timeout. Bubble up the error to see 
		 * how it should be handled.
		 */
		rpc_createerr.cf_stat = RPC_TIMEDOUT;
		goto out_bad;
	}

	switch(prot) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(saddr, prog, vers,
					 RETRY_TIMEOUT, &sock,
					 RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		break;
	case IPPROTO_TCP:
		clnt = clnttcp_create(saddr, prog, vers, &sock,
				      RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		break;
	default:
		goto out_bad;
	}
	if (!clnt)
		goto out_bad;
	memset(&clnt_res, 0, sizeof(clnt_res));
	stat = clnt_call(clnt, NULLPROC,
			 (xdrproc_t)xdr_void, (caddr_t)NULL,
			 (xdrproc_t)xdr_void, (caddr_t)&clnt_res,
			 TIMEOUT);
	if (stat) {
		clnt_geterr(clnt, &rpc_createerr.cf_error);
		rpc_createerr.cf_stat = stat;
	}
	clnt_destroy(clnt);
	if (sock != -1) {
		if (caddr) {
			/* Get the address of our end of this connection */
			socklen_t len = sizeof(*caddr);
			if (getsockname(sock, caddr, &len) != 0)
				caddr->sin_family = 0;
		}
		close(sock);
	}

	if (stat == RPC_SUCCESS)
		return 1;

 out_bad:
	return 0;
}

CLIENT *mnt_openclnt(clnt_addr_t *mnt_server, int *msock)
{
	struct sockaddr_in *mnt_saddr = &mnt_server->saddr;
	struct pmap *mnt_pmap = &mnt_server->pmap;
	CLIENT *clnt = NULL;

	/* contact the mount daemon via TCP */
	mnt_saddr->sin_port = htons((u_short)mnt_pmap->pm_port);
	*msock = get_socket(mnt_saddr, mnt_pmap->pm_prot, TRUE);

	switch (mnt_pmap->pm_prot) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(mnt_saddr,
					 mnt_pmap->pm_prog, mnt_pmap->pm_vers,
					 RETRY_TIMEOUT, msock,
					 MNT_SENDBUFSIZE, MNT_RECVBUFSIZE);
		break;
	case IPPROTO_TCP:
		clnt = clnttcp_create(mnt_saddr,
				      mnt_pmap->pm_prog, mnt_pmap->pm_vers,
				      msock,
				      MNT_SENDBUFSIZE, MNT_RECVBUFSIZE);
		break;
	}
	if (clnt) {
		/* try to mount hostname:dirname */
		clnt->cl_auth = authunix_create_default();
		return clnt;
	}
	return NULL;
}

void mnt_closeclnt(CLIENT *clnt, int msock)
{
	auth_destroy(clnt->cl_auth);
	clnt_destroy(clnt);
	close(msock);
}

