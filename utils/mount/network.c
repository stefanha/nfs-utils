/*
 * network.c -- Provide common network functions for NFS mount/umount
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2007 Chuck Lever <chuck.lever@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <sys/socket.h>

#include "xcommon.h"
#include "mount.h"
#include "nls.h"
#include "nfs_mount.h"
#include "mount_constants.h"
#include "network.h"

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

#ifndef NFS_PORT
#define NFS_PORT 2049
#endif

#define PMAP_TIMEOUT	(10)
#define CONNECT_TIMEOUT	(20)
#define MOUNT_TIMEOUT	(30)

#if SIZEOF_SOCKLEN_T - 0 == 0
#define socklen_t unsigned int
#endif

extern int nfs_mount_data_version;
extern char *progname;
extern int verbose;

static const unsigned long nfs_to_mnt[] = {
	0,
	0,
	1,
	3,
};

static const unsigned long mnt_to_nfs[] = {
	0,
	2,
	2,
	3,
};

/*
 * Map an NFS version into the corresponding Mountd version
 */
unsigned long nfsvers_to_mnt(const unsigned long vers)
{
	if (vers <= 3)
		return nfs_to_mnt[vers];
	return 0;
}

/*
 * Map a Mountd version into the corresponding NFS version
 */
static unsigned long mntvers_to_nfs(const unsigned long vers)
{
	if (vers <= 3)
		return mnt_to_nfs[vers];
	return 0;
}

static const unsigned int probe_udp_only[] = {
	IPPROTO_UDP,
	0,
};

static const unsigned int probe_udp_first[] = {
	IPPROTO_UDP,
	IPPROTO_TCP,
	0,
};

static const unsigned int probe_tcp_first[] = {
	IPPROTO_TCP,
	IPPROTO_UDP,
	0,
};

static const unsigned long probe_nfs2_only[] = {
	2,
	0,
};

static const unsigned long probe_nfs3_first[] = {
	3,
	2,
	0,
};

static const unsigned long probe_mnt1_first[] = {
	1,
	2,
	0,
};

static const unsigned long probe_mnt3_first[] = {
	3,
	1,
	2,
	0,
};

/**
 * nfs_gethostbyname - resolve a hostname to an IPv4 address
 * @hostname: pointer to a C string containing a DNS hostname
 * @saddr: returns an IPv4 address 
 *
 * Returns 1 if successful, otherwise zero.
 */
int nfs_gethostbyname(const char *hostname, struct sockaddr_in *saddr)
{
	struct hostent *hp;

	saddr->sin_family = AF_INET;
	if (!inet_aton(hostname, &saddr->sin_addr)) {
		if ((hp = gethostbyname(hostname)) == NULL) {
			nfs_error(_("%s: can't get address for %s\n"),
					progname, hostname);
			return 0;
		} else {
			if (hp->h_length > sizeof(*saddr)) {
				nfs_error(_("%s: got bad hp->h_length\n"),
						progname);
				hp->h_length = sizeof(*saddr);
			}
			memcpy(&saddr->sin_addr, hp->h_addr, hp->h_length);
		}
	}
	return 1;
}

/*
 * Attempt to connect a socket, but time out after "timeout" seconds.
 *
 * On error return, caller closes the socket.
 */
static int connect_to(int fd, struct sockaddr *addr,
			socklen_t addrlen, int timeout)
{
	int ret, saved;
	fd_set rset, wset;
	struct timeval tv = {
		.tv_sec = timeout,
	};

	saved = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, saved | O_NONBLOCK);

	ret = connect(fd, addr, addrlen);
	if (ret < 0 && errno != EINPROGRESS)
		return -1;
	if (ret == 0)
		goto out;

	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	wset = rset;
	ret = select(fd + 1, &rset, &wset, NULL, &tv);
	if (ret == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
		int error;
		socklen_t len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;
		if (error) {
			errno = error;
			return -1;
		}
	} else
		return -1;

out:
	fcntl(fd, F_SETFL, saved);
	return 0;
}

/*
 * Create a socket that is locally bound to a reserved or non-reserved port.
 *
 * The caller should check rpc_createerr to determine the cause of any error.
 */
static int get_socket(struct sockaddr_in *saddr, unsigned int p_prot,
			unsigned int timeout, int resvp, int conn)
{
	int so, cc, type;
	struct sockaddr_in laddr;
	socklen_t namelen = sizeof(laddr);

	type = (p_prot == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM);
	if ((so = socket (AF_INET, type, p_prot)) < 0)
		goto err_socket;

	laddr.sin_family = AF_INET;
	laddr.sin_port = 0;
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (resvp) {
		if (bindresvport(so, &laddr) < 0)
			goto err_bindresvport;
	} else {
		cc = bind(so, (struct sockaddr *)&laddr, namelen);
		if (cc < 0)
			goto err_bind;
	}
	if (type == SOCK_STREAM || (conn && type == SOCK_DGRAM)) {
		cc = connect_to(so, (struct sockaddr *)saddr, namelen,
				timeout);
		if (cc < 0)
			goto err_connect;
	}
	return so;

err_socket:
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	if (verbose) {
		nfs_error(_("%s: Unable to create %s socket: errno %d (%s)\n"),
			progname, p_prot == IPPROTO_UDP ? _("UDP") : _("TCP"),
			errno, strerror(errno));
	}
	return RPC_ANYSOCK;

err_bindresvport:
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	if (verbose) {
		nfs_error(_("%s: Unable to bindresvport %s socket: errno %d"
				" (%s)\n"),
			progname, p_prot == IPPROTO_UDP ? _("UDP") : _("TCP"),
			errno, strerror(errno));
	}
	close(so);
	return RPC_ANYSOCK;

err_bind:
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	if (verbose) {
		nfs_error(_("%s: Unable to bind to %s socket: errno %d (%s)\n"),
			progname, p_prot == IPPROTO_UDP ? _("UDP") : _("TCP"),
			errno, strerror(errno));
	}
	close(so);
	return RPC_ANYSOCK;

err_connect:
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	if (verbose) {
		nfs_error(_("%s: Unable to connect to %s:%d, errno %d (%s)\n"),
			progname, inet_ntoa(saddr->sin_addr),
			ntohs(saddr->sin_port), errno, strerror(errno));
	}
	close(so);
	return RPC_ANYSOCK;
}

/*
 * getport() is very similar to pmap_getport() with the exception that
 * this version tries to use an ephemeral port, since reserved ports are
 * not needed for GETPORT queries.  This conserves the very limited
 * reserved port space, which helps reduce failed socket binds
 * during mount storms.
 *
 * A side effect of calling this function is that rpccreateerr is set.
 */
static unsigned short getport(struct sockaddr_in *saddr,
				unsigned long program,
				unsigned long version,
				unsigned int proto)
{
	struct sockaddr_in bind_saddr;
	unsigned short port = 0;
	int socket;
	CLIENT *clnt = NULL;
	enum clnt_stat stat;
 
	bind_saddr = *saddr;
	bind_saddr.sin_port = htons(PMAPPORT);

	socket = get_socket(&bind_saddr, proto, PMAP_TIMEOUT, FALSE, FALSE);
	if (socket == RPC_ANYSOCK) {
		if (proto == IPPROTO_TCP &&
		    rpc_createerr.cf_error.re_errno == ETIMEDOUT)
			rpc_createerr.cf_stat = RPC_TIMEDOUT;
		return 0;
	}

	switch (proto) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(&bind_saddr,
					 PMAPPROG, PMAPVERS,
					 RETRY_TIMEOUT, &socket,
					 RPCSMALLMSGSIZE,
					 RPCSMALLMSGSIZE);
		break;
	case IPPROTO_TCP:
		clnt = clnttcp_create(&bind_saddr,
				      PMAPPROG, PMAPVERS,
				      &socket,
				      RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		break;
	}
	if (clnt != NULL) {
		struct pmap parms = {
			.pm_prog	= program,
			.pm_vers	= version,
			.pm_prot	= proto,
		};

		stat = clnt_call(clnt, PMAPPROC_GETPORT,
				 (xdrproc_t)xdr_pmap, (caddr_t)&parms,
				 (xdrproc_t)xdr_u_short, (caddr_t)&port,
				 TIMEOUT);
		if (stat) {
			clnt_geterr(clnt, &rpc_createerr.cf_error);
			rpc_createerr.cf_stat = stat;
		}
		clnt_destroy(clnt);
		if (stat != RPC_SUCCESS)
			port = 0;
		else if (port == 0)
			rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}
	close(socket);

	return port;
}

/*
 * Use the portmapper to discover whether or not the service we want is
 * available. The lists 'versions' and 'protos' define ordered sequences
 * of service versions and udp/tcp protocols to probe for.
 */
static int probe_port(clnt_addr_t *server, const unsigned long *versions,
			const unsigned int *protos)
{
	struct sockaddr_in *saddr = &server->saddr;
	struct pmap *pmap = &server->pmap;
	const unsigned long prog = pmap->pm_prog, *p_vers;
	const unsigned int prot = (u_int)pmap->pm_prot, *p_prot;
	const u_short port = (u_short) pmap->pm_port;
	unsigned long vers = pmap->pm_vers;
	unsigned short p_port;

	p_prot = prot ? &prot : protos;
	p_vers = vers ? &vers : versions;
	rpc_createerr.cf_stat = 0;
	for (;;) {
		p_port = getport(saddr, prog, *p_vers, *p_prot);
		if (p_port) {
			if (!port || port == p_port) {
				saddr->sin_port = htons(p_port);
				if (verbose) {
					printf(_("%s: trying %s prog %ld vers "
						"%ld prot %s port %d\n"),
						progname,
						inet_ntoa(saddr->sin_addr),
						prog, *p_vers,
						*p_prot == IPPROTO_UDP ?
							_("UDP") : _("TCP"),
						p_port);
                                }
				if (clnt_ping(saddr, prog, *p_vers, *p_prot, NULL))
					goto out_ok;
				if (rpc_createerr.cf_stat == RPC_TIMEDOUT)
					goto out_bad;
			}
		}
		if (rpc_createerr.cf_stat != RPC_PROGNOTREGISTERED &&
		    rpc_createerr.cf_stat != RPC_PROGVERSMISMATCH)
			goto out_bad;

		if (!prot) {
			if (*++p_prot)
				continue;
			p_prot = protos;
		}
		if (vers || !*++p_vers)
			break;
	}

out_bad:
	return 0;

out_ok:
	if (!vers)
		pmap->pm_vers = *p_vers;
	if (!prot)
		pmap->pm_prot = *p_prot;
	if (!port)
		pmap->pm_port = p_port;
	rpc_createerr.cf_stat = 0;
	return 1;
}

static int probe_nfsport(clnt_addr_t *nfs_server)
{
	struct pmap *pmap = &nfs_server->pmap;

	if (pmap->pm_vers && pmap->pm_prot && pmap->pm_port)
		return 1;

	if (nfs_mount_data_version >= 4)
		return probe_port(nfs_server, probe_nfs3_first, probe_tcp_first);
	else
		return probe_port(nfs_server, probe_nfs2_only, probe_udp_only);
}

static int probe_mntport(clnt_addr_t *mnt_server)
{
	struct pmap *pmap = &mnt_server->pmap;

	if (pmap->pm_vers && pmap->pm_prot && pmap->pm_port)
		return 1;

	if (nfs_mount_data_version >= 4)
		return probe_port(mnt_server, probe_mnt3_first, probe_udp_first);
	else
		return probe_port(mnt_server, probe_mnt1_first, probe_udp_only);
}

/**
 * probe_bothports - discover the RPC endpoints of mountd and NFS server
 * @mnt_server: pointer to address and pmap argument for mountd results
 * @nfs_server: pointer to address and pmap argument for NFS server
 *
 * Returns 1 if successful, otherwise zero if some error occurred.
 * Note that the arguments are both input and output arguments.
 *
 * A side effect of calling this function is that rpccreateerr is set.
 */
int probe_bothports(clnt_addr_t *mnt_server, clnt_addr_t *nfs_server)
{
	struct pmap *nfs_pmap = &nfs_server->pmap;
	struct pmap *mnt_pmap = &mnt_server->pmap;
	struct pmap save_nfs, save_mnt;
	int res;
	const unsigned long *probe_vers;

	if (mnt_pmap->pm_vers && !nfs_pmap->pm_vers)
		nfs_pmap->pm_vers = mntvers_to_nfs(mnt_pmap->pm_vers);
	else if (nfs_pmap->pm_vers && !mnt_pmap->pm_vers)
		mnt_pmap->pm_vers = nfsvers_to_mnt(nfs_pmap->pm_vers);
	if (nfs_pmap->pm_vers)
		goto version_fixed;

	memcpy(&save_nfs, nfs_pmap, sizeof(save_nfs));
	memcpy(&save_mnt, mnt_pmap, sizeof(save_mnt));
	probe_vers = (nfs_mount_data_version >= 4) ?
			probe_mnt3_first : probe_mnt1_first;

	for (; *probe_vers; probe_vers++) {
		nfs_pmap->pm_vers = mntvers_to_nfs(*probe_vers);
		if ((res = probe_nfsport(nfs_server) != 0)) {
			mnt_pmap->pm_vers = *probe_vers;
			if ((res = probe_mntport(mnt_server)) != 0)
				return 1;
			memcpy(mnt_pmap, &save_mnt, sizeof(*mnt_pmap));
		}
		switch (rpc_createerr.cf_stat) {
		case RPC_PROGVERSMISMATCH:
		case RPC_PROGNOTREGISTERED:
			break;
		default:
			goto out_bad;
		}
		memcpy(nfs_pmap, &save_nfs, sizeof(*nfs_pmap));
	}

out_bad:
	return 0;

version_fixed:
	if (!probe_nfsport(nfs_server))
		goto out_bad;
	return probe_mntport(mnt_server);
}

static int probe_statd(void)
{
	struct sockaddr_in addr;
	unsigned short port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	port = getport(&addr, 100024, 1, IPPROTO_UDP);

	if (port == 0)
		return 0;
	addr.sin_port = htons(port);

	if (clnt_ping(&addr, 100024, 1, IPPROTO_UDP, NULL) <= 0)
		return 0;

	return 1;
}

/**
 * start_statd - attempt to start rpc.statd
 *
 * Returns 1 if statd is running; otherwise zero.
 */
int start_statd(void)
{
#ifdef START_STATD
	struct stat stb;
#endif

	if (probe_statd())
		return 1;

#ifdef START_STATD
	if (stat(START_STATD, &stb) == 0) {
		if (S_ISREG(stb.st_mode) && (stb.st_mode & S_IXUSR)) {
			system(START_STATD);
			if (probe_statd())
				return 1;
		}
	}
#endif

	return 0;
}

/**
 * nfs_call_umount - ask the server to remove a share from it's rmtab
 * @mnt_server: address of RPC MNT program server
 * @argp: directory path of share to "unmount"
 *
 * Returns one if the unmount call succeeded; zero if the unmount
 * failed for any reason.
 *
 * Note that a side effect of calling this function is that rpccreateerr
 * is set.
 */
int nfs_call_umount(clnt_addr_t *mnt_server, dirpath *argp)
{
	CLIENT *clnt;
	enum clnt_stat res = 0;
	int msock;

	if (!probe_mntport(mnt_server))
		return 0;
	clnt = mnt_openclnt(mnt_server, &msock);
	if (!clnt)
		return 0;
	res = clnt_call(clnt, MOUNTPROC_UMNT,
			(xdrproc_t)xdr_dirpath, (caddr_t)argp,
			(xdrproc_t)xdr_void, NULL,
			TIMEOUT);
	mnt_closeclnt(clnt, msock);

	if (res == RPC_SUCCESS)
		return 1;
	return 0;
}

/**
 * mnt_openclnt - get a handle for a remote mountd service
 * @mnt_server: address and pmap arguments of mountd service
 * @msock: returns a file descriptor of the underlying transport socket
 *
 * Returns an active handle for the remote's mountd service
 */
CLIENT *mnt_openclnt(clnt_addr_t *mnt_server, int *msock)
{
	struct sockaddr_in *mnt_saddr = &mnt_server->saddr;
	struct pmap *mnt_pmap = &mnt_server->pmap;
	CLIENT *clnt = NULL;

	mnt_saddr->sin_port = htons((u_short)mnt_pmap->pm_port);
	*msock = get_socket(mnt_saddr, mnt_pmap->pm_prot, MOUNT_TIMEOUT,
				TRUE, FALSE);
	if (*msock == RPC_ANYSOCK) {
		if (rpc_createerr.cf_error.re_errno == EADDRINUSE)
			/*
			 * Probably in-use by a TIME_WAIT connection,
			 * It is worth waiting a while and trying again.
			 */
			rpc_createerr.cf_stat = RPC_TIMEDOUT;
		return NULL;
	}

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

/**
 * mnt_closeclnt - terminate a handle for a remote mountd service
 * @clnt: pointer to an active handle for a remote mountd service
 * @msock: file descriptor of the underlying transport socket
 *
 */
void mnt_closeclnt(CLIENT *clnt, int msock)
{
	auth_destroy(clnt->cl_auth);
	clnt_destroy(clnt);
	close(msock);
}

/**
 * clnt_ping - send an RPC ping to the remote RPC service endpoint
 * @saddr: server's address
 * @prog: target RPC program number
 * @vers: target RPC version number
 * @prot: target RPC protocol
 * @caddr: filled in with our network address
 *
 * Sigh... getport() doesn't actually check the version number.
 * In order to make sure that the server actually supports the service
 * we're requesting, we open and RPC client, and fire off a NULL
 * RPC call.
 *
 * caddr is the network address that the server will use to call us back.
 * On multi-homed clients, this address depends on which NIC we use to
 * route requests to the server.
 *
 * Returns one if successful, otherwise zero.
 */
int clnt_ping(struct sockaddr_in *saddr, const unsigned long prog,
		const unsigned long vers, const unsigned int prot,
		struct sockaddr_in *caddr)
{
	CLIENT *clnt = NULL;
	int sock, stat;
	static char clnt_res;
	struct sockaddr dissolve;

	rpc_createerr.cf_stat = stat = 0;
	sock = get_socket(saddr, prot, CONNECT_TIMEOUT, FALSE, TRUE);
	if (sock == RPC_ANYSOCK) {
		if (rpc_createerr.cf_error.re_errno == ETIMEDOUT) {
			/*
			 * TCP timeout. Bubble up the error to see 
			 * how it should be handled.
			 */
			rpc_createerr.cf_stat = RPC_TIMEDOUT;
		}
		return 0;
	}

	if (caddr) {
		/* Get the address of our end of this connection */
		socklen_t len = sizeof(*caddr);
		if (getsockname(sock, caddr, &len) != 0)
			caddr->sin_family = 0;
	}

	switch(prot) {
	case IPPROTO_UDP:
		/* The socket is connected (so we could getsockname successfully),
		 * but some servers on multi-homed hosts reply from
		 * the wrong address, so if we stay connected, we lose the reply.
		 */
		dissolve.sa_family = AF_UNSPEC;
		connect(sock, &dissolve, sizeof(dissolve));

		clnt = clntudp_bufcreate(saddr, prog, vers,
					 RETRY_TIMEOUT, &sock,
					 RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		break;
	case IPPROTO_TCP:
		clnt = clnttcp_create(saddr, prog, vers, &sock,
				      RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		break;
	}
	if (!clnt) {
		close(sock);
		return 0;
	}
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
	close(sock);

	if (stat == RPC_SUCCESS)
		return 1;
	else
		return 0;
}

/**
 * get_client_address - acquire our local network address
 * @saddr: server's address
 * @caddr: filled in with our network address
 *
 * Discover a network address that the server will use to call us back.
 * On multi-homed clients, this address depends on which NIC we use to
 * route requests to the server.
 *
 * Use a connected datagram socket so as not to leave a socket in TIME_WAIT.
 *
 * Returns one if successful, otherwise zero.
 */
int get_client_address(struct sockaddr_in *saddr, struct sockaddr_in *caddr)
{
	socklen_t len = sizeof(*caddr);
	int socket, err;

	socket = get_socket(saddr, IPPROTO_UDP, CONNECT_TIMEOUT, FALSE, TRUE);
	if (socket == RPC_ANYSOCK)
		return 0;

	err = getsockname(socket, caddr, &len);
	close(socket);

	if (err && verbose) {
		nfs_error(_("%s: getsockname failed: %s"),
				progname, strerror(errno));
		return 0;
	}
	return 1;
}
