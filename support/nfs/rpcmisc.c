/*
 * support/nfs/rpcmisc.c
 *
 * Miscellaneous functions for RPC startup and shutdown.
 * This code is partially snarfed from rpcgen -s tcp -s udp,
 * partly written by Mark Shand, Donald Becker, and Rick 
 * Sladkey. It was tweaked slightly by Olaf Kirch to be
 * usable by both unfsd and mountd.
 *
 * This software may be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "nfslib.h"

static void	closedown(int sig);
static int	makesock(int port, int proto);

#define _RPCSVC_CLOSEDOWN	120
int	_rpcpmstart = 0;
int	_rpcfdtype = 0;
int	_rpcsvcdirty = 0;

void
rpc_init(char *name, int prog, int vers, void (*dispatch)(), int defport)
{
	struct sockaddr_in saddr;
	SVCXPRT	*transp;
	int	sock;
	int	asize;

	asize = sizeof(saddr);
	sock = 0;
	if (getsockname(0, (struct sockaddr *) &saddr, &asize) == 0) {
		int ssize = sizeof (int);
		_rpcfdtype = 0;
		if (saddr.sin_family != AF_INET)
			xlog(L_FATAL, "init: stdin is bound to non-inet addr");
		if (getsockopt(0, SOL_SOCKET, SO_TYPE,
				(char *)&_rpcfdtype, &ssize) == -1)
			xlog(L_FATAL, "getsockopt failed: %s", strerror(errno));
		_rpcpmstart = 1;
	} else {
		pmap_unset(prog, vers);
		sock = RPC_ANYSOCK;
	}

	if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_DGRAM)) {
		static SVCXPRT *last_transp = NULL;
 
		if (_rpcfdtype == 0) {
			if (last_transp
			    && (!defport || defport == last_transp->xp_port)) {
				transp = last_transp;
				goto udp_transport;
			}
			if ((sock = makesock(defport, IPPROTO_UDP)) < 0) {
				xlog(L_FATAL, "%s: cannot make a UDP socket\n",
						name);
			}
		}
		transp = svcudp_create(sock);
		if (transp == NULL) {
			xlog(L_FATAL, "cannot create udp service.");
		}
      udp_transport:
		if (!svc_register(transp, prog, vers, dispatch, IPPROTO_UDP)) {
			xlog(L_FATAL, "unable to register (%s, %d, udp).",
					name, vers);
		}
		last_transp = transp;
	}

	if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_STREAM)) {
		static SVCXPRT *last_transp = NULL;

		if (_rpcfdtype == 0) {
			if (last_transp
			    && (!defport || defport == last_transp->xp_port)) {
				transp = last_transp;
				goto tcp_transport;
			}
			if ((sock = makesock(defport, IPPROTO_TCP)) < 0) {
				xlog(L_FATAL, "%s: cannot make a TCP socket\n",
						name);
			}
		}
		transp = svctcp_create(sock, 0, 0);
		if (transp == NULL) {
			xlog(L_FATAL, "cannot create tcp service.");
		}
      tcp_transport:
		if (!svc_register(transp, prog, vers, dispatch, IPPROTO_TCP)) {
			xlog(L_FATAL, "unable to register (%s, %d, tcp).",
					name, vers);
		}
		last_transp = transp;
	}

	if (_rpcpmstart) {
		signal (SIGALRM, closedown);
		alarm (_RPCSVC_CLOSEDOWN);
	}
}

static void closedown(sig)
int sig;
{
	(void) signal(sig, closedown);
	if (_rpcsvcdirty == 0) {
		extern fd_set svc_fdset;
		static int size;
		int i, openfd;

		if (_rpcfdtype == SOCK_DGRAM)
			exit(0);
		if (size == 0) {
			size = getdtablesize();
		}
		for (i = 0, openfd = 0; i < size && openfd < 2; i++)
			if (FD_ISSET(i, &svc_fdset))
				openfd++;
		if (openfd <= 1)
			exit(0);
	}
	(void) alarm(_RPCSVC_CLOSEDOWN);
}

static int makesock(port, proto)
int port;
int proto;
{
	struct sockaddr_in sin;
	int	s;
	int	sock_type;
	int	val;

	sock_type = (proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
	s = socket(AF_INET, sock_type, proto);
	if (s < 0) {
		xlog(L_FATAL, "Could not make a socket: %s\n",
					strerror(errno));
		return (-1);
	}
	memset((char *) &sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	val = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
		xlog(L_ERROR, "setsockopt failed: %s\n", strerror(errno));

#if 0
	/* I was told it didn't work with gigabit ethernet.
	   Don't bothet with it.  H.J. */
#ifdef SO_SNDBUF
	{
		int sblen, rblen;

		/* 1024 for rpc & transport overheads */
		sblen = rblen = socksz + 1024;
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sblen, sizeof sblen) < 0 ||
		    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rblen, sizeof rblen) < 0)
			xlog(L_ERROR, "setsockopt failed: %s\n", strerror(errno));
	}
#endif				/* SO_SNDBUF */
#endif

	if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
		xlog(L_FATAL, "Could not bind name to socket: %s\n",
					strerror(errno));
		return (-1);
	}
	return (s);
}


/* Log an incoming call. */
void
rpc_logcall(struct svc_req *rqstp, char *xname, char *arg)
{
	char		buff[1024];
	int		buflen=sizeof(buff);
	int		len;
	char		*sp;
	int		i;

	if (!xlog_enabled(D_CALL))
		return;

	sp = buff;
	switch (rqstp->rq_cred.oa_flavor) {
	case AUTH_NULL:
		sprintf(sp, "NULL");
		break;
	case AUTH_UNIX: {
		struct authunix_parms *unix_cred;
		struct tm *tm;

		unix_cred = (struct authunix_parms *) rqstp->rq_clntcred;
		tm = localtime(&unix_cred->aup_time);
		snprintf(sp, buflen, "UNIX %d/%d/%d %02d:%02d:%02d %s %d.%d",
			tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec,
			unix_cred->aup_machname,
			unix_cred->aup_uid,
			unix_cred->aup_gid);
		sp[buflen-1] = 0;
		len = strlen(sp);
		sp += buflen;
		buflen -= len;
		if ((int) unix_cred->aup_len > 0) {
			snprintf(sp, buflen, "+%d", unix_cred->aup_gids[0]);
			sp[buflen-1] = 0;
			len = strlen(sp);
			sp += buflen;
			buflen -= len;
			for (i = 1; i < unix_cred->aup_len; i++) {
				snprintf(sp, buflen, ",%d", 
					unix_cred->aup_gids[i]);
				sp[buflen-1] = 0;
				len = strlen(sp);
				sp += buflen;
				buflen -= len;
			}
		}
		}
		break;
	default:
		sprintf(sp, "CRED %d", rqstp->rq_cred.oa_flavor);
	}
	xlog(D_CALL, "%s [%s]\n\t%s\n", xname, buff, arg);
}
