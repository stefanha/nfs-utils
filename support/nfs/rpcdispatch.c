/*
 * support/nfs/rcpdispatch.c
 *
 * Generic RPC dispatcher.
 *
 * Copyright (C) 1995, 1996, Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "rpcmisc.h"
#include "xlog.h"

void
rpc_dispatch(struct svc_req *rqstp, SVCXPRT *transp,
			struct rpc_dtable *dtable, int nvers,
			void *argp, void *resp)
{
	struct rpc_dentry	*dent;

	if (rqstp->rq_vers > nvers) {
		svcerr_progvers(transp, 1, nvers);
		return;
	}
	dtable += (rqstp->rq_vers - 1);
	if (rqstp->rq_proc > dtable->nproc) {
		svcerr_noproc(transp);
		return;
	}

	dent = dtable->entries + rqstp->rq_proc;

	if (dent->func == NULL) {
		svcerr_noproc(transp);
		return;
	}

	memset(argp, 0, dent->xdr_arg_size);
	memset(resp, 0, dent->xdr_res_size);

	if (!svc_getargs(transp, dent->xdr_arg_fn, argp)) {
		svcerr_decode(transp);
		return;
	}

	if ((dent->func)(rqstp, argp, resp) && resp != 0) {
		if (!svc_sendreply(transp, dent->xdr_res_fn, (caddr_t)resp)) 
			svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, dent->xdr_arg_fn, argp)) {
		xlog(L_ERROR, "failed to free RPC arguments");
		exit (2);
	}
}

#if 0
/*
 * This is our replacement for svc_run. It turns off some signals while
 * executing the server procedures to avoid nasty race conditions.
 */
void
rpc_svcrun(fd_set *morefds, void (*func)(int fd))
{
	sigset_t	block, current;
	fd_set		readfds;

	for (;;) {
		readfds = svc_fdset;
		if (morefds) {
			int	i;

			/* most efficient */
			for (i = 0; i < FD_SETSIZE; i++)
				if (FD_ISSET(i, morefds))
					FD_SET(i, &readfs);
		}
		switch (select(FD_SETSIZE, &readfds, NULL, NULL, NULL)) {
		case -1:
			if (errno == EINTR)
				continue;
			xlog(L_ERROR, "svc_run: - select failed");
			break;
		case 0:
			continue;
		default:
			if (morefds) {
				int	i;

				/* most efficient */
				for (i = 0; i < FD_SETSIZE; i++)
					if (FD_ISSET(i, morefds) &&
					    FD_ISSET(i, &readfds))
						func(i);
			}
			sigemptyset(&block);
			sigaddset(&block, SIGALRM);
			sigaddset(&block, SIGVTALRM);
			sigaddset(&block, SIGIO);
			sigprocmask(SIG_BLOCK, &block, &current);
			svc_getreqset(&readfds);
			sigprocmask(SIG_SETMASK, &current, NULL);
		}
	}
}
#endif
