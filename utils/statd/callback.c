/*
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, Oct. 1996.
 *
 * NSM for Linux.
 */

#include "config.h"
#include "statd.h"
#include "notlist.h"

/* Callback notify list. */
notify_list *cbnl = NULL;


/* 
 * Services SM_NOTIFY requests.
 * Any clients that have asked us to monitor that host are put on
 * the global callback list, which is processed as soon as statd
 * returns to svc_run.
 */
void *
sm_notify_1_svc(struct stat_chge *argp, struct svc_req *rqstp)
{
	notify_list    *lp, *call;
	static char    *result = NULL;

	dprintf(L_DEBUG, "Received SM_NOTIFY from %s, state: %d",
				argp->mon_name, argp->state);

	if ((lp = rtnl) != NULL) {
		log(L_WARNING, "SM_NOTIFY from %s--nobody looking!",
				argp->mon_name, argp->state);
		return ((void *) &result);
	}

	/* okir change: statd doesn't remove the remote host from its
	 * internal monitor list when receiving an SM_NOTIFY call from
	 * it. Lockd will want to continue monitoring the remote host
	 * until it issues an SM_UNMON call.
	 */
	while ((lp = nlist_gethost(lp, argp->mon_name, 0)) != NULL) {
		if (NL_STATE(lp) != argp->state) {
			NL_STATE(lp) = argp->state;
			call = nlist_clone(lp);
			NL_TYPE(call) = NOTIFY_CALLBACK;
			nlist_insert(&notify, call);
		}
		lp = NL_NEXT(lp);
	}

	return ((void *) &result);
}
