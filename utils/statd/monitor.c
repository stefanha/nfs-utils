/*
 * Copyright (C) 1995-1999 Jeffrey A. Uphoff
 * Major rewrite by Olaf Kirch, Dec. 1996.
 * Modified by H.J. Lu, 1998.
 * Tighter access control, Olaf Kirch June 1999.
 *
 * NSM for Linux.
 */

#include "config.h"

#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "misc.h"
#include "statd.h"
#include "notlist.h"

notify_list *		rtnl = NULL;	/* Run-time notify list. */


/*
 * Services SM_MON requests.
 */
struct sm_stat_res *
sm_mon_1_svc(struct mon *argp, struct svc_req *rqstp)
{
	static sm_stat_res result;
	char		*mon_name = argp->mon_id.mon_name,
			*my_name  = argp->mon_id.my_id.my_name;
	struct my_id	*id = &argp->mon_id.my_id;
	char            *path;
	int             fd;
	notify_list	*clnt;
	struct in_addr	my_addr;
#ifdef RESTRICTED_STATD
	struct in_addr	mon_addr, caller;
#else
	struct hostent	*hostinfo = NULL;
#endif

	/* Assume that we'll fail. */
	result.res_stat = STAT_FAIL;
	result.state = -1;	/* State is undefined for STAT_FAIL. */

	/* Restrict access to statd.
	 * In the light of CERT CA-99.05, we tighten access to
	 * statd.			--okir
	 */
#ifdef RESTRICTED_STATD
	/* 1.	Reject anyone not calling from 127.0.0.1.
	 *	Ignore the my_name specified by the caller, and
	 *	use "127.0.0.1" instead.
	 */
	caller = svc_getcaller(rqstp->rq_xprt)->sin_addr;
	if (caller.s_addr != htonl(INADDR_LOOPBACK)) {
		note(N_WARNING,
			"Call to statd from non-local host %s",
			inet_ntoa(caller));
		goto failure;
	}
	my_addr.s_addr = htonl(INADDR_LOOPBACK);
	my_name = "127.0.0.1";

	/* 2.	Reject any registrations for non-lockd services.
	 *
	 *	This is specific to the linux kernel lockd, which
	 *	makes the callback procedure part of the lockd interface.
	 *	It is also prone to break when lockd changes its callback
	 *	procedure number -- which, in fact, has now happened once.
	 *	There must be a better way....   XXX FIXME
	 */
	if (id->my_prog != 100021 ||
	    (id->my_proc != 16 && id->my_proc != 24))
	{
		note(N_WARNING,
			"Attempt to register callback to %d/%d",
			id->my_prog, id->my_proc);
		goto failure;
	}

	/* 3.	mon_name must be an address in dotted quad.
	 *	Again, specific to the linux kernel lockd.
	 */
	if (!inet_aton(mon_name, &mon_addr)) {
		note(N_WARNING,
			"Attempt to register host %s (not a dotted quad)",
			mon_name);
		goto failure;
	}
#else
	/*
	 * Check hostnames.  If I can't look them up, I won't monitor.  This
	 * might not be legal, but it adds a little bit of safety and sanity.
	 */

	/* must check for /'s in hostname!  See CERT's CA-96.09 for details. */
	if (strchr(mon_name, '/')) {
		note(N_CRIT, "SM_MON request for hostname containing '/': %s",
			mon_name);
		note(N_CRIT, "POSSIBLE SPOOF/ATTACK ATTEMPT!");
		goto failure;
	} else if (gethostbyname(mon_name) == NULL) {
		note(N_WARNING, "gethostbyname error for %s", mon_name);
		goto failure;
	} else if (!(hostinfo = gethostbyname(my_name))) {
		note(N_WARNING, "gethostbyname error for %s", my_name);
		goto failure;
	} else
		my_addr = *(struct in_addr *) hostinfo->h_addr;
#endif

	/*
	 * Hostnames checked OK.
	 * Now check to see if this is a duplicate, and warn if so.
	 * I will also return STAT_FAIL. (I *think* this is how I should
	 * handle it.)
	 *
	 * Olaf requests that I allow duplicate SM_MON requests for
	 * hosts due to the way he is coding lockd. No problem,
	 * I'll just do a quickie success return and things should
	 * be happy.
	 */
	if (rtnl) {
		notify_list    *temp = rtnl;

		while ((temp = nlist_gethost(temp, mon_name, 0))) {
			if (matchhostname(NL_MY_NAME(temp), my_name) &&
				NL_MY_PROC(temp) == id->my_proc &&
				NL_MY_PROG(temp) == id->my_prog &&
				NL_MY_VERS(temp) == id->my_vers) {
				/* Hey!  We already know you guys! */
				dprintf(N_DEBUG,
					"Duplicate SM_MON request for %s "
					"from procedure on %s",
					mon_name, my_name);

				/* But we'll let you pass anyway. */
				result.res_stat = STAT_SUCC;
				result.state = MY_STATE;
				return (&result);
			}
			temp = NL_NEXT(temp);
		}
	}

	/*
	 * We're committed...ignoring errors.  Let's hope that a malloc()
	 * doesn't fail.  (I should probably fix this assumption.)
	 */
	if (!(clnt = nlist_new(my_name, mon_name, 0))) {
		note(N_WARNING, "out of memory");
		goto failure;
	}

	NL_ADDR(clnt) = my_addr;
	NL_MY_PROG(clnt) = id->my_prog;
	NL_MY_VERS(clnt) = id->my_vers;
	NL_MY_PROC(clnt) = id->my_proc;
	memcpy(NL_PRIV(clnt), argp->priv, SM_PRIV_SIZE);

	/*
	 * Now, Create file on stable storage for host.
	 */

	path=xmalloc(strlen(SM_DIR)+strlen(mon_name)+2);
	sprintf(path, "%s/%s", SM_DIR, mon_name);
	if ((fd = open(path, O_WRONLY|O_SYNC|O_CREAT, S_IRUSR|S_IWUSR)) < 0) {
		/* Didn't fly.  We won't monitor. */
		note(N_ERROR, "creat(%s) failed: %m", path);
		nlist_free(NULL, clnt);
		free(path);
		goto failure;
	}
	free(path);
	nlist_insert(&rtnl, clnt);
	close(fd);

	result.res_stat = STAT_SUCC;
	result.state = MY_STATE;
	dprintf(N_DEBUG, "MONITORING %s for %s", mon_name, my_name);
	return (&result);

failure:
	note(N_WARNING, "STAT_FAIL to %s for SM_MON of %s", my_name, mon_name);
	return (&result);
}


/*
 * Services SM_UNMON requests.
 *
 * There is no statement in the X/Open spec's about returning an error
 * for requests to unmonitor a host that we're *not* monitoring.  I just
 * return the state of the NSM when I get such foolish requests for lack
 * of any better ideas.  (I also log the "offense.")
 */
struct sm_stat *
sm_unmon_1_svc(struct mon_id *argp, struct svc_req *rqstp)
{
	static sm_stat  result;
	notify_list	*clnt;
	char		*mon_name = argp->mon_name,
			*my_name  = argp->my_id.my_name;
	struct my_id	*id = &argp->my_id;

	result.state = MY_STATE;

	/* Check if we're monitoring anyone. */
	if (!(clnt = rtnl)) {
		note(N_WARNING,
			"Received SM_UNMON request from %s for %s while not "
			"monitoring any hosts.", my_name, argp->mon_name);
		return (&result);
	}

	/*
	 * OK, we are.  Now look for appropriate entry in run-time list.
	 * There should only be *one* match on this, since I block "duplicate"
	 * SM_MON calls.  (Actually, duplicate calls are allowed, but only one
	 * entry winds up in the list the way I'm currently handling them.)
	 */
	while ((clnt = nlist_gethost(clnt, mon_name, 0))) {
		if (matchhostname(NL_MY_NAME(clnt), my_name) &&
			NL_MY_PROC(clnt) == id->my_proc &&
			NL_MY_PROG(clnt) == id->my_prog &&
			NL_MY_VERS(clnt) == id->my_vers) {
			/* Match! */
			dprintf(N_DEBUG, "UNMONITORING %s for %s",
					mon_name, my_name);
			nlist_free(&rtnl, clnt);
			xunlink(SM_DIR, mon_name, 1);

			return (&result);
		} else
			clnt = NL_NEXT(clnt);
	}

	note(N_WARNING, "Received erroneous SM_UNMON request from %s for %s",
		my_name, mon_name);
	return (&result);
}


struct sm_stat *
sm_unmon_all_1_svc(struct my_id *argp, struct svc_req *rqstp)
{
	short int       count = 0;
	static sm_stat  result;
	notify_list	*clnt;

	result.state = MY_STATE;

	if (!(clnt = rtnl)) {
		note(N_WARNING, "Received SM_UNMON_ALL request from %s "
			"while not monitoring any hosts", argp->my_name);
		return (&result);
	}

	while ((clnt = nlist_gethost(clnt, argp->my_name, 1))) {
		if (NL_MY_PROC(clnt) == argp->my_proc &&
			NL_MY_PROG(clnt) == argp->my_prog &&
			NL_MY_VERS(clnt) == argp->my_vers) {
			/* Watch stack! */
			char            mon_name[SM_MAXSTRLEN + 1];
			notify_list	*temp;

			dprintf(N_DEBUG,
				"UNMONITORING (SM_UNMON_ALL) %s for %s",
				NL_MON_NAME(clnt), NL_MY_NAME(clnt));
			strncpy(mon_name, NL_MON_NAME(clnt),
				sizeof (mon_name) - 1);
			mon_name[sizeof (mon_name) - 1] = '\0';
			temp = NL_NEXT(clnt);
			nlist_free(&rtnl, clnt);
			xunlink(SM_DIR, mon_name, 1);
			++count;
			clnt = temp;
		} else
			clnt = NL_NEXT(clnt);
	}

	if (!count) {
		dprintf(N_DEBUG, "SM_UNMON_ALL request from %s with no "
			"SM_MON requests from it.", argp->my_name);
	}

	return (&result);
}
