/*
 * Copyright (C) 1996, 1999 Olaf Kirch
 * Modified by Jeffrey A. Uphoff, 1997-1999.
 * Modified by H.J. Lu, 1998.
 * Modified by Lon Hohberger, Oct. 2000
 *   - Bugfix handling client responses.
 *   - Paranoia on NOTIFY_CALLBACK case
 *
 * NSM for Linux.
 */

/*
 * After reboot, notify all hosts on our notify list. In order not to
 * hang statd with delivery to dead hosts, we perform all RPC calls in
 * parallel.
 *
 * It would have been nice to use the portmapper's rmtcall feature,
 * but that's not possible for security reasons (the portmapper would
 * have to forward the call with root privs for most statd's, which
 * it won't if it's worth its money).
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_rmt.h>
#include <time.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include "sm_inter.h"
#include "statd.h"
#include "notlist.h"
#include "log.h"
#include "ha-callout.h"

#define MAXMSGSIZE	(2048 / sizeof(unsigned int))

static unsigned long	xid = 0;	/* RPC XID counter */
static int		sockfd = -1;	/* notify socket */

/*
 * Initialize callback socket
 */
int
statd_get_socket(int port)
{
	struct sockaddr_in	sin;

	if (sockfd >= 0)
		return sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		note(N_CRIT, "Can't create socket: %m");
		return -1;
	}

	FD_SET(sockfd, &SVC_FDSET);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	/*
	 * If a local hostname is given (-n option to statd), bind to the address
	 * specified. This is required to support clients that ignore the mon_name in
	 * the statd protocol but use the source address from the request packet.
	 */
	if (MY_NAME) {
		struct hostent *hp = gethostbyname(MY_NAME);
		if (hp)
			sin.sin_addr = *(struct in_addr *) hp->h_addr;
	}
	if (port != 0) {
		sin.sin_port = htons(port);
		if (bind(sockfd, &sin, sizeof(sin)) == 0)
			goto out_success;
		note(N_CRIT, "statd: failed to bind to outgoing port, %d\n"
				"       falling back on randomly chosen port\n", port);
	}
	if (bindresvport(sockfd, &sin) < 0) {
		dprintf(N_WARNING,
			"process_hosts: can't bind to reserved port\n");
	}
out_success:
	return sockfd;
}
/*
 * Using the NL_ADDR(lp), reset (if needed) the hostname
 * that will be put in the SM_NOTIFY to the hostname
 * that is associated with the network interface 
 * that was monitored
 */
static void
reset_my_name(notify_list *lp)
{
	struct ifaddrs *ifa = NULL, *ifap;
	struct in_addr netaddr, tmp;
	struct sockaddr_in *sin, *nsin;
	struct hostent *hp;

	netaddr.s_addr = inet_netof(NL_ADDR(lp));
	if (getifaddrs(&ifa) >= 0) {
		for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
			if (!(ifap->ifa_flags & IFF_UP))
				continue;

			note(N_DEBUG, "ifa_name %s\n", ifap->ifa_name);
			if (ifap->ifa_addr == NULL)
				continue;
			if (ifap->ifa_addr->sa_family != AF_INET)
				continue;

			sin = (struct sockaddr_in *)ifap->ifa_addr;
			nsin = (struct sockaddr_in *)ifap->ifa_netmask;
			tmp.s_addr = sin->sin_addr.s_addr & nsin->sin_addr.s_addr;
			if (memcmp(&tmp.s_addr, &netaddr.s_addr, sizeof(netaddr.s_addr)))
				continue;
			hp = gethostbyaddr((char *)&sin->sin_addr, 
				sizeof(sin->sin_addr), AF_INET);
			if (hp == NULL)
				continue;
			if (strcmp(NL_MY_NAME(lp), hp->h_name)) {
				free(NL_MY_NAME(lp));
				NL_MY_NAME(lp)= strdup(hp->h_name);
				note(N_DEBUG, "NL_MY_NAME %s\n", NL_MY_NAME(lp));
			}
		}
	}
	return;
}
/*
 * Try to resolve host name for notify/callback request
 *
 * When compiled with RESTRICTED_STATD defined, we expect all
 * host names to be dotted quads. See monitor.c for details. --okir
 */
#ifdef RESTRICTED_STATD
static int
try_to_resolve(notify_list *lp)
{
	char		*hname;

	if (NL_TYPE(lp) == NOTIFY_REBOOT)
		hname = NL_MON_NAME(lp);
	else
		hname = NL_MY_NAME(lp);
	if (!inet_aton(hname, &(NL_ADDR(lp)))) {
		note(N_ERROR, "%s is not an dotted-quad address", hname);
		NL_TIMES(lp) = 0;
		return 0;
	}

	/* XXX: In order to handle multi-homed hosts, we could do
	 * a reverse lookup, a forward lookup, and cycle through
	 * all the addresses.
	 */
	return 1;
}
#else
static int
try_to_resolve(notify_list *lp)
{
	struct hostent	*hp;
	char		*hname;

	if (NL_TYPE(lp) == NOTIFY_REBOOT)
		hname = NL_MON_NAME(lp);
	else
		hname = NL_MY_NAME(lp);

	dprintf(N_DEBUG, "Trying to resolve %s.", hname);
	if (!(hp = gethostbyname(hname))) {
		herror("gethostbyname");
		NL_TIMES(lp) -= 1;
		return 0;
	}

	if (hp->h_addrtype != AF_INET) {
		note(N_ERROR, "%s is not an AF_INET address", hname);
		NL_TIMES(lp) = 0;
		return 0;
	}

	/* FIXME: should try all addresses for multi-homed hosts in
	 * alternation because one interface might be down/unreachable. */
	NL_ADDR(lp) = *(struct in_addr *) hp->h_addr;

	dprintf(N_DEBUG, "address of %s is %s", hname, inet_ntoa(NL_ADDR(lp)));
	return 1;
}
#endif

static unsigned long
xmit_call(int sockfd, struct sockaddr_in *sin,
	  u_int32_t prog, u_int32_t vers, u_int32_t proc,
	  xdrproc_t func, void *obj)
/* 		__u32 prog, __u32 vers, __u32 proc, xdrproc_t func, void *obj) */
{
	unsigned int		msgbuf[MAXMSGSIZE], msglen;
	struct rpc_msg		mesg;
	struct pmap		pmap;
	XDR			xdr, *xdrs = &xdr;
	int			err;

	if (!xid)
		xid = getpid() + time(NULL);

	mesg.rm_xid = ++xid;
	mesg.rm_direction = CALL;
	mesg.rm_call.cb_rpcvers = 2;
	if (sin->sin_port == 0) {
		sin->sin_port = htons(PMAPPORT);
		mesg.rm_call.cb_prog = PMAPPROG;
		mesg.rm_call.cb_vers = PMAPVERS;
		mesg.rm_call.cb_proc = PMAPPROC_GETPORT;
		pmap.pm_prog = prog;
		pmap.pm_vers = vers;
		pmap.pm_prot = IPPROTO_UDP;
		pmap.pm_port = 0;
		func = (xdrproc_t) xdr_pmap;
		obj  = &pmap;
	} else {
		mesg.rm_call.cb_prog = prog;
		mesg.rm_call.cb_vers = vers;
		mesg.rm_call.cb_proc = proc;
	}
	mesg.rm_call.cb_cred.oa_flavor = AUTH_NULL;
	mesg.rm_call.cb_cred.oa_base = (caddr_t) NULL;
	mesg.rm_call.cb_cred.oa_length = 0;
	mesg.rm_call.cb_verf.oa_flavor = AUTH_NULL;
	mesg.rm_call.cb_verf.oa_base = (caddr_t) NULL;
	mesg.rm_call.cb_verf.oa_length = 0;

	/* Create XDR memory object for encoding */
	xdrmem_create(xdrs, (caddr_t) msgbuf, sizeof(msgbuf), XDR_ENCODE);

	/* Encode the RPC header part and payload */
	if (!xdr_callmsg(xdrs, &mesg) || !func(xdrs, obj)) {
		dprintf(N_WARNING, "xmit_mesg: can't encode RPC message!\n");
		xdr_destroy(xdrs);
		return 0;
	}

	/* Get overall length of datagram */
	msglen = xdr_getpos(xdrs);

	if ((err = sendto(sockfd, msgbuf, msglen, 0,
			(struct sockaddr *) sin, sizeof(*sin))) < 0) {
		dprintf(N_WARNING, "xmit_mesg: sendto failed: %m");
	} else if (err != msglen) {
		dprintf(N_WARNING, "xmit_mesg: short write: %m\n");
	}

	xdr_destroy(xdrs);

	return err == msglen? xid : 0;
}

static notify_list *
recv_rply(int sockfd, struct sockaddr_in *sin, u_long *portp)
{
	unsigned int		msgbuf[MAXMSGSIZE], msglen;
	struct rpc_msg		mesg;
	notify_list		*lp = NULL;
	XDR			xdr, *xdrs = &xdr;
	int			alen = sizeof(*sin);

	/* Receive message */
	if ((msglen = recvfrom(sockfd, msgbuf, sizeof(msgbuf), 0,
			(struct sockaddr *) sin, &alen)) < 0) {
		dprintf(N_WARNING, "recv_rply: recvfrom failed: %m");
		return NULL;
	}

	/* Create XDR object for decoding buffer */
	xdrmem_create(xdrs, (caddr_t) msgbuf, msglen, XDR_DECODE);

	memset(&mesg, 0, sizeof(mesg));
	mesg.rm_reply.rp_acpt.ar_results.where = NULL;
	mesg.rm_reply.rp_acpt.ar_results.proc = (xdrproc_t) xdr_void;

	if (!xdr_replymsg(xdrs, &mesg)) {
		note(N_WARNING, "recv_rply: can't decode RPC message!\n");
		goto done;
	}

	if (mesg.rm_reply.rp_stat != 0) {
		note(N_WARNING, "recv_rply: [%s] RPC status %d\n", 
				inet_ntoa(sin->sin_addr),
				mesg.rm_reply.rp_stat);
		goto done;
	}
	if (mesg.rm_reply.rp_acpt.ar_stat != 0) {
		note(N_WARNING, "recv_rply: [%s] RPC status %d\n",
				inet_ntoa(sin->sin_addr),
				mesg.rm_reply.rp_acpt.ar_stat);
		goto done;
	}

	for (lp = notify; lp != NULL; lp = lp->next) {
		/* LH - this was a bug... it should have been checking
		 * the xid from the response message from the client,
		 * not the static, internal xid */
		if (lp->xid != mesg.rm_xid)
			continue;
		if (lp->addr.s_addr != sin->sin_addr.s_addr) {
			char addr [18];
			strncpy (addr, inet_ntoa(lp->addr),
				 sizeof (addr) - 1);
			addr [sizeof (addr) - 1] = '\0';
			dprintf(N_WARNING, "address mismatch: "
				"expected %s, got %s\n",
				addr, inet_ntoa(sin->sin_addr));
		}
		if (lp->port == 0) {
			if (!xdr_u_long(xdrs, portp)) {
				note(N_WARNING, "recv_rply: [%s] "
					"can't decode reply body!\n",
					inet_ntoa(sin->sin_addr));
				lp = NULL;
				goto done;
			}
		}
		break;
	}

done:
	xdr_destroy(xdrs);
	return lp;
}

/*
 * Notify operation for a single list entry
 */
static int
process_entry(int sockfd, notify_list *lp)
{
	struct sockaddr_in	sin;
	struct status		new_status;
	stat_chge		new_stat;
	xdrproc_t		func;
	void			*objp;
	u_int32_t		proc, vers, prog;
/* 	__u32			proc, vers, prog; */

	if (lp->addr.s_addr == INADDR_ANY && !try_to_resolve(lp))
		return NL_TIMES(lp);
	if (NL_TIMES(lp) == 0) {
		note(N_DEBUG, "Cannot notify %s, giving up.\n",
					inet_ntoa(NL_ADDR(lp)));
		return 0;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = lp->port;
	/* LH - moved address into switch */

	switch (NL_TYPE(lp)) {
	case NOTIFY_REBOOT:
		prog = SM_PROG;
		vers = SM_VERS;
		proc = SM_NOTIFY;

		/* Use source address for notify replies */
		sin.sin_addr   = lp->addr;
		/* 
		 * Unless a static hostname has been defined
		 * set the NL_MY_NAME(lp) hostname to the 
		 * one associated with the network interface
		 */
		if (!(run_mode & STATIC_HOSTNAME))
			reset_my_name(lp);

		func = (xdrproc_t) xdr_stat_chge;
		new_stat.state = MY_STATE;
		new_stat.mon_name = NL_MY_NAME(lp);

		objp = &new_stat;
		break;
	case NOTIFY_CALLBACK:
		prog = NL_MY_PROG(lp);
		vers = NL_MY_VERS(lp);
		proc = NL_MY_PROC(lp);

		/* __FORCE__ loopback for callbacks to lockd ... */
		/* Just in case we somehow ignored it thus far */
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		func = (xdrproc_t) xdr_status;
		objp = &new_status;
		new_status.mon_name = NL_MON_NAME(lp);
		new_status.state    = NL_STATE(lp);
		memcpy(new_status.priv, NL_PRIV(lp), SM_PRIV_SIZE);
		break;
	default:
		note(N_ERROR, "notify_host: unknown notify type %d",
				NL_TYPE(lp));
		return 0;
	}

	lp->xid = xmit_call(sockfd, &sin, prog, vers, proc, func, objp);
	if (!lp->xid) {
		note(N_WARNING, "notify_host: failed to notify %s\n",
				inet_ntoa(lp->addr));
	}
	NL_TIMES(lp) -= 1;

	return 1;
}

/*
 * Process a datagram received on the notify socket
 */
int
process_reply(FD_SET_TYPE *rfds)
{
	struct sockaddr_in	sin;
	notify_list		*lp;
	u_long			port;

	if (sockfd == -1 || !FD_ISSET(sockfd, rfds))
		return 0;

	if (!(lp = recv_rply(sockfd, &sin, &port)))
		return 1;

	if (lp->port == 0) {
		if (port != 0) {
			lp->port = htons((unsigned short) port);
			process_entry(sockfd, lp);
			NL_WHEN(lp) = time(NULL) + NOTIFY_TIMEOUT;
			nlist_remove(&notify, lp);
			nlist_insert_timer(&notify, lp);
			return 1;
		}
		note(N_WARNING, "recv_rply: [%s] service %d not registered",
			inet_ntoa(lp->addr),
			NL_TYPE(lp) == NOTIFY_REBOOT? SM_PROG : NL_MY_PROG(lp));
	} else if (NL_TYPE(lp) == NOTIFY_REBOOT) {
		dprintf(N_DEBUG, "Notification of %s succeeded.",
			NL_MON_NAME(lp));
		xunlink(SM_BAK_DIR, NL_MON_NAME(lp), 0);
	} else {
		dprintf(N_DEBUG, "Callback to %s (for %d) succeeded.",
			NL_MY_NAME(lp), NL_MON_NAME(lp));
	}
	nlist_free(&notify, lp);
	return 1;
}

/*
 * Process a notify list, either for notifying remote hosts after reboot
 * or for calling back (local) statd clients when the remote has notified
 * us of a crash. 
 */
int
process_notify_list(void)
{
	notify_list	*entry;
	time_t		now;
	int		fd;

	if ((fd = statd_get_socket(0)) < 0)
		return 0;

	while ((entry = notify) != NULL && NL_WHEN(entry) < time(&now)) {
		if (process_entry(fd, entry)) {
			NL_WHEN(entry) = time(NULL) + NOTIFY_TIMEOUT;
			nlist_remove(&notify, entry);
			nlist_insert_timer(&notify, entry);
		} else if (NL_TYPE(entry) == NOTIFY_CALLBACK) {
			note(N_ERROR,
				"Can't callback %s (%d,%d), giving up.",
					NL_MY_NAME(entry),
					NL_MY_PROG(entry),
					NL_MY_VERS(entry));
			nlist_free(&notify, entry);
		} else {
			note(N_ERROR,
				"Can't notify %s, giving up.",
					NL_MON_NAME(entry));
			/* PRC: do the HA callout */
			ha_callout("del-client", NL_MON_NAME(entry), NL_MY_NAME(entry), -1);
			xunlink(SM_BAK_DIR, NL_MON_NAME(entry), 0);
			nlist_free(&notify, entry);
		}
	}

	return 1;
}
