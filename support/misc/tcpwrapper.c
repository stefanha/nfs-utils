/* This is copied from portmap 4.0-29 in RedHat. */

 /*
  * pmap_check - additional portmap security.
  * 
  * Always reject non-local requests to update the portmapper tables.
  * 
  * Refuse to forward mount requests to the nfs mount daemon. Otherwise, the
  * requests would appear to come from the local system, and nfs export
  * restrictions could be bypassed.
  * 
  * Refuse to forward requests to the nfsd process.
  * 
  * Refuse to forward requests to NIS (YP) daemons; The only exception is the
  * YPPROC_DOMAIN_NONACK broadcast rpc call that is used to establish initial
  * contact with the NIS server.
  * 
  * Always allocate an unprivileged port when forwarding a request.
  * 
  * If compiled with -DCHECK_PORT, require that requests to register or
  * unregister a privileged port come from a privileged port. This makes it
  * more difficult to replace a critical service by a trojan.
  * 
  * If compiled with -DHOSTS_ACCESS, reject requests from hosts that are not
  * authorized by the /etc/hosts.{allow,deny} files. The local system is
  * always treated as an authorized host. The access control tables are never
  * consulted for requests from the local system, and are always consulted
  * for requests from other hosts.
  * 
  * Author: Wietse Venema (wietse@wzv.win.tue.nl), dept. of Mathematics and
  * Computing Science, Eindhoven University of Technology, The Netherlands.
  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <tcpwrapper.h>
#include <unistd.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <syslog.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/signal.h>
#ifdef SYSV40
#include <netinet/in.h>
#include <rpc/rpcent.h>
#endif

static void logit(int severity, struct sockaddr_in *addr,
		  u_long procnum, u_long prognum, char *text);
static void toggle_verboselog(int sig);
int     verboselog = 0;
int     allow_severity = LOG_INFO;
int     deny_severity = LOG_WARNING;

/* A handful of macros for "readability". */

#ifdef HAVE_LIBWRAP
/* coming from libwrap.a (tcp_wrappers) */
extern int hosts_ctl(char *daemon, char *name, char *addr, char *user);
#else
int hosts_ctl(char *daemon, char *name, char *addr, char *user)
{
	return 0;
}
#endif

#define	legal_port(a,p) \
  (ntohs((a)->sin_port) < IPPORT_RESERVED || (p) >= IPPORT_RESERVED)

#define log_bad_port(addr, proc, prog) \
  logit(deny_severity, addr, proc, prog, ": request from unprivileged port")

#define log_bad_host(addr, proc, prog) \
  logit(deny_severity, addr, proc, prog, ": request from unauthorized host")

#define log_bad_owner(addr, proc, prog) \
  logit(deny_severity, addr, proc, prog, ": request from non-local host")

#define	log_no_forward(addr, proc, prog) \
  logit(deny_severity, addr, proc, prog, ": request not forwarded")

#define log_client(addr, proc, prog) \
  logit(allow_severity, addr, proc, prog, "")

#define ALLOW 1
#define DENY 0

int
good_client(daemon, addr)
char *daemon;
struct sockaddr_in *addr;
{
    struct hostent *hp;
    char **sp;
    char *tmpname;

	/* First check the address. */
	if (hosts_ctl(daemon, "", inet_ntoa(addr->sin_addr), "") == DENY)
		return DENY;

	/* Now do the hostname lookup */
	hp = gethostbyaddr ((const char *) &(addr->sin_addr),
		sizeof (addr->sin_addr), AF_INET);
	if (!hp)
		return DENY; /* never heard of it. misconfigured DNS? */

	/* Make sure the hostent is authorative. */
	tmpname = strdup(hp->h_name);
	if (!tmpname)
		return DENY;
	hp = gethostbyname(tmpname);
	free(tmpname);
	if (!hp)
		return DENY; /* never heard of it. misconfigured DNS? */

	/* Now make sure the address is on the list */
	for (sp = hp->h_addr_list ; *sp ; sp++) {
	    if (memcmp(*sp, &(addr->sin_addr), hp->h_length) == 0)
			break;
	}
	if (!*sp)
	    return DENY; /* it was a FAKE. */

	/* Check the official name and address. */
	if (hosts_ctl(daemon, hp->h_name, inet_ntoa(addr->sin_addr), "") == DENY)
		return DENY;

	/* Now check aliases. */
	for (sp = hp->h_aliases; *sp ; sp++) {
		if (hosts_ctl(daemon, *sp, inet_ntoa(addr->sin_addr), "") == DENY)
	    	return DENY;
	}

   return ALLOW;
}

/* check_startup - additional startup code */

void    check_startup(void)
{

    /*
     * Give up root privileges so that we can never allocate a privileged
     * port when forwarding an rpc request.
     *
     * Fix 8/3/00 Philipp Knirsch: First lookup our rpc user. If we find it,
     * switch to that uid, otherwise simply resue the old bin user and print
     * out a warning in syslog.
     */

    struct passwd *pwent;

    pwent = getpwnam("rpc");
    if (pwent == NULL) {
        syslog(LOG_WARNING, "user rpc not found, reverting to user bin");
        if (setuid(1) == -1) {
            syslog(LOG_ERR, "setuid(1) failed: %m");
            exit(1);
        }
    }
    else {
        if (setuid(pwent->pw_uid) == -1) {
            syslog(LOG_WARNING, "setuid() to rpc user failed: %m");
            if (setuid(1) == -1) {
                syslog(LOG_ERR, "setuid(1) failed: %m");
                exit(1);
            }
        }
    }

    (void) signal(SIGINT, toggle_verboselog);
}

/* check_default - additional checks for NULL, DUMP, GETPORT and unknown */

int
check_default(daemon, addr, proc, prog)
char *daemon;
struct sockaddr_in *addr;
u_long  proc;
u_long  prog;
{
	if (!(from_local(addr) || good_client(daemon, addr))) {
		log_bad_host(addr, proc, prog);
		return (FALSE);
	}
	if (verboselog)
		log_client(addr, proc, prog);

    return (TRUE);
}

/* check_privileged_port - additional checks for privileged-port updates */
int
check_privileged_port(struct sockaddr_in *addr,	
		      u_long proc, u_long prog, u_long port)
{
#ifdef CHECK_PORT
    if (!legal_port(addr, port)) {
	log_bad_port(addr, proc, prog);
	return (FALSE);
    }
#endif
    return (TRUE);
}

/* toggle_verboselog - toggle verbose logging flag */

static void toggle_verboselog(int sig)
{
    (void) signal(sig, toggle_verboselog);
    verboselog = !verboselog;
}

/* logit - report events of interest via the syslog daemon */

static void logit(int severity, struct sockaddr_in *addr,
		  u_long procnum, u_long prognum, char *text)
{
    char   *procname;
    char    procbuf[16 + 4 * sizeof(u_long)];
    char   *progname;
    char    progbuf[16 + 4 * sizeof(u_long)];
    struct rpcent *rpc;

    /*
     * Fork off a process or the portmap daemon might hang while
     * getrpcbynumber() or syslog() does its thing.
     *
     * Don't forget to wait for the children, too...
     */

    if (fork() == 0) {

	/* Try to map program number to name. */

	if (prognum == 0) {
	    progname = "";
	} else if ((rpc = getrpcbynumber((int) prognum))) {
	    progname = rpc->r_name;
	} else {
	    snprintf(progname = progbuf, sizeof (progbuf),
		     "prog (%lu)", prognum);
	}

	/* Try to map procedure number to name. */

	snprintf(procname = procbuf, sizeof (procbuf),
		 "proc (%lu)", (u_long) procnum);

	/* Write syslog record. */

	syslog(severity, "connect from %s to %s in %s%s",
	       inet_ntoa(addr->sin_addr), procname, progname, text);
	exit(0);
    }
}
