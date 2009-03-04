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
#include <sys/queue.h>
#include <sys/stat.h>
#include <tcpd.h>

#include "xlog.h"

#ifdef SYSV40
#include <netinet/in.h>
#include <rpc/rpcent.h>
#endif

static void logit(int severity, struct sockaddr_in *addr,
		  u_long procnum, u_long prognum, char *text);
static void toggle_verboselog(int sig);
static int check_files(void);

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

typedef struct _haccess_t {
	TAILQ_ENTRY(_haccess_t) list;
	int access;
    struct in_addr addr;
} haccess_t;

#define HASH_TABLE_SIZE 1021
typedef struct _hash_head {
	TAILQ_HEAD(host_list, _haccess_t) h_head;
} hash_head;
hash_head haccess_tbl[HASH_TABLE_SIZE];
static haccess_t *haccess_lookup(struct sockaddr_in *addr, u_long);
static void haccess_add(struct sockaddr_in *addr, u_long, int);

inline unsigned int strtoint(char *str)
{
	unsigned int n = 0;
	int len = strlen(str);
	int i;

	for (i=0; i < len; i++)
		n+=((int)str[i])*i;

	return n;
}
static inline int hashint(unsigned int num)
{
	return num % HASH_TABLE_SIZE;
}
#define HASH(_addr, _prog) \
	hashint((strtoint((_addr))+(_prog)))

void haccess_add(struct sockaddr_in *addr, u_long prog, int access)
{
	hash_head *head;
 	haccess_t *hptr;
	int hash;

	hptr = (haccess_t *)malloc(sizeof(haccess_t));
	if (hptr == NULL)
		return;

	hash = HASH(inet_ntoa(addr->sin_addr), prog);
	head = &(haccess_tbl[hash]);

	hptr->access = access;
	hptr->addr.s_addr = addr->sin_addr.s_addr;

	if (TAILQ_EMPTY(&head->h_head))
		TAILQ_INSERT_HEAD(&head->h_head, hptr, list);
	else
		TAILQ_INSERT_TAIL(&head->h_head, hptr, list);
}
haccess_t *haccess_lookup(struct sockaddr_in *addr, u_long prog)
{
	hash_head *head;
 	haccess_t *hptr;
	int hash;

	hash = HASH(inet_ntoa(addr->sin_addr), prog);
	head = &(haccess_tbl[hash]);

	TAILQ_FOREACH(hptr, &head->h_head, list) {
		if (hptr->addr.s_addr == addr->sin_addr.s_addr)
			return hptr;
	}
	return NULL;
}

int
good_client(daemon, addr)
char *daemon;
struct sockaddr_in *addr;
{
	struct request_info req;

	request_init(&req, RQ_DAEMON, daemon, RQ_CLIENT_SIN, addr, 0);
	sock_methods(&req);

	if (hosts_access(&req)) 
		return ALLOW;

	return DENY;
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

/* check_files - check to see if either access files have changed */

static int check_files()
{
	static time_t allow_mtime, deny_mtime;
	struct stat astat, dstat;
	int changed = 0;

	if (stat("/etc/hosts.allow", &astat) < 0)
		astat.st_mtime = 0;
	if (stat("/etc/hosts.deny", &dstat) < 0)
		dstat.st_mtime = 0;

	if(!astat.st_mtime || !dstat.st_mtime)
		return changed;

	if (astat.st_mtime != allow_mtime)
		changed = 1;
	else if (dstat.st_mtime != deny_mtime)
		changed = 1;

	allow_mtime = astat.st_mtime;
	deny_mtime = dstat.st_mtime;

	return changed;
}

/* check_default - additional checks for NULL, DUMP, GETPORT and unknown */

int
check_default(daemon, addr, proc, prog)
char *daemon;
struct sockaddr_in *addr;
u_long  proc;
u_long  prog;
{
	haccess_t *acc = NULL;
	int changed = check_files();

	acc = haccess_lookup(addr, prog);
	if (acc && changed == 0)
		return (acc->access);

	if (!(from_local(addr) || good_client(daemon, addr))) {
		log_bad_host(addr, proc, prog);
		if (acc)
			acc->access = FALSE;
		else 
			haccess_add(addr, prog, FALSE);
		return (FALSE);
	}
	if (verboselog)
		log_client(addr, proc, prog);

	if (acc)
		acc->access = TRUE;
	else 
		haccess_add(addr, prog, TRUE);
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
