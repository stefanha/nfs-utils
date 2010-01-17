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

#ifdef HAVE_LIBWRAP
#include <unistd.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <tcpd.h>

#include "tcpwrapper.h"
#include "xlog.h"

#ifdef SYSV40
#include <netinet/in.h>
#include <rpc/rpcent.h>
#endif

static int check_files(void);

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

static unsigned long
strtoint(const char *str)
{
	unsigned long i, n = 0;
	size_t len = strlen(str);

	for (i = 0; i < len; i++)
		n += (unsigned char)str[i] * i;

	return n;
}

static unsigned int
hashint(const unsigned long num)
{
	return (unsigned int)(num % HASH_TABLE_SIZE);
}

static unsigned int
HASH(const char *addr, const unsigned long program)
{
	return hashint(strtoint(addr) + program);
}

void haccess_add(struct sockaddr_in *addr, u_long prog, int access)
{
	hash_head *head;
	haccess_t *hptr;
	unsigned int hash;

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
	unsigned int hash;

	hash = HASH(inet_ntoa(addr->sin_addr), prog);
	head = &(haccess_tbl[hash]);

	TAILQ_FOREACH(hptr, &head->h_head, list) {
		if (hptr->addr.s_addr == addr->sin_addr.s_addr)
			return hptr;
	}
	return NULL;
}

static void
logit(const struct sockaddr_in *sin)
{
	char buf[INET_ADDRSTRLEN];

	xlog_warn("connect from %s denied: request from unauthorized host",
			inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)));
		
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

/**
 * check_default - additional checks for NULL, DUMP, GETPORT and unknown
 * @daemon: pointer to '\0'-terminated ASCII string containing name of the
 *		daemon requesting the access check
 * @addr: pointer to socket address containing address of caller
 * @prog: RPC program number caller is attempting to access
 *
 * Returns TRUE if the caller is allowed access; otherwise FALSE is returned.
 */
int
check_default(char *daemon, struct sockaddr_in *addr, u_long prog)
{
	haccess_t *acc = NULL;
	int changed = check_files();

	acc = haccess_lookup(addr, prog);
	if (acc && changed == 0)
		return (acc->access);

	if (!(from_local((struct sockaddr *)addr) || good_client(daemon, addr))) {
		logit(addr);
		if (acc)
			acc->access = FALSE;
		else 
			haccess_add(addr, prog, FALSE);
		return (FALSE);
	}

	if (acc)
		acc->access = TRUE;
	else 
		haccess_add(addr, prog, TRUE);

    return (TRUE);
}

#endif	/* HAVE_LIBWRAP */
