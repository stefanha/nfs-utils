/*
 * support/export/client.c
 *
 * Maintain list of nfsd clients.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"

/* netgroup stuff never seems to be defined in any header file. Linux is
 * not alone in this.
 */
#if !defined(__GLIBC__) || __GLIBC__ < 2
extern int	innetgr(char *netgr, char *host, char *, char *);
#endif

static char	*add_name(char *old, const char *add);
static int	client_init(nfs_client *clp, const char *hname,
					struct hostent *hp);

nfs_client	*clientlist[MCL_MAXTYPES] = { NULL, };


static void
init_addrlist(nfs_client *clp, const struct hostent *hp)
{
	char **ap;
	int i;

	if (hp == NULL)
		return;

	ap = hp->h_addr_list;
	for (i = 0; *ap != NULL && i < NFSCLNT_ADDRMAX; i++, ap++)
		clp->m_addrlist[i] = *(struct in_addr *)*ap;

	clp->m_naddr = i;
}

static void
client_free(nfs_client *clp)
{
	free(clp->m_hostname);
	free(clp);
}

/* if canonical is set, then we *know* this is already a canonical name
 * so hostname lookup is avoided.
 * This is used when reading /proc/fs/nfs/exports
 */
nfs_client *
client_lookup(char *hname, int canonical)
{
	nfs_client	*clp = NULL;
	int		htype;
	struct hostent	*hp = NULL;

	htype = client_gettype(hname);

	if (htype == MCL_FQDN && !canonical) {
		struct hostent *hp2;
		hp = gethostbyname(hname);
		if (hp == NULL || hp->h_addrtype != AF_INET) {
			xlog(L_ERROR, "%s has non-inet addr", hname);
			return NULL;
		}
		/* make sure we have canonical name */
		hp2 = hostent_dup(hp);
		hp = gethostbyaddr(hp2->h_addr, hp2->h_length,
				   hp2->h_addrtype);
		if (hp) {
			hp = hostent_dup(hp);
			/* but now we might not have all addresses... */
			if (hp2->h_addr_list[1]) {
				struct hostent *hp3 =
					gethostbyname(hp->h_name);
				if (hp3) {
					free(hp);
					hp = hostent_dup(hp3);
				}
			}
			free(hp2);
		} else
			hp = hp2;

		hname = (char *) hp->h_name;

		for (clp = clientlist[htype]; clp; clp = clp->m_next) {
			if (client_check(clp, hp))
				break;
		}
	} else {
		for (clp = clientlist[htype]; clp; clp = clp->m_next) {
			if (strcasecmp(hname, clp->m_hostname)==0)
				break;
		}
	}

	if (clp == NULL) {
		clp = calloc(1, sizeof(*clp));
		if (clp == NULL)
			goto out;
		clp->m_type = htype;
		if (!client_init(clp, hname, NULL)) {
			client_free(clp);
			clp = NULL;
			goto out;
		}
		client_add(clp);
	}

	if (htype == MCL_FQDN && clp->m_naddr == 0)
		init_addrlist(clp, hp);

out:
	if (hp)
		free (hp);

	return clp;
}

nfs_client *
client_dup(nfs_client *clp, struct hostent *hp)
{
	nfs_client		*new;

	new = (nfs_client *)malloc(sizeof(*new));
	if (new == NULL)
		return NULL;
	memcpy(new, clp, sizeof(*new));
	new->m_type = MCL_FQDN;
	new->m_hostname = NULL;

	if (!client_init(new, hp->h_name, hp)) {
		client_free(new);
		return NULL;
	}
	client_add(new);
	return new;
}

static int
client_init(nfs_client *clp, const char *hname, struct hostent *hp)
{
	clp->m_hostname = strdup(hname);
	if (clp->m_hostname == NULL)
		return 0;

	clp->m_exported = 0;
	clp->m_count = 0;
	clp->m_naddr = 0;

	if (clp->m_type == MCL_SUBNETWORK) {
		char	*cp = strchr(clp->m_hostname, '/');
		static char slash32[] = "/32";

		if(!cp) cp = slash32;
		*cp = '\0';
		clp->m_addrlist[0].s_addr = inet_addr(clp->m_hostname);
		if (strchr(cp + 1, '.')) {
			clp->m_addrlist[1].s_addr = inet_addr(cp+1);
		}
		else {
			int netmask = atoi(cp + 1);
			if (0 < netmask && netmask <= 32) {
				clp->m_addrlist[1].s_addr =
					htonl ((uint32_t) ~0 << (32 - netmask));
			}
			else {
				xlog(L_ERROR, "invalid netmask `%s' for %s",
					     cp + 1, clp->m_hostname);
				return 0;
			}
		}
		*cp = '/';
		return 1;
	}
	
	init_addrlist(clp, hp);
	return 1;
}

void
client_add(nfs_client *clp)
{
	nfs_client	**cpp;

	if (clp->m_type < 0 || clp->m_type >= MCL_MAXTYPES)
		xlog(L_FATAL, "unknown client type in client_add");
	cpp = clientlist + clp->m_type;
	while (*cpp)
		cpp = &((*cpp)->m_next);
	clp->m_next = NULL;
	*cpp = clp;
}

void
client_release(nfs_client *clp)
{
	if (clp->m_count <= 0)
		xlog(L_FATAL, "client_free: m_count <= 0!");
	clp->m_count--;
}

void
client_freeall(void)
{
	nfs_client	*clp, **head;
	int		i;

	for (i = 0; i < MCL_MAXTYPES; i++) {
		head = clientlist + i;
		while (*head) {
			*head = (clp = *head)->m_next;
			client_free(clp);
		}
	}
}

struct hostent *
client_resolve(struct in_addr addr)
{
	struct hostent *he = NULL;

	if (clientlist[MCL_WILDCARD] || clientlist[MCL_NETGROUP])
		he = get_reliable_hostbyaddr((const char*)&addr, sizeof(addr), AF_INET);
	if (he == NULL)
		he = get_hostent((const char*)&addr, sizeof(addr), AF_INET);

	return he;
}

/**
 * client_compose - Make a list of cached hostnames that match an IP address
 * @he: pointer to hostent containing IP address information to match
 *
 * Gather all known client hostnames that match the IP address, and sort
 * the result into a comma-separated list.
 *
 * Returns a '\0'-terminated ASCII string containing a comma-separated
 * sorted list of client hostnames, or NULL if no client records matched
 * the IP address or memory could not be allocated.  Caller must free the
 * returned string with free(3).
 */
char *
client_compose(struct hostent *he)
{
	char *name = NULL;
	int i;

	for (i = 0 ; i < MCL_MAXTYPES; i++) {
		nfs_client	*clp;
		for (clp = clientlist[i]; clp ; clp = clp->m_next) {
			if (!client_check(clp, he))
				continue;
			name = add_name(name, clp->m_hostname);
		}
	}
	return name;
}

/**
 * client_member - check if @name is contained in the list @client
 * @client: '\0'-terminated ASCII string containing
 *		comma-separated list of hostnames
 * @name: '\0'-terminated ASCII string containing hostname to look for
 *
 * Returns 1 if @name was found in @client, otherwise zero is returned.
 */
int
client_member(const char *client, const char *name)
{
	size_t l = strlen(name);

	while (*client) {
		if (strncmp(client, name, l) == 0 &&
		    (client[l] == ',' || client[l] == '\0'))
			return 1;
		client = strchr(client, ',');
		if (client == NULL)
			return 0;
		client++;
	}
	return 0;
}

static int
name_cmp(const char *a, const char *b)
{
	/* compare strings a and b, but only upto ',' in a */
	while (*a && *b && *a != ',' && *a == *b)
		a++, b++;
	if (!*b && (!*a || *a == ','))
		return 0;
	if (!*b) return 1;
	if (!*a || *a == ',') return -1;
	return *a - *b;
}

static char *
add_name(char *old, const char *add)
{
	size_t len = strlen(add) + 2;
	char *new;
	char *cp;
	if (old) len += strlen(old);
	
	new = malloc(len);
	if (!new) {
		free(old);
		return NULL;
	}
	cp = old;
	while (cp && *cp && name_cmp(cp, add) < 0) {
		/* step cp forward over a name */
		char *e = strchr(cp, ',');
		if (e)
			cp = e+1;
		else
			cp = cp + strlen(cp);
	}
	strncpy(new, old, cp-old);
	new[cp-old] = 0;
	if (cp != old && !*cp)
		strcat(new, ",");
	strcat(new, add);
	if (cp && *cp) {
		strcat(new, ",");
		strcat(new, cp);
	}
	free(old);
	return new;
}

/*
 * Check each address listed in @hp against each address
 * stored in @clp.  Return 1 if a match is found, otherwise
 * zero.
 */
static int
check_fqdn(const nfs_client *clp, const struct hostent *hp)
{
	struct in_addr addr;
	char **ap;
	int i;

	for (ap = hp->h_addr_list; *ap; ap++) {
		addr = *(struct in_addr *)*ap;

		for (i = 0; i < clp->m_naddr; i++)
			if (clp->m_addrlist[i].s_addr == addr.s_addr)
				return 1;
	}
	return 0;
}

/*
 * Check each address listed in @hp against the subnetwork or
 * host address stored in @clp.  Return 1 if an address in @hp
 * matches the host address stored in @clp, otherwise zero.
 */
static int
check_subnetwork(const nfs_client *clp, const struct hostent *hp)
{
	struct in_addr addr;
	char **ap;

	for (ap = hp->h_addr_list; *ap; ap++) {
		addr = *(struct in_addr *)*ap;

		if (!((clp->m_addrlist[0].s_addr ^ addr.s_addr) &
		      clp->m_addrlist[1].s_addr))
			return 1;
	}
	return 0;
}

/*
 * Check if a wildcard nfs_client record matches the canonical name
 * or the aliases of a host.  Return 1 if a match is found, otherwise
 * zero.
 */
static int
check_wildcard(const nfs_client *clp, const struct hostent *hp)
{
	char *cname = clp->m_hostname;
	char *hname = hp->h_name;
	char **ap;

	if (wildmat(hname, cname))
		return 1;

	/* See if hname aliases listed in /etc/hosts or nis[+]
	 * match the requested wildcard */
	for (ap = hp->h_aliases; *ap; ap++) {
		if (wildmat(*ap, cname))
			return 1;
	}

	return 0;
}

/*
 * Check if @hp's hostname or aliases fall in a given netgroup.
 * Return 1 if @hp represents a host in the netgroup, otherwise zero.
 */
#ifdef HAVE_INNETGR
static int
check_netgroup(const nfs_client *clp, const struct hostent *hp)
{
	const char *netgroup = clp->m_hostname + 1;
	const char *hname = hp->h_name;
	struct hostent *nhp = NULL;
	struct sockaddr_in addr;
	int match, i;
	char *dot;

	/* First, try to match the hostname without
	 * splitting off the domain */
	if (innetgr(netgroup, hname, NULL, NULL))
		return 1;

	/* See if hname aliases listed in /etc/hosts or nis[+]
	 * match the requested netgroup */
	for (i = 0; hp->h_aliases[i]; i++) {
		if (innetgr(netgroup, hp->h_aliases[i], NULL, NULL))
			return 1;
	}

	/* If hname is ip address convert to FQDN */
	if (inet_aton(hname, &addr.sin_addr) &&
	   (nhp = gethostbyaddr((const char *)&(addr.sin_addr),
	    sizeof(addr.sin_addr), AF_INET))) {
		hname = nhp->h_name;
		if (innetgr(netgroup, hname, NULL, NULL))
			return 1;
	}

	/* Okay, strip off the domain (if we have one) */
	dot = strchr(hname, '.');
	if (dot == NULL)
		return 0;

	*dot = '\0';
	match = innetgr(netgroup, hname, NULL, NULL);
	*dot = '.';

	return match;
}
#else	/* !HAVE_INNETGR */
static int
check_netgroup(__attribute__((unused)) const nfs_client *clp,
		__attribute__((unused)) const struct hostent *hp)
{
	return 0;
}
#endif	/* !HAVE_INNETGR */

/**
 * client_check - check if IP address information matches a cached nfs_client
 * @clp: pointer to a cached nfs_client record
 * @hp: pointer to hostent containing host IP information
 *
 * Returns 1 if the address information matches the cached nfs_client,
 * otherwise zero.
 */
int
client_check(nfs_client *clp, struct hostent *hp)
{
	switch (clp->m_type) {
	case MCL_FQDN:
		return check_fqdn(clp, hp);
	case MCL_SUBNETWORK:
		return check_subnetwork(clp, hp);
	case MCL_WILDCARD:
		return check_wildcard(clp, hp);
	case MCL_NETGROUP:
		return check_netgroup(clp, hp);
	case MCL_ANONYMOUS:
		return 1;
	case MCL_GSS:
		return 0;
	default:
		xlog(D_GENERAL, "%s: unrecognized client type: %d",
				__func__, clp->m_type);
	}

	return 0;
}

int
client_gettype(char *ident)
{
	char	*sp;

	if (ident[0] == '\0' || strcmp(ident, "*")==0)
		return MCL_ANONYMOUS;
	if (strncmp(ident, "gss/", 4) == 0)
		return MCL_GSS;
	if (ident[0] == '@') {
#ifndef HAVE_INNETGR
		xlog(L_WARNING, "netgroup support not compiled in");
#endif
		return MCL_NETGROUP;
	}
	for (sp = ident; *sp; sp++) {
		if (*sp == '*' || *sp == '?' || *sp == '[')
			return MCL_WILDCARD;
		if (*sp == '/')
			return MCL_SUBNETWORK;
		if (*sp == '\\' && sp[1])
			sp++;
	}
	/* check for N.N.N.N */
	sp = ident;
	if(!isdigit(*sp) || strtoul(sp, &sp, 10) > 255 || *sp != '.') return MCL_FQDN;
	sp++; if(!isdigit(*sp) || strtoul(sp, &sp, 10) > 255 || *sp != '.') return MCL_FQDN;
	sp++; if(!isdigit(*sp) || strtoul(sp, &sp, 10) > 255 || *sp != '.') return MCL_FQDN;
	sp++; if(!isdigit(*sp) || strtoul(sp, &sp, 10) > 255 || *sp != '\0') return MCL_FQDN;
	/* we lie here a bit. but technically N.N.N.N == N.N.N.N/32 :) */
	return MCL_SUBNETWORK;
}
