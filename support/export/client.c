/*
 * support/export/client.c
 *
 * Maintain list of nfsd clients.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "xmalloc.h"
#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"

/* netgroup stuff never seems to be defined in any header file. Linux is
 * not alone in this.
 */
#if !defined(__GLIBC__) || __GLIBC__ < 2
extern int	innetgr(char *netgr, char *host, char *, char *);
#endif
static void	client_init(nfs_client *clp, const char *hname,
					struct hostent *hp);
static int	client_checkaddr(nfs_client *clp, struct in_addr addr);

nfs_client	*clientlist[MCL_MAXTYPES] = { NULL, };


nfs_client *
client_lookup(char *hname)
{
	nfs_client	*clp = NULL;
	int		htype;
	struct hostent	*hp = NULL;

	htype = client_gettype(hname);

	if (htype == MCL_FQDN) {
		hp = gethostbyname(hname);
		if (hp == NULL || hp->h_addrtype != AF_INET) {
			xlog(L_ERROR, "%s has non-inet addr", hname);
			return NULL;
		}
		hp = hostent_dup (hp);
		hname = (char *) hp->h_name;

		for (clp = clientlist[htype]; clp; clp = clp->m_next) {
			if (client_check(clp, hp))
				break;
		}
	} else {
		for (clp = clientlist[htype]; clp; clp = clp->m_next) {
			if (strcmp(hname, clp->m_hostname)==0)
				break;
		}
	}

	if (!clp) {
		clp = (nfs_client *) xmalloc(sizeof(*clp));
		memset(clp, 0, sizeof(*clp));
		clp->m_type = htype;
		client_init(clp, hname, NULL);
		client_add(clp);
	}

	if (htype == MCL_FQDN && clp->m_naddr == 0 && hp != NULL) {
		char	**ap = hp->h_addr_list;
		int	i;

		for (i = 0; *ap && i < NFSCLNT_ADDRMAX; i++, ap++)
			clp->m_addrlist[i] = *(struct in_addr *)*ap;
		clp->m_naddr = i;
	}

	if (hp)
		free (hp);

	return clp;
}

nfs_client *
client_dup(nfs_client *clp, struct hostent *hp)
{
	nfs_client		*new;

	new = (nfs_client *) xmalloc(sizeof(*new));
	memcpy(new, clp, sizeof(*new));
	new->m_type = MCL_FQDN;

	client_init(new, (char *) hp->h_name, hp);
	client_add(new);
	return new;
}

static void
client_init(nfs_client *clp, const char *hname, struct hostent *hp)
{
	if (hp) {
		strncpy(clp->m_hostname, hp->h_name,
			sizeof (clp->m_hostname) -  1);
	} else {
		strncpy(clp->m_hostname, hname,
			sizeof (clp->m_hostname) - 1);
	}
	clp->m_hostname[sizeof (clp->m_hostname) - 1] = '\0';

	clp->m_exported = 0;
	clp->m_count = 0;

	if (clp->m_type == MCL_SUBNETWORK) {
		char	*cp = strchr(clp->m_hostname, '/');

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
				xlog(L_FATAL, "invalid netmask `%s' for %s",
				     cp + 1, clp->m_hostname);
			}
		}
		*cp = '/';
		clp->m_naddr = 0;
	} else if (!hp) {
		clp->m_naddr = 0;
	} else {
		char	**ap = hp->h_addr_list;
		int	i;

		for (i = 0; *ap && i < NFSCLNT_ADDRMAX; i++, ap++) {
			clp->m_addrlist[i] = *(struct in_addr *)*ap;
		}
		clp->m_naddr = i;
	}
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
			xfree(clp);
		}
	}
}

nfs_client *
client_find(struct hostent *hp)
{
	nfs_client	*clp;
	int		i;

	for (i = 0; i < MCL_MAXTYPES; i++) {
		for (clp = clientlist[i]; clp; clp = clp->m_next) {
			if (!client_check(clp, hp))
				continue;
#ifdef notdef
			if (clp->m_type == MCL_FQDN)
				return clp;
			return client_dup(clp, hp);
#else
			return clp;
#endif
		}
	}
	return NULL;
}

/*
 * Match a host (given its hostent record) to a client record. This
 * is usually called from mountd.
 */
int
client_check(nfs_client *clp, struct hostent *hp)
{
	char	*hname = (char *) hp->h_name;
	char	*cname = clp->m_hostname;
	char	**ap;

	switch (clp->m_type) {
	case MCL_FQDN:
	case MCL_SUBNETWORK:
		for (ap = hp->h_addr_list; *ap; ap++) {
			if (client_checkaddr(clp, *(struct in_addr *) *ap))
				return 1;
		}
		return 0;
	case MCL_WILDCARD:
		if (wildmat(hname, cname))
			return 1;
		else {
			for (ap = hp->h_aliases; *ap; ap++)
				if (wildmat(*ap, cname))
					return 1;
		}
		return 0;
	case MCL_NETGROUP:
#ifdef HAVE_INNETGR
		{
			char	*dot;
			int	match;

			/* First, try to match the hostname without
			 * splitting off the domain */
			if (innetgr(cname+1, hname, NULL, NULL))
				return 1;

			/* Okay, strip off the domain (if we have one) */
			if ((dot = strchr(hname, '.')) == NULL)
				return 0;

			*dot = '\0';
			match = innetgr(cname+1, hname, NULL, NULL);
			*dot = '.';

			return match;
		}
#else
		return 0;
#endif
	case MCL_ANONYMOUS:
		return 1;
	default:
		xlog(L_FATAL, "internal: bad client type %d", clp->m_type);
	}

	return 0;
}

static int
client_checkaddr(nfs_client *clp, struct in_addr addr)
{
	int	i;

	switch (clp->m_type) {
	case MCL_FQDN:
		for (i = 0; i < clp->m_naddr; i++) {
			if (clp->m_addrlist[i].s_addr == addr.s_addr)
				return 1;
		}
		return 0;
	case MCL_SUBNETWORK:
		return !((clp->m_addrlist[0].s_addr ^ addr.s_addr)
			& clp->m_addrlist[1].s_addr);
	}
	return 0;
}

int
client_gettype(char *ident)
{
	char	*sp;

	if (ident[0] == '\0')
		return MCL_ANONYMOUS;
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
	return MCL_FQDN;
}
