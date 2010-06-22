/*
 * support/export/hostname.c
 *
 * Functions for hostname.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*
#define TEST
*/

#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>

#include <xlog.h>
#ifdef TEST
#define xmalloc malloc
#else
#include "xmalloc.h"
#include "misc.h"
#endif

#include "sockaddr.h"
#include "exportfs.h"

#ifndef HAVE_DECL_AI_ADDRCONFIG
#define AI_ADDRCONFIG	0
#endif

#define ALIGNMENT	sizeof (char *)

static int
align (int len, int al)
{
  int i;
  i = len % al;
  if (i)
    len += al - i;
  return len;
}

struct hostent *
get_hostent (const char *addr, int len, int type)
{
  struct hostent *cp;
  int len_ent;
  const char *name;
  int len_name;
  int num_aliases = 1;
  int len_aliases = sizeof (char *);
  int num_addr_list = 1;
  int len_addr_list = sizeof (char *);
  int pos;
  struct in_addr *ipv4;

  switch (type)
    {
    case AF_INET:
      ipv4 = (struct in_addr *) addr;
      name = inet_ntoa (*ipv4);
      break;

    default:
      return NULL;
    }

  len_ent = align (sizeof (*cp), ALIGNMENT);
  len_name = align (strlen (name) + 1, ALIGNMENT);

  num_addr_list++;
  len_addr_list += align (len, ALIGNMENT) + sizeof (char *);

  cp = (struct hostent *) xmalloc (len_ent + len_name + len_aliases
				   + len_addr_list);

  cp->h_addrtype = type;
  cp->h_length = len;
  pos = len_ent;
  cp->h_name = (char *) &(((char *) cp) [pos]);
  strcpy (cp->h_name, name);

  pos += len_name;
  cp->h_aliases = (char **) &(((char *) cp) [pos]);
  pos += num_aliases * sizeof (char *);
  cp->h_aliases [0] = NULL;

  pos = len_ent + len_name + len_aliases;
  cp->h_addr_list = (char **) &(((char *) cp) [pos]);
  pos += num_addr_list * sizeof (char *);
  cp->h_addr_list [0] = (char *) &(((char *) cp) [pos]);
  memcpy (cp->h_addr_list [0], addr, cp->h_length);
  pos += align (cp->h_length, ALIGNMENT);
  cp->h_addr_list [1] = NULL;

  return cp;
}

struct hostent *
hostent_dup (struct hostent *hp)
{
  int len_ent = align (sizeof (*hp), ALIGNMENT);
  int len_name = align (strlen (hp->h_name) + 1, ALIGNMENT);
  int num_aliases = 1;
  int len_aliases = sizeof (char *);
  int num_addr_list = 1;
  int len_addr_list = sizeof (char *);
  int pos, i;
  char **sp;
  struct hostent *cp;

  for (sp = hp->h_aliases; sp && *sp; sp++)
    {
      num_aliases++;
      len_aliases += align (strlen (*sp) + 1, ALIGNMENT)
		     + sizeof (char *);
    }

  for (sp = hp->h_addr_list; *sp; sp++)
    {
      num_addr_list++;
      len_addr_list += align (hp->h_length, ALIGNMENT)
		       + sizeof (char *);
    }

  cp = (struct hostent *) xmalloc (len_ent + len_name + len_aliases
				   + len_addr_list);

  *cp = *hp;
  pos = len_ent;
  cp->h_name = (char *) &(((char *) cp) [pos]);
  strcpy (cp->h_name, hp->h_name);

  pos += len_name;
  cp->h_aliases = (char **) &(((char *) cp) [pos]);
  pos += num_aliases * sizeof (char *);
  for (sp = hp->h_aliases, i = 0; i < num_aliases; i++, sp++)
    if (sp && *sp)
      {
	cp->h_aliases [i] = (char *) &(((char *) cp) [pos]);
	strcpy (cp->h_aliases [i], *sp);
	pos += align (strlen (*sp) + 1, ALIGNMENT);
      }
    else
      cp->h_aliases [i] = NULL;

  pos = len_ent + len_name + len_aliases;
  cp->h_addr_list = (char **) &(((char *) cp) [pos]);
  pos += num_addr_list * sizeof (char *);
  for (sp = hp->h_addr_list, i = 0; i < num_addr_list; i++, sp++)
    if (*sp)
      {
	cp->h_addr_list [i] = (char *) &(((char *) cp) [pos]);
	memcpy (cp->h_addr_list [i], *sp, hp->h_length);
	pos += align (hp->h_length, ALIGNMENT);
      }
    else
      cp->h_addr_list [i] = *sp;

  return cp;
}

#ifdef HAVE_GETNAMEINFO
static socklen_t
sockaddr_size(const struct sockaddr *sap)
{
	if (sap->sa_family != AF_INET)
		return 0;
	return (socklen_t)sizeof(struct sockaddr_in);
}
#endif	/* HAVE_GETNAMEINFO */

/**
 * host_ntop - generate presentation address given a sockaddr
 * @sap: pointer to socket address
 * @buf: working storage
 * @buflen: size of @buf in bytes
 *
 * Returns a pointer to a @buf.
 */
#ifdef HAVE_GETNAMEINFO
char *
host_ntop(const struct sockaddr *sap, char *buf, const size_t buflen)
{
	socklen_t salen = sockaddr_size(sap);
	int error;

	memset(buf, 0, buflen);

	if (salen == 0) {
		(void)strncpy(buf, "bad family", buflen - 1);
		return buf;
	}

	error = getnameinfo(sap, salen, buf, (socklen_t)buflen,
						NULL, 0, NI_NUMERICHOST);
	if (error != 0) {
		buf[0] = '\0';
		(void)strncpy(buf, "bad address", buflen - 1);
	}

	return buf;
}
#else	/* !HAVE_GETNAMEINFO */
char *
host_ntop(const struct sockaddr *sap, char *buf, const size_t buflen)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)(char *)sap;

	memset(buf, 0, buflen);

	if (sin->sin_family != AF_INET)
		(void)strncpy(buf, "bad family", buflen - 1);
		return buf;
	}

	if (inet_ntop(AF_INET, &sin->sin_addr.s_addr, buf, buflen) != NULL)
		return buf;

	buf[0] = '\0';
	(void)strncpy(buf, "bad address", buflen - 1);
	return buf;
}
#endif	/* !HAVE_GETNAMEINFO */

/**
 * host_pton - return addrinfo for a given presentation address
 * @paddr: pointer to a '\0'-terminated ASCII string containing an
 *		IP presentation address
 *
 * Returns address info structure, or NULL if an error occurs.  Caller
 * must free the returned structure with freeaddrinfo(3).
 */
__attribute_malloc__
struct addrinfo *
host_pton(const char *paddr)
{
	struct addrinfo *ai = NULL;
	struct addrinfo hint = {
		/* don't return duplicates */
		.ai_protocol	= (int)IPPROTO_UDP,
		.ai_flags	= AI_NUMERICHOST,
		.ai_family	= AF_UNSPEC,
	};
	struct sockaddr_in sin;
	int error;

	/*
	 * Although getaddrinfo(3) is easier to use and supports
	 * IPv6, it recognizes incomplete addresses like "10.4"
	 * as valid AF_INET addresses.  It also accepts presentation
	 * addresses that end with a blank.
	 *
	 * inet_pton(3) is much stricter.  Use it to be certain we
	 * have a real AF_INET presentation address, before invoking
	 * getaddrinfo(3) to generate the full addrinfo list.
	 */
	if (inet_pton(AF_INET, paddr, &sin.sin_addr) == 0)
		return NULL;

	error = getaddrinfo(paddr, NULL, &hint, &ai);
	switch (error) {
	case 0:
		return ai;
	case EAI_NONAME:
		if (paddr == NULL)
			xlog(D_GENERAL, "%s: passed a NULL presentation address",
				__func__);
		break;
	case EAI_SYSTEM:
		xlog(D_GENERAL, "%s: failed to convert %s: (%d) %m",
				__func__, paddr, errno);
		break;
	default:
		xlog(D_GENERAL, "%s: failed to convert %s: %s",
				__func__, paddr, gai_strerror(error));
		break;
	}

	return NULL;
}

/**
 * host_addrinfo - return addrinfo for a given hostname
 * @hostname: pointer to a '\0'-terminated ASCII string containing a hostname
 *
 * Returns address info structure with ai_canonname filled in, or NULL
 * if no information is available for @hostname.  Caller must free the
 * returned structure with freeaddrinfo(3).
 */
__attribute_malloc__
struct addrinfo *
host_addrinfo(const char *hostname)
{
	struct addrinfo *ai = NULL;
	struct addrinfo hint = {
		.ai_family	= AF_INET,
		/* don't return duplicates */
		.ai_protocol	= (int)IPPROTO_UDP,
		.ai_flags	= AI_ADDRCONFIG | AI_CANONNAME,
	};
	int error;

	error = getaddrinfo(hostname, NULL, &hint, &ai);
	switch (error) {
	case 0:
		return ai;
	case EAI_SYSTEM:
		xlog(D_GENERAL, "%s: failed to resolve %s: (%d) %m",
				__func__, hostname, errno);
		break;
	default:
		xlog(D_GENERAL, "%s: failed to resolve %s: %s",
				__func__, hostname, gai_strerror(error));
		break;
	}

	return NULL;
}

/**
 * host_canonname - return canonical hostname bound to an address
 * @sap: pointer to socket address to look up
 *
 * Discover the canonical hostname associated with the given socket
 * address.  The host's reverse mapping is verified in the process.
 *
 * Returns a '\0'-terminated ASCII string containing a hostname, or
 * NULL if no hostname can be found for @sap.  Caller must free
 * the string.
 */
#ifdef HAVE_GETNAMEINFO
__attribute_malloc__
char *
host_canonname(const struct sockaddr *sap)
{
	socklen_t salen = sockaddr_size(sap);
	char buf[NI_MAXHOST];
	int error;

	if (salen == 0) {
		xlog(D_GENERAL, "%s: unsupported address family %d",
				__func__, sap->sa_family);
		return NULL;
	}

	memset(buf, 0, sizeof(buf));
	error = getnameinfo(sap, salen, buf, (socklen_t)sizeof(buf),
							NULL, 0, NI_NAMEREQD);
	switch (error) {
	case 0:
		break;
	case EAI_SYSTEM:
		xlog(D_GENERAL, "%s: getnameinfo(3) failed: (%d) %m",
				__func__, errno);
		return NULL;
	default:
		(void)getnameinfo(sap, salen, buf, (socklen_t)sizeof(buf),
							NULL, 0, NI_NUMERICHOST);
		xlog(D_GENERAL, "%s: failed to resolve %s: %s",
				__func__, buf, gai_strerror(error));
		return NULL;
	}

	return strdup(buf);
}
#else	/* !HAVE_GETNAMEINFO */
__attribute_malloc__
char *
host_canonname(const struct sockaddr *sap)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)(char *)sap;
	const struct in_addr *addr = &sin->sin_addr;
	struct hostent *hp;

	if (sap->sa_family != AF_INET)
		return NULL;

	hp = gethostbyaddr(addr, (socklen_t)sizeof(addr), AF_INET);
	if (hp == NULL)
		return NULL;

	return strdup(hp->h_name);
}
#endif	/* !HAVE_GETNAMEINFO */

/**
 * host_reliable_addrinfo - return addrinfo for a given address
 * @sap: pointer to socket address to look up
 *
 * Reverse and forward lookups are performed to ensure the address has
 * proper forward and reverse mappings.
 *
 * Returns address info structure with ai_canonname filled in, or NULL
 * if no information is available for @sap.  Caller must free the returned
 * structure with freeaddrinfo(3).
 */
__attribute_malloc__
struct addrinfo *
host_reliable_addrinfo(const struct sockaddr *sap)
{
	struct addrinfo *ai;
	char *hostname;

	hostname = host_canonname(sap);
	if (hostname == NULL)
		return NULL;

	ai = host_addrinfo(hostname);

	free(hostname);
	return ai;
}

/**
 * host_numeric_addrinfo - return addrinfo without doing DNS queries
 * @sap: pointer to socket address
 *
 * Returns address info structure, or NULL if an error occurred.
 * Caller must free the returned structure with freeaddrinfo(3).
 */
#ifdef HAVE_GETNAMEINFO
__attribute_malloc__
struct addrinfo *
host_numeric_addrinfo(const struct sockaddr *sap)
{
	socklen_t salen = sockaddr_size(sap);
	char buf[INET_ADDRSTRLEN];
	struct addrinfo *ai;
	int error;

	if (salen == 0) {
		xlog(D_GENERAL, "%s: unsupported address family %d",
				__func__, sap->sa_family);
		return NULL;
	}

	memset(buf, 0, sizeof(buf));
	error = getnameinfo(sap, salen, buf, (socklen_t)sizeof(buf),
						NULL, 0, NI_NUMERICHOST);
	switch (error) {
	case 0:
		break;
	case EAI_SYSTEM:
		xlog(D_GENERAL, "%s: getnameinfo(3) failed: (%d) %m",
				__func__, errno);
		return NULL;
	default:
		xlog(D_GENERAL, "%s: getnameinfo(3) failed: %s",
				__func__, gai_strerror(error));
		return NULL;
	}

	ai = host_pton(buf);

	/*
	 * getaddrinfo(AI_NUMERICHOST) never fills in ai_canonname
	 */
	if (ai != NULL) {
		free(ai->ai_canonname);		/* just in case */
		ai->ai_canonname = strdup(buf);
		if (ai->ai_canonname == NULL) {
			freeaddrinfo(ai);
			ai = NULL;
		}
	}

	return ai;
}
#else	/* !HAVE_GETNAMEINFO */
__attribute_malloc__
struct addrinfo *
host_numeric_addrinfo(const struct sockaddr *sap)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sap;
	const struct in_addr *addr = &sin->sin_addr;
	char buf[INET_ADDRSTRLEN];
	struct addrinfo *ai;

	if (sap->sa_family != AF_INET)
		return NULL;

	memset(buf, 0, sizeof(buf));
	if (inet_ntop(AF_INET, (char *)addr, buf,
					(socklen_t)sizeof(buf)) == NULL)
		return NULL;

	ai = host_pton(buf);

	/*
	 * getaddrinfo(AI_NUMERICHOST) never fills in ai_canonname
	 */
	if (ai != NULL) {
		ai->ai_canonname = strdup(buf);
		if (ai->ai_canonname == NULL) {
			freeaddrinfo(ai);
			ai = NULL;
		}
	}

	return ai;
}
#endif	/* !HAVE_GETNAMEINFO */

static int
is_hostname(const char *sp)
{
  if (*sp == '\0' || *sp == '@')
    return 0;

  for (; *sp; sp++)
    {
      if (*sp == '*' || *sp == '?' || *sp == '[' || *sp == '/')
	return 0;
      if (*sp == '\\' && sp[1])
	sp++;
    }

  return 1;
}

int
matchhostname (const char *h1, const char *h2)
{
  struct hostent *hp1, *hp2;
  int status;

  if (strcasecmp (h1, h2) == 0)
    return 1;

  if (!is_hostname (h1) || !is_hostname (h2))
    return 0;

  hp1 = gethostbyname (h1);
  if (hp1 == NULL)
    return 0;

  hp1 = hostent_dup (hp1);

  hp2 = gethostbyname (h2);
  if (hp2)
    {
      if (strcasecmp (hp1->h_name, hp2->h_name) == 0)
	status = 1;
      else
	{
	  char **ap1, **ap2;

	  status = 0;
	  for (ap1 = hp1->h_addr_list; *ap1 && status == 0; ap1++)
	    for (ap2 = hp2->h_addr_list; *ap2; ap2++)
	      if (memcmp (*ap1, *ap2, sizeof (struct in_addr)) == 0)
		{
		  status = 1;
		  break;
		}
	}
    }
  else
    status = 0;

  free (hp1);
  return status;
}


/* Map IP to hostname, and then map back to addr to make sure it is a
 * reliable hostname
 */
struct hostent *
get_reliable_hostbyaddr(const char *addr, int len, int type)
{
	struct hostent *hp = NULL;

	struct hostent *reverse;
	struct hostent *forward;
	char **sp;

	reverse = gethostbyaddr (addr, len, type);
	if (!reverse)
		return NULL;

	/* must make sure the hostent is authorative. */

	reverse = hostent_dup (reverse);
	forward = gethostbyname (reverse->h_name);

	if (forward) {
		/* now make sure the "addr" is in the list */
		for (sp = forward->h_addr_list ; *sp ; sp++) {
			if (memcmp (*sp, addr, forward->h_length) == 0)
				break;
		}

		if (*sp) {
			/* it's valid */
			hp = hostent_dup (forward);
		}
		else {
			/* it was a FAKE */
			xlog (L_WARNING, "Fake hostname %s for %s - forward lookup doesn't match reverse",
			      reverse->h_name, inet_ntoa(*(struct in_addr*)addr));
		}
	}
	else {
		/* never heard of it. misconfigured DNS? */
		xlog (L_WARNING, "Fake hostname %s for %s - forward lookup doesn't exist",
		      reverse->h_name, inet_ntoa(*(struct in_addr*)addr));
	}

	free (reverse);
	return hp;
}


#ifdef TEST
void
print_host (struct hostent *hp)
{
  char **sp;

  if (hp)
    {
      printf ("official hostname: %s\n", hp->h_name);
      printf ("aliases:\n");
      for (sp = hp->h_aliases; *sp; sp++)
	printf ("  %s\n", *sp);
      printf ("IP addresses:\n");
      for (sp = hp->h_addr_list; *sp; sp++)
	printf ("  %s\n", inet_ntoa (*(struct in_addr *) *sp));
    }
  else
    printf ("Not host information\n");
}

int
main (int argc, char **argv)
{
  struct hostent *hp = gethostbyname (argv [1]);
  struct hostent *cp;
  struct in_addr addr;

  print_host (hp);

  if (hp)
    {
      cp = hostent_dup (hp);
      print_host (cp);
      free (cp);
    }
  printf ("127.0.0.1 == %s: %d\n", argv [1],
	  matchhostname ("127.0.0.1", argv [1]));
  addr.s_addr = inet_addr(argv [2]);
  printf ("%s\n", inet_ntoa (addr));
  cp = get_hostent ((const char *)&addr, sizeof(addr), AF_INET);
  print_host (cp);
  return 0;
}
#endif
