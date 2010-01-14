/*
 * Copyright 2009 Oracle.  All rights reserved.
 *
 * This file is part of nfs-utils.
 *
 * nfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * nfs-utils is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nfs-utils.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * NSM for Linux.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <netdb.h>

#include "sockaddr.h"
#include "statd.h"
#include "xlog.h"

/*
 * Look up the hostname; report exceptional errors.  Caller must
 * call freeaddrinfo(3) if a valid addrinfo is returned.
 */
__attribute_malloc__
static struct addrinfo *
get_addrinfo(const char *hostname, const struct addrinfo *hint)
{
	struct addrinfo *ai = NULL;
	int error;

	error = getaddrinfo(hostname, NULL, hint, &ai);
	switch (error) {
	case 0:
		return ai;
	case EAI_NONAME:
		break;
	default:
		xlog(D_GENERAL, "%s: failed to resolve host %s: %s",
				__func__, hostname, gai_strerror(error));
	}

	return NULL;
}

/**
 * statd_matchhostname - check if two hostnames are equivalent
 * @hostname1: C string containing hostname
 * @hostname2: C string containing hostname
 *
 * Returns true if the hostnames are the same, the hostnames resolve
 * to the same canonical name, or the hostnames resolve to at least
 * one address that is the same.  False is returned if the hostnames
 * do not match in any of these ways, if either hostname contains
 * wildcard characters, if either hostname is a netgroup name, or
 * if an error occurs.
 */
_Bool
statd_matchhostname(const char *hostname1, const char *hostname2)
{
	struct addrinfo *ai1, *ai2, *results1 = NULL, *results2 = NULL;
	struct addrinfo hint = {
		.ai_family	= AF_UNSPEC,
		.ai_flags	= AI_CANONNAME,
		.ai_protocol	= (int)IPPROTO_UDP,
	};
	_Bool result = false;

	if (strcasecmp(hostname1, hostname2) == 0) {
		result = true;
		goto out;
	}

	results1 = get_addrinfo(hostname1, &hint);
	if (results1 == NULL)
		goto out;
	results2 = get_addrinfo(hostname2, &hint);
	if (results2 == NULL)
		goto out;

	if (strcasecmp(results1->ai_canonname, results2->ai_canonname) == 0) {
		result = true;
		goto out;
	}

	for (ai1 = results1; ai1 != NULL; ai1 = ai1->ai_next)
		for (ai2 = results2; ai2 != NULL; ai2 = ai2->ai_next)
			if (nfs_compare_sockaddr(ai1->ai_addr, ai2->ai_addr)) {
				result = true;
				break;
			}

out:
	freeaddrinfo(results2);
	freeaddrinfo(results1);

	xlog(D_CALL, "%s: hostnames %s", __func__,
			(result ? "matched" : "did not match"));
	return result;
}
