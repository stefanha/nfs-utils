/*
 * keys.c		Key management for nfsd. Currently, keys
 *			are kept in a single file only, but eventually,
 *			support for a key server should be added.
 *
 * Copyright (C) 1995 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/stat.h>
#include "nfslib.h"
#include "exportfs.h"
#include "xmalloc.h"

struct keycache {
	struct keycache *	k_next;
	struct nfskeyent	k_data;
};

static struct keycache *	keycache = NULL;
static time_t			lastmod = 0;

static void	key_reload(void);


struct nfskey *
key_lookup(char *hname)
{
	struct keycache	*kc;

	key_reload();

	for (kc = keycache; kc; kc = kc->k_next) {
#if 0
		if (matchhostname(kc->k_data.k_hostname, hname))
#else
		if (!strcmp(kc->k_data.k_hostname, hname))
#endif
			return &kc->k_data.k_key;
	}

	return NULL;
}

static void
key_reload(void)
{
	struct stat	stb;
	struct keycache	*cp;
	struct nfskeyent *kp;

	if (stat(_PATH_NFSKEYS, &stb) >= 0 && stb.st_mtime == lastmod)
		return;

	while (keycache) {
		cp = keycache->k_next;
		xfree(keycache);
		keycache = cp;
	}

	setnfskeyent(_PATH_NFSKEYS);
	while ((kp = getnfskeyent()) != NULL) {
		cp = (struct keycache *) xmalloc(sizeof(*cp));
		cp->k_data = *kp;
		cp->k_next = keycache;
		keycache = cp;
	}
	endnfskeyent();

	lastmod = stb.st_mtime;
}
