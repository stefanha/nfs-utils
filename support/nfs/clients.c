/*
 * support/nfs/nfsclient.c
 *
 * Parse the nfsclients file.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include "xmalloc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "xio.h"

static XFILE	*cfp = NULL;
static int	*squash_uids = NULL,
		*squash_gids = NULL;
static int	squash_uidlen = 0,
		squash_gidlen = 0;
static char	*hosts = NULL;

static int	parsesquash(char *list, int **idp, int *lenp);
static int	parsenum(char **cpp);
static int	parsekey(struct nfskey *keyp, char *str);
static int	hexdigit(char c);
static int	gettag(char *tag, int len);
static int	getattr(char *attr, int alen, char *value, int vlen);
static void	syntaxerr(char *msg);

#ifndef isblank
#define isblank(c)	((c) == ' ' || (c) == '\t')
#endif

void
setnfsclntent(char *fname)
{
	if (cfp)
		xfclose(cfp);
	if (!fname)
		fname = _PATH_NFSCLIENTS;
	if ((cfp = xfopen(fname)) == NULL)
		xlog(L_ERROR, "can't open %s for reading", fname);
}

struct nfsclntent *
getnfsclntent(void)
{
	static struct nfsclntent cle;
	static char	*hostptr = NULL;
	char		attr[32], val[512], *sp;
	int		ok;

	if (!cfp)
		endnfsclntent();

again:
	if (hosts) {
		if (hostptr)
			goto nexthost;
		xfree(hosts);
		hosts = NULL;
	}

	if ((ok = gettag(cle.c_tag, sizeof(cle.c_tag))) < 0)
		syntaxerr("expected tag");
	if (ok <= 0)
		return NULL;

	cle.c_hostname[0] = '\0';
	cle.c_fhkey.k_type = CLE_KEY_NONE;
	cle.c_mapping = CLE_MAP_IDENT;
	cle.c_anonuid = -2;
	cle.c_anongid = -2;

	if (squash_uids)
		xfree(squash_uids);
	if (squash_gids)
		xfree(squash_gids);
	squash_uids = squash_gids = NULL;
	squash_uidlen = squash_gidlen = 0;

	while (ok) {
		if ((ok = getattr(attr, sizeof(attr), val, sizeof(val))) < 0)
			return NULL;
		if (!ok)
			break;
		if (attr[0] == 'h' && !strcmp(attr, "hosts")) {
			int	l0 = hosts? strlen(hosts) : 0;

			hosts = (char *) xrealloc(hosts, l0+strlen(val)+2);
			if (l0)
				hosts[l0++] = ':';
			strcpy(hosts+l0, val);
		} else
		if (attr[0] == 'f' && !strcmp(attr, "fhmac")) {
			if (!parsekey(&cle.c_fhkey, val))
				return NULL;
		} else
		if (attr[0] == 'm' && !strcmp(attr, "mapping")) {
			if (!strcmp(val, "identity"))
				cle.c_mapping = CLE_MAP_IDENT;
			else if (!strcmp(val, "file"))
				cle.c_mapping = CLE_MAP_FILE;
			else if (!strcmp(val, "daemon"))
				cle.c_mapping = CLE_MAP_UGIDD;
			else {
				syntaxerr("invalid mapping type");
				return NULL;
			}
		} else
		if (attr[0] == 's' && !strcmp(attr, "squash_uids")) {
			if (!parsesquash(val, &squash_uids, &squash_uidlen))
				return NULL;
		} else
		if (attr[0] == 's' && !strcmp(attr, "squash_gids")) {
			if (!parsesquash(val, &squash_gids, &squash_gidlen))
				return NULL;
		} else
		if (attr[0] == 'a' && !strcmp(attr, "anonuid"))
			cle.c_anonuid = atoi(val);
		else
		if (attr[0] == 'a' && !strcmp(attr, "anongid"))
			cle.c_anongid = atoi(val);
		else
			syntaxerr("unknown attribute");
	}

	cle.c_squashuids = squash_uids;
	cle.c_squashgids = squash_gids;

	/* This is the anon entry */
	if (!hosts) {
		if (strcmp(cle.c_tag, "anonymous")) {
			xlog(L_ERROR, "nfsclients entry %s allows anonymous "
					"access. Ignored.", cle.c_tag);
			goto again;
		}
		return &cle;
	}
	hostptr = hosts;

nexthost:
	if (*hostptr == ':' && strcmp(cle.c_tag, "anonymous")) {
		xlog(L_ERROR, "nfsclients entry %s allows anonymous "
				"access. Ignored.", cle.c_tag);
		while (*hostptr == ':')
			hostptr++;
	}

	/* Ignore trailing colons */
	if (!*hostptr) {
		hostptr = NULL;
		goto again;
	}

	sp = hostptr;
	hostptr = strchr(hostptr, ':');
	if (hostptr)
		*hostptr++ = '\0';
	strncpy(cle.c_hostname, sp, sizeof(cle.c_hostname) - 1);
	cle.c_hostname [sizeof(cle.c_hostname) - 1] = '\0';
	return &cle;
}

void
endnfsclntent(void)
{
	if (cfp)
		xfclose(cfp);
	if (squash_uids)
		xfree(squash_uids);
	if (squash_gids)
		xfree(squash_gids);
	if (hosts)
		xfree(hosts);
	cfp = NULL;
	squash_uids = NULL;
	squash_gids = NULL;
	hosts = NULL;
}

static int
parsekey(struct nfskey *keyp, char *str)
{
	char	*sp;
	int	i, l, x0, x1;


	if ((sp = strchr(str, ':')) != NULL)
		*sp++ = '\0';
	if (!strcmp(str, "null"))
		keyp->k_type = CLE_KEY_NULL;
	else if (!strcmp(str, "md5"))
		keyp->k_type = CLE_KEY_MD5;
	else if (!strcmp(str, "sha"))
		keyp->k_type = CLE_KEY_SHA;
	else {
		syntaxerr("unknown key type");
		return 0;
	}
	if (keyp->k_type == CLE_KEY_NULL) {
		keyp->k_len = 0;
		if (sp)
			syntaxerr("unexpected key data for null key");
		return sp? 0 : 1;
	} else if (sp) {
		if ((l = strlen(sp)) & 1) {
			syntaxerr("odd key length");
			return 0;
		}

		l >>= 1;
		for (i = 0; i < l && i < sizeof(keyp->k_key); i++, sp += 2) {
			if ((x0 = hexdigit(sp[0])) == 0xff ||
			    (x1 = hexdigit(sp[1])) == 0xff) {
				syntaxerr("bad key digit");
				return 0;
			}
			keyp->k_key[i] = (x0 << 4) | x1;
		}
		keyp->k_len = i;
		return 1;
	}
	return 0;
}

static int
hexdigit(char c)
{
	if ((c = tolower(c)) >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return 0xff;
}

static int
parsesquash(char *list, int **idp, int *lenp)
{
	char	*cp = list;
	int	id0, id1;
	int	len = *lenp;
	int	*id = *idp;

	do {
		id0 = parsenum(&cp);
		if (*cp == '-') {
			cp++;
			id1 = parsenum(&cp);
		} else {
			id1 = id0;
		}
		if (id0 == -1 || id1 == -1) {
			syntaxerr("uid/gid -1 not permitted");
			return 0;
		}
		if ((len % 8) == 0)
			id = (int *) xrealloc(id, (len + 9) * sizeof(*id));
		id[len++] = id0;
		id[len++] = id1;
		if (!*cp)
			break;
		if (*cp != ',') {
			syntaxerr("bad uid/gid list");
			return 0;
		}
		cp++;
	} while(1);

	id[len] = -1;
	*lenp = len;
	*idp = id;
	return 1;
}

static int
parsenum(char **cpp)
{
	char	*cp = *cpp, c;
	int	num = 0;

	if (**cpp == '-')
		(*cpp)++;
	while (isdigit(**cpp))
		(*cpp)++;
	c = **cpp; **cpp = '\0'; num = atoi(cp); **cpp = c;
	return num;
}

static int
gettag(char *tag, int len)
{
	xskip(cfp, " \t\n");
	return xgettok(cfp, ':', tag, len);
}

static int
getattr(char *attr, int alen, char *value, int vlen)
{
	int	ok;

	xskip(cfp, " \t");
	if ((ok = xgettok(cfp, '=', attr, alen)) < 0)
		xlog(L_ERROR, "error parsing attribute");
	if (ok <= 0)
		return ok;
	xskip(cfp, " \t=");

	return xgettok(cfp, 0, value, vlen);
}

static void
syntaxerr(char *msg)
{
	xlog(L_ERROR, "syntax error in nfsclients file (line %d): %s",
				cfp->x_line, msg);
}

