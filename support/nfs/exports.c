/*
 * support/nfs/export.c
 *
 * Parse the exports file. Derived from the unfsd implementation.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *		Alexander O. Yuriev, <alex@bach.cis.temple.edu>
 *
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "config.h"

#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include "nfslib.h"
#include "exportfs.h"
#include "xmalloc.h"
#include "xlog.h"
#include "xio.h"

#define EXPORT_DEFAULT_FLAGS	\
  (NFSEXP_READONLY|NFSEXP_ROOTSQUASH|NFSEXP_GATHERED_WRITES)

int export_errno;

static char	*efname = NULL;
static XFILE	*efp = NULL;
static int	first;
static int	*squids = NULL, nsquids = 0,
		*sqgids = NULL, nsqgids = 0;

static int	getexport(char *exp, int len);
static int	getpath(char *path, int len);
static int	parseopts(char *cp, struct exportent *ep, int warn);
static int	parsesquash(char *list, int **idp, int *lenp, char **ep);
static int	parsenum(char **cpp);
static int	parsemaptype(char *type);
static void	freesquash(void);
static void	syntaxerr(char *msg);

void
setexportent(char *fname, char *type)
{
	if (efp)
		endexportent();
	if (!fname)
		fname = _PATH_EXPORTS;
	if (!(efp = xfopen(fname, type)))
		xlog(L_ERROR, "can't open %s for %sing",
				fname, strcmp(type, "r")? "writ" : "read");
	efname = strdup(fname);
	first = 1;
}

struct exportent *
getexportent(int fromkernel, int fromexports)
{
	static struct exportent	ee;
	char		exp[512];
	char		rpath[MAXPATHLEN+1];
	char		*opt, *sp;
	int		ok;

	if (!efp)
		return NULL;

	freesquash();
	ee.e_flags = EXPORT_DEFAULT_FLAGS;
	/* some kernels assume the default is sync rather than
	 * async.  More recent kernels always report one or other,
	 * but this test makes sure we assume same as kernel
	 * Ditto for wgather
	 */
	if (fromkernel) {
		ee.e_flags &= ~NFSEXP_ASYNC;
		ee.e_flags &= ~NFSEXP_GATHERED_WRITES;
	}
	ee.e_maptype = CLE_MAP_IDENT;
	ee.e_anonuid = -2;
	ee.e_anongid = -2;
	ee.e_squids = NULL;
	ee.e_sqgids = NULL;
	ee.e_mountpoint = NULL;
	ee.e_nsquids = 0;
	ee.e_nsqgids = 0;

	if (first || (ok = getexport(exp, sizeof(exp))) == 0) {
		ok = getpath(ee.e_path, sizeof(ee.e_path));
		if (ok <= 0)
			return NULL;
		strncpy (ee.m_path, ee.e_path, sizeof (ee.m_path) - 1);
		ee.m_path [sizeof (ee.m_path) - 1] = '\0';
		ok = getexport(exp, sizeof(exp));
	}
	if (ok < 0) {
		xlog(L_ERROR, "expected client(options...)");
		export_errno = EINVAL;
		return NULL;
	}
	first = 0;

	/* Check for default client */
	if (ok == 0)
		exp[0] = '\0';
	if ((opt = strchr(exp, '(')) != NULL) {
		if (opt == exp) 
			xlog(L_WARNING, "No host name given with %s %s, suggest *%s to avoid warning", ee.e_path, exp, exp);
		*opt++ = '\0';
		if (!(sp = strchr(opt, ')')) || sp[1] != '\0') {
			syntaxerr("bad option list");
			export_errno = EINVAL;
			return NULL;
		}
		*sp = '\0';
	} else {
	    xlog(L_WARNING, "No options for %s %s: suggest %s(sync) to avoid warning", ee.e_path, exp, exp);
	}
	if (strlen(exp) >= sizeof(ee.e_hostname)) {
		syntaxerr("client name too long");
		export_errno = EINVAL;
		return NULL;
	}
	strncpy(ee.e_hostname, exp, sizeof (ee.e_hostname) - 1);
	ee.e_hostname[sizeof (ee.e_hostname) - 1] = '\0';

	if (parseopts(opt, &ee, fromexports) < 0)
		return NULL;

	/* resolve symlinks */
	if (realpath(ee.e_path, rpath) != NULL) {
		rpath[sizeof (rpath) - 1] = '\0';
		strncpy(ee.e_path, rpath, sizeof (ee.e_path) - 1);
		ee.e_path[sizeof (ee.e_path) - 1] = '\0';
		strncpy (ee.m_path, ee.e_path, sizeof (ee.m_path) - 1);
		ee.m_path [sizeof (ee.m_path) - 1] = '\0';
	}

	return &ee;
}

void
putexportent(struct exportent *ep)
{
	FILE	*fp;
	int	*id, i;
	char	*esc=ep->e_path;

	if (!efp)
		return;

	fp = efp->x_fp;
	for (i=0; esc[i]; i++)
	        if (iscntrl(esc[i]) || esc[i] == '"' || esc[i] == '\\'|| isspace(esc[i]))
			fprintf(fp, "\\%03o", esc[i]);
		else
			fprintf(fp, "%c", esc[i]);

	fprintf(fp, "\t%s(", ep->e_hostname);
	fprintf(fp, "%s,", (ep->e_flags & NFSEXP_READONLY)? "ro" : "rw");
	fprintf(fp, "%ssync,", (ep->e_flags & NFSEXP_ASYNC)? "a" : "");
	fprintf(fp, "%swdelay,", (ep->e_flags & NFSEXP_GATHERED_WRITES)?
				"" : "no_");
	fprintf(fp, "%shide,", (ep->e_flags & NFSEXP_NOHIDE)?
				"no" : "");
	fprintf(fp, "%scrossmnt,", (ep->e_flags & NFSEXP_CROSSMOUNT)?
				"" : "no");
	fprintf(fp, "%ssecure,", (ep->e_flags & NFSEXP_INSECURE_PORT)?
				"in" : "");
	fprintf(fp, "%sroot_squash,", (ep->e_flags & NFSEXP_ROOTSQUASH)?
				"" : "no_");
	fprintf(fp, "%sall_squash,", (ep->e_flags & NFSEXP_ALLSQUASH)?
				"" : "no_");
	fprintf(fp, "%ssubtree_check,", (ep->e_flags & NFSEXP_NOSUBTREECHECK)?
		"no_" : "");
	fprintf(fp, "%ssecure_locks,", (ep->e_flags & NFSEXP_NOAUTHNLM)?
		"in" : "");
	fprintf(fp, "%sacl,", (ep->e_flags & NFSEXP_NOACL)?
		"no_" : "");
	if (ep->e_flags & NFSEXP_FSID) {
		fprintf(fp, "fsid=%d,", ep->e_fsid);
	}
	if (ep->e_mountpoint)
		fprintf(fp, "mountpoint%s%s,",
			ep->e_mountpoint[0]?"=":"", ep->e_mountpoint);

	fprintf(fp, "mapping=");
	switch (ep->e_maptype) {
	case CLE_MAP_IDENT:
		fprintf(fp, "identity,");
		break;
	case CLE_MAP_UGIDD:
		fprintf(fp, "ugidd,");
		break;
	case CLE_MAP_FILE:
		fprintf(fp, "file,");
		break;
	default:
		xlog(L_ERROR, "unknown mapping type for %s:%s",
					ep->e_hostname, ep->e_path);
	}
	if ((id = ep->e_squids) != NULL) {
		fprintf(fp, "squash_uids=");
		for (i = 0; i < ep->e_nsquids; i += 2)
			if (id[i] != id[i+1])
				fprintf(fp, "%d-%d,", id[i], id[i+1]);
			else
				fprintf(fp, "%d,", id[i]);
	}
	if ((id = ep->e_sqgids) != NULL) {
		fprintf(fp, "squash_gids=");
		for (i = 0; i < ep->e_nsquids; i += 2)
			if (id[i] != id[i+1])
				fprintf(fp, "%d-%d,", id[i], id[i+1]);
			else
				fprintf(fp, "%d,", id[i]);
	}
	fprintf(fp, "anonuid=%d,anongid=%d)\n", ep->e_anonuid, ep->e_anongid);
}

void
endexportent(void)
{
	if (efp)
		xfclose(efp);
	efp = NULL;
	if (efname)
		free(efname);
	efname = NULL;
	freesquash();
}

void
dupexportent(struct exportent *dst, struct exportent *src)
{
	int	n;

	*dst = *src;
	if ((n = src->e_nsquids) != 0) {
		dst->e_squids = (int *) xmalloc(n * sizeof(int));
		memcpy(dst->e_squids, src->e_squids, n * sizeof(int));
	}
	if ((n = src->e_nsqgids) != 0) {
		dst->e_sqgids = (int *) xmalloc(n * sizeof(int));
		memcpy(dst->e_sqgids, src->e_sqgids, n * sizeof(int));
	}
	if (src->e_mountpoint)
		dst->e_mountpoint = strdup(src->e_mountpoint);
}

struct exportent *
mkexportent(char *hname, char *path, char *options)
{
	static struct exportent	ee;

	ee.e_flags = EXPORT_DEFAULT_FLAGS;
	ee.e_maptype = CLE_MAP_IDENT;
	ee.e_anonuid = -2;
	ee.e_anongid = -2;
	ee.e_squids = NULL;
	ee.e_sqgids = NULL;
	ee.e_mountpoint = NULL;
	ee.e_nsquids = 0;
	ee.e_nsqgids = 0;

	if (strlen(hname) >= sizeof(ee.e_hostname)) {
		xlog(L_WARNING, "client name %s too long", hname);
		return NULL;
	}
	strncpy(ee.e_hostname, hname, sizeof (ee.e_hostname) - 1);
	ee.e_hostname[sizeof (ee.e_hostname) - 1] = '\0';
	if (strlen(path) >= sizeof(ee.e_path)) {
		xlog(L_WARNING, "path name %s too long", path);
		return NULL;
	}
	strncpy(ee.e_path, path, sizeof (ee.e_path));
	ee.e_path[sizeof (ee.e_path) - 1] = '\0';
	strncpy (ee.m_path, ee.e_path, sizeof (ee.m_path) - 1);
	ee.m_path [sizeof (ee.m_path) - 1] = '\0';
	if (parseopts(options, &ee, 0) < 0)
		return NULL;
	return &ee;
}

int
updateexportent(struct exportent *eep, char *options)
{
	if (parseopts(options, eep, 0) < 0)
		return 0;
	return 1;
}

/*
 * Parse option string pointed to by cp and set mount options accordingly.
 */
static int
parseopts(char *cp, struct exportent *ep, int warn)
{
	int	had_sync_opt = 0;
	char 	*flname = efname?efname:"command line";
	int	flline = efp?efp->x_line:0;

	squids = ep->e_squids; nsquids = ep->e_nsquids;
	sqgids = ep->e_sqgids; nsqgids = ep->e_nsqgids;

	if (!cp)
		goto out;

	while (isblank(*cp))
		cp++;

	while (*cp) {
		char *opt = strdup(cp);
		char *optstart = cp;
		while (*cp && *cp != ',')
			cp++;
		if (*cp) {
			opt[cp-optstart] = '\0';
			cp++;
		}

		/* process keyword */
		if (strcmp(opt, "ro") == 0)
			ep->e_flags |= NFSEXP_READONLY;
		else if (strcmp(opt, "rw") == 0)
			ep->e_flags &= ~NFSEXP_READONLY;
		else if (!strcmp(opt, "secure"))
			ep->e_flags &= ~NFSEXP_INSECURE_PORT;
		else if (!strcmp(opt, "insecure"))
			ep->e_flags |= NFSEXP_INSECURE_PORT;
		else if (!strcmp(opt, "sync")) {
			had_sync_opt = 1;
			ep->e_flags &= ~NFSEXP_ASYNC;
		} else if (!strcmp(opt, "async")) {
			had_sync_opt = 1;
			ep->e_flags |= NFSEXP_ASYNC;
		} else if (!strcmp(opt, "nohide"))
			ep->e_flags |= NFSEXP_NOHIDE;
		else if (!strcmp(opt, "hide"))
			ep->e_flags &= ~NFSEXP_NOHIDE;
		else if (!strcmp(opt, "crossmnt"))
			ep->e_flags |= NFSEXP_CROSSMOUNT;
		else if (!strcmp(opt, "nocrossmnt"))
			ep->e_flags &= ~NFSEXP_CROSSMOUNT;
		else if (!strcmp(opt, "wdelay"))
			ep->e_flags |= NFSEXP_GATHERED_WRITES;
		else if (!strcmp(opt, "no_wdelay"))
			ep->e_flags &= ~NFSEXP_GATHERED_WRITES;
		else if (strcmp(opt, "root_squash") == 0)
			ep->e_flags |= NFSEXP_ROOTSQUASH;
		else if (!strcmp(opt, "no_root_squash"))
			ep->e_flags &= ~NFSEXP_ROOTSQUASH;
		else if (strcmp(opt, "all_squash") == 0)
			ep->e_flags |= NFSEXP_ALLSQUASH;
		else if (strcmp(opt, "no_all_squash") == 0)
			ep->e_flags &= ~NFSEXP_ALLSQUASH;
		else if (strcmp(opt, "subtree_check") == 0)
			ep->e_flags &= ~NFSEXP_NOSUBTREECHECK;
		else if (strcmp(opt, "no_subtree_check") == 0)
			ep->e_flags |= NFSEXP_NOSUBTREECHECK;
		else if (strcmp(opt, "auth_nlm") == 0)
			ep->e_flags &= ~NFSEXP_NOAUTHNLM;
		else if (strcmp(opt, "no_auth_nlm") == 0)
			ep->e_flags |= NFSEXP_NOAUTHNLM;
		else if (strcmp(opt, "secure_locks") == 0)
			ep->e_flags &= ~NFSEXP_NOAUTHNLM;
		else if (strcmp(opt, "insecure_locks") == 0)
			ep->e_flags |= NFSEXP_NOAUTHNLM;
		else if (strcmp(opt, "acl") == 0)
			ep->e_flags &= ~NFSEXP_NOACL;
		else if (strcmp(opt, "no_acl") == 0)
			ep->e_flags |= NFSEXP_NOACL;
		else if (strncmp(opt, "mapping=", 8) == 0)
			ep->e_maptype = parsemaptype(opt+8);
		else if (strcmp(opt, "map_identity") == 0)	/* old style */
			ep->e_maptype = CLE_MAP_IDENT;
		else if (strcmp(opt, "map_daemon") == 0)	/* old style */
			ep->e_maptype = CLE_MAP_UGIDD;
		else if (strncmp(opt, "anonuid=", 8) == 0) {
			char *oe;
			ep->e_anonuid = strtol(opt+8, &oe, 10);
			if (opt[8]=='\0' || *oe != '\0') {
				xlog(L_ERROR, "%s: %d: bad anonuid \"%s\"\n",
				     flname, flline, opt);	
bad_option:
				free(opt);
				export_errno = EINVAL;
				return -1;
			}
		} else if (strncmp(opt, "anongid=", 8) == 0) {
			char *oe;
			ep->e_anongid = strtol(opt+8, &oe, 10);
			if (opt[8]=='\0' || *oe != '\0') {
				xlog(L_ERROR, "%s: %d: bad anongid \"%s\"\n",
				     flname, flline, opt);	
				goto bad_option;
			}
		} else if (strncmp(opt, "squash_uids=", 12) == 0) {
			if (parsesquash(opt+12, &squids, &nsquids, &cp) < 0) {
				goto bad_option;
			}
		} else if (strncmp(opt, "squash_gids=", 12) == 0) {
			if (parsesquash(opt+12, &sqgids, &nsqgids, &cp) < 0) {
				goto bad_option;
			}
		} else if (strncmp(opt, "fsid=", 5) == 0) {
			char *oe;
			ep->e_fsid = strtoul(opt+5, &oe, 0);
			if (opt[5]=='\0' || *oe != '\0') {
				xlog(L_ERROR, "%s: %d: bad fsid \"%s\"\n",
				     flname, flline, opt);	
				goto bad_option;
			}
			ep->e_flags |= NFSEXP_FSID;
		} else if (strcmp(opt, "mountpoint")==0 ||
			   strcmp(opt, "mp") == 0 ||
			   strncmp(opt, "mountpoint=", 11)==0 ||
			   strncmp(opt, "mp=", 3) == 0) {
			char * mp = strchr(opt, '=');
			if (mp)
				ep->e_mountpoint = strdup(mp+1);
			else
				ep->e_mountpoint = strdup("");
		} else {
			xlog(L_ERROR, "%s:%d: unknown keyword \"%s\"\n",
					flname, flline, opt);
			ep->e_flags |= NFSEXP_ALLSQUASH | NFSEXP_READONLY;
			goto bad_option;
		}
		free(opt);
		while (isblank(*cp))
			cp++;
	}

	ep->e_squids = squids;
	ep->e_sqgids = sqgids;
	ep->e_nsquids = nsquids;
	ep->e_nsqgids = nsqgids;

out:
	if (warn && !had_sync_opt && !(ep->e_flags & NFSEXP_READONLY))
		xlog(L_WARNING, "%s [%d]: No 'sync' or 'async' option specified for export \"%s:%s\".\n"
				"  Assuming default behaviour ('sync').\n"
		     		"  NOTE: this default has changed from previous versions\n",

				flname, flline,
				ep->e_hostname, ep->e_path);

	return 1;
}

static int
parsesquash(char *list, int **idp, int *lenp, char **ep)
{
	char	*cp = list;
	int	id0, id1;
	int	len = *lenp;
	int	*id = *idp;

	if (**ep)
	    *--(*ep) = ',';

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
			return -1;
		}
		if ((len % 8) == 0)
			id = (int *) xrealloc(id, (len + 8) * sizeof(*id));
		id[len++] = id0;
		id[len++] = id1;
		if (!*cp || *cp == ')' || (*cp == ',' && !isdigit(cp[1])))
			break;
		if (*cp != ',') {
			syntaxerr("bad uid/gid list");
			return -1;
		}
		cp++;
	} while(1);

	if (**ep == ',') (*ep)++;

	*lenp = len;
	*idp = id;
	return 1;
}

static void
freesquash(void)
{
	if (squids) {
		xfree (squids);
		squids = NULL;
		nsquids = 0;
	}
	if (sqgids) {
		xfree (sqgids);
		sqgids = NULL;
		nsqgids = 0;
	}
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
parsemaptype(char *type)
{
	if (!strcmp(type, "identity"))
		return CLE_MAP_IDENT;
	if (!strcmp(type, "ugidd"))
		return CLE_MAP_UGIDD;
	if (!strcmp(type, "file"))
		return CLE_MAP_FILE;
	syntaxerr("invalid map type");
	return CLE_MAP_IDENT;	/* default */
}

static int
getpath(char *path, int len)
{
	xskip(efp, " \t\n");
	return xgettok(efp, 0, path, len);
}

static int
getexport(char *exp, int len)
{
	int	ok;

	xskip(efp, " \t");
	if ((ok = xgettok(efp, 0, exp, len)) < 0)
		xlog(L_ERROR, "%s:%d: syntax error",
			efname?"command line":efname, efp->x_line);
	return ok;
}

static void
syntaxerr(char *msg)
{
	xlog(L_ERROR, "%s:%d: syntax error: %s",
			efname, efp?efp->x_line:0, msg);
}

