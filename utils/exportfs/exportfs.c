/*
 * utils/exportfs/exportfs.c
 *
 * Export file systems to knfsd
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 *
 * Extensive changes, 1999, Neil Brown <neilb@cse.unsw.edu.au>
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <netdb.h>
#include <errno.h>
#include "xmalloc.h"
#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "xmalloc.h"
#include "xlog.h"

static void	export_all(int verbose);
static void	exportfs(char *arg, char *options, int verbose);
static void	unexportfs(char *arg, int verbose);
static void	exports_update(int verbose);
static void	dump(int verbose);
static void	error(nfs_export *exp, int err);
static void	usage(void);


int
main(int argc, char **argv)
{
	char	*options = NULL;
	int	f_export = 1;
	int	f_all = 0;
	int	f_verbose = 0;
	int	f_reexport = 0;
	int	f_ignore = 0;
	int	i, c;
	int	new_cache = 0;
	int	force_flush = 0;

	xlog_open("exportfs");

	export_errno = 0;

	while ((c = getopt(argc, argv, "aio:ruvf")) != EOF) {
		switch(c) {
		case 'a':
			f_all = 1;
			break;
		case 'i':
			f_ignore = 1;
			break;
		case 'o':
			options = optarg;
			break;
		case 'r':
			f_reexport = 1;
			f_all = 1;
			break;
		case 'u':
			f_export = 0;
			break;
		case 'v':
			f_verbose = 1;
			break;
		case 'f':
			force_flush = 1;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind != argc && f_all) {
		fprintf(stderr,"exportfs: extra arguments are not permitted with -a or -r.\n");
		return 1;
	}
	if (f_ignore && (f_all || ! f_export)) {
		fprintf(stderr,"exportfs: -i not meaningful with -a, -r or -u.\n");
		return 1;
	}
	if (f_reexport && ! f_export) {
		fprintf(stderr, "exportfs: -r and -u are incompatible.\n");
		return 1;
	}
	new_cache = check_new_cache();
	if (optind == argc && ! f_all) {
		if (force_flush) {
			if (new_cache)
				cache_flush(1);
			else {
				fprintf(stderr, "exportfs: -f: only available with new cache controls: mount /proc/fs/nfsd first\n");
				exit(1);
			}
			return 0;
		} else {
			xtab_export_read();
			dump(f_verbose);
			return 0;
		}
	}

	if (f_export && ! f_ignore)
		export_read(_PATH_EXPORTS);
	if (f_export) {
		if (f_all)
			export_all(f_verbose);
		else
			for (i = optind; i < argc ; i++)
				exportfs(argv[i], options, f_verbose);
	}
	/* If we are unexporting everything, then
	 * don't care about what should be exported, as that
	 * may require DNS lookups..
	 */
	if (! ( !f_export && f_all)) {
		/* note: xtab_*_read does not update entries if they already exist,
		 * so this will not lose new options
		 */
		if (!f_reexport)
			xtab_export_read();
		if (!f_export)
			for (i = optind ; i < argc ; i++)
				unexportfs(argv[i], f_verbose);
		if (!new_cache)
			rmtab_read();
	}
	if (!new_cache) {
		xtab_mount_read();
		exports_update(f_verbose);
	}
	xtab_export_write();
	if (new_cache)
		cache_flush(force_flush);
	if (!new_cache)
		xtab_mount_write();

	return export_errno;
}

static void
exports_update_one(nfs_export *exp, int verbose)
{
		/* check mountpoint option */
	if (exp->m_mayexport &&
	    exp->m_export.e_mountpoint &&
	    !is_mountpoint(exp->m_export.e_mountpoint[0]?
			   exp->m_export.e_mountpoint:
			   exp->m_export.e_path)) {
		printf("%s not exported as %s not a mountpoint.\n",
		       exp->m_export.e_path, exp->m_export.e_mountpoint);
		exp->m_mayexport = 0;
	}
	if (exp->m_mayexport && ((exp->m_exported<1) || exp->m_changed)) {
		if (verbose)
			printf("%sexporting %s:%s to kernel\n",
			       exp->m_exported ?"re":"",
			       exp->m_client->m_hostname,
			       exp->m_export.e_path);
		if (!export_export(exp))
			error(exp, errno);
	}
	if (exp->m_exported && ! exp->m_mayexport) {
		if (verbose)
			printf("unexporting %s:%s from kernel\n",
			       exp->m_client->m_hostname,
			       exp->m_export.e_path);
		if (!export_unexport(exp))
			error(exp, errno);
	}
}


/* we synchronise intention with reality.
 * entries with m_mayexport get exported
 * entries with m_exported but not m_mayexport get unexported
 * looking at m_client->m_type == MCL_FQDN and m_client->m_type == MCL_GSS only
 */
static void
exports_update(int verbose)
{
	nfs_export 	*exp;

	for (exp = exportlist[MCL_FQDN]; exp; exp=exp->m_next) {
		exports_update_one(exp, verbose);
	}
	for (exp = exportlist[MCL_GSS]; exp; exp=exp->m_next) {
		exports_update_one(exp, verbose);
	}
}
			
/*
 * export_all finds all entries and
 *    marks them xtabent and mayexport so that they get exported
 */
static void
export_all(int verbose)
{
	nfs_export	*exp;
	int		i;

	for (i = 0; i < MCL_MAXTYPES; i++) {
		for (exp = exportlist[i]; exp; exp = exp->m_next) {
			if (verbose)
				printf("exporting %s:%s\n",
				       exp->m_client->m_hostname, 
				       exp->m_export.e_path);
			exp->m_xtabent = 1;
			exp->m_mayexport = 1;
			exp->m_changed = 1;
		}
	}
}


static void
exportfs(char *arg, char *options, int verbose)
{
	struct exportent *eep;
	nfs_export	*exp;
	struct hostent	*hp = NULL;
	char		*path;
	char		*hname = arg;
	int		htype;

	if ((path = strchr(arg, ':')) != NULL)
		*path++ = '\0';

	if (!path || *path != '/') {
		fprintf(stderr, "Invalid exporting option: %s\n", arg);
		return;
	}

	if ((htype = client_gettype(hname)) == MCL_FQDN &&
	    (hp = gethostbyname(hname)) != NULL) {
		struct hostent *hp2 = hostent_dup (hp);
		hp = gethostbyaddr(hp2->h_addr, hp2->h_length,
				   hp2->h_addrtype);
		if (hp) {
			free(hp2);
			hp = hostent_dup(hp);
		} else
			hp = hp2;
		exp = export_find(hp, path);
		hname = hp->h_name;
	} else {
		exp = export_lookup(hname, path, 0);
	}

	if (!exp) {
		if (!(eep = mkexportent(hname, path, options)) ||
		    !(exp = export_create(eep, 0))) {
			if (hp) free (hp);
			return;
		}
	} else if (!updateexportent(&exp->m_export, options)) {
		if (hp) free (hp);
		return;
	}

	if (verbose)
		printf("exporting %s:%s\n", exp->m_client->m_hostname, 
			exp->m_export.e_path);
	exp->m_xtabent = 1;
	exp->m_mayexport = 1;
	exp->m_changed = 1;
	if (hp) free (hp);
}

static void
unexportfs(char *arg, int verbose)
{
	nfs_export	*exp;
	struct hostent	*hp = NULL;
	char		*path;
	char		*hname = arg;
	int		htype;

	if ((path = strchr(arg, ':')) != NULL)
		*path++ = '\0';

	if (!path || *path != '/') {
		fprintf(stderr, "Invalid unexporting option: %s\n",
			arg);
		return;
	}

	if ((htype = client_gettype(hname)) == MCL_FQDN) {
		if ((hp = gethostbyname(hname)) != 0) {
			hp = hostent_dup (hp);
			hname = (char *) hp->h_name;
		}
	}

	for (exp = exportlist[htype]; exp; exp = exp->m_next) {
		if (path && strcmp(path, exp->m_export.e_path))
			continue;
		if (htype != exp->m_client->m_type)
			continue;
		if (htype == MCL_FQDN
		    && !matchhostname(exp->m_export.e_hostname,
					  hname))
			continue;
		if (htype != MCL_FQDN
		    && strcasecmp(exp->m_export.e_hostname, hname))
			continue;
		if (verbose) {
#if 0
			if (exp->m_exported) {
				printf("unexporting %s:%s from kernel\n",
				       exp->m_client->m_hostname,
				       exp->m_export.e_path);
			}
			else
#endif
				printf("unexporting %s:%s\n",
					exp->m_client->m_hostname, 
					exp->m_export.e_path);
		}
#if 0
		if (exp->m_exported && !export_unexport(exp))
			error(exp, errno);
#endif
		exp->m_xtabent = 0;
		exp->m_mayexport = 0;
	}

	if (hp) free (hp);
}

static char
dumpopt(char c, char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	printf("%c", c);
	vprintf(fmt, ap);
	va_end(ap);
	return ',';
}

static void
dump(int verbose)
{
	nfs_export	*exp;
	struct exportent *ep;
	int		htype;
	char		*hname, c;

	for (htype = 0; htype < MCL_MAXTYPES; htype++) {
		for (exp = exportlist[htype]; exp; exp = exp->m_next) {
			ep = &exp->m_export;
			if (!exp->m_xtabent)
			    continue; /* neilb */
			if (htype == MCL_ANONYMOUS)
				hname = "<world>";
			else
				hname = ep->e_hostname;
			if (strlen(ep->e_path) > 14)
				printf("%-14s\n\t\t%s", ep->e_path, hname);
			else
				printf("%-14s\t%s", ep->e_path, hname);
			if (!verbose) {
				printf("\n");
				continue;
			}
			c = '(';
			if (ep->e_flags & NFSEXP_READONLY)
				c = dumpopt(c, "ro");
			else
				c = dumpopt(c, "rw");
			if (ep->e_flags & NFSEXP_ASYNC)
				c = dumpopt(c, "async");
			if (ep->e_flags & NFSEXP_GATHERED_WRITES)
				c = dumpopt(c, "wdelay");
			if (ep->e_flags & NFSEXP_NOHIDE)
				c = dumpopt(c, "nohide");
			if (ep->e_flags & NFSEXP_CROSSMOUNT)
				c = dumpopt(c, "crossmnt");
			if (ep->e_flags & NFSEXP_INSECURE_PORT)
				c = dumpopt(c, "insecure");
			if (ep->e_flags & NFSEXP_ROOTSQUASH)
				c = dumpopt(c, "root_squash");
			else
				c = dumpopt(c, "no_root_squash");
			if (ep->e_flags & NFSEXP_ALLSQUASH)
				c = dumpopt(c, "all_squash");
			if (ep->e_flags & NFSEXP_NOSUBTREECHECK)
				c = dumpopt(c, "no_subtree_check");
			if (ep->e_flags & NFSEXP_NOAUTHNLM)
				c = dumpopt(c, "insecure_locks");
			if (ep->e_flags & NFSEXP_FSID)
				c = dumpopt(c, "fsid=%d", ep->e_fsid);
			if (ep->e_mountpoint)
				c = dumpopt(c, "mountpoint%s%s", 
					    ep->e_mountpoint[0]?"=":"", 
					    ep->e_mountpoint);
			if (ep->e_maptype == CLE_MAP_UGIDD)
				c = dumpopt(c, "mapping=ugidd");
			else if (ep->e_maptype == CLE_MAP_FILE)
				c = dumpopt(c, "mapping=file");
			if (ep->e_anonuid != -2)
				c = dumpopt(c, "anonuid=%d", ep->e_anonuid);
			if (ep->e_anongid != -2)
				c = dumpopt(c, "anongid=%d", ep->e_anongid);

			printf("%c\n", (c != '(')? ')' : ' ');
		}
	}
}

static void
error(nfs_export *exp, int err)
{
	fprintf(stderr, "%s:%s: %s\n", exp->m_client->m_hostname, 
		exp->m_export.e_path, strerror(err));
}

static void
usage(void)
{
	fprintf(stderr, "usage: exportfs [-aruv] [host:/path]\n");
	exit(1);
}
