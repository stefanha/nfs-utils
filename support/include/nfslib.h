/*
 * support/include/nfslib.h
 *
 * General support functions for NFS user-space programs.
 *
 * Copyright (C) 1995 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef NFSLIB_H
#define NFSLIB_H

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <paths.h>
#include <rpcsvc/nfs_prot.h>
#include <nfs/nfs.h>
#include "xlog.h"

#ifndef _PATH_EXPORTS
#define _PATH_EXPORTS		"/etc/exports"
#endif
#ifndef _PATH_XTAB
#define _PATH_XTAB		NFS_STATEDIR "/xtab"
#endif
#ifndef _PATH_XTABTMP
#define _PATH_XTABTMP		NFS_STATEDIR "/xtab.tmp"
#endif
#ifndef _PATH_ETAB
#define _PATH_ETAB		NFS_STATEDIR "/etab"
#endif
#ifndef _PATH_ETABTMP
#define _PATH_ETABTMP		NFS_STATEDIR "/etab.tmp"
#endif
#ifndef _PATH_RMTAB
#define _PATH_RMTAB		NFS_STATEDIR "/rmtab"
#endif
#ifndef _PATH_RMTABTMP
#define _PATH_RMTABTMP		_PATH_RMTAB ".tmp"
#endif
#ifndef _PATH_PROC_EXPORTS
#define	_PATH_PROC_EXPORTS	"/proc/fs/nfs/exports"
#endif

enum cle_maptypes {
	CLE_MAP_IDENT = 0,
	CLE_MAP_FILE,
	CLE_MAP_UGIDD,
};

/*
 * Data related to a single exports entry as returned by getexportent.
 * FIXME: export options should probably be parsed at a later time to 
 * allow overrides when using exportfs.
 */
struct exportent {
	char		e_hostname[NFSCLNT_IDMAX+1];
	char		e_path[NFS_MAXPATHLEN+1];
	/* The mount path may be different from the exported path due
	   to submount. It may change for every mount. The idea is we
	   set m_path every time when we process a mount. We should not
	   use it for anything else. */
	char		m_path[NFS_MAXPATHLEN+1];
	int		e_flags;
	int		e_maptype;
	int		e_anonuid;
	int		e_anongid;
	int *		e_squids;
	int		e_nsquids;
	int *		e_sqgids;
	int		e_nsqgids;
};

struct rmtabent {
	char		r_client[NFSCLNT_IDMAX+1];
	char		r_path[NFS_MAXPATHLEN+1];
	int		r_count;
};

/*
 * configuration file parsing
 */
void			setexportent(char *fname, char *type);
struct exportent *	getexportent(void);
void			putexportent(struct exportent *xep);
void			endexportent(void);
struct exportent *	mkexportent(char *hname, char *path, char *opts);
void			dupexportent(struct exportent *dst,
					struct exportent *src);
int			updateexportent(struct exportent *eep, char *options);

int			setrmtabent(char *type);
struct rmtabent *	getrmtabent(int log, long *pos);
void			putrmtabent(struct rmtabent *xep, long *pos);
void			endrmtabent(void);
void			rewindrmtabent(void);
FILE *			fsetrmtabent(char *fname, char *type);
struct rmtabent *	fgetrmtabent(FILE *fp, int log, long *pos);
void			fputrmtabent(FILE *fp, struct rmtabent *xep, long *pos);
void			fendrmtabent(FILE *fp);
void			frewindrmtabent(FILE *fp);

/*
 * wildmat borrowed from INN
 */
int			wildmat(char *text, char *pattern);

/*
 * nfsd library functions.
 */
int			nfsctl(int, struct nfsctl_arg *, union nfsctl_res *);
int			nfssvc(int port, int nrservs);
int			nfsaddclient(struct nfsctl_client *clp);
int			nfsdelclient(struct nfsctl_client *clp);
int			nfsexport(struct nfsctl_export *exp);
int			nfsunexport(struct nfsctl_export *exp);
struct nfs_fh_len *	getfh_old(struct sockaddr *addr, dev_t dev, ino_t ino);
struct nfs_fh_len *	getfh(struct sockaddr *addr, const char *);
struct nfs_fh_len *	getfh_size(struct sockaddr *addr, const char *, int size);

/* lockd. */
int			lockdsvc();

#endif /* NFSLIB_H */
