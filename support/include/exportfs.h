/*
 * support/include/exportfs.h
 *
 * Declarations for exportfs and mountd
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef EXPORTFS_H
#define EXPORTFS_H

#include <netdb.h>
#include "nfslib.h"

enum {
	MCL_FQDN = 0,
	MCL_SUBNETWORK,
	MCL_IPADDR = MCL_SUBNETWORK,
	MCL_WILDCARD,
	MCL_NETGROUP,
	MCL_ANONYMOUS,
	MCL_MAXTYPES
};

typedef struct mclient {
	struct mclient *	m_next;
	char			m_hostname[NFSCLNT_IDMAX+1];
	int			m_type;
	int			m_naddr;
	struct in_addr		m_addrlist[NFSCLNT_ADDRMAX];
	int			m_exported;	/* exported to nfsd */
	int			m_count;
} nfs_client;

typedef struct mexport {
	struct mexport *	m_next;
	struct mclient *	m_client;
	struct exportent	m_export;
	int			m_exported : 1,	/* known to knfsd */
				m_xtabent  : 1,	/* xtab entry exists */
				m_mayexport: 1,	/* derived from xtabbed */
				m_changed  : 1; /* options (may) have changed */
} nfs_export;

extern nfs_client *		clientlist[MCL_MAXTYPES];
extern nfs_export *		exportlist[MCL_MAXTYPES];

nfs_client *			client_lookup(char *hname);
nfs_client *			client_find(struct hostent *);
void				client_add(nfs_client *);
nfs_client *			client_dup(nfs_client *, struct hostent *);
int				client_gettype(char *hname);
int				client_check(nfs_client *, struct hostent *);
int				client_match(nfs_client *, char *hname);
void				client_release(nfs_client *);
void				client_freeall(void);

int				export_read(char *fname);
void				export_add(nfs_export *);
void				export_reset(nfs_export *);
nfs_export *			export_lookup(char *hname, char *path);
nfs_export *			export_find(struct hostent *, char *path);
struct exportent *		export_allowed(struct hostent *, char *path);
nfs_export *			export_create(struct exportent *);
nfs_export *			export_dup(nfs_export *, struct hostent *);
void				export_freeall(void);
int				export_export(nfs_export *);
int				export_unexport(nfs_export *);

int				xtab_mount_read(void);
int				xtab_export_read(void);
int				xtab_mount_write(void);
int				xtab_export_write(void);
void				xtab_append(nfs_export *);

int				rmtab_read(void);

struct nfskey *			key_lookup(char *hname);

#endif /* EXPORTFS_H */
