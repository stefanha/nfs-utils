#ifndef _NFS_NFS_H
#define _NFS_NFS_H

#include <linux/posix_types.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <rpcsvc/nfs_prot.h>
#include <nfs/export.h>

struct dentry;

/*
 * This is the new "dentry style" Linux NFSv2 file handle.
 *
 * The xino and xdev fields are currently used to transport the
 * ino/dev of the exported inode.
 */
struct nfs_fhbase {
	struct dentry *	fb_dentry;	/* dentry cookie */
	u_int32_t		fb_ino;		/* our inode number */
	u_int32_t		fb_dirino;	/* dir inode number */
	u_int32_t		fb_dev;		/* our device */
	u_int32_t		fb_xdev;
	u_int32_t		fb_xino;
};

#define NFS_FH_PADDING		(NFS_FHSIZE - sizeof(struct nfs_fhbase))
struct knfs_fh {
	struct nfs_fhbase	fh_base;
	u_int8_t			fh_cookie[NFS_FH_PADDING];
};

#define fh_dcookie		fh_base.fb_dentry
#define fh_ino			fh_base.fb_ino
#define fh_dirino		fh_base.fb_dirino
#define fh_dev			fh_base.fb_dev
#define fh_xdev			fh_base.fb_xdev
#define fh_xino			fh_base.fb_xino

/*
 * Version of the syscall interface
 */
#define NFSCTL_VERSION		0x0201

/*
 * These are the commands understood by nfsctl().
 */
#define NFSCTL_SVC		0	/* This is a server process. */
#define NFSCTL_ADDCLIENT	1	/* Add an NFS client. */
#define NFSCTL_DELCLIENT	2	/* Remove an NFS client. */
#define NFSCTL_EXPORT		3	/* export a file system. */
#define NFSCTL_UNEXPORT		4	/* unexport a file system. */
#define NFSCTL_UGIDUPDATE	5	/* update a client's uid/gid map. */
#define NFSCTL_GETFH		6	/* get an fh (used by mountd) */
#define NFSCTL_GETFD		7	/* get an fh by path (used by mountd) */

/* Above this is for lockd. */
#define NFSCTL_LOCKD		0x10000
#define LOCKDCTL_SVC		NFSCTL_LOCKD



/* SVC */
struct nfsctl_svc {
	unsigned short		svc_port;
	int			svc_nthreads;
};

/* ADDCLIENT/DELCLIENT */
struct nfsctl_client {
	char			cl_ident[NFSCLNT_IDMAX+1];
	int			cl_naddr;
	struct in_addr		cl_addrlist[NFSCLNT_ADDRMAX];
	int			cl_fhkeytype;
	int			cl_fhkeylen;
	unsigned char		cl_fhkey[NFSCLNT_KEYMAX];
};

/* EXPORT/UNEXPORT */
struct nfsctl_export {
	char			ex_client[NFSCLNT_IDMAX+1];
	char			ex_path[NFS_MAXPATHLEN+1];
	__kernel_dev_t		ex_dev;
	__kernel_ino_t		ex_ino;
	int			ex_flags;
	__kernel_uid_t		ex_anon_uid;
	__kernel_gid_t		ex_anon_gid;
};

/* UGIDUPDATE */
struct nfsctl_uidmap {
	char *			ug_ident;
	__kernel_uid_t		ug_uidbase;
	int			ug_uidlen;
	__kernel_uid_t *	ug_udimap;
	__kernel_gid_t		ug_gidbase;
	int			ug_gidlen;
	__kernel_gid_t *	ug_gdimap;
};

/* GETFH */
struct nfsctl_fhparm {
	struct sockaddr		gf_addr;
	__kernel_dev_t		gf_dev;
	__kernel_ino_t		gf_ino;
	int			gf_version;
};

/* GETFD */
struct nfsctl_fdparm {
	struct sockaddr		gd_addr;
	char			gd_path[NFS_MAXPATHLEN+1];
	int			gd_version;
};

/*
 * This is the argument union.
 */
struct nfsctl_arg {
	int			ca_version;	/* safeguard */
	union {
		struct nfsctl_svc	u_svc;
		struct nfsctl_client	u_client;
		struct nfsctl_export	u_export;
		struct nfsctl_uidmap	u_umap;
		struct nfsctl_fhparm	u_getfh;
		struct nfsctl_fdparm	u_getfd;
		unsigned int		u_debug;
	} u;
#define ca_svc		u.u_svc
#define ca_client	u.u_client
#define ca_export	u.u_export
#define ca_umap		u.u_umap
#define ca_getfh	u.u_getfh
#define ca_getfd	u.u_getfd
#define ca_authd	u.u_authd
#define ca_debug	u.u_debug
};

union nfsctl_res {
	struct knfs_fh		cr_getfh;
	unsigned int		cr_debug;
};

#endif /* _NFS_NFS_H */
