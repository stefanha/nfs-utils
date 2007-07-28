/* 
 * conn.h -- Connection routines for NFS mount / umount code.
 *
 * 2006-06-06 Amit Gud <agud@redhat.com>
 * - Moved code snippets here from util-linux/mount
 */

#ifndef _CONN_H
#define _CONN_H

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

#include <rpc/pmap_prot.h>
#include <rpc/clnt.h>

typedef struct {
	char **hostname;
	struct sockaddr_in saddr;
	struct pmap pmap;
} clnt_addr_t;

/* RPC call timeout values */
static const struct timeval TIMEOUT = { 20, 0 };
static const struct timeval RETRY_TIMEOUT = { 3, 0 };

#endif /* _CONN_H */

