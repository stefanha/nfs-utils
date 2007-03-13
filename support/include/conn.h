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

#define MNT_SENDBUFSIZE ((u_int)2048)
#define MNT_RECVBUFSIZE ((u_int)1024)

typedef struct {
	char **hostname;
	struct sockaddr_in saddr;
	struct pmap pmap;
} clnt_addr_t;

/* RPC call timeout values */
static const struct timeval TIMEOUT = { 20, 0 };
static const struct timeval RETRY_TIMEOUT = { 3, 0 };

int clnt_ping(struct sockaddr_in *, const u_long, const u_long, const u_int,
	      struct sockaddr_in *);
u_long nfsvers_to_mnt(const u_long);
u_long mntvers_to_nfs(const u_long);
int get_socket(struct sockaddr_in *, u_int, int, int);
CLIENT * mnt_openclnt(clnt_addr_t *, int *);
void mnt_closeclnt(CLIENT *, int);

#endif /* _CONN_H */

