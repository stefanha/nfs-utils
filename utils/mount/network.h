/*
 * network.h -- Provide common network functions for NFS mount/umount
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2007 Chuck Lever <chuck.lever@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 */

#include <rpc/pmap_prot.h>
#include <rpc/clnt.h>

#include "mount.h"

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

#define MNT_SENDBUFSIZE (2048U)
#define MNT_RECVBUFSIZE (1024U)

typedef struct {
	char **hostname;
	struct sockaddr_in saddr;
	struct pmap pmap;
} clnt_addr_t;

/* RPC call timeout values */
static const struct timeval TIMEOUT = { 20, 0 };
static const struct timeval RETRY_TIMEOUT = { 3, 0 };

int probe_bothports(clnt_addr_t *, clnt_addr_t *);
int nfs_gethostbyname(const char *, struct sockaddr_in *);
int get_client_address(struct sockaddr_in *, struct sockaddr_in *);
int nfs_call_umount(clnt_addr_t *, dirpath *);
int clnt_ping(struct sockaddr_in *, const unsigned long,
		const unsigned long, const unsigned int,
		struct sockaddr_in *);

int start_statd(void);

unsigned long nfsvers_to_mnt(const unsigned long);

CLIENT *mnt_openclnt(clnt_addr_t *, int *);
void mnt_closeclnt(CLIENT *, int);
