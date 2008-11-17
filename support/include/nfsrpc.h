/*
 * nfsrpc.h -- RPC client APIs provided by support/nfs
 *
 * Copyright (C) 2008 Oracle Corporation.  All rights reserved.
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

#ifndef __NFS_UTILS_NFSRPC_H
#define __NFS_UTILS_NFSRPC_H

#include <rpc/types.h>

/*
 * Conventional RPC program numbers
 */
#ifndef RPCBPROG
#define RPCBPROG	((rpcprog_t)100000)
#endif
#ifndef PMAPPROG
#define PMAPPROG	((rpcprog_t)100000)
#endif

#ifndef NFSPROG
#define NFSPROG		((rpcprog_t)100003)
#endif
#ifndef MOUNTPROG
#define MOUNTPROG	((rpcprog_t)100005)
#endif
#ifndef NLMPROG
#define NLMPROG		((rpcprog_t)100021)
#endif
#ifndef NSMPROG
#define NSMPROG		((rpcprog_t)100024)
#endif

/*
 * Look up an RPC program name in /etc/rpc
 */
extern rpcprog_t	nfs_getrpcbyname(const rpcprog_t, const char *table[]);

/*
 * Look up a port number in /etc/services for an RPC program
 */
extern unsigned short	nfs_getportbynumber(const rpcprog_t program,
				const unsigned short transport);

/*
 * Acquire an RPC CLIENT *
 */
extern CLIENT		*nfs_get_rpcclient(const struct sockaddr *,
				const socklen_t, const unsigned short,
				const rpcprog_t, const rpcvers_t,
				struct timeval *);

#endif	/* __NFS_UTILS_NFSRPC_H */
