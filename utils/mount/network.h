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

#include "conn.h"
#include "mount.h"

#define MNT_SENDBUFSIZE (2048U)
#define MNT_RECVBUFSIZE (1024U)

int probe_bothports(clnt_addr_t *, clnt_addr_t *);
int nfs_gethostbyname(const char *, struct sockaddr_in *);
int nfs_call_umount(clnt_addr_t *, dirpath *);

int start_statd(void);

CLIENT *mnt_openclnt(clnt_addr_t *, int *);
void mnt_closeclnt(CLIENT *, int);
