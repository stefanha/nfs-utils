#ifndef _NFS_UMOUNT_H
#define _NFS_UMOUNT_H

#include "conn.h"
#include "mount.h"

int nfsumount(int, char **);
int nfs_call_umount(clnt_addr_t *, dirpath *);
void umount_usage();

#endif
