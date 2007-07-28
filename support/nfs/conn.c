/*
 * conn.c -- NFS client mount / umount connection code support functions
 *
 * 2006-06-06 Amit Gud <agud@redhat.com>
 * - Moved code snippets to nfs-utils/support/nfs from util-linux/mount/nfsmount.c
 *
 */

#include "config.h"
#include <errno.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conn.h"

