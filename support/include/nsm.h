/*
 * Copyright 2009 Oracle.  All rights reserved.
 *
 * This file is part of nfs-utils.
 *
 * nfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * nfs-utils is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nfs-utils.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * NSM for Linux.
 */

#ifndef NFS_UTILS_SUPPORT_NSM_H
#define NFS_UTILS_SUPPORT_NSM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <netdb.h>
#include <time.h>

#include "sm_inter.h"

typedef unsigned int
		(*nsm_populate_t)(const char *hostname,
				const struct sockaddr *sap,
				const struct mon *mon,
				const time_t timestamp);

/* file.c */

extern _Bool	nsm_setup_pathnames(const char *progname,
				const char *parentdir);
extern _Bool	nsm_is_default_parentdir(void);
extern _Bool	nsm_drop_privileges(const int pidfd);

extern int	nsm_get_state(_Bool update);
extern void	nsm_update_kernel_state(const int state);

extern unsigned int
		nsm_retire_monitored_hosts(void);
extern unsigned int
		nsm_load_monitor_list(nsm_populate_t func);
extern unsigned int
		nsm_load_notify_list(nsm_populate_t func);

extern _Bool	nsm_insert_monitored_host(const char *hostname,
			const struct sockaddr *sap, const struct mon *m);
extern void	nsm_delete_monitored_host(const char *hostname);
extern void	nsm_delete_notified_host(const char *hostname);

#endif	/* !NFS_UTILS_SUPPORT_NSM_H */
