/* 
 * Copyright (C) 1995-1997, 1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, Dec. 1996.
 *
 * NSM for Linux.
 */

#include "config.h"
#include "sm_inter.h"
#include "system.h"
#include "log.h"

/*
 * Paths and filenames.
 */
#if defined(NFS_STATEDIR)
# define DIR_BASE	NFS_STATEDIR "/"
#else
# define DIR_BASE	"/var/lib/nfs/"
#endif
#define SM_DIR		DIR_BASE "sm"
#define SM_BAK_DIR	DIR_BASE "sm.bak"
#define SM_STAT_PATH	DIR_BASE "state"

/*
 * Status definitions.
 */
#define STAT_FAIL	stat_fail
#define STAT_SUCC	stat_succ

/*
 * Function prototypes.
 */
extern void	change_state(void);
extern void	do_regist(u_long, void (*)());
extern void	my_svc_run(void);
extern void	notify_hosts(void);
extern void	shuffle_dirs(void);
extern int	process_notify_list(void);
extern int	process_reply(FD_SET_TYPE *);
extern char *	xstrdup(const char *);
extern void *	xmalloc(size_t);
extern void	xunlink (char *, char *, short int);

/*
 * Host status structure and macros.
 */
stat_chge		SM_stat_chge;
#define MY_NAME		SM_stat_chge.mon_name
#define MY_STATE	SM_stat_chge.state

/*
 * Some timeout values.  (Timeout values are in whole seconds.)
 */
#define CALLBACK_TIMEOUT	 3 /* For client call-backs. */
#define NOTIFY_TIMEOUT		 5 /* For status-change notifications. */
#define SELECT_TIMEOUT		10 /* Max select() timeout when work to do. */
#define MAX_TRIES		 5 /* Max number of tries for any host. */
