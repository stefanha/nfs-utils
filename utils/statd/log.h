/*
 * Copyright (C) 1995 Olaf Kirch
 * Modified by Jeffrey A. Uphoff, 1996, 1997, 1999.
 *
 * NSM for Linux.
 */

/*
 * 	logging functionality
 *	260295	okir
 */

#ifndef _LOCKD_LOG_H_
#define _LOCKD_LOG_H_

#include <syslog.h>

void	log_init(char *name);
void	log_background(void);
void	log_enable(int facility);
int	log_enabled(int facility);
void	log(int level, char *fmt, ...);
void	die(char *fmt, ...);

/*
 * Map per-application severity to system severity. What's fatal for
 * lockd is merely an itching spot from the universe's point of view.
 */
#define L_CRIT		LOG_CRIT
#define L_FATAL		LOG_ERR
#define L_ERROR		LOG_WARNING
#define L_WARNING	LOG_NOTICE
#define L_DEBUG		LOG_DEBUG

#ifdef DEBUG
#define dprintf		log
#else
#define dprintf		if (0) log
#endif

#endif /* _LOCKD_LOG_H_ */
