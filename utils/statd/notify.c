/*
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, Oct. 1996.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

/*
 * NSM notify list handling.
 */

#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "misc.h"
#include "statd.h"
#include "notlist.h"

/*
 * Initial (startup) notify list.
 */
notify_list		*inl = NULL;


/* 
 * Get list of hosts from stable storage, build list of hosts to
 * contact. These hosts are added to the global RPC notify list
 * which is processed as soon as statd enters svc_run.
 */
void
notify_hosts(void)
{
	DIR            *nld;
	struct dirent  *de;
	notify_list    *call;

	if (!(nld = opendir(SM_BAK_DIR))) {
		perror("opendir");
		exit(errno);
	}

	while ((de = readdir(nld))) {
		if (de->d_name[0] == '.')
			continue;

		/* The following can happen for loopback NFS mounts
		 * (e.g. with cfsd) */
		if (matchhostname(de->d_name, MY_NAME)
		 || matchhostname(de->d_name, "localhost")) {
			char *fname;
			fname=xmalloc(strlen(SM_BAK_DIR)+sizeof(de->d_name)+2);
			dprintf(L_DEBUG, "We're on our own notify list?!?");
			sprintf(fname, "%s/%s",  SM_BAK_DIR, de->d_name);
			if (unlink(fname)) 
				log(L_ERROR, "unlink(%s): %s", 
					fname, strerror(errno));
			free(fname);
			continue;
		}

		call = nlist_new(MY_NAME, de->d_name, -1);
		NL_TYPE(call) = NOTIFY_REBOOT;
		nlist_insert(&notify, call);
	}

	if (closedir(nld) == -1) {
		perror("closedir");
		exit(1);
	}
}
