/*
 * QUOTA    An implementation of the diskquota system for the LINUX
 *          operating system. QUOTA is implemented using the BSD systemcall
 *          interface as the means of communication with the user level.
 *          Should work for all filesystems because of integration into the
 *          VFS layer of the operating system.
 *          This is based on the Melbourne quota system wich uses both user and
 *          group quota files.
 *
 *          Determines if a filesystem has quota enabled and how the quotafile
 *          is named.
 *
 * Version: $Id: hasquota.c,v 2.6 1996/11/17 16:59:46 mvw Exp mvw $
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License
 *          as published by the Free Software Foundation; either version
 *          2 of the License, or (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#define _LINUX_QUOTA_VERSION 1

#include <sys/types.h>
#include <sys/quota.h>
#include <limits.h>
#include <string.h>
#include "mntent.h"
#include "xmalloc.h"

#undef min
#define min(x,y) ((x) < (y)) ? (x) : (y)

#define CORRECT_FSTYPE(type) \
((!strcmp(type,MNTTYPE_EXT2)) || (!strcmp(type,MNTTYPE_EXT3)))

char *qfextension[] = INITQFNAMES;

/*
 * Check to see if a particular quota is to be enabled.
 */
int
hasquota(struct mntent *mnt, int type, char **qfnamep)
{
   char *qfname = QUOTAFILENAME;
   char *option, *pathname;

   if (!CORRECT_FSTYPE(mnt->mnt_type))
      return (0);

   if (((type == USRQUOTA) && (option = hasmntopt(mnt, MNTOPT_USRQUOTA)) != (char *)0) ||
       ((type == GRPQUOTA) && (option = hasmntopt(mnt, MNTOPT_GRPQUOTA)) != (char *)0)) {
      if ((pathname = strchr(option, '=')) == (char *)0) {
	  *qfnamep=xmalloc(strlen(mnt->mnt_dir)+strlen(qfname)+strlen(qfextension[type])+3);
	  (void) sprintf(*qfnamep, "%s%s%s.%s", mnt->mnt_dir,
			(mnt->mnt_dir[strlen(mnt->mnt_dir) - 1] == '/') ? "" : "/",
			qfname, qfextension[type]);
      } else {
         if ((option = strchr(++pathname, ',')) != (char *)NULL) {
	    int len=option-pathname;
	    *qfnamep=xmalloc(len);
            memcpy(*qfnamep, pathname, len-1);
            (*qfnamep) [len-1] = '\0';
	 }
         else {
	    *qfnamep=xstrdup(pathname);
	 }
      }
      return (1);
   } else
      return (0);
}
