/*
 * QUOTA    An implementation of the diskquota system for the LINUX
 *          operating system. QUOTA is implemented using the BSD systemcall
 *          interface as the means of communication with the user level.
 *          Should work for all filesystems because of integration into the
 *          VFS layer of the operating system.
 *          This is based on the Melbourne quota system wich uses both user and
 *          group quota files.
 *
 *          This part does the lookup of the info.
 *
 * Version: $Id: rquota_server.c,v 2.9 1996/11/17 16:59:46 mvw Exp mvw $
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License
 *          as published by the Free Software Foundation; either version
 *          2 of the License, or (at your option) any later version.
 */
#include "config.h"

#include <rpc/rpc.h>
#include "rquota.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/quota.h>
#include <dirent.h>
#include <paths.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mntent.h"
#include "xmalloc.h"

#define TYPE_EXTENDED	0x01
#define ACTIVE		0x02

#ifdef ELM
#define _PATH_DEV_DSK   "/dev/dsk/"
#else
#define _PATH_DEV_DSK   "/dev/"
#endif

/*
 * Global unix authentication credentials.
 */
extern struct authunix_parms *unix_cred;

char *nfsmount_to_devname(char *pathname, int *blksize)
{
   DIR *dp;
   dev_t device;
   struct stat st;
   struct dirent *de;
   static char *devicename = NULL;
   static int devicelen = 0;

   if (stat(pathname, &st) == -1)
      return (char *)0;

   device = st.st_dev;
   *blksize = st.st_blksize;

   /*
    * search for devicename in _PATH_DEV_DSK dir.
    */
   if ((dp = opendir(_PATH_DEV_DSK)) == (DIR *)0)
      return (char *)0;

   while ((de = readdir(dp)) != (struct dirent *)0) {
      if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
         continue;

      if (devicelen == 0) {
	 devicelen = sizeof (_PATH_DEV_DSK) + strlen (de->d_name) + 1;
	 devicename = (char *) xmalloc (devicelen);
      }
      else {
	  int newlen = sizeof (_PATH_DEV_DSK) + strlen (de->d_name) + 1;
	  if (newlen > devicelen) {
	      devicelen = newlen;
	      devicename = (char *) xrealloc (devicename, devicelen);
	  }
      }

      strcpy(devicename, _PATH_DEV_DSK);
      strcat(devicename, de->d_name);
      if (stat(devicename, &st) == -1)
         continue;

      if (!S_ISBLK(st.st_mode))
         continue;

      if ((device == st.st_rdev) && S_ISBLK(st.st_mode))
         break;
   }
   closedir(dp);

   if (de != (struct dirent *)0) {
      return devicename;
   } else
      return (char *)0;
}

int in_group (gid_t *gids, u_int len, gid_t gid)
{
   int cnt = 0;

   while (cnt < len) {
      if (gids[cnt] == gid)
         return 1;
      cnt++;
   }
   return 0;
}

getquota_rslt *getquotainfo(int flags, caddr_t *argp, struct svc_req *rqstp)
{
   static getquota_rslt result;
   union {
      getquota_args *args;
      ext_getquota_args *ext_args;
   } arguments;
   FILE *fp;
   struct dqblk dq_dqb;
   struct mntent *mnt;
   char *pathname, *devicename, *qfpathname;
   int fd, err, id, type;

   /*
    * First check authentication.
    */
   if (flags & TYPE_EXTENDED) {
      arguments.ext_args = (ext_getquota_args *)argp;
      id = arguments.ext_args->gqa_id;
      type = arguments.ext_args->gqa_type;
      pathname = arguments.ext_args->gqa_pathp;

      if (type == USRQUOTA && unix_cred->aup_uid && unix_cred->aup_uid != id) {
         result.status = Q_EPERM;
         return(&result);
      }

      if (type == GRPQUOTA && unix_cred->aup_uid && unix_cred->aup_gid != id &&
          !in_group((gid_t *)unix_cred->aup_gids, unix_cred->aup_len, id)) {
         result.status = Q_EPERM;
         return(&result);
      }
   } else {
      arguments.args = (getquota_args *)argp;
      id = arguments.args->gqa_uid;
      type = USRQUOTA;
      pathname = arguments.args->gqa_pathp;

      if (unix_cred->aup_uid && unix_cred->aup_uid != id) {
         result.status = Q_EPERM;
         return(&result);
      }
   }

   /*
    * Convert a nfs_mountpoint to a local devicename.
    */
   if ((devicename = nfsmount_to_devname(pathname,
        &result.getquota_rslt_u.gqr_rquota.rq_bsize)) == (char *)0) {
      result.status = Q_NOQUOTA;   
      return(&result);
   }

   fp = setmntent(MNTTAB, "r");
   while ((mnt = getmntent(fp)) != (struct mntent *)0) {
      if (strcmp(devicename, mnt->mnt_fsname))
         continue;

      if (hasquota(mnt, type, &qfpathname)) {
         if ((err = quotactl(QCMD(Q_GETQUOTA, type), devicename, id,
            (caddr_t)&dq_dqb)) == -1 && !(flags & ACTIVE)) {
            if ((fd = open(qfpathname, O_RDONLY)) < 0)
	    {
	       free(qfpathname);
               continue;
	    }
            free(qfpathname);
            lseek(fd, (long) dqoff(id), L_SET);
            switch (read(fd, &dq_dqb, sizeof(struct dqblk))) {
               case 0:/* EOF */
                  /*
                   * Convert implicit 0 quota (EOF) into an
                   * explicit one (zero'ed dqblk)
                   */
                  memset((caddr_t)&dq_dqb, 0, sizeof(struct dqblk));
                  break;
               case sizeof(struct dqblk):   /* OK */
                  break;
               default:   /* ERROR */
                  close(fd);
                  continue;
            }
            close(fd);
         }
         endmntent(fp);

         if (err && (flags & ACTIVE)) {
            result.status = Q_NOQUOTA;   
            return(&result);
         }

         result.status = Q_OK;   
         result.getquota_rslt_u.gqr_rquota.rq_active = (err == 0) ? TRUE : FALSE;
         /*
          * Make a copy of the info into the last part of the remote quota
          * struct which is exactly the same.
          */
         memcpy((caddr_t *)&result.getquota_rslt_u.gqr_rquota.rq_bhardlimit,
                (caddr_t *)&dq_dqb, sizeof(struct dqblk));

         return(&result);
      }
   }
   endmntent(fp);

   result.status = Q_NOQUOTA;   
   return(&result);
}

getquota_rslt *rquotaproc_getquota_1(getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(0, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getactivequota_1(getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(ACTIVE, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getquota_2(ext_getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(TYPE_EXTENDED, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getactivequota_2(ext_getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(TYPE_EXTENDED | ACTIVE, (caddr_t *)argp, rqstp));
}
